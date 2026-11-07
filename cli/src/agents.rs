//! Coding agents inside envs: install (through short-lived egress grants), link the luoto
//! briefing into the agent's global instructions, register the sandbox MCP server, run.

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use chrono::TimeDelta;
use luoto_shared::policy::Rule;
use luoto_shared::profiles;

use std::collections::BTreeMap;

use crate::config::{EnvFile, ProviderValue};
use crate::connect::exec_login;
use crate::env::{self, Ctx, UID};
use crate::text::sh_quote;
use crate::{names, sync};

pub fn list() -> Result<ExitCode> {
    println!("agents:");
    for n in profiles::agent_names() {
        let a = profiles::agent(n).context("agent profile")?;
        println!(
            "  {n:<10} {} (providers: {})",
            a.description,
            a.providers.join(", ")
        );
    }
    println!("\nproviders (configure under [credentials.<provider>]):");
    for n in profiles::provider_names() {
        let p = profiles::provider(n).context("provider profile")?;
        let kinds: Vec<&String> = p.auth.keys().collect();
        println!(
            "  {n:<10} {} — {} via {}",
            p.description,
            p.host,
            kinds
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn profile(agent: &str) -> Result<profiles::Agent> {
    profiles::agent(agent)
        .with_context(|| format!("unknown agent `{agent}` (see `luoto agent list`)"))
}

/// Whether the agent's command is on the dev user's login PATH.
fn installed(ctx: &Ctx, dev: &str, a: &profiles::Agent) -> bool {
    ctx.rt.exec_sh(
        dev,
        UID,
        &format!("command -v {} >/dev/null", sh_quote(&a.command)),
    )
}

/// Install `agent` in a running env unless it is there: grant its install hosts for 15
/// minutes, run the install steps as the dev user, revoke the grants; then wire up briefing
/// and MCP. `up` calls it for the agents the config lists ([`ensure`]).
pub fn install(ctx: &Ctx, env_name: &str, agent: &str) -> Result<()> {
    let a = profile(agent)?;
    let dev = names::dev(env_name);
    if !installed(ctx, &dev, &a) && !a.install.is_empty() {
        println!(
            "installing {} in `{env_name}` (temporary access: {})…",
            a.description,
            a.install_hosts.join(", ")
        );
        let rules: Vec<Rule> = a.install_hosts.iter().map(|h| Rule::read(h)).collect();
        let script = a.install.join(" && ");
        let status = sync::with_grants(
            ctx,
            env_name,
            &rules,
            TimeDelta::minutes(15),
            &format!("installing {agent} (auto-revoked)"),
            || {
                ctx.rt.interactive([
                    "exec",
                    "-u",
                    UID,
                    "-w",
                    "/workspace",
                    &dev,
                    "sh",
                    "-lc",
                    &script,
                ])
            },
        )??;
        if status.success() && !installed(ctx, &dev, &a) {
            bail!(
                "{agent} installed, but `{}` is not on the login PATH (~/.local/bin, mise shims)",
                a.command
            );
        }
        if !status.success() {
            bail!(
                "installing {agent} failed; see `luoto egress -e {env_name} --denied --since 15m`"
            );
        }
    }
    let opts = env::layered(ctx, env_name)?
        .agents
        .get(agent)
        .cloned()
        .unwrap_or_default();
    register(ctx, env_name, &a, &opts)?;
    Ok(())
}

/// For the agents `cfg` lists (the accepted luoto.toml's included) with no credential: ask
/// how each authenticates on a terminal, as `agent add` always has, else let it log in
/// inside; the answer goes into the env's config. `up` asks before it starts the gate, so the
/// gate has it.
pub fn ask_missing(ctx: &Ctx, env_name: &str, cfg: &crate::config::EnvConfig) -> Result<()> {
    let own = EnvFile::load(&ctx.paths, env_name)?.cfg;
    let lacking: Vec<String> = cfg
        .agents
        .names()
        .filter(|n| profiles::agent(n).is_some_and(|a| !has_credential(&own, &a)))
        .cloned()
        .collect();
    credentials(ctx, env_name, &lacking, crate::prompt::interactive())
}

/// Install each of `agents` that the env lacks (one call finds them) and say how it logs in,
/// unless `quiet`.
pub fn ensure(ctx: &Ctx, env_name: &str, agents: &[String], quiet: bool) -> Result<()> {
    let wanted: Vec<(&String, profiles::Agent)> = agents
        .iter()
        .filter_map(|n| Some((n, profiles::agent(n)?)))
        .filter(|(_, a)| !a.install.is_empty())
        .collect();
    if wanted.is_empty() {
        return Ok(());
    }
    let script = wanted
        .iter()
        .map(|(_, a)| {
            let c = sh_quote(&a.command);
            format!("command -v {c} >/dev/null || echo {c}")
        })
        .collect::<Vec<_>>()
        .join("; ")
        + "; true";
    let dev = names::dev(env_name);
    // A login shell, for the PATH agents install to (~/.local/bin, mise shims).
    let out = ctx
        .rt
        .run(["exec", "-u", UID, dev.as_str(), "sh", "-lc", &script])
        .context("look for the env's agents")?;
    let missing: Vec<&str> = out.lines().map(str::trim).collect();
    let cfg = EnvFile::load(&ctx.paths, env_name)?.cfg;
    for (name, a) in &wanted {
        if missing.contains(&a.command.as_str()) {
            install(ctx, env_name, name)?;
            if quiet {
                continue;
            }
            println!(
                "{} is ready ({}): luoto agent run -e {env_name} {name}",
                a.description,
                auth_summary(&cfg, a, env_name)
            );
        }
    }
    Ok(())
}

/// How agent `a` authenticates in the env, in a few words.
fn auth_summary(cfg: &crate::config::EnvConfig, a: &profiles::Agent, env_name: &str) -> String {
    let found = a
        .providers
        .iter()
        .find_map(|p| Some((p, cfg.credentials.providers.get(p)?)));
    match found {
        _ if a.providers.is_empty() => "no credential needed".into(),
        Some((_, entries))
            if entries
                .values()
                .any(|v| matches!(v, ProviderValue::Flag(true))) =>
        {
            format!(
                "it logs in inside: `luoto shell -e {env_name}`, then `{}`",
                a.command
            )
        }
        Some((p, entries)) => format!(
            "the gate adds [credentials.{p}] {}",
            entries.keys().cloned().collect::<Vec<_>>().join(", ")
        ),
        None => format!("no credential yet: {}", credential_help(a, env_name)),
    }
}

/// For each of `agents` that has no credential in the env yet: ask for one on a terminal (as
/// `agent add` does), else log in inside where the provider allows it, else say how to add one.
fn credentials(ctx: &Ctx, env_name: &str, agents: &[String], interactive: bool) -> Result<()> {
    for a in agents.iter().filter_map(|n| profiles::agent(n)) {
        if !ask_credential(ctx, env_name, &a, interactive)? {
            println!("\n{}", credential_help(&a, env_name));
        }
    }
    Ok(())
}

/// Whether agent `a` can authenticate in the env, asking for a credential when `interactive`
/// and it can't yet; the answer goes into the env's config. With none chosen, an agent whose
/// provider allows it logs in inside the env, so an agent the user added works at once. Only
/// without that does the provider's API stay closed: installed, but unable to connect.
fn ask_credential(
    ctx: &Ctx,
    env_name: &str,
    a: &profiles::Agent,
    interactive: bool,
) -> Result<bool> {
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    if has_credential(&f.cfg, a) {
        return Ok(true);
    }
    if interactive
        && let Some((provider, entries)) = crate::wizard::credential(&f.cfg, a, &ctx.global)?
    {
        f.set_provider_credential(&provider, &entries)?;
        return Ok(true);
    }
    let Some((name, p)) = a.providers.iter().find_map(|n| {
        profiles::provider(n)
            .filter(|p| !p.login_hosts.is_empty())
            .map(|p| (n, p))
    }) else {
        return Ok(false);
    };
    let entry = ("login_inside".to_string(), ProviderValue::Flag(true));
    f.set_provider_credential(name, &BTreeMap::from([entry]))?;
    println!("\n{}", login_notice(a, name, &p, env_name));
    Ok(true)
}

/// Says that `a` logs in inside the env, what that costs, and how to keep a credential outside.
fn login_notice(a: &profiles::Agent, name: &str, p: &profiles::Provider, env_name: &str) -> String {
    // Each provider's `login_how` says where the session lives.
    let mut out = format!(
        "{} logs in inside the env ([credentials.{name}] login_inside = true). {}",
        a.description,
        p.login_how.as_deref().unwrap_or_default()
    );
    if !p.auth.is_empty() {
        let kinds: Vec<&str> = p.auth.keys().map(String::as_str).collect();
        out.push_str(&format!(
            "\nTo keep a credential outside instead, the gate adding it to each request, replace \
             login_inside with {} (`luoto edit -e {env_name}`).",
            kinds.join(" or ")
        ));
    }
    out
}

/// Whether the env holds a credential (or a login-inside opt-in) for one of the agent's
/// providers. Agents without providers (local models) need none.
fn has_credential(cfg: &crate::config::EnvConfig, a: &profiles::Agent) -> bool {
    a.providers.is_empty()
        || cfg
            .credentials
            .providers
            .keys()
            .any(|p| a.providers.contains(p))
}

/// What to add so the gate can authenticate the agent's model API.
fn credential_help(a: &profiles::Agent, env_name: &str) -> String {
    let provider = a.providers.first().and_then(|p| profiles::provider(p));
    let name = a.providers.first().map_or("anthropic", String::as_str);
    if let Some(p) = provider.as_ref().filter(|p| p.auth.is_empty()) {
        return format!(
            "{} signs in inside the sandbox. Allow it in the env's config (`luoto edit -e \
             {env_name}`):\n\n  [credentials.{name}]\n  login_inside = true\n\n{}",
            a.description,
            p.login_how.as_deref().unwrap_or_default()
        );
    }
    let kind = provider
        .as_ref()
        .and_then(|p| {
            p.suggested
                .clone()
                .or_else(|| p.auth.keys().next().cloned())
        })
        .unwrap_or_else(|| "api_key".into());
    let mut out = format!(
        "{} needs a credential for {}. The gate adds it to each request; the sandbox never \
         holds it. Add to the env's config (`luoto edit -e {env_name}`):\n\n  \
         [credentials.{name}]\n  {kind} = \"op://<vault>/<item>/<field>\"   # or keyring:<service>/<account>, env:<NAME>",
        a.description,
        a.providers.join(" or ")
    );
    if let Some(p) = provider {
        for (k, auth) in &p.auth {
            out.push_str(&format!("\n\n{k}: the {}. {}", auth.label, auth.how));
        }
        if let Some(how) = p.login_how.as_deref().filter(|_| !p.login_hosts.is_empty()) {
            out.push_str(&format!(
                "\n\nlogin_inside = true: log in inside the sandbox instead. {how}"
            ));
        }
    }
    out
}

/// Put the env on its current config before an agent works in it: a stopped env comes up, a
/// running one picks up edits made since (a new credential, an agent's rules).
fn ready(ctx: &Ctx, env_name: &str) -> Result<()> {
    if sync::reapply(ctx, env_name)?.is_none() {
        env::up(ctx, env_name, &env::UpOptions::default())?;
    }
    Ok(())
}

/// Link the luoto briefing into the agent's instructions and register the sandbox MCP server.
/// A merge into the agent's own config files, so `up` repeats it after copying home files
/// that may have replaced those files.
pub fn register(ctx: &Ctx, env_name: &str, a: &profiles::Agent) -> Result<()> {
    let mut args = vec![
        "exec".to_string(),
        "-u".into(),
        UID.into(),
        names::dev(env_name),
        "/opt/luoto/bin/sandbox".into(),
        "agent-setup".into(),
    ];
    if let Some(kind) = &a.mcp {
        args.push("--mcp".into());
        args.push(kind.clone());
    }
    for b in &a.briefing {
        args.push("--briefing".into());
        args.push(b.clone());
    }
    ctx.rt.run(&args)?;
    Ok(())
}

/// List `agent` in the env's config, unless the config (or the accepted luoto.toml) does.
fn list_agent(ctx: &Ctx, env_name: &str, agent: &str) -> Result<bool> {
    if env::layered(ctx, env_name)?.agents.contains(agent) {
        return Ok(false);
    }
    EnvFile::load(&ctx.paths, env_name)?.add_agent(agent)?;
    Ok(true)
}

/// `luoto agent add`: list the agent in the env's config; `up` asks how it authenticates,
/// installs it and says how it logs in.
pub fn add(env_name: &str, agent: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let a = profile(agent)?;
    let listed = !list_agent(&ctx, env_name, agent)?;
    let dev = names::dev(env_name);
    let there = listed && ctx.rt.is_running(&dev) && installed(&ctx, &dev, &a);
    env::up(&ctx, env_name, &env::UpOptions::default())?;
    if there {
        let cfg = EnvFile::load(&ctx.paths, env_name)?.cfg;
        println!(
            "{} is in `{env_name}` already ({}): luoto agent run -e {env_name} {agent}",
            a.description,
            auth_summary(&cfg, &a, env_name)
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `luoto agent run`: as `agent add` when the env doesn't have the agent ready, then run it.
pub fn run(env_name: &str, agent: &str, yolo: bool, args: &[String]) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let a = profile(agent)?;
    let added = list_agent(&ctx, env_name, agent)?;
    let dev = names::dev(env_name);
    let cfg = EnvFile::load(&ctx.paths, env_name)?.cfg;
    if added || !ctx.rt.is_running(&dev) || !has_credential(&cfg, &a) || !installed(&ctx, &dev, &a)
    {
        env::up(
            &ctx,
            env_name,
            &env::UpOptions {
                quiet: true,
                ..Default::default()
            },
        )?;
    } else {
        ready(&ctx, env_name)?;
    }
    if !has_credential(&EnvFile::load(&ctx.paths, env_name)?.cfg, &a) {
        eprintln!(
            "{}\n\nThen run `luoto agent run -e {env_name} {agent}` again.",
            credential_help(&a, env_name)
        );
        return Ok(ExitCode::FAILURE);
    }
    let mut argv = vec![sh_quote(&a.command)];
    if yolo {
        argv.extend(a.yolo.iter().map(|s| sh_quote(s)));
    }
    argv.extend(args.iter().map(|s| sh_quote(s)));
    exec_login(&ctx, env_name, &format!("exec {}", argv.join(" ")))
}
