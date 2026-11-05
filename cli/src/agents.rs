//! Coding agents inside envs: install (through short-lived egress grants), link the luoto
//! briefing into the agent's global instructions, register the sandbox MCP server, run.

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use chrono::TimeDelta;
use luoto_shared::policy::Rule;
use luoto_shared::profiles;

use crate::config::EnvFile;
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
/// and MCP.
pub fn install(ctx: &Ctx, env_name: &str, agent: &str) -> Result<()> {
    let a = profile(agent)?;
    let dev = names::dev(env_name);
    // An agent the accepted luoto.toml lists is the project's; only others join the user's file.
    if !env::layered(ctx, env_name)?
        .agents
        .iter()
        .any(|x| x == agent)
    {
        let mut f = EnvFile::load(&ctx.paths, env_name)?;
        let mut agents = f.cfg.agents.clone();
        agents.push(agent.to_string());
        f.set_list("agents", &agents)?;
        // The agent's hosts, environment and toolchains (e.g. node) come with the env.
        env::up(
            ctx,
            env_name,
            &env::UpOptions {
                quiet: true,
                ..Default::default()
            },
        )?;
    }
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
    register(ctx, env_name, &a)?;
    Ok(())
}

/// For each of `agents` that has no credential in the env yet: ask for one on a terminal (as
/// `agent add` does, "later" included), else, or when put off, say how to add it.
pub fn credentials(ctx: &Ctx, env_name: &str, agents: &[String], interactive: bool) -> Result<()> {
    for a in agents.iter().filter_map(|n| profiles::agent(n)) {
        if !ask_credential(ctx, env_name, &a, interactive)? {
            println!("\n{}", credential_help(&a, env_name));
        }
    }
    Ok(())
}

/// Whether agent `a` can authenticate in the env, asking for a credential when `interactive`
/// and it can't yet; the answer goes into the env's config. Without one the provider's API
/// host stays closed, so the agent fails to connect even though it is installed.
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
    Ok(false)
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

pub fn add(env_name: &str, agent: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let a = profile(agent)?;
    // Before `ready`, so the env picks up a credential given now.
    let can_auth = ask_credential(&ctx, env_name, &a, std::io::stdin().is_terminal())?;
    ready(&ctx, env_name)?;
    install(&ctx, env_name, agent)?;
    if !can_auth {
        eprintln!(
            "\n{} is installed but can't reach its API yet: {}",
            a.description,
            credential_help(&a, env_name)
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{} is ready: luoto agent run -e {env_name} {agent}",
        a.description
    );
    Ok(ExitCode::SUCCESS)
}

pub fn run(env_name: &str, agent: &str, yolo: bool, args: &[String]) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let a = profile(agent)?;
    let can_auth = ask_credential(&ctx, env_name, &a, std::io::stdin().is_terminal())?;
    ready(&ctx, env_name)?;
    // The first run installs it, through the same short-lived grants as `agent add`.
    install(&ctx, env_name, agent)?;
    if !can_auth {
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
