//! Coding agents inside envs: install (through short-lived egress grants), link the luoto
//! briefing into the agent's global instructions, register the sandbox MCP server, run.

use std::io::{self, IsTerminal};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::TimeDelta;
use luoto_shared::policy::Rule;
use luoto_shared::profiles;

use std::collections::BTreeMap;

use crate::config::{EnvFile, ProviderValue};
use crate::connect::exec_login;
use crate::env::{self, Ctx, UID};
use crate::logs::InstallLog;
use crate::text::sh_quote;
use crate::{events, names, secrets, sync};

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
        let what = format!(
            "installing {} in `{env_name}` (temporary access: {})",
            a.description,
            a.install_hosts.join(", ")
        );
        println!("{what}…");
        let log = InstallLog::new(&ctx.paths, env_name);
        log.note(&what);
        let rules: Vec<Rule> = a.install_hosts.iter().map(|h| Rule::read(h)).collect();
        let script = a.install.join(" && ");
        let status = sync::with_grants(
            ctx,
            env_name,
            &rules,
            TimeDelta::minutes(15),
            &format!("installing {agent} (auto-revoked)"),
            || {
                log.run(
                    &ctx.rt,
                    [
                        "exec",
                        "-u",
                        UID,
                        "-w",
                        "/workspace",
                        &dev,
                        "sh",
                        "-lc",
                        &script,
                    ],
                )
            },
        )??;
        log.note(&if status.success() {
            format!("installed {agent}")
        } else {
            format!("installing {agent} failed ({status})")
        });
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

/// The agents `cfg` lists (the accepted luoto.toml's included) that have no credential.
fn lacking(ctx: &Ctx, env_name: &str, cfg: &crate::config::EnvConfig) -> Result<Vec<String>> {
    let own = EnvFile::load(&ctx.paths, env_name)?.cfg;
    Ok(cfg
        .agents
        .names()
        .filter(|n| profiles::agent(n).is_some_and(|a| !has_credential(&own, &a)))
        .cloned()
        .collect())
}

/// For the agents `cfg` lists with no credential: on a terminal, ask how each authenticates,
/// as `agent add` does, and write the answer into the env's config (`up` asks before it
/// starts the gate, so the gate has it). Without one, say what to add and change nothing.
pub fn ask_missing(ctx: &Ctx, env_name: &str, cfg: &crate::config::EnvConfig) -> Result<()> {
    let lacking = lacking(ctx, env_name, cfg)?;
    if crate::prompt::interactive() {
        return credentials(ctx, env_name, &lacking, true);
    }
    for a in lacking.iter().filter_map(|n| profiles::agent(n)) {
        eprintln!("note: {}", credential_help(&a, env_name));
    }
    Ok(())
}

/// For a command that adds agents without a terminal (`init --yes`, `agent add`, the UI's new
/// env): each of the env's agents with no credential logs in inside where its provider allows
/// it, as the user asked for the agent there and then.
pub fn login_inside_unless_set(ctx: &Ctx, env_name: &str) -> Result<()> {
    if crate::prompt::interactive() {
        return Ok(());
    }
    let lacking = lacking(ctx, env_name, &env::layered(ctx, env_name)?)?;
    credentials(ctx, env_name, &lacking, false)
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
    // One agent that fails to install leaves the others to try.
    let mut failed = Vec::new();
    for (name, a) in &wanted {
        if !missing.contains(&a.command.as_str()) {
            continue;
        }
        if let Err(e) = install(ctx, env_name, name) {
            failed.push(format!("{name}: {e:#}"));
            continue;
        }
        if !quiet {
            println!(
                "{} is ready ({}): luoto agent run -e {env_name} {name}",
                a.description,
                auth_summary(&cfg, a, env_name)
            );
        }
    }
    if !failed.is_empty() {
        bail!("{}", failed.join("; "));
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
pub fn register(
    ctx: &Ctx,
    env_name: &str,
    a: &profiles::Agent,
    opts: &crate::config::AgentOpts,
) -> Result<()> {
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
    for set in &a.first_run {
        args.push("--set".into());
        args.push(serde_json::to_string(set)?);
    }
    for (key, value) in opts.values() {
        if let Some(s) = a.settings.get(key) {
            let set = profiles::JsonSet {
                file: s.file.clone(),
                path: s.path.clone(),
                value: serde_json::Value::String(value.to_string()),
            };
            args.push("--set".into());
            args.push(serde_json::to_string(&set)?);
        }
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

/// Write the credentials `specs` name for `agents` (`--credential`), without the prompt:
/// `KIND=REF`, `PROVIDER.KIND=REF` where the agents' providers share a kind, or
/// `[PROVIDER.]login_inside`. A reference must resolve now, as the prompt checks it.
pub fn set_credentials(
    ctx: &Ctx,
    env_name: &str,
    agents: &[String],
    specs: &[String],
) -> Result<()> {
    let providers: Vec<(String, profiles::Provider)> = agents
        .iter()
        .filter_map(|n| profiles::agent(n))
        .flat_map(|a| a.providers)
        .filter_map(|p| Some((p.clone(), profiles::provider(&p)?)))
        .collect();
    for spec in specs {
        let (key, reference) = match spec.split_once('=') {
            Some((k, r)) => (k.trim(), Some(r.trim())),
            None => (spec.trim(), None),
        };
        let (named, kind) = match key.split_once('.') {
            Some((p, k)) => (Some(p), k),
            None => (None, key),
        };
        let takes = |p: &profiles::Provider| match reference {
            Some(_) => p.auth.contains_key(kind),
            None => kind == "login_inside" && !p.login_hosts.is_empty(),
        };
        let fits: Vec<&(String, profiles::Provider)> = providers
            .iter()
            .filter(|(n, p)| named.is_none_or(|x| x == n) && takes(p))
            .collect();
        let (provider, _) = match fits.as_slice() {
            [one] => *one,
            [] => bail!(
                "--credential {}: none of the agents' providers ({}) takes it",
                crate::text::display(key),
                providers
                    .iter()
                    .map(|(n, p)| format!(
                        "{n}: {}{}",
                        p.auth.keys().cloned().collect::<Vec<_>>().join(", "),
                        if p.login_hosts.is_empty() {
                            ""
                        } else {
                            ", login_inside"
                        }
                    ))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            _ => bail!(
                "--credential {}: several providers take it; name one as PROVIDER.{kind}",
                crate::text::display(key)
            ),
        };
        let value = match reference {
            Some(r) => {
                secrets::check_ref(r)?;
                secrets::resolve(&ctx.global, r)
                    .with_context(|| format!("--credential {key}: {r} doesn't resolve"))?;
                ProviderValue::Ref(r.to_string())
            }
            None => ProviderValue::Flag(true),
        };
        EnvFile::load(&ctx.paths, env_name)?
            .set_provider_credential(provider, &BTreeMap::from([(kind.to_string(), value)]))?;
        println!("[credentials.{provider}] {kind} written to env `{env_name}`");
    }
    Ok(())
}

/// `luoto agent add`: list the agent in the env's config (and its `--credential`); `up` asks
/// for a credential it still lacks, installs it and says how it logs in.
pub fn add(env_name: &str, agent: &str, credential: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let a = profile(agent)?;
    if let Some(c) = credential {
        set_credentials(&ctx, env_name, &[agent.to_string()], &[c.to_string()])?;
    }
    let listed = !list_agent(&ctx, env_name, agent)?;
    login_inside_unless_set(&ctx, env_name)?;
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

/// What `luoto run` exits with when the agent ran out of `--timeout`, as `timeout(1)` does.
pub const TIMED_OUT: u8 = 124;

/// What `luoto run` exits with after Ctrl-C, as a shell reports SIGINT.
const INTERRUPTED: u8 = 130;

/// Why `luoto run` stopped the agent before it ended.
#[derive(Clone, Copy)]
enum Stop {
    Timeout,
    Interrupt,
    /// Its answer could be written nowhere.
    Output,
}

/// From now on Ctrl-C only counts, for `luoto run` to stop the agent in the env.
fn count_interrupts() -> Arc<AtomicUsize> {
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        rt.block_on(async {
            while tokio::signal::ctrl_c().await.is_ok() {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });
    });
    count
}

/// The variable that marks the processes of one `luoto run` in the env, whatever group or
/// session they moved to.
const RUN_MARK: &str = "LUOTO_RUN";

/// Signals `$1` to each process whose environment holds `$2` (the run's mark) and to the
/// process group each leads, which takes in children that dropped the mark.
const SIGNAL_RUN: &str = r#"for d in /proc/[0-9]*; do
  tr '\0' '\n' 2>/dev/null <"$d/environ" | grep -qxF "$2" || continue
  p=${d#/proc/}
  kill -s "$1" -- "-$p" 2>/dev/null
  kill -s "$1" "$p" 2>/dev/null
done
true"#;

/// How long after its timeout a run gets SIGTERM, SIGKILL, and then has the runtime's client
/// here killed, for an env that no longer answers.
const STOP_STEPS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_secs(10),
    Duration::from_secs(15),
];

/// How far back the denial summary reads the gate's log: the VM's clock may lag this one.
const CLOCK_SLACK: TimeDelta = TimeDelta::minutes(10);

/// `--timeout`: a duration as rules take it (30m, 2h), above zero.
fn parse_timeout(s: &str) -> Result<Duration> {
    crate::rules::parse_ttl(s)?
        .to_std()
        .ok()
        .filter(|d| !d.is_zero())
        .with_context(|| format!("--timeout {s}: give a duration above zero"))
}

/// `luoto run`: one prompt, no terminal. Lists the agent if the env doesn't, brings the env up
/// (as a child whose output goes to stderr, with nothing to answer on), then runs the agent's
/// headless command line: its answer on stdout or in `output`, its exit code returned, or
/// [`TIMED_OUT`] once it ran past `timeout` and was stopped. What the gate denied meanwhile
/// is listed on stderr.
pub fn headless(
    env_name: &str,
    agent: &str,
    prompt: &str,
    output: Option<&str>,
    timeout: Option<&str>,
    down: bool,
) -> Result<ExitCode> {
    use std::process::Stdio;
    let ctx = Ctx::load()?;
    let a = profile(agent)?;
    if a.headless.is_empty() {
        bail!("{} has no headless mode in luoto", a.description);
    }
    let prompt = prompt.trim();
    if prompt.is_empty() || prompt.len() > 100_000 {
        bail!("the prompt is empty or longer than 100 kB");
    }
    let limit = timeout.map(parse_timeout).transpose()?;
    // The answer's file, made before the run: a path that can't be written fails now.
    let out_file = output.map(crate::workspace::expand).unwrap_or_default();
    if output.is_some() {
        std::fs::write(&out_file, b"")
            .with_context(|| format!("can't write {}", out_file.display()))?;
    }
    list_agent(&ctx, env_name, agent)?;
    let progress = Stdio::from(std::io::stderr());
    let up = std::process::Command::new(std::env::current_exe()?)
        .args(["up", "-e", env_name, "--quiet"])
        .stdin(Stdio::null())
        .stdout(progress)
        .status()?;
    if !up.success() {
        bail!("`luoto up -e {env_name}` failed");
    }
    if !has_credential(&EnvFile::load(&ctx.paths, env_name)?.cfg, &a) {
        bail!("{}", credential_help(&a, env_name));
    }
    let argv: Vec<String> = std::iter::once(sh_quote(&a.command))
        .chain(
            a.headless
                .iter()
                .map(|x| sh_quote(&x.replace("{prompt}", prompt))),
        )
        .collect();
    let script = format!("exec {}", argv.join(" "));
    let dev = names::dev(env_name);
    let mark = format!("{RUN_MARK}={}", hex::encode(rand::random::<[u8; 8]>()));
    // The gate's log as the agent starts, so the summary leaves out what `up` did.
    let since = (chrono::Utc::now() - CLOCK_SLACK).to_rfc3339();
    let gate_at_start =
        events::gate_events(&ctx.rt, env_name, Some(&since)).map(|evs| events::Mark::of(&evs));
    let mut cmd = ctx.rt.command();
    cmd.args([
        "exec",
        "-u",
        UID,
        "-w",
        "/workspace",
        "-e",
        &mark,
        dev.as_str(),
        "sh",
        "-c",
        crate::connect::LOGIN,
        &script,
    ])
    .stdin(Stdio::null());
    // The agent's output is the sandbox's text: written as it is, never run, and escaped on a
    // terminal, where its escape sequences could otherwise drive it.
    let err_tty = std::io::stderr().is_terminal();
    cmd.stdout(Stdio::piped()).stderr(if err_tty {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    // Ctrl-C is for luoto, which stops the agent inside the env: the runtime's client would
    // only drop its end and leave the agent running.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let interrupts = count_interrupts();
    let mut child = cmd.spawn()?;
    let started = Instant::now();
    let errs = child
        .stderr
        .take()
        .map(|e| std::thread::spawn(move || relay(e, &mut std::io::stderr(), true)));
    let out = child.stdout.take().context("the agent's output")?;
    let (status, relayed, stopped) = std::thread::scope(|s| -> Result<_> {
        let mut relayer = Some(s.spawn(|| answer(out, output, &out_file, err_tty)));
        let mut relayed = Ok(());
        let mut stop: Option<(Instant, Stop)> = None;
        let mut steps = 0;
        let status = loop {
            if let Some(r) = relayer.take_if(|r| r.is_finished()) {
                relayed = r
                    .join()
                    .unwrap_or_else(|_| Err(io::Error::other("relay failed")));
                if relayed.is_err() {
                    stop.get_or_insert((Instant::now(), Stop::Output));
                }
            }
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if stop.is_none() {
                if limit.is_some_and(|l| started.elapsed() >= l) {
                    eprintln!(
                        "the agent ran past --timeout {}; stopping it",
                        timeout.unwrap_or_default().trim()
                    );
                    stop = Some((Instant::now(), Stop::Timeout));
                } else if interrupts.load(Ordering::SeqCst) > 0 {
                    eprintln!("stopping the agent in the env (Ctrl-C again: without waiting)");
                    stop = Some((Instant::now(), Stop::Interrupt));
                }
            }
            if let Some((from, _)) = stop {
                let over = if interrupts.load(Ordering::SeqCst) > 1 {
                    Duration::MAX
                } else {
                    from.elapsed()
                };
                while STOP_STEPS.get(steps).is_some_and(|at| over >= *at) {
                    match steps {
                        0 => signal_run(&ctx, &dev, &mark, "TERM"),
                        1 => signal_run(&ctx, &dev, &mark, "KILL"),
                        _ => {
                            let _ = child.kill();
                        }
                    }
                    steps += 1;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // The agent may end before its stragglers, or the client before the agent (Ctrl-C
        // reaches it on Windows).
        let stop = stop
            .map(|(_, why)| why)
            .or_else(|| (interrupts.load(Ordering::SeqCst) > 0).then_some(Stop::Interrupt));
        if stop.is_some() {
            if steps == 0 {
                signal_run(&ctx, &dev, &mark, "TERM");
            }
            if steps < 2 {
                signal_run(&ctx, &dev, &mark, "KILL");
            }
        }
        if let Some(r) = relayer {
            relayed = r
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("relay failed")));
        }
        Ok((status, relayed, stop))
    })?;
    if let Some(t) = errs {
        let _ = t.join();
    }
    let run_events = gate_at_start
        .and_then(|at| Ok(at.after(events::gate_events(&ctx.rt, env_name, Some(&since))?)));
    match run_events {
        Ok(mut evs) => {
            // Muted denials stay out, as in `luoto egress`.
            if let Ok(mutes) = env::mutes(&ctx, env_name) {
                mutes.hide(&mut evs);
            }
            eprint!("{}", events::fmt_denials(env_name, &events::denials(&evs)));
        }
        Err(e) => eprintln!("warning: no summary of the gate's denials ({e:#})"),
    }
    relayed?;
    crate::disk::hint_growth(&ctx, env_name);
    if down {
        match env::down(&ctx, env_name) {
            Ok(()) => eprintln!("env `{env_name}` stopped"),
            Err(e) => eprintln!("warning: env `{env_name}` not stopped ({e:#})"),
        }
    }
    match stopped {
        Some(Stop::Timeout) => return Ok(ExitCode::from(TIMED_OUT)),
        Some(Stop::Interrupt) => return Ok(ExitCode::from(INTERRUPTED)),
        Some(Stop::Output) | None => {}
    }
    Ok(ExitCode::from(
        status.code().unwrap_or(1).clamp(0, 255) as u8
    ))
}

/// Send `signal` to the processes of the run `mark` names in the env's dev container. As the
/// dev user: root there lacks CAP_SYS_PTRACE, so it can't read another user's environ.
fn signal_run(ctx: &Ctx, dev: &str, mark: &str, signal: &str) {
    ctx.rt.succeeds([
        "exec", "-u", UID, dev, "sh", "-c", SIGNAL_RUN, "sh", signal, mark,
    ]);
}

/// Write the agent's answer to `path` when given (the rest to stderr should that fail), else
/// to stdout.
fn answer(
    mut out: impl io::Read,
    path: Option<&str>,
    file: &std::path::Path,
    err_tty: bool,
) -> io::Result<()> {
    let Some(path) = path else {
        let terminal = io::stdout().is_terminal();
        return relay(&mut out, &mut io::stdout().lock(), terminal);
    };
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file);
    match opened.map(|mut f| relay(&mut out, &mut f, false)) {
        Ok(Ok(())) => Ok(()),
        // A write that fails leaves the rest on stderr rather than lost.
        Ok(Err(e)) | Err(e) => {
            eprintln!("warning: {path} not written whole ({e}); the rest follows");
            relay(&mut out, &mut io::stderr(), err_tty)
        }
    }
}

/// The most of an agent's answer `luoto run` writes.
const ANSWER_CAP: usize = 64 << 20;

/// Copy what the sandbox prints to `to`, up to [`ANSWER_CAP`]: escaped (`text::lines`) for a
/// `terminal`, as it is elsewhere.
fn relay(
    mut from: impl std::io::Read,
    to: &mut dyn std::io::Write,
    terminal: bool,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    let mut pending = Vec::new();
    let mut left = ANSWER_CAP;
    loop {
        let n = from.read(&mut buf)?;
        let take = n.min(left);
        if take < n && left > 0 {
            eprintln!("warning: the output was cut at {} MiB", ANSWER_CAP >> 20);
        }
        left -= take;
        if terminal {
            pending.extend_from_slice(&buf[..take]);
            // Whole lines, so a character split between reads is decoded whole.
            let upto = if n == 0 || pending.len() > 1 << 16 {
                pending.len()
            } else {
                pending
                    .iter()
                    .rposition(|b| *b == b'\n')
                    .map_or(0, |i| i + 1)
            };
            if upto > 0 {
                let text = String::from_utf8_lossy(&pending[..upto]);
                to.write_all(crate::text::lines(&text).as_bytes())?;
                to.flush()?;
                pending.drain(..upto);
            }
        } else {
            to.write_all(&buf[..take])?;
        }
        if n == 0 {
            return to.flush();
        }
    }
}

/// `luoto agent rm`: drop the agent from the env's config, and its hosts from the policy of a
/// running env. Its install and sessions stay in the env's home.
pub fn rm(env_name: &str, agent: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let a = profile(agent)?;
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    if !f.cfg.agents.contains(agent) {
        if env::layered(&ctx, env_name)?.agents.contains(agent) {
            bail!(
                "{agent} comes from the team's luoto.toml; `luoto project ignore` stops applying \
                 that file"
            );
        }
        bail!("env `{env_name}` has no agent `{agent}`");
    }
    f.remove_agent(agent)?;
    sync::reapply(&ctx, env_name)?;
    println!(
        "removed {} from env `{env_name}`; its files stay in the env's home (`{}` in \
         ~/.local/bin), and its [credentials] stay in the config",
        a.description, a.command
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_is_a_duration_above_zero() {
        assert_eq!(parse_timeout("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_timeout("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_timeout("2h").unwrap(), Duration::from_secs(7200));
        assert!(parse_timeout("0").is_err());
        assert!(parse_timeout("1y").is_err());
        assert!(parse_timeout("soon").is_err());
    }
}
