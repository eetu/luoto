//! Env and policy commands: what the CLI prints around the core functions.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use luoto_shared::api::{AccessRequest, RequestStatus};
use luoto_shared::events::Verdict;
use luoto_shared::policy::Mode;

use crate::config::{self, EnvFile};
use crate::env::{self, Ctx, UpOptions};
use crate::prompt::confirm;
use crate::rules::{self, AllowOpts};
use crate::state::EnvState;
use crate::{ctl, events, machine, names, project, sync, workspace};

/// Show, accept or drop the project's luoto.toml settings for an env.
pub fn project(name: &str, accept: bool, forget: bool, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if forget {
        project::ignore(&ctx, name)?;
        println!("`{name}` no longer applies the project's luoto.toml");
        return Ok(ExitCode::SUCCESS);
    }
    let st = project::status(&ctx, name)?;
    let show = |lines: &[(String, String)]| project::print_entries(lines, "  ");
    match st.state {
        project::State::None => println!("the project has no luoto.toml"),
        project::State::Invalid => println!(
            "the project's luoto.toml is not applied: {}",
            st.error.as_deref().unwrap_or("")
        ),
        project::State::Removed => {
            println!("the project no longer has luoto.toml; these accepted settings still apply:");
            show(&st.accepted);
        }
        project::State::Accepted => {
            println!("luoto.toml is accepted and applies to `{name}`:");
            show(&st.current);
        }
        project::State::Declined => {
            println!("luoto.toml is ignored for `{name}` (this version):");
            show(&st.current);
        }
        project::State::Changed => {
            println!("luoto.toml changed since you accepted it:");
            for l in &st.diff {
                println!("  {l}");
            }
        }
        project::State::New => {
            println!("luoto.toml (not accepted; written in the repository, so review it):");
            show(&st.current);
        }
    }
    crate::init::print_needs(name, &st.needs);
    let pending = st.pending();
    if !accept {
        if pending {
            println!("apply:  luoto project apply -e {name}");
            if st.state != project::State::Declined {
                println!("ignore: luoto project ignore -e {name}");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    let Some(text) = st.text.filter(|_| pending) else {
        return Ok(ExitCode::SUCCESS);
    };
    if !yes && !confirm("Apply these settings to this env?") {
        println!("nothing changed (non-interactive: add --yes)");
        return Ok(ExitCode::FAILURE);
    }
    if project::apply(&ctx, name, &text)? {
        println!("applied to `{name}`");
    } else {
        println!("accepted; applies on `luoto up -e {name}`");
    }
    Ok(ExitCode::SUCCESS)
}

/// What `pull` writes where (`workspace::pull_targets`), from the env's config.
pub fn pull_targets(
    ctx: &Ctx,
    name: &str,
    to: Option<PathBuf>,
    repo: Option<&str>,
) -> Result<Vec<workspace::PullTarget>> {
    let ws = env::layered(ctx, name)?.workspace;
    let present = EnvState::load(&ctx.paths, name)?
        .map(|s| s.repos)
        .unwrap_or_default();
    workspace::pull_targets(&ws, to, repo, &present)
}

pub fn pull(
    name: &str,
    to: Option<&str>,
    repo: Option<&str>,
    include_risky: bool,
    include_git: bool,
    yes: bool,
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    crate::connect::ensure_running(&ctx, name)?;
    let to = match to {
        Some(t) => {
            std::fs::create_dir_all(workspace::expand(t))?;
            Some(workspace::canonical(t)?)
        }
        None => None,
    };
    let mut plans = Vec::new();
    for t in pull_targets(&ctx, name, to, repo)? {
        let plan = workspace::plan_pull(&ctx, name, &t, include_git)?;
        if let Some(r) = &plan.repo {
            println!("\nrepo {r}:");
        }
        workspace::describe(&plan, &mut std::io::stdout())?;
        plans.push(plan);
    }
    let changed = |p: &workspace::PullPlan| {
        p.entries
            .iter()
            .filter(|e| include_risky || e.risky.is_none())
            .count()
    };
    if plans.iter().all(|p| p.entries.is_empty()) {
        println!("nothing to pull");
        return Ok(ExitCode::SUCCESS);
    }
    let writable: usize = plans.iter().map(changed).sum();
    if writable == 0 {
        println!("only risky files changed; re-run with --include-risky after reviewing them");
        return Ok(ExitCode::SUCCESS);
    }
    let dirs: Vec<&str> = plans
        .iter()
        .filter(|p| changed(p) > 0)
        .map(|p| p.dir.as_str())
        .collect();
    if !yes
        && !confirm(&format!(
            "Write {writable} file(s) into {}?",
            dirs.join(", ")
        ))
    {
        bail!("nothing written (use --yes to skip the prompt)");
    }
    let (mut written, mut skipped) = (0, 0);
    for plan in &plans {
        let (w, s) = workspace::apply_pull(plan, include_risky)?;
        written += w;
        skipped += s;
    }
    println!(
        "wrote {written} file(s){}",
        if skipped > 0 {
            format!("; skipped {skipped} risky (review, then --include-risky)")
        } else {
            String::new()
        }
    );
    Ok(ExitCode::SUCCESS)
}

pub fn up(name: &str, selftest: bool, recreate: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if recreate {
        env::remove_dev(&ctx, name)?;
    }
    env::up(
        &ctx,
        name,
        &UpOptions {
            no_selftest: !selftest,
            quiet: false,
        },
    )?;
    Ok(ExitCode::SUCCESS)
}

pub fn down(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if machine::stopped(&ctx.rt) {
        println!("env `{name}` is not running (luoto's VM is stopped)");
        return Ok(ExitCode::SUCCESS);
    }
    env::down(&ctx, name)?;
    println!("env `{name}` stopped");
    // The VM stays up for a quick `up`; the watcher stops it after `idle_stop` without envs.
    crate::watch::spawn(&ctx);
    Ok(ExitCode::SUCCESS)
}

pub fn rm(name: &str, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    config::validate_name(name)?;
    let cfg = ctx.paths.env_config(name);
    if !cfg.exists() {
        bail!("no env `{name}` (`luoto ls` lists them)");
    }
    if !yes
        && !confirm(&format!(
            "Delete env `{name}` with its workspace, home and config? \
             Work not pushed or pulled (`luoto pull`) is lost"
        ))
    {
        bail!("aborted (`luoto rm -e {name} --yes` skips the question)");
    }
    // Volumes live in the VM, which may have stopped on idle.
    env::ensure_vm(&ctx)?;
    env::remove(&ctx, name)?;
    crate::ssh::forget_host_key(&ctx, name)?;
    std::fs::remove_file(&cfg)?;
    crate::ssh::write_config(&ctx)?;
    println!("env `{name}` removed");
    Ok(ExitCode::SUCCESS)
}

pub fn ls() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let envs = config::list_envs(&ctx.paths)?;
    if envs.is_empty() {
        println!("no envs yet: `luoto init` in a project folder, or `luoto init <new-folder>`");
        return Ok(ExitCode::SUCCESS);
    }
    let states = ctx.rt.states().unwrap_or_default();
    if states.vm_stopped {
        println!("luoto's VM is stopped; `luoto up` starts it with the env\n");
    }
    println!(
        "{:<20} {:<10} {:<10} {:<28} PRESETS",
        "ENV", "DEV", "GATE", "IMAGE"
    );
    for e in envs {
        let (dev, gate) = states.env(&e);
        let (image, presets) = match EnvFile::load(&ctx.paths, &e) {
            Ok(f) => (env::env_image(&ctx, &f.cfg), f.cfg.presets.join(",")),
            Err(_) => ("(invalid config)".into(), String::new()),
        };
        println!("{e:<20} {dev:<10} {gate:<10} {image:<28} {presets}");
    }
    Ok(ExitCode::SUCCESS)
}

pub fn status(name: &str, json: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if json {
        let p = env::plan(&ctx, name)?;
        println!("{}", serde_json::to_string_pretty(&p.compiled.policy)?);
        return Ok(ExitCode::SUCCESS);
    }
    let f = EnvFile::load(&ctx.paths, name)?;
    let states = ctx.rt.states().unwrap_or_default();
    let (dev, gate) = if states.vm_stopped {
        (
            "stopped (luoto's VM is off)".to_string(),
            "stopped".to_string(),
        )
    } else {
        states.env(name)
    };
    println!(
        "env {name}\n  config: {}\n  dev:    {dev}\n  gate:   {gate}",
        f.path.display()
    );
    println!(
        "  isolation: {}",
        crate::init::isolation_text(f.cfg.isolation, ctx.global.gvisor.is_some())
    );
    println!(
        "  idle:   {}",
        match crate::idle::limit(&ctx.global, &f.cfg) {
            Some(d) => format!(
                "stops after {} min with no shell, editor, agent or server running",
                d.as_secs() / 60
            ),
            None => "never stops on its own".into(),
        }
    );
    println!(
        "  folder: {} (copied in; `luoto pull` brings changes back)",
        f.cfg.workspace.dir.as_deref().unwrap_or("none")
    );
    if gate == "running" {
        let s = ctl::gate_status(&ctx.rt, name)?;
        println!(
            "  policy: {} rules, CA {}, vault {}, {} pending request(s)",
            s.rules,
            if s.ca_installed { "ok" } else { "missing" },
            if s.vault_configured {
                "configured"
            } else {
                "not configured"
            },
            s.pending_requests
        );
    }
    if let Ok(v) = ctl::vault_status(&ctx.rt) {
        println!(
            "  vault:  {}",
            if v.locked {
                "LOCKED — `luoto up` or `luoto vault unlock` loads it"
            } else {
                "unlocked"
            }
        );
        if let Some(e) = v.envs.iter().find(|e| e.env == name) {
            if !e.bindings.is_empty() {
                println!("  credentials: {}", e.bindings.join(", "));
            }
            if !e.missing.is_empty() {
                println!("  missing secrets: {}", e.missing.join(", "));
            }
        }
    }
    print_rules(&env::plan(&ctx, name)?);
    Ok(ExitCode::SUCCESS)
}

fn print_rules(p: &env::Plan) {
    println!("\n{:<22} {:<38} {:<28} ORIGIN", "RULE", "HOST", "ACCESS");
    for r in &p.compiled.policy.rules {
        let mut access = r.rule.access.describe();
        if r.rule.mode == Mode::Tunnel {
            access = "tunnel (any)".into();
        }
        let extra = [
            (!r.rule.paths.is_empty()).then(|| format!("paths {}", r.rule.paths.join(","))),
            r.rule
                .expires
                .map(|e| format!("until {}", e.format("%m-%d %H:%M"))),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        println!(
            "{:<22} {:<38} {:<28} {} {extra}",
            r.id, r.rule.host, access, r.origin
        );
    }
    if !p.compiled.policy.injections.is_empty() {
        println!("\ncredentials injected by the gate:");
        for i in &p.compiled.policy.injections {
            println!("  {:<38} binding {}", i.host, i.binding);
        }
    }
    if !p.compiled.policy.denies.is_empty() {
        println!("\nfixed denies: {}", p.compiled.policy.denies.len());
    }
}

pub fn allow(name: &str, o: AllowOpts) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let rule = rules::build_rule(&o)?;
    let summary = format!(
        "{} {}{}{}",
        rule.host,
        rule.access.describe(),
        if rule.paths.is_empty() {
            String::new()
        } else {
            format!(" paths {}", rule.paths.join(","))
        },
        rule.expires
            .map(|e| format!(" until {}", e.format("%Y-%m-%d %H:%M UTC")))
            .unwrap_or_default()
    );
    let id = rule.id.clone().unwrap_or_default();
    rules::accepting_risks(o.force, |force| {
        rules::add_rule_checked(&ctx, name, rule.clone(), force)
    })?;
    println!("allowed {summary} (rule {id}); revoke with `luoto revoke -e {name} {id}`");
    Ok(ExitCode::SUCCESS)
}

pub fn revoke(name: &str, rule: &str) -> Result<ExitCode> {
    let n = rules::remove(&Ctx::load()?, name, rule)?;
    println!("removed {n} rule(s)");
    Ok(ExitCode::SUCCESS)
}

/// What the sandbox asked for and why, escaped: the sandbox wrote all of it.
fn fmt_request(r: &AccessRequest) -> String {
    let what = match &r.install {
        Some(i @ luoto_shared::api::Install::Preset { .. }) => format!(
            "{}, kept in the env's config",
            crate::text::display(&i.describe())
        ),
        Some(i) => format!(
            "install {}, kept in the env's config",
            crate::text::display(&i.describe())
        ),
        None => format!(
            "{} {:?}{}",
            crate::text::display(&r.host),
            r.access,
            if r.paths.is_empty() {
                String::new()
            } else {
                format!(" paths {}", crate::text::display(&r.paths.join(",")))
            }
        ),
    };
    format!(
        "{what}\n   reason (written by the sandbox, untrusted): {:?}",
        r.reason
    )
}

/// The pending requests of `name`, or of every env, each with its env.
fn pending(ctx: &Ctx, name: Option<&str>) -> Result<Vec<(String, AccessRequest)>> {
    let envs = match name {
        Some(n) => vec![n.to_string()],
        None => config::list_envs(&ctx.paths)?,
    };
    let states = ctx.rt.states().unwrap_or_default();
    let mut out = Vec::new();
    for e in envs {
        for r in rules::requests(ctx, &e, &states)? {
            if r.status == RequestStatus::Pending {
                out.push((e.clone(), r));
            }
        }
    }
    Ok(out)
}

fn print_request(e: &str, r: &AccessRequest) {
    println!(
        "{e} #{}  {}\n   approve: luoto approve -e {e} {}   reject: luoto reject -e {e} {}",
        r.id,
        fmt_request(r),
        r.id,
        r.id
    );
}

pub fn requests(name: Option<&str>, watch: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let now = pending(&ctx, name)?;
    for (e, r) in &now {
        print_request(e, r);
    }
    if !watch {
        if now.is_empty() {
            println!("no pending requests");
        }
        return Ok(ExitCode::SUCCESS);
    }
    println!("watching for requests (Ctrl-C stops)…");
    let mut seen: std::collections::HashSet<(String, u64)> =
        now.into_iter().map(|(e, r)| (e, r.id)).collect();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        for (e, r) in pending(&ctx, name).unwrap_or_default() {
            if seen.insert((e.clone(), r.id)) {
                // The terminal's bell: a request waits for you.
                print!("\x07");
                print_request(&e, &r);
            }
        }
    }
}

pub fn approve(name: &str, id: u64, ttl: Option<&str>, yes: bool, force: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let req = rules::request(&ctx, name, id)?;
    println!("request #{id}: {}", fmt_request(&req));
    if !yes && !confirm("Approve?") {
        bail!("not approved (use --yes to skip the prompt)");
    }
    if req.install.is_some() {
        println!("{}", rules::approve_install(&ctx, name, &req)?);
        return Ok(ExitCode::SUCCESS);
    }
    let rule = rules::accepting_risks(force, |force| rules::approve(&ctx, name, &req, ttl, force))?;
    println!("approved: {} {}", rule.host, rule.access.describe());
    Ok(ExitCode::SUCCESS)
}

pub fn reject(name: &str, id: u64, note: Option<String>) -> Result<ExitCode> {
    rules::reject(&Ctx::load()?, name, id, note)?;
    println!("rejected request #{id}");
    Ok(ExitCode::SUCCESS)
}

pub fn egress(name: &str, denied: bool, since: Option<&str>, json: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let evs = events::gate_events(&ctx.rt, name, since)?;
    let mut summary = events::summarize(&evs);
    if denied {
        summary.retain(|s| s.denied > 0 || s.dns_only);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(ExitCode::SUCCESS);
    }
    if summary.is_empty() {
        println!(
            "no egress recorded{}",
            since
                .map(|s| format!(" in the last {s}"))
                .unwrap_or_default()
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<40} {:>6} {:>6}  {:<14} {:<10} LAST / HINT",
        "HOST", "ALLOW", "DENY", "METHODS", "VIA"
    );
    for s in summary {
        let methods: Vec<&str> = s.methods.iter().map(String::as_str).collect();
        let via: Vec<&str> = s.intakes.iter().map(String::as_str).collect();
        let hint = if s.dns_only {
            "looked up, never connected".to_string()
        } else if s.tls_rejected {
            format!(
                "client rejected our CA → luoto allow -e {name} {} --tunnel",
                s.host
            )
        } else if s.denied > 0 && s.last_reason.as_deref() == Some("explicit") {
            s.last_message.clone().unwrap_or_default()
        } else if s.denied > 0 {
            let private = s.host.ends_with(".internal")
                || s.host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(luoto_shared::host::is_private);
            format!(
                "{} → luoto allow -e {name} {}{}{}",
                s.last_message.clone().unwrap_or_default(),
                s.host,
                if s.wants_write { " --write" } else { "" },
                if private {
                    " --private (exposes a service on your machine/network)"
                } else {
                    ""
                }
            )
        } else {
            s.last_rule
                .clone()
                .map(|r| format!("rule {r}"))
                .unwrap_or_default()
        };
        println!(
            "{:<40} {:>6} {:>6}  {:<14} {:<10} {}",
            crate::text::display(&s.host),
            s.allowed,
            s.denied,
            crate::text::display(&methods.join(",")),
            via.join(","),
            crate::text::display(&hint)
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn logs(name: &str, follow: bool, denied: bool, since: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let show = |e: &luoto_shared::events::Event| !denied || e.verdict == Some(Verdict::Deny);
    if follow {
        events::follow(&ctx.rt, &names::gate(name), since, |e| {
            if show(&e) {
                println!("{}", events::fmt_event(&e));
            }
            true
        })?;
    } else {
        for e in events::gate_events(&ctx.rt, name, since)? {
            if show(&e) {
                println!("{}", events::fmt_event(&e));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn open_editor(path: &std::path::Path) -> Result<()> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".into()
            } else {
                "vi".into()
            }
        });
    let status = std::process::Command::new(&editor)
        .arg(path)
        .status()
        .with_context(|| format!("run {editor}"))?;
    if !status.success() {
        bail!("editor exited with {status}");
    }
    Ok(())
}

pub fn edit(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let path = ctx.paths.env_config(name);
    if !path.exists() {
        bail!("no env `{name}`");
    }
    open_editor(&path)?;
    match sync::reapply(&ctx, name)? {
        Some(p) => println!(
            "applied ({} rules). Image, port, isolation and resource changes need `luoto up -e {name} --recreate`.",
            p.compiled.policy.rules.len()
        ),
        None => println!(
            "config is valid ({} rules)",
            env::plan(&ctx, name)?.compiled.policy.rules.len()
        ),
    }
    Ok(ExitCode::SUCCESS)
}

pub fn vault_status() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let v = ctl::vault_status(&ctx.rt)?;
    println!(
        "vault {}",
        if v.locked {
            "LOCKED — `luoto vault unlock` (or `luoto up`) loads the secrets"
        } else {
            "unlocked"
        }
    );
    for e in &v.envs {
        println!(
            "  {:<20} {}{}",
            e.env,
            if e.bindings.is_empty() {
                "no credentials".to_string()
            } else {
                e.bindings.join(", ")
            },
            if e.missing.is_empty() {
                String::new()
            } else {
                format!("  (missing: {})", e.missing.join(", "))
            }
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn unlock() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let n = sync::unlock_all(&ctx)?;
    println!("vault unlocked; {n} env(s) registered");
    Ok(ExitCode::SUCCESS)
}

pub fn lock() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let failed = sync::lock_all(&ctx)?;
    if !failed.is_empty() {
        eprintln!("lock incomplete:\n  {}", failed.join("\n  "));
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "vault locked: credentials wiped from the vault and every gate; credentialed hosts \
         return 403 until `luoto vault unlock` (sandbox secrets already in running envs stay until \
         `luoto down`)"
    );
    Ok(ExitCode::SUCCESS)
}
