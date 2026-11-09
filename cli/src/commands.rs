//! Env and policy commands: what the CLI prints around the core functions.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use luoto_shared::api::{AccessRequest, Narrowing, RequestStatus};
use luoto_shared::events::Verdict;
use luoto_shared::policy::Mode;

use crate::config::{self, EnvFile};
use crate::env::{self, Ctx, UpOptions};
use crate::prompt::confirm;
use crate::rules::{self, AllowOpts};
use crate::state::EnvState;
use crate::{ctl, disk, events, machine, names, ports, project, sync, workspace};

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
        project::State::Unread => {
            println!(
                "`{name}` is stopped and its luoto.toml is only in the env: `luoto up -e {name}` \
                 reads it"
            );
            if !st.accepted.is_empty() {
                println!("the accepted settings apply:");
                show(&st.accepted);
            }
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

/// Print a luoto.toml from the env's settings, or write it to the env's folder, or into the
/// running env for an env cloned from a remote (replacing one there only with `force`, after
/// showing what changes).
pub fn project_suggest(name: &str, write: bool, force: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let cfg = EnvFile::load(&ctx.paths, name)?.cfg;
    let accepted = project::accepted(&ctx, name).map(|(_, p)| p);
    let s = project::suggest(name, &cfg, accepted.as_ref())?;
    for l in &s.left_out {
        eprintln!("left out: {l}");
    }
    if !write {
        // Paths of approved requests came from the sandbox.
        print!("{}", crate::text::lines(&s.text));
        return Ok(ExitCode::SUCCESS);
    }
    let (dir, path) = match &cfg.workspace.dir {
        Some(d) => {
            let dir = workspace::canonical(d)?;
            let path = dir.join(project::FILE).display().to_string();
            (Some(dir), path)
        }
        None => {
            if !ctx.rt.is_running(&names::dev(name)) {
                bail!(
                    "env `{name}` has its workspace only in the env, and it is stopped: \
                     `luoto up -e {name}` first"
                );
            }
            (
                None,
                format!("/workspace/{} in env `{name}`", project::FILE),
            )
        }
    };
    let old = match &dir {
        Some(d) => project::read_host(d)?,
        None => project::read_env(&ctx, name)?,
    };
    if let Some(old) = old {
        match project::parse(&old) {
            Ok(p) if p == s.config => {
                println!("{path} already has these settings");
                return Ok(ExitCode::SUCCESS);
            }
            Ok(p) => {
                println!("against {path}:");
                for l in project::diff(&p, &s.config) {
                    println!("  {l}");
                }
            }
            Err(e) => println!(
                "{path} doesn't parse: {}",
                crate::text::lines(&format!("{e:#}"))
            ),
        }
        if !force {
            println!("not written: --force replaces it (its comments too)");
            return Ok(ExitCode::FAILURE);
        }
    }
    match &dir {
        Some(d) => project::write_host(d, &s.text)?,
        None => project::write_env(&ctx, name, &s.text)?,
    }
    println!("wrote {path}: review it, then commit it");
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
    let ws = EnvFile::load(&ctx.paths, name)?.cfg.workspace;
    if let (None, Some(url)) = (&ws.dir, &ws.url)
        && to.is_none()
    {
        bail!(
            "env `{name}` is cloned from {} and has no folder on this machine: `luoto pull --to \
             <new folder>` copies its files out (its work leaves by git push)",
            crate::text::display(url)
        );
    }
    crate::connect::ensure_running(&ctx, name)?;
    let to = match to {
        Some(t) => {
            std::fs::create_dir_all(workspace::expand(t))?;
            let dest = workspace::canonical(t)?;
            workspace::check_pull_dest(&dest)?;
            // The env's files have no folder of theirs here, so they go somewhere new unless
            // you say otherwise: in a folder that holds other things, a file of theirs could
            // be one a tool of yours acts on.
            if ws.dir.is_none()
                && std::fs::read_dir(&dest)?.next().is_some()
                && !confirm(&format!(
                    "{} is not empty. Pull the env's files into it?",
                    dest.display()
                ))
            {
                bail!(
                    "nothing written: pick a new or empty folder (a folder with files in it \
                     needs a yes on a terminal)"
                );
            }
            Some(dest)
        }
        None => None,
    };
    let mut plans = Vec::new();
    let targets = pull_targets(&ctx, name, to, repo)?;
    let own: Vec<&str> = targets.iter().filter_map(|t| t.repo.as_deref()).collect();
    let left: Vec<&str> = targets
        .iter()
        .flat_map(|t| &t.skip)
        .map(String::as_str)
        .filter(|n| !own.contains(n))
        .collect();
    if !left.is_empty() {
        println!(
            "left out: {} (`luoto pull --repo <name>` brings one)",
            left.join(", ")
        );
    }
    for t in targets {
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

pub fn up(name: &str, selftest: bool, recreate: bool, quiet: bool) -> Result<ExitCode> {
    up_env(&Ctx::load()?, name, selftest, recreate, quiet)?;
    Ok(ExitCode::SUCCESS)
}

fn up_env(ctx: &Ctx, name: &str, selftest: bool, recreate: bool, quiet: bool) -> Result<()> {
    if recreate {
        env::remove_dev(ctx, name)?;
    }
    env::up(
        ctx,
        name,
        &UpOptions {
            no_selftest: !selftest,
            quiet,
            ..Default::default()
        },
    )
}

/// `f` on each of `envs`, its error printed as it fails; one that fails leaves the rest to go.
/// The ones that failed.
fn each_env(envs: &[String], mut f: impl FnMut(&str) -> Result<()>) -> Vec<String> {
    let mut failed = Vec::new();
    for name in envs {
        if let Err(e) = f(name) {
            eprintln!("luoto: `{name}`: {}", crate::text::lines(&format!("{e:#}")));
            failed.push(name.clone());
        }
    }
    failed
}

/// The end of a command on several envs: which failed, and a failing exit code if any did.
fn each_env_result(verb: &str, total: usize, failed: &[String]) -> ExitCode {
    if failed.is_empty() {
        return ExitCode::SUCCESS;
    }
    eprintln!(
        "\nluoto: {verb} failed for {} of {total} env(s): {}",
        failed.len(),
        failed.join(", ")
    );
    ExitCode::FAILURE
}

/// Every env up, asking nothing: what an env needs from you is printed instead, for
/// `luoto up -e <env>` to ask.
pub fn up_all(selftest: bool, recreate: bool, quiet: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let envs = config::list_envs(&ctx.paths)?;
    if envs.is_empty() {
        println!("no envs yet: `luoto init` in a project folder, or `luoto init <new-folder>`");
        return Ok(ExitCode::SUCCESS);
    }
    crate::prompt::never_ask();
    let mut first = true;
    let failed = each_env(&envs, |name| {
        println!("{}== {name} ==", if first { "" } else { "\n" });
        first = false;
        up_env(&ctx, name, selftest, recreate, quiet)
    });
    Ok(each_env_result("up", envs.len(), &failed))
}

/// Stop every env that runs; the vault keeps running.
pub fn down_all() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if machine::stopped(&ctx.rt) {
        println!("no env is running (luoto's VM is stopped)");
        return Ok(ExitCode::SUCCESS);
    }
    let states = ctx.rt.states()?;
    let running: Vec<String> = config::list_envs(&ctx.paths)?
        .into_iter()
        .filter(|e| states.running(&names::dev(e)) || states.running(&names::gate(e)))
        .collect();
    if running.is_empty() {
        println!("no env is running");
        return Ok(ExitCode::SUCCESS);
    }
    let failed = each_env(&running, |name| {
        env::down(&ctx, name)?;
        println!("env `{name}` stopped");
        Ok(())
    });
    crate::watch::spawn(&ctx);
    Ok(each_env_result("down", running.len(), &failed))
}

pub fn down(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if machine::stopped(&ctx.rt) {
        println!("env `{name}` is not running (luoto's VM is stopped)");
        return Ok(ExitCode::SUCCESS);
    }
    // While its dev container still runs, to name its build folders.
    disk::hint_growth(&ctx, name);
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
    // An env cloned from a remote has no folder: what isn't pushed exists only in the env.
    let url = EnvFile::load(&ctx.paths, name).ok().and_then(|f| {
        f.cfg
            .workspace
            .url
            .filter(|_| f.cfg.workspace.dir.is_none())
    });
    if let Some(url) = &url {
        println!(
            "`{name}` is cloned from {}: its work exists only in the env, unless pushed",
            crate::text::display(url)
        );
    }
    // A state that won't load must not keep an env from being removed.
    let repos = EnvState::load(&ctx.paths, name)
        .ok()
        .flatten()
        .map(|s| s.repos)
        .unwrap_or_default();
    if ctx.rt.is_running(&names::dev(name)) {
        match crate::repos::unpushed(&ctx, name, &repos) {
            Ok(found) if found.is_empty() => {}
            Ok(found) => {
                println!("Work in `{name}` that no remote has:");
                for w in found {
                    println!("  {w}");
                }
            }
            Err(e) => println!(
                "  git status failed in the env: {}",
                crate::text::lines(&format!("{e:#}"))
            ),
        }
    } else if url.is_some() || !repos.is_empty() {
        println!(
            "`{name}` is stopped: after `luoto up -e {name}`, `luoto rm` names the repos with work \
             no remote has"
        );
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

pub fn reset_home(name: &str, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    config::validate_name(name)?;
    if !ctx.paths.env_config(name).exists() {
        bail!("no env `{name}` (`luoto ls` lists them)");
    }
    if !yes
        && !confirm(&format!(
            "Discard the home of `{name}`: dotfiles, shell history, agents' logins and state, \
             toolchains? The workspace stays"
        ))
    {
        bail!("aborted (`luoto reset-home -e {name} --yes` skips the question)");
    }
    let running = ctx.rt.is_running(&names::dev(name));
    if !env::reset_home(&ctx, name)? {
        println!("`{name}` has no home yet: nothing to discard");
        return Ok(ExitCode::SUCCESS);
    }
    println!("discarded the home of `{name}`");
    if running {
        // Back as it was, with its agents and toolchains installed anew.
        env::up(&ctx, name, &UpOptions::default())?;
    } else {
        println!("`luoto up -e {name}` starts it with a fresh home");
    }
    Ok(ExitCode::SUCCESS)
}

pub fn ls(size: bool) -> Result<ExitCode> {
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
    let sizes = if size && !states.vm_stopped {
        disk::sizes(&ctx.rt)
            .map_err(|e| eprintln!("warning: sizes not read: {e:#}"))
            .ok()
    } else {
        None
    };
    let size_of = |e: &str| {
        let d = sizes.as_ref().map(|s| s.env(e));
        match d {
            Some(d) if !d.parts.is_empty() => disk::human(d.total),
            _ => "-".into(),
        }
    };
    let rows: Vec<(String, String, String, String)> = envs
        .iter()
        .map(|e| match EnvFile::load(&ctx.paths, e) {
            Ok(f) => (
                e.clone(),
                from(&f.cfg.workspace),
                env::env_image(&ctx, &f.cfg),
                f.cfg.presets.join(","),
            ),
            Err(_) => (
                e.clone(),
                String::new(),
                "(invalid config)".into(),
                String::new(),
            ),
        })
        .collect();
    let width = rows
        .iter()
        .map(|r| r.1.chars().count())
        .max()
        .unwrap_or(0)
        .max(4);
    let size_col = |text: &str| {
        if size {
            format!("{text:<10} ")
        } else {
            String::new()
        }
    };
    println!(
        "{:<20} {:<10} {:<10} {}{:<width$} {:<28} PRESETS",
        "ENV",
        "DEV",
        "GATE",
        size_col("SIZE"),
        "FROM",
        "IMAGE"
    );
    for (e, from, image, presets) in rows {
        let (dev, gate) = states.env(&e);
        let sz = size_col(&size_of(&e));
        println!("{e:<20} {dev:<10} {gate:<10} {sz}{from:<width$} {image:<28} {presets}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Where an env's workspace comes from, for `ls`: its folder (`~` for home), or the remote
/// cloned in it.
fn from(ws: &config::Workspace) -> String {
    match (&ws.dir, &ws.url) {
        (Some(d), _) => crate::ssh::tilde(std::path::Path::new(d)),
        (None, Some(u)) => crate::text::display(u),
        (None, None) => "-".into(),
    }
}

pub fn status(name: &str, json: bool, size: bool) -> Result<ExitCode> {
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
    let ws = &f.cfg.workspace;
    match (&ws.dir, &ws.url) {
        (None, Some(url)) => println!(
            "  workspace: cloned from {}{} in the env; nothing on this machine (work leaves by \
             git push, or `luoto pull --to <new folder>`)",
            crate::text::display(url),
            ws.branch
                .as_deref()
                .map(|b| format!(" ({})", crate::text::display(b)))
                .unwrap_or_default()
        ),
        (dir, _) => println!(
            "  folder: {} (copied in; `luoto pull` brings changes back)",
            dir.as_deref().unwrap_or("none")
        ),
    }
    let ca_dir = ctx.paths.env_state(name);
    if let Some(n) = crate::ca::notice(&ca_dir, name) {
        println!("  CA:     {n}");
    }
    let plan = env::plan(&ctx, name);
    if dev == "running" {
        let published = plan.as_ref().map_or(&f.cfg.ports, |p| &p.cfg.ports);
        print_ports(
            name,
            &ports::of_env(&ctx.paths, name, published, gate == "running"),
        );
    }
    if gate == "running" {
        let s = ctl::gate_status(&ctx.rt, name)?;
        let current = crate::ca::load(&ca_dir).ok().flatten();
        let ca = match (&s.ca_pem_sha256, current) {
            _ if !s.ca_installed => "missing",
            (Some(gate), Some(c)) if *gate != c.pem_sha256() => {
                "outdated (`luoto up` installs the current one)"
            }
            _ => "ok",
        };
        println!(
            "  policy: {} rules, CA {ca}, vault {}, {} pending request(s)",
            s.rules,
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
    // Last of the lines: the runtime walks every volume for it.
    if size && !states.vm_stopped {
        match disk::sizes(&ctx.rt) {
            Ok(s) => println!("  disk:   {}", s.env(name).describe()),
            Err(e) => println!("  disk:   not read ({e:#})"),
        }
    }
    print_rules(&plan?);
    Ok(ExitCode::SUCCESS)
}

fn print_ports(name: &str, p: &ports::EnvPorts) {
    let open: Vec<String> = p.open().into_iter().map(ports::url).collect();
    println!(
        "  ports:  {}",
        if open.is_empty() {
            "none forwarded".to_string()
        } else {
            open.join("  ")
        }
    );
    for port in &p.taken {
        println!(
            "          {port} is taken on this machine: `luoto forward -e {name} <port>:{port}`"
        );
    }
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
            r.rule.idle.as_ref().map(|i| format!("idle {i}")),
            r.rule
                .expires
                .map(|e| format!("until {}", e.format("%m-%d %H:%M"))),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
        let host = match r.rule.port {
            Some(port) => format!("{}:{port}", r.rule.host),
            None => r.rule.host.clone(),
        };
        println!(
            "{:<22} {:<38} {:<28} {} {extra}",
            r.id, host, access, r.origin
        );
    }
    if !p.compiled.policy.injections.is_empty() {
        println!("\ncredentials injected by the gate:");
        for i in &p.compiled.policy.injections {
            println!("  {:<38} binding {}", i.host, i.binding);
        }
    }
    if !p.cfg.deny.is_empty() {
        println!("\ndenied whatever allows them:");
        for d in &p.cfg.deny {
            println!("  {}", project::deny_line(d));
        }
    }
    if !p.cfg.mute.is_empty() {
        println!("\nmuted (still denied; `luoto egress --all` shows them):");
        for m in &p.cfg.mute {
            let paths = if m.paths.is_empty() {
                String::new()
            } else {
                format!(" {}", m.paths.join(" "))
            };
            println!("  {}{paths}", m.host);
        }
    }
    let fixed = p
        .compiled
        .policy
        .denies
        .len()
        .saturating_sub(p.cfg.deny.len());
    if fixed > 0 {
        println!("\nfixed denies: {fixed}");
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
        None => match r.port {
            Some(port) => format!(
                "a tunnel to {}:{port}, uninspected: any protocol and any data",
                crate::text::display(&r.host)
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
        },
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

pub fn approve(
    name: &str,
    id: u64,
    ttl: Option<&str>,
    narrow: &Narrowing,
    yes: bool,
    force: bool,
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let req = rules::request(&ctx, name, id)?;
    println!("request #{id}: {}", fmt_request(&req));
    if !narrow.is_empty() {
        // Before asking: a narrowing that would widen the request is refused here.
        let rule = rules::grant(&req, narrow)?;
        println!("grants less: {}", rules::describe(&rule));
    }
    if !yes && !confirm("Approve?") {
        bail!("not approved (use --yes to skip the prompt)");
    }
    match rules::accepting_risks(force, |force| {
        rules::approve(&ctx, name, &req, ttl, narrow, force)
    })? {
        rules::Approved::Installed { installed } => println!("{installed}"),
        rules::Approved::Rule(rule) => println!("approved: {}", rules::describe(&rule)),
    }
    Ok(ExitCode::SUCCESS)
}

pub fn reject(name: &str, id: u64, note: Option<String>) -> Result<ExitCode> {
    rules::reject(&Ctx::load()?, name, id, note)?;
    println!("rejected request #{id}");
    Ok(ExitCode::SUCCESS)
}

/// `all`: also the denials the env's mutes hide.
pub fn egress(
    name: &str,
    denied: bool,
    all: bool,
    since: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let mutes = env::mutes(&ctx, name)?;
    let mut evs = events::gate_events(&ctx.rt, name, since)?;
    let hidden = if all { 0 } else { mutes.hide(&mut evs) };
    let mut summary = events::summarize(&evs, &mutes);
    if denied {
        summary.retain(|s| s.denied > 0 || s.dns_only);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(ExitCode::SUCCESS);
    }
    let footer = || {
        if hidden > 0 {
            println!(
                "{hidden} muted denial{} left out (`luoto egress --all` shows them)",
                if hidden == 1 { "" } else { "s" }
            );
        }
    };
    if summary.is_empty() {
        println!(
            "no egress recorded{}",
            since
                .map(|s| format!(" in the last {s}"))
                .unwrap_or_default()
        );
        footer();
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
        } else if s.denied > 0 && s.muted == s.denied {
            format!("muted: {}", s.last_message.clone().unwrap_or_default())
        } else if s.tls_rejected {
            format!(
                "client rejected our CA → luoto allow -e {name} {} --tunnel",
                s.host
            )
        } else if s.denied > 0
            && (s.last_reason.as_deref() == Some("explicit")
                || s.host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(luoto_shared::host::is_never_dialed))
        {
            // No rule opens these (the metadata service, the gate's own ranges): the message
            // says what does, if anything.
            s.last_message.clone().unwrap_or_default()
        } else if s.denied > 0 && s.last_reason.as_deref() == Some("path_not_allowed") {
            // Other paths of the host are open (a relay may be open only for some): allowing
            // all of it would undo that.
            let glob = s
                .last_denied_path
                .as_deref()
                .and_then(luoto_shared::host::path_glob)
                .unwrap_or_else(|| "<path glob>".into());
            format!(
                "{} → luoto allow -e {name} {} --path '{glob}'",
                s.last_message.clone().unwrap_or_default(),
                s.host,
            )
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
    footer();
    Ok(ExitCode::SUCCESS)
}

/// `all`: also the denials the env's mutes hide.
pub fn logs(
    name: &str,
    follow: bool,
    denied: bool,
    all: bool,
    since: Option<&str>,
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let mutes = if all {
        events::Mutes::default()
    } else {
        env::mutes(&ctx, name)?
    };
    let show = |e: &luoto_shared::events::Event| {
        (!denied || e.verdict == Some(Verdict::Deny)) && !mutes.hides(e)
    };
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

pub fn reload(env: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    // An env's refs load whether held or not; the vault's own are only read again.
    let (refs, held_only) = match env {
        Some(e) => {
            let name = workspace::resolve(&ctx.paths, Some(e))?;
            (env::plan(&ctx, &name)?.compiled.vault_refs(), false)
        }
        None => (
            crate::ctl::vault_status(&ctx.rt)?
                .loaded_refs
                .into_iter()
                .collect(),
            true,
        ),
    };
    if refs.is_empty() {
        println!("the vault holds no secrets to read again (`luoto vault unlock` loads them)");
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("reading {} secret(s) from your secret store…", refs.len());
    let r = sync::reload(&ctx, &refs, held_only)?;
    println!(
        "read {}: {} changed{}",
        r.read,
        r.changed,
        if r.changed > 0 { ", in use now" } else { "" }
    );
    if !r.failed.is_empty() {
        eprintln!(
            "not read (their old values stay):\n  {}",
            r.failed.join("\n  ")
        );
        return Ok(ExitCode::FAILURE);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_env_failing_leaves_the_rest_to_go() {
        let envs: Vec<String> = ["a", "b", "c"].map(String::from).to_vec();
        let mut tried = Vec::new();
        let failed = each_env(&envs, |n| {
            tried.push(n.to_string());
            if n == "b" {
                bail!("no");
            }
            Ok(())
        });
        assert_eq!(tried, envs);
        assert_eq!(failed, ["b"]);
        assert_eq!(each_env_result("up", 3, &failed), ExitCode::FAILURE);
        assert_eq!(each_env_result("up", 3, &[]), ExitCode::SUCCESS);
    }
}
