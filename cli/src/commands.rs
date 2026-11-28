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
use crate::{ctl, disk, egress, events, machine, names, ports, project, sync, workspace};

/// Show, accept or drop the project's luoto.toml settings for an env.
pub fn project(
    name: &str,
    apply: Option<project::Take>,
    forget: bool,
    yes: bool,
) -> Result<ExitCode> {
    let accept = apply.is_some();
    let ctx = Ctx::load()?;
    if forget {
        project::ignore(&ctx, name)?;
        out!("`{name}` no longer applies the project's luoto.toml");
        return Ok(ExitCode::SUCCESS);
    }
    let mut took = None;
    if let Some(take) = apply {
        took = project::take_from_folder(&ctx, name, take)?;
    } else if let project::FolderCopy::Newer(_) = project::folder_copy(&ctx, name)? {
        out!(
            "luoto.toml in your folder changed since the env took its copy: `luoto project \
             apply -e {name}` takes it in"
        );
    }
    let st = project::status(&ctx, name)?;
    // What was taken is what is reviewed and applied, not what the env made of it since.
    if !project::taken_intact(took.as_deref(), st.text.as_deref()) {
        bail!(
            "luoto.toml in `{name}` is no longer the text taken from your folder: something in \
             the env changed it meanwhile. Nothing is applied; `luoto project apply -e {name}` \
             reviews what is there"
        );
    }
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
            out!("luoto.toml is accepted and applies to `{name}`:");
            show(&st.current);
        }
        project::State::Declined => {
            out!("luoto.toml is ignored for `{name}` (this version):");
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
            out!(
                "env `{name}` is not running, and its luoto.toml is only in the env: `luoto up \
                 -e {name}` reads it"
            );
            if !st.accepted.is_empty() {
                println!("the accepted settings apply:");
                show(&st.accepted);
            }
        }
    }
    // Applying asks for them on a terminal (below); otherwise they are what to add.
    if !(accept && crate::prompt::interactive()) {
        crate::init::print_needs(name, &st.needs);
    }
    let pending = st.pending();
    if !accept {
        if pending {
            out!("apply:  `luoto project apply -e {name}`");
            if st.state != project::State::Declined {
                out!("ignore: `luoto project ignore -e {name}`");
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    let Some(text) = st.text.filter(|_| pending) else {
        return Ok(ExitCode::SUCCESS);
    };
    if !yes && !confirm("Apply these settings to this env?") {
        return Err(crate::prompt::declined(
            "applied",
            &format!("luoto project apply -e {name} --yes"),
        ));
    }
    let running = project::apply(&ctx, name, &text)?;
    if running {
        out!("applied to `{name}`");
    } else {
        out!("accepted; applies on `luoto up -e {name}`");
    }
    // Without a terminal, what they need was printed above.
    if crate::prompt::interactive()
        && crate::needs::ask(&ctx, name, crate::wizard::Mode::Missing)?
        && running
    {
        sync::reapply(&ctx, name)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Print a luoto.toml from the env's settings, or write it to the env's folder, or into the
/// running env for an env cloned from a remote (replacing one there only with `overwrite`,
/// after showing what changes).
pub fn project_suggest(name: &str, write: bool, overwrite: bool) -> Result<ExitCode> {
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
    if cfg.workspace.dir.is_none() && cfg.workspace.url.is_none() {
        bail!(
            "a virtual workspace has no luoto.toml to write; `luoto project suggest -e {name}` \
             prints one for a repository of the team's"
        );
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
        if !overwrite {
            bail!(
                "{path} not written: `luoto project suggest -e {name} --write --overwrite` \
                 replaces it (its comments too)"
            );
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

/// What `luoto pull` was asked for.
#[derive(Default)]
pub struct PullOpts<'a> {
    pub to: Option<&'a str>,
    pub repo: Option<&'a str>,
    pub include_risky: bool,
    pub include_git: bool,
    pub overwrite: bool,
    pub yes: bool,
}

pub fn pull(name: &str, o: PullOpts) -> Result<ExitCode> {
    let PullOpts {
        to,
        repo,
        include_risky,
        include_git,
        overwrite,
        yes,
    } = o;
    let take = workspace::Take {
        risky: include_risky,
        conflicts: overwrite,
    };
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
    let _lock = crate::autopull::lock(&ctx.paths, name)?;
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
        out!(
            "left out: {} (`luoto pull --repo <name>` brings one)",
            left.join(", ")
        );
    }
    for t in &targets {
        let plan = crate::progress::wait("comparing the env's files with yours", || {
            workspace::plan_pull(&ctx, name, t, include_git)
        })?;
        if let Some(r) = &plan.repo {
            head!("\nrepo {r}:");
        }
        workspace::describe(&plan, &mut std::io::stdout(), crate::style::out())?;
        plans.push(plan);
    }
    let changed = |p: &workspace::PullPlan| p.entries.iter().filter(|e| take.takes(e)).count();
    // What is the same on both sides is known from here on, written or not.
    let settle = |written: &[Vec<String>]| {
        for ((t, plan), w) in targets.iter().zip(&plans).zip(written) {
            workspace::settle(&ctx, name, t, plan, w);
        }
    };
    let none = vec![Vec::new(); plans.len()];
    if plans.iter().all(|p| p.entries.is_empty()) {
        println!("nothing to pull");
        settle(&none);
        crate::autopull::reviewed(&ctx.paths, name);
        return Ok(ExitCode::SUCCESS);
    }
    let writable: usize = plans.iter().map(changed).sum();
    if writable == 0 {
        println!("nothing written:");
        let all = || plans.iter().flat_map(|p| &p.entries);
        let conflicts = all().filter(|e| e.conflict()).count();
        let risky = all().filter(|e| !e.conflict()).count();
        if risky > 0 {
            out!("  {risky} risky: `--include-risky` after reviewing them");
        }
        if conflicts > 0 {
            out!("  {conflicts} changed here too: `--overwrite` takes the env's");
        }
        settle(&none);
        // Looked at, which is what a run cut short waits for.
        crate::autopull::reviewed(&ctx.paths, name);
        return Ok(ExitCode::SUCCESS);
    }
    let dirs: Vec<String> = plans
        .iter()
        .filter(|p| changed(p) > 0)
        .map(|p| crate::ssh::tilde(std::path::Path::new(&p.dir)))
        .collect();
    if !yes
        && !confirm(&format!(
            "Write {writable} file(s) into {}?",
            dirs.join(", ")
        ))
    {
        return Err(crate::prompt::declined(
            "written",
            &format!("luoto pull -e {name} --yes"),
        ));
    }
    let (mut skipped, mut conflicts) = (0, 0);
    let mut written = Vec::new();
    let mut failed = Vec::new();
    for plan in &plans {
        let done = crate::progress::wait("writing", || workspace::apply_pull(plan, take));
        skipped += done.skipped;
        conflicts += done.conflicts;
        failed.extend(done.failed);
        if let Some(why) = done.unsynced {
            crate::progress::warn(&format!(
                "{} not synced to disk ({why}): a power cut now could lose what was written",
                plan.dir
            ));
        }
        written.push(done.written);
    }
    settle(&written);
    crate::autopull::reviewed(&ctx.paths, name);
    head!(
        "wrote {} file(s)",
        written.iter().map(Vec::len).sum::<usize>()
    );
    if skipped > 0 {
        out!("skipped {skipped} risky (review them, then `luoto pull -e {name} --include-risky`)");
    }
    if conflicts > 0 {
        out!(
            "kept {conflicts} of yours changed here too (`luoto pull -e {name} --overwrite` \
             takes the env's)"
        );
    }
    if failed.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    err!("{} file(s) not written:", failed.len());
    for (path, why) in failed.iter().take(30) {
        eprintln!(
            "  {} — {}",
            crate::text::display(path),
            crate::text::display(why)
        );
    }
    if failed.len() > 30 {
        eprintln!("  … and {} more", failed.len() - 30);
    }
    Ok(ExitCode::FAILURE)
}

/// `luoto pull --on-stop on|off`: whether every stop of the env first pulls its files into
/// its folders, with nobody reviewing them. Then the summary.
pub fn pull_on_stop(name: &str, on: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let mut f = EnvFile::load(&ctx.paths, name)?;
    let pull = format!("luoto pull -e {name}");
    if !on {
        let was = f.cfg.workspace.dangerously_pull_on_stop;
        if was {
            f.set_pull_on_stop(false)?;
            crate::autopull::turned_off(&ctx.paths, name);
        }
        let title = format!(
            "env `{name}` {} when it stops",
            if was {
                "no longer pulls"
            } else {
                "doesn't pull"
            }
        );
        let rows = [
            ("pull", format!("{pull} (reviewed)")),
            ("turn on", format!("luoto pull --on-stop on -e {name}")),
        ];
        block!("{}", crate::prompt::summary(&title, &rows));
        return Ok(ExitCode::SUCCESS);
    }
    let ws = &f.cfg.workspace;
    if !ws.has_folder() {
        bail!(
            "env `{name}` has no folder on this machine to pull into ({}): its work leaves by \
             git push, or `luoto pull --to <folder>`",
            match &ws.url {
                Some(url) => format!("it is cloned from {}", crate::text::display(url)),
                None => "a virtual workspace whose repos are all clones".to_string(),
            }
        );
    }
    let mut folders: Vec<String> = ws.dir.iter().cloned().collect();
    folders.extend(ws.repos.values().filter_map(|r| r.dir.clone()));
    let present = seeded_repos(&ctx, name);
    // A copy with no record of what it started from waits for one reviewed pull.
    let unbased = EnvState::load(&ctx.paths, name).ok().flatten().is_some()
        && workspace::pull_targets(ws, None, None, &present)
            .unwrap_or_default()
            .iter()
            .any(|t| t.home && t.base(&ctx.paths, name).is_none());
    f.set_pull_on_stop(true)?;
    if ctx.rt.is_running(&names::dev(name)) {
        crate::autopull::started(&ctx.paths, name);
    }
    let folders: Vec<String> = folders
        .iter()
        .map(|d| crate::ssh::tilde(&workspace::expand(d)))
        .collect();
    let mut rows = vec![
        ("into", folders.join(", ")),
        (
            "when",
            "`luoto down`, the idle stop, the UI's stop, a run's --down/--rm".to_string(),
        ),
        (
            "writes",
            "what the env changed and you didn't, with nobody reviewing it".to_string(),
        ),
        (
            "held back",
            "what tools here run by themselves, and files you changed too".to_string(),
        ),
        ("review", pull.clone()),
        ("turn off", format!("luoto pull --on-stop off -e {name}")),
    ];
    if unbased {
        rows.insert(
            1,
            (
                "first",
                "a reviewed pull that leaves nothing: its copy has no base yet".to_string(),
            ),
        );
    }
    let title = format!("env `{name}` pulls into your folder whenever it stops");
    block!("{}", crate::prompt::summary(&title, &rows));
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
            crate::progress::error(&format!(
                "`{name}`: {}",
                crate::text::lines(&format!("{e:#}"))
            ));
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
    eprintln!();
    crate::progress::error(&format!(
        "{verb} failed for {} of {total} env(s): {}",
        failed.len(),
        failed.join(", ")
    ));
    ExitCode::FAILURE
}

/// Every env up, asking nothing: what an env needs from you is printed instead, for
/// `luoto up -e <env>` to ask.
pub fn up_all(selftest: bool, recreate: bool, quiet: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let envs = config::list_envs(&ctx.paths)?;
    if envs.is_empty() {
        out!("no envs yet: `luoto init` in a project folder, or `luoto init <new-folder>`");
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
    let mut incomplete = false;
    let failed = each_env(&running, |name| {
        let stopped = crate::autopull::stop(&ctx, name, crate::autopull::Why::Down, false)?;
        out!("env `{name}` stopped");
        if let Some(r) = &stopped.report {
            r.print(&mut std::io::stdout(), crate::style::out(), 30);
            incomplete |= r.incomplete();
        }
        Ok(())
    });
    crate::watch::spawn(&ctx);
    if failed.is_empty() && incomplete {
        return Ok(ExitCode::from(crate::autopull::INCOMPLETE));
    }
    Ok(each_env_result("down", running.len(), &failed))
}

/// `luoto down`'s exit code: [`autopull::INCOMPLETE`] when the stop pulled and something the
/// env holds didn't land, so a job doesn't take the folder for done.
fn down_code(stopped: &crate::autopull::Stopped) -> ExitCode {
    match &stopped.report {
        Some(r) if r.incomplete() => ExitCode::from(crate::autopull::INCOMPLETE),
        _ => ExitCode::SUCCESS,
    }
}

/// `luoto down`: stop the env, its files pulled into its folder first when its own file
/// says so (`autopull::stop`). `idle` is the watcher's stop, whose output is its log.
pub fn down(name: &str, idle: bool) -> Result<ExitCode> {
    use crate::autopull::{self, Why};
    let ctx = Ctx::load()?;
    // A pull still owed to its folder is done from its volume, VM started for it.
    let owed = autopull::on(&ctx.paths, name) && autopull::Pending::load(&ctx.paths, name).owed();
    if machine::stopped(&ctx.rt) && !owed {
        out!("env `{name}` is not running (luoto's VM is stopped)");
        return Ok(ExitCode::SUCCESS);
    }
    if idle {
        let stopped = autopull::stop(&ctx, name, Why::Idle, false)?;
        if let Some(r) = &stopped.report {
            r.print(&mut std::io::stdout(), crate::style::out(), 10);
        }
        return Ok(down_code(&stopped));
    }
    // While its dev container still runs, to name its build folders.
    disk::hint_growth(&ctx, name);
    let stopped = autopull::stop(&ctx, name, Why::Down, false)?;
    if stopped.was_running {
        out!("env `{name}` stopped");
    } else {
        out!("env `{name}` was not running");
    }
    if let Some(r) = &stopped.report {
        r.print(&mut std::io::stdout(), crate::style::out(), 30);
    }
    // The VM stays up for a quick `up`; the watcher stops it after `idle_stop` without envs.
    crate::watch::spawn(&ctx);
    Ok(down_code(&stopped))
}

pub fn rm(name: &str, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    config::validate_name(name)?;
    let cfg = ctx.paths.env_config(name);
    if !cfg.exists() {
        return Err(config::no_env(name));
    }
    // An env cloned from a remote has no folder: what isn't pushed exists only in the env.
    let url = EnvFile::load(&ctx.paths, name).ok().and_then(|f| {
        f.cfg
            .workspace
            .url
            .filter(|_| f.cfg.workspace.dir.is_none())
    });
    if let Some(url) = &url {
        out!(
            "`{name}` is cloned from {}: its work exists only in the env, unless pushed",
            crate::text::display(url)
        );
    }
    let ws = EnvFile::load(&ctx.paths, name)
        .ok()
        .map(|f| f.cfg.workspace);
    if ws
        .as_ref()
        .is_some_and(|w| w.dir.is_none() && w.url.is_none())
    {
        out!(
            "`{name}` is a virtual workspace: what is only in its /workspace, and its clones' \
             work unless pushed, goes with it"
        );
    }
    let repos = seeded_repos(&ctx, name);
    if ctx.rt.is_running(&names::dev(name)) {
        match crate::repos::unpushed(&ctx, name, &repos) {
            Ok(found) if found.is_empty() => {}
            Ok(found) => {
                out!("Work in `{name}` that no remote has:");
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
        out!(
            "env `{name}` is not running: after `luoto up -e {name}`, `luoto rm` names the repos \
             with work no remote has"
        );
    }
    if !yes
        && !confirm(&format!(
            "Delete env `{name}` with its workspace, home and config? \
             Work not pushed or pulled (`luoto pull`) is lost"
        ))
    {
        return Err(crate::prompt::declined(
            "removed",
            &format!("luoto rm -e {name} --yes"),
        ));
    }
    remove_env(&ctx, name)?;
    out!("env `{name}` removed");
    Ok(ExitCode::SUCCESS)
}

/// The repos luoto put at `/workspace/<name>` in `name`. A state that won't load must not
/// keep an env from being removed.
fn seeded_repos(ctx: &Ctx, name: &str) -> std::collections::BTreeSet<String> {
    EnvState::load(&ctx.paths, name)
        .ok()
        .flatten()
        .map(|s| s.repos)
        .unwrap_or_default()
}

/// The work in running env `name` that no remote has, as `luoto rm` names it: `/workspace`
/// and each of its repos.
pub fn unpushed(ctx: &Ctx, name: &str) -> Result<Vec<crate::repos::Unpushed>> {
    crate::repos::unpushed(ctx, name, &seeded_repos(ctx, name))
}

/// What running env `name` holds that its folder, and its repos' folders, don't have: for
/// each folder with something, what. Nothing for an env with no folder here.
pub fn unpulled(ctx: &Ctx, name: &str) -> Result<Vec<workspace::Unpulled>> {
    let ws = env::layered(ctx, name)?.workspace;
    let targets = if ws.dir.is_some() {
        pull_targets(ctx, name, None, None)?
    } else {
        // Without a folder of its own, only its repos copied in from one have a folder.
        let mut all = Vec::new();
        for repo in seeded_repos(ctx, name) {
            if ws.repos.get(&repo).is_some_and(|r| r.dir.is_some()) {
                all.extend(pull_targets(ctx, name, None, Some(&repo))?);
            }
        }
        all
    };
    let _waiting = crate::progress::waiting("comparing the env's files with yours");
    let mut found = Vec::new();
    for t in &targets {
        let u = workspace::unpulled(ctx, name, t)?;
        if u.any() {
            found.push(u);
        }
    }
    Ok(found)
}

/// Remove env `name`: its containers and volumes, its host key and its config file.
pub fn remove_env(ctx: &Ctx, name: &str) -> Result<()> {
    // Volumes live in the VM, which may have stopped on idle; a deleted VM took them along.
    if machine::gone(&ctx.rt) {
        env::forget(ctx, name)?;
    } else {
        env::ensure_vm(ctx)?;
        env::remove(ctx, name)?;
    }
    crate::ssh::forget_host_key(ctx, name)?;
    std::fs::remove_file(ctx.paths.env_config(name))?;
    crate::ssh::write_config(ctx)?;
    Ok(())
}

pub fn reset_home(name: &str, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    config::validate_name(name)?;
    if !ctx.paths.env_config(name).exists() {
        return Err(config::no_env(name));
    }
    if !yes
        && !confirm(&format!(
            "Discard the home of `{name}`: dotfiles, shell history, agents' logins and state, \
             toolchains? The workspace stays"
        ))
    {
        return Err(crate::prompt::declined(
            "discarded",
            &format!("luoto reset-home -e {name} --yes"),
        ));
    }
    let running = ctx.rt.is_running(&names::dev(name));
    if !env::reset_home(&ctx, name)? {
        out!("env `{name}` has no home yet: nothing to discard");
        return Ok(ExitCode::SUCCESS);
    }
    out!("discarded the home of `{name}`");
    if running {
        // Back as it was, with its agents and toolchains installed anew.
        env::up(&ctx, name, &UpOptions::default())?;
    } else {
        out!("`luoto up -e {name}` starts it with a fresh home");
    }
    Ok(ExitCode::SUCCESS)
}

pub fn list(size: bool, json: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let envs = config::list_envs(&ctx.paths)?;
    if envs.is_empty() && json {
        println!("[]");
        return Ok(ExitCode::SUCCESS);
    }
    if envs.is_empty() {
        out!("no envs yet: `luoto init` in a project folder, or `luoto init <new-folder>`");
        return Ok(ExitCode::SUCCESS);
    }
    let states = ctx.rt.states().unwrap_or_default();
    if states.vm_stopped && !json {
        out!("luoto's VM is stopped; `luoto up` starts it with the env\n");
    }
    let sizes = if size && !states.vm_stopped {
        crate::progress::wait("measuring every volume", || disk::sizes(&ctx.rt))
            .map_err(|e| crate::progress::warn(&format!("sizes not read: {e:#}")))
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
    let now = chrono::Utc::now();
    if json {
        let listed: Vec<ListedEnv> = rows
            .into_iter()
            .map(|(env, from, image, presets)| {
                let (dev, gate) = states.env(&env);
                let running = states.running(&names::dev(&env));
                ListedEnv {
                    last_used: match running {
                        true => Some(now),
                        false => crate::used::of(&ctx.paths, &env).time(),
                    },
                    size: sizes.as_ref().map(|s| s.env(&env).total),
                    presets: presets
                        .split(',')
                        .filter(|p| !p.is_empty())
                        .map(str::to_string)
                        .collect(),
                    env,
                    dev,
                    gate,
                    from,
                    image,
                }
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&listed)?);
        return Ok(ExitCode::SUCCESS);
    }
    let rows: Vec<ListRow> = rows
        .into_iter()
        .map(|(env, from, image, presets)| {
            let (dev, gate) = states.env(&env);
            let running = states.running(&names::dev(&env));
            ListRow {
                used: match running {
                    true => "now".into(),
                    false => crate::used::of(&ctx.paths, &env).shown(now),
                },
                size: size.then(|| size_of(&env)),
                env,
                dev,
                gate,
                from,
                image,
                presets,
            }
        })
        .collect();
    let style = crate::style::out();
    for (i, line) in list_lines(&rows, crate::text::columns()).iter().enumerate() {
        // The heading, and each env's presets under it, step back for the envs.
        if i == 0 || line.starts_with(' ') {
            println!("{}", style.dim(line));
        } else {
            println!("{line}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// An env in `luoto list --json`.
#[derive(serde::Serialize)]
struct ListedEnv {
    env: String,
    dev: String,
    gate: String,
    /// Bytes on disk, with `--size`.
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    /// When it was last used: now while it runs; none without a record.
    last_used: Option<chrono::DateTime<chrono::Utc>>,
    from: String,
    image: String,
    presets: Vec<String>,
}

/// An env in `luoto list`.
struct ListRow {
    env: String,
    dev: String,
    gate: String,
    /// With `--size`.
    size: Option<String>,
    /// When it was last used (`used.rs`): `now` while it runs.
    used: String,
    from: String,
    image: String,
    presets: String,
}

/// `luoto list`: a heading, then each env on a line, its columns as wide as what they hold,
/// and its presets on the lines under it, wrapped to `width`.
fn list_lines(rows: &[ListRow], width: usize) -> Vec<String> {
    let wide = |head: &str, of: &dyn Fn(&ListRow) -> &str| {
        rows.iter()
            .map(|r| of(r).chars().count())
            .fold(head.len(), usize::max)
    };
    let (env_w, dev_w, gate_w, from_w) = (
        wide("ENV", &|r| &r.env),
        wide("DEV", &|r| &r.dev),
        wide("GATE", &|r| &r.gate),
        wide("FROM", &|r| &r.from),
    );
    let size_w = wide("SIZE", &|r| r.size.as_deref().unwrap_or(""));
    let used_w = wide("USED", &|r| &r.used);
    let sized = rows.iter().any(|r| r.size.is_some());
    let line =
        |env: &str, dev: &str, gate: &str, size: &str, used: &str, from: &str, image: &str| {
            let size = if sized {
                format!("{size:<size_w$}  ")
            } else {
                String::new()
            };
            format!(
                "{env:<env_w$}  {dev:<dev_w$}  {gate:<gate_w$}  {size}{used:<used_w$}  \
             {from:<from_w$}  {image}"
            )
            .trim_end()
            .to_string()
        };
    let mut out = vec![line("ENV", "DEV", "GATE", "SIZE", "USED", "FROM", "IMAGE")];
    for r in rows {
        out.push(line(
            &r.env,
            &r.dev,
            &r.gate,
            r.size.as_deref().unwrap_or(""),
            &r.used,
            &r.from,
            &r.image,
        ));
        if !r.presets.is_empty() {
            let presets = r.presets.replace(',', ", ");
            out.extend(
                crate::text::hang("  presets  ", &presets, width)
                    .lines()
                    .map(String::from),
            );
        }
    }
    out
}

/// Where an env's workspace comes from, for `list`: its folder (`~` for home), or the remote
/// cloned in it.
fn from(ws: &config::Workspace) -> String {
    match (&ws.dir, &ws.url) {
        (Some(d), _) => crate::ssh::tilde(std::path::Path::new(d)),
        (None, Some(u)) => crate::text::display(u),
        (None, None) => match ws.repos.len() {
            1 => "1 repo".into(),
            n => format!("{n} repos"),
        },
    }
}

/// How `luoto status` prints.
pub enum StatusAs {
    Text,
    /// What the text says, as JSON.
    Json,
    /// The compiled policy the gate gets.
    PolicyJson,
}

pub fn status(name: &str, shape: StatusAs, size: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if let StatusAs::PolicyJson = shape {
        let p = env::plan(&ctx, name)?;
        println!("{}", serde_json::to_string_pretty(&p.compiled.policy)?);
        return Ok(ExitCode::SUCCESS);
    }
    let json = matches!(shape, StatusAs::Json);
    let mut j = serde_json::Map::new();
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
    let mut rows: Vec<(&str, String)> = vec![
        ("config", f.path.display().to_string()),
        ("dev", dev.clone()),
        ("gate", gate.clone()),
        (
            "isolation",
            crate::init::isolation_text(
                ctx.rt.flavor == crate::runtime::Flavor::Apple,
                f.cfg.isolation,
                ctx.global.gvisor.is_some(),
            )
            .to_string(),
        ),
        (
            "idle",
            match crate::idle::limit(&ctx.global, &f.cfg) {
                Some(d) => format!(
                    "stops after {} min with no shell, editor, agent or server running",
                    d.as_secs() / 60
                ),
                None => "never stops on its own".into(),
            },
        ),
    ];
    j.insert("env".into(), name.into());
    j.insert("config".into(), f.path.display().to_string().into());
    j.insert("dev".into(), dev.clone().into());
    j.insert("gate".into(), gate.clone().into());
    j.insert("isolation".into(), rows[3].1.clone().into());
    j.insert(
        "idle_stop".into(),
        crate::idle::limit(&ctx.global, &f.cfg)
            .map(|d| serde_json::json!({ "seconds": d.as_secs() }))
            .unwrap_or_default(),
    );
    let open = f.cfg.egress.open_at(chrono::Utc::now())?;
    // Open: `{"until": null}` with no end.
    j.insert(
        "egress_open".into(),
        open.map(|until| serde_json::json!({ "until": until }))
            .unwrap_or_default(),
    );
    if let Some(until) = open {
        let width = crate::text::columns().saturating_sub(STATUS_KEYS);
        rows.push(("egress", egress::state_line(name, until, width)));
    }
    let ws = &f.cfg.workspace;
    j.insert(
        "workspace".into(),
        serde_json::json!({
            "folder": ws.dir,
            "remote": ws.url,
            "branch": ws.branch,
            "repos": ws.repos.keys().collect::<Vec<_>>(),
        }),
    );
    j.insert("pull_on_stop".into(), ws.dangerously_pull_on_stop.into());
    rows.push(match (&ws.dir, &ws.url) {
        (None, Some(url)) => (
            "workspace",
            format!(
                "cloned from {}{} in the env; nothing on this machine (work leaves by git push, \
                 or `luoto pull -e {name} --to <new folder>`)",
                crate::text::display(url),
                ws.branch
                    .as_deref()
                    .map(|b| format!(" ({})", crate::text::display(b)))
                    .unwrap_or_default()
            ),
        ),
        (None, None) => (
            "workspace",
            if ws.repos.values().any(|r| r.dir.is_some()) {
                format!(
                    "virtual: no folder of its own; /workspace holds its repos (`luoto pull -e \
                     {name}` brings each copied from a folder back to it)"
                )
            } else if ws.repos.is_empty() {
                "virtual: no folder of its own, nothing from this machine; `luoto repo add` adds \
                 repos"
                    .to_string()
            } else {
                "virtual: no folder of its own; /workspace holds its clones, whose work leaves by \
                 git push"
                    .to_string()
            },
        ),
        (Some(dir), _) => (
            "folder",
            format!("{dir} (copied in; `luoto pull -e {name}` brings changes back)"),
        ),
    });
    if f.cfg.workspace.dangerously_pull_on_stop {
        rows.push((
            "pull",
            format!(
                "at every stop, with nobody reviewing it (`luoto pull --on-stop off -e {name}` \
                 ends that)"
            ),
        ));
    }
    let ca_dir = ctx.paths.env_state(name);
    if let Some(n) = crate::ca::notice(&ca_dir, name) {
        rows.push(("CA", n));
    }
    let plan = env::plan(&ctx, name);
    if dev == "running" {
        let published = plan.as_ref().map_or(&f.cfg.ports, |p| &p.cfg.ports);
        let p = ports::of_env(&ctx.paths, name, published, gate == "running");
        let urls: Vec<String> = p.open().into_iter().map(ports::url).collect();
        j.insert("ports".into(), urls.into());
        rows.push(("ports", ports_text(name, &p)));
    }
    if gate == "running" {
        let s = ctl::gate_status(&ctx.rt, name)?;
        let current = crate::ca::load(&ca_dir).ok().flatten();
        let ca = match (&s.ca_pem_sha256, current) {
            _ if !s.ca_installed => "missing".to_string(),
            (Some(gate), Some(c)) if *gate != c.pem_sha256() => {
                format!("outdated (`luoto up -e {name}` installs the current one)")
            }
            _ => "ok".to_string(),
        };
        j.insert(
            "policy".into(),
            serde_json::json!({
                "rules": s.rules,
                "ca": ca,
                "vault_configured": s.vault_configured,
                "pending_requests": s.pending_requests,
            }),
        );
        rows.push((
            "policy",
            format!(
                "{} rules, CA {ca}, vault {}, {} pending request(s)",
                s.rules,
                if s.vault_configured {
                    "configured"
                } else {
                    "not configured"
                },
                s.pending_requests
            ),
        ));
    }
    if let Ok(v) = ctl::vault_status(&ctx.rt) {
        j.insert("vault_locked".into(), v.locked.into());
        rows.push((
            "vault",
            if v.locked { LOCKED } else { "unlocked" }.to_string(),
        ));
        if let Some(e) = v.envs.iter().find(|e| e.env == name) {
            j.insert("credentials".into(), e.bindings.clone().into());
            j.insert(
                "missing_secrets".into(),
                e.missing
                    .iter()
                    .map(|r| crate::secrets::shown_ref(r))
                    .collect::<Vec<_>>()
                    .into(),
            );
            if !e.bindings.is_empty() {
                rows.push(("credentials", e.bindings.join(", ")));
            }
            if !e.missing.is_empty() {
                rows.push(("missing secrets", shown_refs(&e.missing)));
            }
        }
    }
    // Last of the rows: the runtime walks every volume for it.
    if size && !states.vm_stopped {
        let disk = match crate::progress::wait("measuring every volume", || disk::sizes(&ctx.rt)) {
            Ok(s) => {
                j.insert("size".into(), s.env(name).total.into());
                s.env(name).describe()
            }
            Err(e) => format!("not read ({e:#})"),
        };
        rows.push(("disk", disk));
    }
    if json {
        let plan = plan?;
        j.insert("warnings".into(), plan.compiled.warnings.clone().into());
        let policy = serde_json::to_value(&plan.compiled.policy)?;
        j.insert("rules".into(), policy["rules"].clone());
        println!("{}", serde_json::to_string_pretty(&j)?);
        return Ok(ExitCode::SUCCESS);
    }
    block!(
        "{}",
        crate::prompt::rows(&format!("env {name}"), &rows, crate::text::columns())
    );
    let plan = plan?;
    for w in &plan.compiled.warnings {
        crate::progress::warn(w);
    }
    print_rules(&plan);
    Ok(ExitCode::SUCCESS)
}

/// The columns before a status row's value.
const STATUS_KEYS: usize = 2 + "missing secrets".len() + 3;

/// What `status` and `vault status` say of a locked vault.
const LOCKED: &str = "locked: `luoto vault unlock` (or `luoto up`) loads the secrets";

/// The env's forwarded ports, and a line for each taken here.
fn ports_text(name: &str, p: &ports::EnvPorts) -> String {
    let open: Vec<String> = p.open().into_iter().map(ports::url).collect();
    let mut out = if open.is_empty() {
        "none forwarded".to_string()
    } else {
        open.join(", ")
    };
    match p.temporary.len() {
        0 => {}
        1 => out.push_str(", and 1 port picked for a server"),
        n => out.push_str(&format!(", and {n} ports picked for servers")),
    }
    for port in &p.taken {
        out.push_str(&format!(
            "\n{port} is taken on this machine: `luoto forward -e {name} <port>:{port}`"
        ));
    }
    out
}

fn print_rules(p: &env::Plan) {
    let rows: Vec<RuleRow> = p
        .compiled
        .policy
        .rules
        .iter()
        .map(|r| RuleRow {
            id: r.id.clone(),
            host: match r.rule.port {
                Some(port) => format!("{}:{port}", r.rule.host),
                None => r.rule.host.clone(),
            },
            access: match (&r.rule.mode, &r.rule.access) {
                (Mode::Tunnel, _) => "tunnel (any)".into(),
                (
                    _,
                    luoto_shared::policy::Access::Level(luoto_shared::policy::AccessLevel::Read),
                ) => READ_ONLY.into(),
                (_, a) => a.describe(),
            },
            origin: r.origin.to_string(),
            more: [
                (!r.rule.paths.is_empty()).then(|| format!("paths {}", r.rule.paths.join(", "))),
                r.rule.idle.as_ref().map(|i| format!("idle {i}")),
                r.rule
                    .expires
                    .map(|e| format!("until {}", egress::at_text(e))),
            ]
            .into_iter()
            .flatten()
            .collect(),
        })
        .collect();
    let style = crate::style::out();
    println!();
    for (i, line) in rule_lines(&rows, crate::text::columns()).iter().enumerate() {
        // The heading, the origins and what narrows a rule step back for the rules.
        let rule = line.starts_with("  ") && !line.starts_with("    ");
        if i > 0 && rule {
            println!("{line}");
        } else {
            println!("{}", style.dim(line));
        }
    }
    if !p.compiled.policy.injections.is_empty() {
        head!("\ncredentials injected by the gate:");
        for i in &p.compiled.policy.injections {
            println!("  {:<38} binding {}", i.host, i.binding);
        }
    }
    if !p.cfg.deny.is_empty() {
        head!("\ndenied whatever allows them:");
        for d in &p.cfg.deny {
            println!("  {}", project::deny_line(d));
        }
    }
    if !p.cfg.mute.is_empty() {
        head!("\nmuted (still denied; `luoto egress --all` shows them):");
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
    let mut rule = rules::build_rule(&o)?;
    // A normal-looking name on a private address (the user's network, a VPN) is reached only
    // by a rule that says so: asked here, where it is decided.
    let resolved = if rule.allow_private {
        rules::Resolved::default()
    } else {
        rules::resolve(&rule.host)
    };
    let private = resolved.private.join(", ");
    if !private.is_empty()
        && crate::prompt::confirm(&format!(
            "{} resolves to {private}, a private address (your network or a VPN). Let the rule \
             reach it?",
            rule.host
        ))
    {
        rule.allow_private = true;
    }
    let id = rule.id.clone().unwrap_or_default();
    let mut rows = vec![("access", rule.access.describe())];
    if !rule.paths.is_empty() {
        rows.push(("paths", rule.paths.join(",")));
    }
    if let Some(e) = rule.expires {
        rows.push(("expires", egress::at_text(e)));
    }
    if let Some(ca) = &rule.ca {
        rows.push(("trusts CA", crate::text::display(ca)));
    }
    rows.push(("rule", id.clone()));
    rows.push(("revoke it", format!("luoto revoke -e {name} {id}")));
    let title = format!("allowed {}", rule.host);
    rules::accepting_risks(o.force, |force| {
        rules::add_rule_checked(&ctx, name, rule.clone(), force)
    })?;
    block!("{}", crate::prompt::summary(&title, &rows));
    if !private.is_empty() && !rule.allow_private {
        out!(
            "{} resolves to {private}, which the rule doesn't reach: `luoto allow -e {name} {} \
             --private` makes one that does",
            rule.host,
            rules::allow_args(&rule)
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn revoke(name: &str, rule: &str) -> Result<ExitCode> {
    let n = rules::remove(&Ctx::load()?, name, rule)?;
    head!("removed {n} rule(s)");
    Ok(ExitCode::SUCCESS)
}

/// A rule in `luoto status`.
struct RuleRow {
    id: String,
    host: String,
    access: String,
    origin: String,
    /// What narrows it: its paths, its idle limit, its expiry.
    more: Vec<String>,
}

/// Read access in the rules table; a line under the table says which methods it is.
const READ_ONLY: &str = "read-only";

/// The rules of `luoto status`, in the policy's order: a heading, each origin on a line
/// before the run of rules it made, each rule under it (id, host, access, in columns as wide
/// as what they hold), and what narrows a rule on the lines under it, wrapped to `width`.
fn rule_lines(rows: &[RuleRow], width: usize) -> Vec<String> {
    let id_w = rows
        .iter()
        .map(|r| r.id.chars().count())
        .fold("RULE".len(), usize::max);
    let host_w = rows
        .iter()
        .map(|r| r.host.chars().count())
        .fold("HOST".len(), usize::max);
    let mut out = vec![format!("  {:<id_w$}  {:<host_w$}  ACCESS", "RULE", "HOST")];
    let mut origin = None;
    for r in rows {
        if origin != Some(&r.origin) {
            out.push(r.origin.clone());
            origin = Some(&r.origin);
        }
        out.push(format!(
            "  {:<id_w$}  {:<host_w$}  {}",
            r.id, r.host, r.access
        ));
        for m in &r.more {
            out.extend(
                crate::text::hang("    ", m, width)
                    .lines()
                    .map(String::from),
            );
        }
    }
    if rows.iter().any(|r| r.access == READ_ONLY) {
        out.push(format!("{READ_ONLY}: GET, HEAD, OPTIONS"));
    }
    out
}

/// What the sandbox asked for and why, escaped: the sandbox wrote all of it.
fn fmt_request(r: &AccessRequest) -> String {
    let what = match &r.install {
        Some(i @ luoto_shared::api::Install::Preset { name }) => {
            // The hosts are luoto's own data; the name is the sandbox's.
            let opens = match crate::rules::preset_hosts(name) {
                Some(hosts) => hosts
                    .iter()
                    .map(|h| format!("\n     {h}"))
                    .collect::<String>(),
                None => "\n     nothing: luoto has no such preset".into(),
            };
            format!(
                "{}, kept in the env's config\n   opens:{opens}",
                crate::text::display(&i.describe())
            )
        }
        Some(i @ luoto_shared::api::Install::Var { .. }) => format!(
            "{}, a plain value from you, readable by any code in the env",
            crate::text::display(&i.describe())
        ),
        Some(i) => format!(
            "install {}, kept in the env's config",
            crate::text::display(&i.describe())
        ),
        None => {
            let at = r.target();
            if r.is_tunnel() {
                format!(
                    "a tunnel to {}, uninspected: any protocol and any data",
                    crate::text::display(&at)
                )
            } else {
                format!(
                    "{} {}{}{}",
                    crate::text::display(&at),
                    luoto_shared::policy::Access::Level(r.access).describe(),
                    if r.paths.is_empty() {
                        String::new()
                    } else {
                        format!(" paths {}", crate::text::display(&r.paths.join(",")))
                    },
                    if r.ws { ", websockets too" } else { "" }
                )
            }
        }
    };
    let private = if r.private {
        "\n   on your network or VPN: a private address, or one only a VPN reaches"
    } else {
        ""
    };
    format!(
        "{what}{private}\n   reason (written by the sandbox, untrusted): {:?}",
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
    let style = crate::style::out();
    println!(
        "{}  {}\n   {} {}   {} {}",
        style.head(&format!("{e} #{}", r.id)),
        fmt_request(r),
        style.dim("approve:"),
        style.head(&format!("luoto approve -e {e} {}", r.id)),
        style.dim("reject:"),
        style.head(&format!("luoto reject -e {e} {}", r.id))
    );
}

pub fn requests(name: Option<&str>, follow: bool, json: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let now = pending(&ctx, name)?;
    if json {
        #[derive(serde::Serialize)]
        struct Pending<'a> {
            env: &'a str,
            #[serde(flatten)]
            request: &'a AccessRequest,
        }
        let listed: Vec<Pending> = now
            .iter()
            .map(|(env, request)| Pending { env, request })
            .collect();
        println!("{}", serde_json::to_string_pretty(&listed)?);
        return Ok(ExitCode::SUCCESS);
    }
    for (e, r) in &now {
        print_request(e, r);
    }
    if !follow {
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

/// How `luoto approve` grants: its flags.
pub struct Approval {
    /// The rule reaches the host on the user's network or VPN.
    pub private: bool,
    /// Nothing asked.
    pub yes: bool,
    /// Its risks accepted.
    pub force: bool,
}

pub fn approve(
    name: &str,
    id: u64,
    ttl: Option<&str>,
    narrow: &Narrowing,
    how: Approval,
) -> Result<ExitCode> {
    let Approval {
        mut private,
        yes,
        force,
    } = how;
    let ctx = Ctx::load()?;
    let req = rules::request(&ctx, name, id)?;
    println!("request #{id}: {}", fmt_request(&req));
    // Its value is the answer: where it is kept, asked here, and Esc there declines.
    if req
        .install
        .as_ref()
        .and_then(luoto_shared::api::Install::variable)
        .is_some()
    {
        if !narrow.is_empty() || ttl.is_some() {
            bail!("request #{id} asks for a variable: there is no access to narrow or expire");
        }
        if !crate::vars::approve(&ctx, name, &req)? {
            bail!("not approved");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if !narrow.is_empty() {
        // Before asking: a narrowing that would widen the request is refused here.
        let rule = rules::grant(&req, narrow)?;
        println!("grants less: {}", rules::describe(&rule));
    }
    if req.private && !private {
        // `--yes` approves as asked.
        private = yes
            || confirm(&format!(
                "It asks to reach {} on your network or VPN. Let the rule reach it there?",
                crate::text::display(&req.host)
            ));
    }
    // What the yes accepts, shown before it is asked (`--yes` leaves them to `--force`).
    let shown = rules::approval_risks(&ctx, name, &req, narrow, private)?;
    if !yes {
        for r in &shown {
            crate::progress::warn(r);
        }
    }
    let question = if shown.is_empty() {
        "Approve?"
    } else {
        "Approve, accepting these risks?"
    };
    if !yes && !confirm(question) {
        let private = if private { " --private" } else { "" };
        return Err(crate::prompt::declined(
            "approved",
            &format!("luoto approve -e {name} {id}{private} --yes"),
        ));
    }
    let asked = private;
    // Looked up only once approved, as the gate does: the name is the sandbox's, and a lookup
    // carries whatever it put in it. On a private address here, it is reached only if the
    // user says so.
    let host = narrow.host.as_deref().unwrap_or(&req.host);
    let resolved = if private || req.private || req.install.is_some() {
        rules::Resolved::default()
    } else {
        rules::resolve(host)
    };
    let at = resolved.private.join(", ");
    if !at.is_empty() && !yes {
        private = confirm(&format!(
            "{} resolves to {at}, a private address (your network or a VPN). Let the rule reach \
             it?",
            crate::text::display(host)
        ));
    }
    // A yes on the terminal accepted the risks it showed; private access since adds its own.
    let force = force || (!yes && private == asked);
    match rules::accepting_risks(force, |force| {
        rules::approve(&ctx, name, &req, ttl, narrow, private, force)
    })? {
        rules::Approved::Installed { installed } => out_text!("{installed}"),
        rules::Approved::Rule(rule) => {
            head!(
                "approved: {}{}{}",
                rules::describe(&rule),
                if rule.allow_private {
                    ", on your network or VPN"
                } else {
                    ""
                },
                rule.expires
                    .map(|e| format!(", until {}", egress::at_text(e)))
                    .unwrap_or_default()
            );
            if !at.is_empty() && !rule.allow_private {
                out!(
                    "{} resolves to {at}, which the rule doesn't reach: `luoto allow -e {name} {} \
                     --private` makes one that does",
                    crate::text::display(&rule.host),
                    rules::allow_args(&rule)
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub fn reject(name: &str, id: u64, note: Option<String>) -> Result<ExitCode> {
    rules::reject(&Ctx::load()?, name, id, note)?;
    head!("rejected request #{id}");
    Ok(ExitCode::SUCCESS)
}

/// Which hosts `luoto egress` lists.
#[derive(Clone, Copy, PartialEq)]
pub enum Only {
    All,
    /// Those with denials, or only lookups.
    Denied,
    /// Those open egress let requests out to.
    Opened,
}

/// The `luoto allow` that lets a host's last denial through: on its port (a rule without one
/// covers 80 and 443), as a tunnel for what isn't HTTP, with upgrades, writes or private
/// access where it needed them.
fn allow_hint(name: &str, s: &events::HostSummary) -> String {
    let private = s.host.ends_with(".internal")
        || s.host
            .parse::<std::net::IpAddr>()
            .is_ok_and(luoto_shared::host::is_private);
    let host = if s.host.contains(':') {
        format!("[{}]", s.host)
    } else {
        s.host.clone()
    };
    let target = match s.last_denied_at.as_ref().map(|(_, p)| *p) {
        Some(p) if p != 80 && p != 443 => format!("{host}:{p}"),
        _ => s.host.clone(),
    };
    let how = match s.last_reason.as_deref() {
        Some("not_http") => " --tunnel",
        Some("websocket_not_allowed") => " --ws",
        _ if s.wants_write => " --write",
        _ => "",
    };
    format!(
        "{}{} → luoto allow -e {name} {target}{how}{}",
        s.last_message.clone().unwrap_or_default(),
        if private {
            " (--private exposes a service on your machine or network)"
        } else {
            ""
        },
        if private { " --private" } else { "" }
    )
}

/// `all`: also the denials the env's mutes hide.
pub fn egress(
    name: &str,
    only: Only,
    all: bool,
    since: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let mutes = env::mutes(&ctx, name)?;
    let mut evs = events::gate_events(&ctx.rt, name, since)?;
    let hidden = if all { 0 } else { mutes.hide(&mut evs) };
    let mut summary = events::summarize(&evs, &mutes);
    match only {
        Only::All => {}
        Only::Denied => summary.retain(|s| s.denied > 0 || s.dns_only),
        Only::Opened => summary.retain(|s| s.opened > 0),
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(ExitCode::SUCCESS);
    }
    if only == Only::Opened {
        if summary.is_empty() {
            println!(
                "open egress let nothing out{}",
                since
                    .map(|s| format!(" in the last {s}"))
                    .unwrap_or_default()
            );
            return Ok(ExitCode::SUCCESS);
        }
        heading!("{:<40} {:>6}  {:<14} VIA", "HOST", "OPEN", "METHODS");
        for s in &summary {
            let methods: Vec<&str> = s.methods.iter().map(String::as_str).collect();
            let via: Vec<&str> = s.intakes.iter().map(String::as_str).collect();
            println!(
                "{:<40} {:>6}  {:<14} {}",
                crate::text::display(&s.host),
                s.opened,
                crate::text::display(&methods.join(",")),
                via.join(",")
            );
        }
        out!("`luoto egress keep -e {name}` keeps them");
        return Ok(ExitCode::SUCCESS);
    }
    let footer = || {
        if hidden > 0 {
            out!(
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
    let mut rows = Vec::new();
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
        } else if let Some(service) = (s.denied > 0)
            .then(|| crate::packages::service_of(&s.host, s.last_denied_path.as_deref()))
            .flatten()
        {
            // A private feed: a rule alone gets its 401; the env's token opens it.
            let a = if service.starts_with('A') { "an" } else { "a" };
            format!(
                "{} → {a} {service} feed: luoto feed add -e {name} <feed URL>",
                s.last_message.clone().unwrap_or_default()
            )
        } else if s.denied > 0 && s.last_reason.as_deref() == Some("path_not_allowed") {
            // Other paths of the host are open (a relay may be open only for some): allowing
            // all of it would undo that.
            let glob = s
                .last_denied_path
                .as_deref()
                .and_then(luoto_shared::host::path_glob)
                .unwrap_or_else(|| "<path glob>".into());
            format!(
                "{} → luoto allow -e {name} {} --path '{glob}'{}",
                s.last_message.clone().unwrap_or_default(),
                s.host,
                if s.wants_write { " --write" } else { "" },
            )
        } else if s.denied > 0 {
            allow_hint(name, &s)
        } else if s.opened > 0 {
            format!("open egress → luoto egress keep -e {name}")
        } else {
            s.last_rule
                .clone()
                .map(|r| format!("rule {r}"))
                .unwrap_or_default()
        };
        rows.push((
            crate::text::display(&s.host),
            s.allowed,
            s.denied,
            crate::text::display(&methods.join(",")),
            via.join(","),
            crate::text::display(&hint),
        ));
    }
    // Columns as wide as what they hold, and each hint on a line of its own under its host:
    // a fix command fits 80 columns there.
    let host_w = rows
        .iter()
        .map(|r| r.0.chars().count())
        .fold("HOST".len(), usize::max);
    let methods_w = rows
        .iter()
        .map(|r| r.3.chars().count())
        .fold("METHODS".len(), usize::max);
    let style = crate::style::out();
    let width = crate::text::columns();
    heading!(
        "{:<host_w$} {:>6} {:>6}  {:<methods_w$}  VIA",
        "HOST",
        "ALLOW",
        "DENY",
        "METHODS"
    );
    for (host, allowed, denied, methods, via, hint) in &rows {
        // What was denied stands out: its count, and the command under it.
        let count = format!("{denied:>6}");
        let count = if *denied > 0 {
            style.head(&count)
        } else {
            count
        };
        println!("{host:<host_w$} {allowed:>6} {count}  {methods:<methods_w$}  {via}");
        for line in hint_lines(hint, width) {
            println!("{}", style.aside(&line));
        }
    }
    footer();
    Ok(ExitCode::SUCCESS)
}

/// A host's hint under it in `luoto egress`, within `width`: on one line where it fits, else
/// what happened wrapped, and the command that allows it (after ` → `) on a line of its own.
fn hint_lines(hint: &str, width: usize) -> Vec<String> {
    use unicode_width::UnicodeWidthStr;
    if hint.is_empty() {
        return Vec::new();
    }
    let one = format!("  {hint}");
    if one.width() <= width {
        return vec![one];
    }
    let (why, command) = match hint.rsplit_once(" → ") {
        Some((why, command)) => (why, Some(command)),
        None => (hint, None),
    };
    let mut out: Vec<String> = crate::text::wrap(why, "  ", width)
        .lines()
        .map(String::from)
        .collect();
    out.extend(command.map(|c| format!("  → {c}")));
    out
}

/// `luoto egress open`: for `window` (default an hour), then the summary.
pub fn egress_open(name: &str, window: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let window = window.unwrap_or(egress::WINDOW);
    let until = egress::until(egress::parse_window(window).context("--for")?);
    let running = egress::open(&ctx, name, until)?;
    let mut rows = vec![
        (
            "reaches",
            "any HTTP(S) host but muted ones and those with your credentials".to_string(),
        ),
        ("close it", format!("luoto egress close -e {name}")),
        ("keep hosts", format!("luoto egress keep -e {name}")),
    ];
    if !running {
        rows.push(("applies", format!("at `luoto up -e {name}`")));
    }
    let title = format!(
        "egress of `{name}` is open {}",
        egress::until_text(Some(until))
    );
    block!("{}", crate::prompt::summary(&title, &rows));
    Ok(ExitCode::SUCCESS)
}

/// `luoto egress close`.
pub fn egress_close(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if !egress::close(&ctx, name)? {
        out!("egress of `{name}` was not open");
        return Ok(ExitCode::SUCCESS);
    }
    let rows = [
        ("keep hosts", format!("luoto egress keep -e {name}")),
        ("open again", format!("luoto egress open -e {name}")),
    ];
    let title = format!("egress of `{name}` is closed: only its rules allow");
    block!("{}", crate::prompt::summary(&title, &rows));
    Ok(ExitCode::SUCCESS)
}

/// `luoto egress keep`: what open egress reached, offered as presets and rules; the presets
/// and read rules are checked, a write is kept only when picked. `yes` keeps what is checked.
pub fn egress_keep(name: &str, since: Option<&str>, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let opened = events::opened(&events::gate_events(&ctx.rt, name, since)?);
    if opened.is_empty() {
        out!(
            "open egress let nothing out of `{name}`{}",
            since
                .map(|s| format!(" in the last {s}"))
                .unwrap_or_default()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let plan = env::plan(&ctx, name)?;
    let p = egress::propose(&plan.compiled.policy, &plan.cfg.presets, &opened);
    if p.is_empty() {
        out!("the rules of `{name}` already allow what open egress let out");
        return Ok(ExitCode::SUCCESS);
    }
    let methods = |host: &str| {
        opened
            .iter()
            .find(|o| o.host == host)
            .map(|o| o.methods().join(", "))
            .unwrap_or_default()
    };
    let mut rows: Vec<(String, String, bool)> = p
        .presets
        .iter()
        .map(|(preset, hosts)| {
            let hosts: Vec<String> = hosts.iter().map(|h| crate::text::display(h)).collect();
            (format!("preset {preset}"), hosts.join(", "), true)
        })
        .collect();
    for r in &p.rules {
        let write = r.access.allows("POST");
        let what = if write {
            format!(
                "write ({}): code in the env can upload to it",
                crate::text::display(&methods(&r.host))
            )
        } else {
            format!("read ({})", crate::text::display(&methods(&r.host)))
        };
        // The sandbox chose these hosts: each is yours to pick, never pre-checked.
        rows.push((egress::rule_target(r), what, false));
    }
    let picked: Vec<usize> = if yes {
        (0..rows.len()).filter(|i| rows[*i].2).collect()
    } else if !crate::prompt::interactive() {
        out!("open egress let out of `{name}`:");
        let wide = rows.iter().map(|r| r.0.chars().count()).max().unwrap_or(0);
        for (label, what, _) in &rows {
            println!("  {label:<wide$}  {what}");
        }
        out!("`luoto egress keep -e {name} --yes` keeps the presets");
        if !p.rules.is_empty() {
            println!("a host only as you allow it:");
            for r in &p.rules {
                let port = r.port.map(|p| format!(" --port {p}")).unwrap_or_default();
                let write = if r.access.allows("POST") {
                    " --write"
                } else {
                    ""
                };
                println!(
                    "  luoto allow -e {name} {}{write}{port}",
                    crate::text::display(&r.host)
                );
            }
        }
        return Ok(ExitCode::SUCCESS);
    } else {
        match crate::wizard::pick_kept(&rows)? {
            Some(picked) => picked,
            None => {
                return Err(crate::prompt::declined(
                    "kept",
                    &format!("luoto egress keep -e {name} --yes"),
                ));
            }
        }
    };
    let presets: Vec<String> = p
        .presets
        .iter()
        .enumerate()
        .filter(|(i, _)| picked.contains(i))
        .map(|(_, (preset, _))| preset.clone())
        .collect();
    let rules: Vec<luoto_shared::policy::Rule> = p
        .rules
        .iter()
        .enumerate()
        .filter(|(i, _)| picked.contains(&(i + p.presets.len())))
        .map(|(_, r)| r.clone())
        .collect();
    if presets.is_empty() && rules.is_empty() {
        println!("nothing kept");
        return Ok(ExitCode::SUCCESS);
    }
    egress::keep(&ctx, name, &presets, &rules)?;
    let mut summary: Vec<(&str, String)> = Vec::new();
    if !presets.is_empty() {
        summary.push(("presets", presets.join(", ")));
    }
    if !rules.is_empty() {
        let kept: Vec<String> = rules
            .iter()
            .map(|r| {
                let access = if r.access.allows("POST") {
                    "write"
                } else {
                    "read"
                };
                format!("{} {access}", egress::rule_target(r))
            })
            .collect();
        summary.push(("rules", kept.join(", ")));
        summary.push(("remove one", format!("luoto revoke -e {name} <host>")));
    }
    if let Ok(Some(until)) = EnvFile::load(&ctx.paths, name)?
        .cfg
        .egress
        .open_at(chrono::Utc::now())
    {
        summary.push((
            "egress",
            format!(
                "still open {}: luoto egress close -e {name}",
                egress::until_text(until)
            ),
        ));
    }
    block!(
        "{}",
        crate::prompt::summary(&format!("kept in `{name}`"), &summary)
    );
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
                println!("{}", events::fmt_event_local(&e));
            }
            true
        })?;
    } else {
        for e in events::gate_events(&ctx.rt, name, since)? {
            if show(&e) {
                println!("{}", events::fmt_event_local(&e));
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

/// `luoto project needs`: the `[needs]` questions again, and a running env takes the answers.
pub fn project_needs(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if crate::needs::ask(&ctx, name, crate::wizard::Mode::Change)? {
        sync::reapply(&ctx, name)?;
    }
    Ok(ExitCode::SUCCESS)
}

pub fn edit(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let path = ctx.paths.env_config(name);
    if !path.exists() {
        return Err(config::no_env(name));
    }
    let before = env::plan(&ctx, name).ok();
    open_editor(&path)?;
    let p = match sync::reapply(&ctx, name)? {
        Some(p) => {
            head!("applied ({} rules)", p.compiled.policy.rules.len());
            if before.is_none_or(|b| needs_recreate(&b, &p)) {
                out!(
                    "the dev container keeps its image, ports, isolation and resources until \
                     `luoto up -e {name} --recreate`"
                );
            }
            p
        }
        None => {
            let p = env::plan(&ctx, name)?;
            println!("config is valid ({} rules)", p.compiled.policy.rules.len());
            p
        }
    };
    for w in &p.compiled.warnings {
        crate::progress::warn(w);
    }
    Ok(ExitCode::SUCCESS)
}

/// Whether going from `before` to `after` changes what the dev container is made with.
fn needs_recreate(before: &env::Plan, after: &env::Plan) -> bool {
    let made = |p: &env::Plan| {
        (
            p.image.clone(),
            p.cfg.ports.clone(),
            p.cfg.isolation,
            p.cfg.resources.clone(),
        )
    };
    made(before) != made(after)
}

pub fn vault_status() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let v = ctl::vault_status(&ctx.rt)?;
    println!("vault {}", if v.locked { LOCKED } else { "unlocked" });
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
                format!("  (missing: {})", shown_refs(&e.missing))
            }
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn shown_refs(refs: &[String]) -> String {
    refs.iter()
        .map(|r| crate::secrets::shown_ref(r))
        .collect::<Vec<_>>()
        .join(", ")
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
        out!("the vault holds no secrets to read again (`luoto vault unlock` loads them)");
        return Ok(ExitCode::SUCCESS);
    }
    let r = crate::progress::step(
        &format!("reading {} secret(s) from your secret store", refs.len()),
        || sync::reload(&ctx, &refs, held_only),
    )?;
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
    out!(
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
    fn an_egress_hint_allows_what_the_denial_needed() {
        let denied = |reason: &str, port: u16| events::HostSummary {
            host: "db.example.com".into(),
            denied: 1,
            last_reason: Some(reason.into()),
            last_denied_at: Some(("GET".into(), port)),
            ..Default::default()
        };
        for (reason, port, fix) in [
            ("not_http", 5432, "db.example.com:5432 --tunnel"),
            ("no_rule", 443, "db.example.com"),
            ("no_rule", 8443, "db.example.com:8443"),
            ("websocket_not_allowed", 5173, "db.example.com:5173 --ws"),
        ] {
            let hint = allow_hint("web", &denied(reason, port));
            assert!(
                hint.ends_with(&format!("luoto allow -e web {fix}")),
                "{hint}"
            );
        }
    }

    #[test]
    fn a_preset_request_shows_the_hosts_it_opens() {
        let req = |name: &str| AccessRequest {
            id: 1,
            host: String::new(),
            port: None,
            mode: None,
            access: luoto_shared::policy::AccessLevel::Read,
            paths: vec![],
            private: false,
            ws: false,
            reason: "to install packages".into(),
            status: RequestStatus::Pending,
            created: chrono::Utc::now(),
            resolved: None,
            note: None,
            install: Some(luoto_shared::api::Install::Preset { name: name.into() }),
        };
        let text = fmt_request(&req("npm"));
        assert!(
            text.contains("kept in the env's config\n   opens:\n     "),
            "{text}"
        );
        assert!(
            text.contains("\n     registry.npmjs.org read-only\n"),
            "{text}"
        );
        assert!(
            text.ends_with("reason (written by the sandbox, untrusted): \"to install packages\"")
        );
        assert!(text.lines().all(|l| l.chars().count() <= 80), "{text}");
        assert!(fmt_request(&req("nope")).contains("nothing: luoto has no such preset"));
    }

    fn fits(lines: &[String]) {
        for l in lines {
            assert!(l.chars().count() <= 79, "{l}");
        }
    }

    #[test]
    fn list_puts_an_envs_presets_under_it() {
        let row = |env: &str, used: &str, presets: &str| ListRow {
            env: env.into(),
            dev: "running".into(),
            gate: "running".into(),
            size: None,
            used: used.into(),
            from: "~/src/web".into(),
            image: "localhost/luoto-base:dev".into(),
            presets: presets.into(),
        };
        let lines = list_lines(
            &[
                row(
                    "web",
                    "now",
                    "debian,github,github-releases,toolchains,crates,npm,pypi,go,ruby",
                ),
                row("api", "45d ago", ""),
                row("old", "unknown", ""),
            ],
            79,
        );
        assert_eq!(
            lines,
            [
                "ENV  DEV      GATE     USED     FROM       IMAGE",
                "web  running  running  now      ~/src/web  localhost/luoto-base:dev",
                "  presets  debian, github, github-releases, toolchains, crates, npm, pypi, go,",
                "           ruby",
                "api  running  running  45d ago  ~/src/web  localhost/luoto-base:dev",
                "old  running  running  unknown  ~/src/web  localhost/luoto-base:dev",
            ]
        );
        fits(&lines);
    }

    #[test]
    fn rules_stand_under_their_origin_with_what_narrows_them() {
        let row = |id: &str, host: &str, access: &str, origin: &str, more: &[&str]| RuleRow {
            id: id.into(),
            host: host.into(),
            access: access.into(),
            origin: origin.into(),
            more: more.iter().map(|m| m.to_string()).collect(),
        };
        let lines = rule_lines(
            &[
                row(
                    "github-releases-0",
                    "github.com",
                    READ_ONLY,
                    "preset:github-releases",
                    &[
                        "paths /*/*/releases, /*/*/releases/**, /*/*/info/refs, /*/*.git/info/refs, /x",
                    ],
                ),
                row(
                    "github-releases-1",
                    "release-assets.githubusercontent.com",
                    READ_ONLY,
                    "preset:github-releases",
                    &[],
                ),
                row("r1", "a.example:8443", "POST", "host", &["until 14:05"]),
            ],
            79,
        );
        fits(&lines);
        assert_eq!(
            lines,
            [
                "  RULE               HOST                                  ACCESS",
                "preset:github-releases",
                "  github-releases-0  github.com                            read-only",
                "    paths /*/*/releases, /*/*/releases/**, /*/*/info/refs, /*/*.git/info/refs,",
                "    /x",
                "  github-releases-1  release-assets.githubusercontent.com  read-only",
                "host",
                "  r1                 a.example:8443                        POST",
                "    until 14:05",
                "read-only: GET, HEAD, OPTIONS",
            ]
        );
    }

    #[test]
    fn a_long_hint_gives_its_command_a_line() {
        assert_eq!(
            hint_lines(
                "no rule allows a.example → luoto allow -e web a.example",
                79
            ),
            ["  no rule allows a.example → luoto allow -e web a.example"]
        );
        let long = hint_lines(
            "no rule allows db.internal (--private exposes a service on your machine or \
             network) → luoto allow -e web db.internal --private",
            79,
        );
        fits(&long);
        assert_eq!(
            long,
            [
                "  no rule allows db.internal (--private exposes a service on your machine or",
                "  network)",
                "  → luoto allow -e web db.internal --private",
            ]
        );
        assert!(hint_lines("", 79).is_empty());
    }

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
