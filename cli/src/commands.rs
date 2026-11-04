//! Env and policy commands.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use chrono::{TimeDelta, Utc};
use luoto_shared::api::{AccessRequest, RequestStatus};
use luoto_shared::ctl::GateCtl;
use luoto_shared::events::Verdict;
use luoto_shared::policy::{Access, AccessLevel, Mode, Rule, RuleOrigin, Severity, validate_rule};

use crate::config::{self, EnvConfig, EnvFile, Workspace, new_rule_id};
use crate::env::{self, Ctx, UpOptions};
use crate::{ctl, detect, events, names, project, workspace};

pub fn parse_ttl(s: &str) -> Result<TimeDelta> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num
        .parse()
        .with_context(|| format!("bad duration `{s}` (use 30m, 1h, 2d)"))?;
    Ok(match unit {
        "s" => TimeDelta::seconds(n),
        "m" | "" => TimeDelta::minutes(n),
        "h" => TimeDelta::hours(n),
        "d" => TimeDelta::days(n),
        _ => bail!("bad duration unit in `{s}` (use s, m, h, d)"),
    })
}

pub fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    matches!(line.trim(), "y" | "Y" | "yes")
}

#[derive(Default)]
pub struct InitOpts {
    pub dir: Option<String>,
    pub name: Option<String>,
    pub image: Option<String>,
    pub presets: Vec<String>,
    /// `tool=version` defaults.
    pub tools: Vec<String>,
    pub agents: Vec<String>,
    pub ports: Vec<u16>,
    pub isolation: Option<config::Isolation>,
    pub no_up: bool,
    pub yes: bool,
    /// Ignore the folder's luoto.toml.
    pub no_project: bool,
}

/// Presets every new env starts with; the folder's files add more.
pub const DEFAULT_PRESETS: &[&str] = &["debian", "github", "toolchains"];

/// The env `luoto init` would create.
pub struct Proposal {
    pub name: String,
    pub cfg: EnvConfig,
    pub found: detect::Detected,
    /// The folder's luoto.toml (text and settings); creating the env accepts it.
    pub project: Option<(String, project::ProjectConfig)>,
    /// Why the folder's luoto.toml is not part of the proposal.
    pub project_error: Option<String>,
    /// gVisor is set up, so it is the default isolation.
    pub gvisor: bool,
    /// The folder is missing (`make_folder` creates it) or empty: nothing to detect.
    pub new_folder: bool,
}

/// Defaults plus what the folder says about itself; explicit options replace both. Touches
/// nothing on disk.
pub fn propose(paths: &crate::paths::Paths, o: &InitOpts) -> Result<Proposal> {
    let (name, workspace) = new_workspace(paths, o.dir.as_deref(), o.name.as_deref())?;
    let dir = std::path::PathBuf::from(workspace.dir.as_deref().unwrap_or_default());
    let new_folder = std::fs::read_dir(&dir).map_or(true, |mut d| d.next().is_none());
    let (project, project_error) = if o.no_project || new_folder {
        (None, None)
    } else {
        match project::read_host(&dir)
            .and_then(|t| t.map(|t| project::parse(&t).map(|p| (t, p))).transpose())
        {
            Ok(p) => (p, None),
            Err(e) => (None, Some(format!("{e:#}"))),
        }
    };
    let found = if new_folder {
        detect::Detected::default()
    } else {
        detect::detect(&dir)
    };
    let presets = if o.presets.is_empty() {
        let mut p: Vec<String> = DEFAULT_PRESETS.iter().map(|s| s.to_string()).collect();
        for (n, _) in &found.presets {
            if !p.contains(n) {
                p.push(n.clone());
            }
        }
        p
    } else {
        o.presets.clone()
    };
    let mut tools = std::collections::BTreeMap::new();
    for t in &o.tools {
        let (k, v) = t
            .split_once('=')
            .with_context(|| format!("--tool {t}: expected TOOL=VERSION, e.g. node=24"))?;
        tools.insert(
            k.trim().to_string(),
            toml::Value::String(v.trim().to_string()),
        );
    }
    // A runtime the project needs but pins nowhere gets a default (its files still win).
    for t in &found.defaults {
        tools
            .entry(t.tool.clone())
            .or_insert_with(|| toml::Value::String(t.version.clone()));
    }
    let cfg = EnvConfig {
        image: o.image.clone(),
        workspace,
        presets,
        tools,
        agents: o.agents.clone(),
        ports: o.ports.clone(),
        isolation: o.isolation,
        ..Default::default()
    };
    let global = config::load_global(paths)?;
    let p = Proposal {
        name,
        cfg,
        found,
        project,
        project_error,
        gvisor: global.gvisor.is_some(),
        new_folder,
    };
    check(&p)?;
    Ok(p)
}

/// The proposed config compiles, with the folder's luoto.toml layered in.
fn check(p: &Proposal) -> Result<()> {
    let mut effective = p.cfg.clone();
    if let Some((_, pc)) = &p.project {
        project::layer(&mut effective, pc);
    }
    crate::compile::compile(&p.name, &effective, std::net::Ipv4Addr::new(10, 213, 0, 2))?;
    Ok(())
}

fn print_proposal(p: &Proposal) {
    const INDENT: &str = "             ";
    let ws = &p.cfg.workspace;
    println!(
        "env `{}`{}",
        p.name,
        ws.dir
            .as_deref()
            .map(|d| format!(" from {d}"))
            .unwrap_or_default()
    );
    let exists = ws
        .dir
        .as_deref()
        .is_some_and(|d| std::path::Path::new(d).exists());
    if exists {
        println!(
            "  workspace  copy: the env works on its own copy; changes leave by git push or `luoto pull`"
        );
    } else {
        println!(
            "  workspace  new folder, created now: the env starts empty, and `luoto pull` fills the folder"
        );
    }
    println!("  isolation  {}", isolation_text(p.cfg.isolation, p.gvisor));
    let presets: Vec<String> = p
        .cfg
        .presets
        .iter()
        .map(|n| match p.found.presets.iter().find(|(f, _)| f == n) {
            Some((_, file)) => format!("{n} ({})", crate::text::display(file)),
            None => n.clone(),
        })
        .collect();
    println!("  presets    {}", presets.join(", "));
    let mut tools: Vec<String> = p
        .found
        .tools
        .iter()
        .map(|t| {
            let shown = format!("{} {} ({})", t.tool, t.version, t.source);
            crate::text::display(&shown)
        })
        .collect();
    for (k, v) in &p.cfg.tools {
        if !p.found.tools.iter().any(|t| &t.tool == k) {
            let v = v.as_str().unwrap_or("?");
            let why = match p
                .found
                .defaults
                .iter()
                .find(|t| &t.tool == k && t.version == v)
            {
                Some(t) => format!(
                    "default: {} pins no version",
                    crate::text::display(&t.source)
                ),
                None => "--tool".into(),
            };
            tools.push(format!("{k} {v} ({why})"));
        }
    }
    if tools.is_empty() {
        println!(
            "  toolchains none pinned; in the env, `mise use <tool>@<version>` adds one to the project"
        );
    } else {
        println!(
            "  toolchains {}\n{INDENT}installed by mise in the env; the project's files keep deciding versions",
            tools.join(", ")
        );
    }
    if !p.cfg.agents.is_empty() {
        println!("  agents     {}", p.cfg.agents.join(", "));
    }
    for (provider, entries) in &p.cfg.credentials.providers {
        let how: Vec<String> = entries
            .iter()
            .map(|(k, v)| match v {
                config::ProviderValue::Ref(r) => format!("{k} from {r}"),
                config::ProviderValue::Flag(_) => "logs in inside the sandbox".to_string(),
            })
            .collect();
        println!("  credential {provider}: {}", how.join(", "));
    }
    if !p.cfg.ports.is_empty() {
        let ports: Vec<String> = p.cfg.ports.iter().map(u16::to_string).collect();
        println!("  ports      {}", ports.join(", "));
    }
    if let Some(i) = &p.cfg.image {
        println!("  image      {i}");
    }
    if let Some((_, pc)) = &p.project {
        println!("  luoto.toml settings written in the repository, so review them:");
        project::print_summary(pc, "               ");
    }
    if let Some(e) = &p.project_error {
        println!("  luoto.toml not used: {}", project::clean(e));
    }
}

/// How an env is separated from luoto's VM, as `init` and `status` say it.
pub fn isolation_text(chosen: Option<config::Isolation>, gvisor: bool) -> &'static str {
    match chosen {
        Some(config::Isolation::Container) => {
            "container: shares the VM's kernel (builds about 1.6× faster, weaker)"
        }
        _ if gvisor => "gVisor: its own user-space kernel (builds about 1.6× slower)",
        Some(config::Isolation::Gvisor) => "gVisor, not set up yet: run `luoto setup`",
        None => "container: shares the VM's kernel (`luoto setup` installs gVisor)",
    }
}

/// luoto's own VM is stopped, so nothing in it can be asked about.
fn vm_stopped(ctx: &Ctx) -> bool {
    crate::machine::is_luoto(ctx.rt.connection.as_deref()) && !crate::machine::running(&ctx.rt.bin)
}

/// One-letter answer to `question`; Enter picks `default`.
fn ask(question: &str, default: char) -> char {
    print!("{question} ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim()
        .chars()
        .next()
        .map_or(default, |c| c.to_ascii_lowercase())
}

/// An env's name and workspace for a folder (default: the current one), which need not
/// exist yet: `make_folder` creates it once the env is wanted.
pub fn new_workspace(
    paths: &crate::paths::Paths,
    dir: Option<&str>,
    name: Option<&str>,
) -> Result<(String, Workspace)> {
    let dir = match dir {
        Some(d) if workspace::expand(d).exists() => workspace::canonical(d)?,
        Some(d) => std::path::absolute(workspace::expand(d))?,
        None => std::env::current_dir()?.canonicalize()?,
    };
    if dir.exists() && !dir.is_dir() {
        bail!("{} is not a folder", dir.display());
    }
    if let Some(parent) = dir.parent()
        && !parent.is_dir()
    {
        bail!(
            "{} does not exist; luoto creates only the last folder of a path",
            parent.display()
        );
    }
    if let Some(other) = workspace::env_for_dir(paths, &dir)?
        && config::EnvFile::load(paths, &other)
            .ok()
            .and_then(|f| f.cfg.workspace.dir)
            .is_some_and(|od| workspace::canonical(&od).is_ok_and(|od| od == dir))
    {
        bail!("{} already belongs to env `{other}`", dir.display());
    }
    let name = match name {
        Some(n) => n.to_string(),
        None => workspace::name_from(&dir.display().to_string()),
    };
    config::validate_name(&name)
        .with_context(|| format!("pick a name with --name (derived `{name}` is not valid)"))?;
    Ok((
        name,
        Workspace {
            dir: Some(dir.display().to_string()),
        },
    ))
}

/// Create the proposal's folder if it is missing (its parent must exist), and record it as
/// the canonical path.
pub fn make_folder(p: &mut Proposal) -> Result<()> {
    let dir = p
        .cfg
        .workspace
        .dir
        .clone()
        .context("the env has no folder")?;
    let path = std::path::Path::new(&dir);
    if !path.exists() {
        std::fs::create_dir(path).with_context(|| format!("create {dir}"))?;
        println!("created {dir}");
    }
    p.cfg.workspace.dir = Some(workspace::canonical(&dir)?.display().to_string());
    Ok(())
}

pub fn init(o: InitOpts) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    // `init` again in an env's own folder: detect anew and offer what is missing.
    if o.name.is_none()
        && let Some(dir) = match &o.dir {
            Some(d) => workspace::canonical(d).ok(),
            None => std::env::current_dir()?.canonicalize().ok(),
        }
        && let Some(existing) = workspace::env_for_dir(&ctx.paths, &dir)?
        && EnvFile::load(&ctx.paths, &existing)?
            .cfg
            .workspace
            .dir
            .is_some_and(|d| workspace::canonical(&d).is_ok_and(|d| d == dir))
    {
        return redetect(&ctx, &existing, &dir, &o);
    }
    let mut p = propose(&ctx.paths, &o)?;
    let interactive = !o.yes && std::io::stdin().is_terminal();
    if interactive && p.new_folder {
        println!(
            "{} is {}, so there is nothing to detect: pick what the env needs.",
            p.cfg.workspace.dir.as_deref().unwrap_or_default(),
            if std::path::Path::new(p.cfg.workspace.dir.as_deref().unwrap_or_default()).exists() {
                "empty"
            } else {
                "new"
            }
        );
        crate::wizard::customize(&mut p)?;
        check(&p)?;
        println!();
    }
    print_proposal(&p);
    if interactive {
        loop {
            match ask("\nCreate it? [Y/n/c = customize]", 'y') {
                'y' => break,
                'n' => {
                    println!("nothing created");
                    return Ok(ExitCode::SUCCESS);
                }
                'c' => {
                    crate::wizard::customize(&mut p)?;
                    check(&p)?;
                    println!();
                    print_proposal(&p);
                }
                _ => println!("y creates it, n stops, c goes through the settings one by one"),
            }
        }
    }
    // The repository wrote luoto.toml, so it gets its own answer.
    let accept_project = match &p.project {
        Some(_) if interactive => confirm("\nApply the repository's luoto.toml (listed above)?"),
        // Without a terminal only `--yes` accepts what the repository wrote.
        Some(_) => o.yes,
        None => false,
    };
    make_folder(&mut p)?;
    let name = p.name.clone();
    let f = EnvFile::create(&ctx.paths, &name, &p.cfg)?;
    println!("created env `{name}` ({})", f.path.display());
    let mut agents = p.cfg.agents.clone();
    if let Some((text, pc)) = &p.project {
        if accept_project {
            project::accept(&ctx, &name, text)?;
            for a in &pc.agents {
                if !agents.contains(a) {
                    agents.push(a.clone());
                }
            }
        } else {
            // The decline lives in the env's state, which `plan` creates.
            env::plan(&ctx, &name)?;
            project::forget(&ctx, &name, Some(text))?;
            println!("luoto.toml not applied (`luoto project apply -e {name}` applies it later)");
        }
    }
    if let Some(hint) = p
        .cfg
        .workspace
        .dir
        .as_deref()
        .and_then(|d| origin_url(std::path::Path::new(d)))
        .and_then(|u| credential_hint(&name, &u, &p.cfg.credentials))
    {
        println!("{hint}");
    }
    if !o.no_up {
        env::up(
            &ctx,
            &name,
            &UpOptions {
                selftest: true,
                quiet: false,
            },
        )?;
        for a in &agents {
            crate::agents::install(&ctx, &name, a)?;
        }
    }
    if let Some((_, pc)) = p.project.as_ref().filter(|_| accept_project) {
        print_needs(&name, pc, &EnvFile::load(&ctx.paths, &name)?.cfg);
    }
    println!(
        "\nYour settings for every env (shell rc files, .gitconfig, .claude/settings.json, …) go in \
         {}: copied in on each `up`, and readable by code in the env, so keep secrets out.",
        crate::ssh::tilde(&ctx.paths.home_files())
    );
    Ok(ExitCode::SUCCESS)
}

/// Offer what the project suggests now and the env's config lacks. The project is the env's
/// own copy while it runs (work happens there), else the folder.
fn redetect(ctx: &Ctx, name: &str, dir: &std::path::Path, o: &InitOpts) -> Result<ExitCode> {
    let running = ctx.rt.container_state(&names::dev(name)).as_deref() == Some("running");
    let (found, source) = if running {
        (
            crate::deps::detect_in_env(ctx, name)?,
            "its workspace".to_string(),
        )
    } else {
        (detect::detect(dir), dir.display().to_string())
    };
    let heading = format!("env `{name}` exists; {source} now suggests:");
    if !offer(ctx, name, &found, &heading, o.yes)? {
        println!("env `{name}` already has what {source} suggests");
        return Ok(ExitCode::SUCCESS);
    }
    if !o.no_up {
        env::up(
            ctx,
            name,
            &UpOptions {
                selftest: true,
                quiet: false,
            },
        )?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Offer what detection found and the env's config lacks: presets, and default toolchains
/// for runtimes, package managers and task runners the project doesn't pin. Only adds; what
/// is in the config stays. Whether the config changed.
pub fn offer(
    ctx: &Ctx,
    name: &str,
    found: &detect::Detected,
    heading: &str,
    yes: bool,
) -> Result<bool> {
    let mut file = EnvFile::load(&ctx.paths, name)?;
    let presets: Vec<&(String, String)> = found
        .presets
        .iter()
        .filter(|(p, _)| !file.cfg.presets.contains(p))
        .collect();
    let tools: Vec<&detect::ToolPin> = found
        .defaults
        .iter()
        .filter(|t| !file.cfg.tools.contains_key(&t.tool))
        .collect();
    if presets.is_empty() && tools.is_empty() {
        return Ok(false);
    }
    // Paths can come from the env's workspace: printed cleaned.
    println!("{heading}");
    for (p, f) in &presets {
        println!("  preset    + {p} ({})", project::clean(f));
    }
    for t in &tools {
        println!(
            "  toolchain + {} {} (default: {} pins no version)",
            t.tool,
            t.version,
            project::clean(&t.source)
        );
    }
    if !yes
        && std::io::stdin().is_terminal()
        && ask(&format!("Add them to `{name}`? [Y/n]"), 'y') == 'n'
    {
        println!("nothing changed");
        return Ok(false);
    }
    if !presets.is_empty() {
        let mut all = file.cfg.presets.clone();
        all.extend(presets.iter().map(|(p, _)| p.clone()));
        file.set_list("presets", &all)?;
    }
    for t in &tools {
        file.set_in_table("tools", &t.tool, &t.version)?;
    }
    println!("updated {}", file.path.display());
    Ok(true)
}

fn print_needs(name: &str, p: &project::ProjectConfig, cfg: &EnvConfig) {
    let needs = project::missing_needs(p, cfg);
    if !needs.is_empty() {
        println!(
            "\nThe project needs credentials only you can add (`luoto edit -e {name}`):\n\n{}\n",
            needs.join("\n\n")
        );
    }
}

/// Show, accept or drop the project's luoto.toml settings for an env.
pub fn project(name: &str, accept: bool, forget: bool, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let st = project::status(&ctx, name)?;
    if forget {
        project::forget(&ctx, name, st.text.as_deref())?;
        env::reapply(&ctx, name)?;
        println!("`{name}` no longer applies the project's luoto.toml");
        return Ok(ExitCode::SUCCESS);
    }
    let show = |lines: &[(String, String)]| project::print_entries(lines, "  ");
    match st.state {
        "none" => println!("the project has no luoto.toml"),
        "invalid" => println!(
            "the project's luoto.toml is not applied: {}",
            st.error.as_deref().unwrap_or("")
        ),
        "removed" => {
            println!("the project no longer has luoto.toml; these accepted settings still apply:");
            show(&st.accepted);
        }
        "accepted" => {
            println!("luoto.toml is accepted and applies to `{name}`:");
            show(&st.current);
        }
        "declined" => {
            println!("luoto.toml is ignored for `{name}` (this version):");
            show(&st.current);
        }
        "changed" => {
            println!("luoto.toml changed since you accepted it:");
            for l in &st.diff {
                println!("  {l}");
            }
        }
        _ => {
            println!("luoto.toml (not accepted; written in the repository, so review it):");
            show(&st.current);
        }
    }
    if !st.needs.is_empty() {
        println!(
            "\nThe project needs credentials only you can add (`luoto edit -e {name}`):\n\n{}\n",
            st.needs.join("\n\n")
        );
    }
    let pending = matches!(st.state, "changed" | "new" | "declined");
    if !accept {
        if pending {
            println!("apply:  luoto project apply -e {name}");
            if st.state != "declined" {
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
    project::accept(&ctx, name, &text)?;
    if ctx.rt.container_state(&names::dev(name)).as_deref() == Some("running") {
        env::up(
            &ctx,
            name,
            &UpOptions {
                selftest: false,
                quiet: true,
            },
        )?;
        println!("applied to `{name}`");
    } else {
        println!("accepted; applies on `luoto up -e {name}`");
    }
    Ok(ExitCode::SUCCESS)
}

/// The URL of a folder's `origin` remote, if any.
fn origin_url(dir: &std::path::Path) -> Option<String> {
    let cfg = std::fs::read_to_string(dir.join(".git").join("config")).ok()?;
    let mut in_origin = false;
    for line in cfg.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_origin = l == "[remote \"origin\"]";
            continue;
        }
        if in_origin
            && let Some(url) = l
                .strip_prefix("url")
                .map(|r| r.trim_start_matches([' ', '=']).trim())
        {
            return Some(url.to_string());
        }
    }
    None
}

/// `owner/repo` of a GitHub remote URL, HTTPS or SSH.
fn github_repo(url: &str) -> Option<String> {
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("git@github.com:"))
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))?;
    let repo = path.trim_end_matches('/').trim_end_matches(".git");
    (repo.split('/').count() == 2).then(|| repo.to_string())
}

/// `ssh://…` or scp-like `user@host:path`.
fn is_ssh_url(url: &str) -> bool {
    url.starts_with("ssh://") || (!url.contains("://") && url.contains(':'))
}

/// After `init`: the credential that lets the env fetch and push `origin`, in the form its URL
/// uses, unless the env has one that would. An SSH remote stays SSH with `[credentials.ssh]`;
/// with only the forge's HTTPS credential it goes to HTTPS, which works too.
fn credential_hint(name: &str, url: &str, creds: &config::Credentials) -> Option<String> {
    let (has, table, host, repo, token) = if let Some(repo) = github_repo(url) {
        (
            creds.github.is_some(),
            "github",
            "github.com",
            project::clean(&repo),
            "fine-grained PAT, or app_id + installation_id + private_key",
        )
    } else {
        let (r, _) = crate::azure::parse_url(url)?;
        let repo = format!(
            "{}/{}/{}",
            project::clean(&r.org),
            project::clean(&crate::azure::decode(&r.project)),
            project::clean(&crate::azure::decode(&r.name))
        );
        (
            creds.azure_devops.is_some(),
            "azure_devops",
            "ssh.dev.azure.com",
            repo,
            "PAT with Code (Read & write)",
        )
    };
    if has {
        return None;
    }
    let edit = format!("`luoto edit -e {name}`");
    if is_ssh_url(url) {
        return creds.ssh.is_none().then(|| {
            format!(
                "To fetch and push {repo} over SSH, give the env a key ({edit}); the vault keeps it:\n\n  \
                 [credentials.ssh]\n  \
                 key = \"op://<vault>/<item>/private key?ssh-format=openssh\"   # a deploy key reaches only this repo\n  \
                 hosts = [\"{host}\"]\n\n\
                 luoto can't limit an SSH key to repos; [credentials.{table}] over HTTPS can."
            )
        });
    }
    Some(format!(
        "To fetch and push {repo} from the env, give it a credential ({edit}):\n\n  \
         [credentials.{table}]\n  \
         token = \"op://<vault>/<item>/<field>\"   # {token}\n  \
         repos = [\"{repo}\"]"
    ))
}

fn workspace_dir(f: &EnvFile) -> Option<std::path::PathBuf> {
    f.cfg
        .workspace
        .dir
        .as_deref()
        .and_then(|d| workspace::canonical(d).ok())
}

pub fn pull(
    name: &str,
    to: Option<&str>,
    include_risky: bool,
    include_git: bool,
    yes: bool,
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let f = EnvFile::load(&ctx.paths, name)?;
    crate::connect::ensure_running(&ctx, name)?;
    let dest = match to {
        Some(t) => {
            std::fs::create_dir_all(workspace::expand(t))?;
            workspace::canonical(t)?
        }
        None => workspace_dir(&f).context("this env has no folder; pass --to <dir>")?,
    };
    let plan = workspace::plan_pull(&ctx, name, &dest, include_git)?;
    workspace::describe(&plan, &mut std::io::stdout())?;
    if plan.entries.is_empty() {
        println!("nothing to pull");
        return Ok(ExitCode::SUCCESS);
    }
    let writable = plan
        .entries
        .iter()
        .filter(|e| include_risky || e.risky.is_none())
        .count();
    if writable == 0 {
        println!("only risky files changed; re-run with --include-risky after reviewing them");
        return Ok(ExitCode::SUCCESS);
    }
    if !yes
        && !confirm(&format!(
            "Write {writable} file(s) into {}?",
            dest.display()
        ))
    {
        bail!("nothing written (use --yes to skip the prompt)");
    }
    let (written, skipped) = workspace::apply_pull(&plan, include_risky)?;
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
        // The VM first: with it stopped there is no container to see, so none would go.
        env::ensure_vm(&ctx)?;
        // Workspace and home volumes are kept; the container's own filesystem is not.
        ctx.rt.remove_container(&names::dev(name))?;
    }
    env::up(
        &ctx,
        name,
        &UpOptions {
            selftest,
            quiet: false,
        },
    )?;
    Ok(ExitCode::SUCCESS)
}

pub fn down(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if vm_stopped(&ctx) {
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
    let stopped = vm_stopped(&ctx);
    if stopped {
        println!("luoto's VM is stopped; `luoto up` starts it with the env\n");
    }
    println!(
        "{:<20} {:<10} {:<10} {:<28} PRESETS",
        "ENV", "DEV", "GATE", "IMAGE"
    );
    for e in envs {
        let (dev, gate) = if stopped {
            ("stopped".to_string(), "stopped".to_string())
        } else {
            env::status_line(&ctx, &e)
        };
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
    let (dev, gate) = if vm_stopped(&ctx) {
        (
            "stopped (luoto's VM is off)".to_string(),
            "stopped".to_string(),
        )
    } else {
        env::status_line(&ctx, name)
    };
    println!(
        "env {name}\n  config: {}\n  dev:    {dev}\n  gate:   {gate}",
        f.path.display()
    );
    println!(
        "  isolation: {}",
        isolation_text(f.cfg.isolation, ctx.global.gvisor.is_some())
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

pub struct AllowOpts {
    pub name: String,
    pub host: String,
    pub write: bool,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub ttl: Option<String>,
    pub tunnel: bool,
    pub ws: bool,
    pub private: bool,
    pub port: Option<u16>,
    pub note: Option<String>,
    pub force: bool,
}

pub fn build_rule(o: &AllowOpts) -> Result<Rule> {
    let host = o.host.trim();
    let host = if host == "*" || host.contains('/') || host.starts_with("*.") {
        host.to_string()
    } else {
        luoto_shared::host::normalize_host(crate::connect::host_of(host).as_str())?
    };
    let access = if !o.methods.is_empty() {
        Access::Methods(o.methods.iter().map(|m| m.to_ascii_uppercase()).collect())
    } else if o.write || o.tunnel {
        Access::Level(AccessLevel::Write)
    } else {
        Access::Level(AccessLevel::Read)
    };
    Ok(Rule {
        id: Some(new_rule_id()),
        host,
        port: o.port,
        access,
        paths: o.paths.clone(),
        expires: o
            .ttl
            .as_deref()
            .map(parse_ttl)
            .transpose()?
            .map(|d| Utc::now() + d),
        mode: if o.tunnel {
            Mode::Tunnel
        } else {
            Mode::Inspect
        },
        ws: o.ws,
        max_body: None,
        allow_private: o.private,
        note: o.note.clone(),
        ignore_case: false,
    })
}

/// Refuse a tunnel over a host where the env's gate strips credentials, guards writes or
/// applies a deny (see `Policy::tunnel_bypass`).
pub fn check_tunnel(ctx: &Ctx, name: &str, rule: &Rule) -> Result<()> {
    if rule.mode != Mode::Tunnel {
        return Ok(());
    }
    if let Some(why) = env::plan(ctx, name)?
        .compiled
        .policy
        .tunnel_bypass(&rule.host)
    {
        bail!("{why}");
    }
    Ok(())
}

pub fn add_rule_checked(ctx: &Ctx, name: &str, rule: Rule, force: bool) -> Result<()> {
    let issues = validate_rule(&rule, RuleOrigin::Host);
    if let Some(e) = issues.iter().find(|i| i.severity == Severity::Error) {
        bail!("{}", e.message);
    }
    check_tunnel(ctx, name, &rule)?;
    let risks: Vec<&str> = issues.iter().map(|i| i.message.as_str()).collect();
    if !risks.is_empty() && !force {
        for r in &risks {
            eprintln!("risk: {r}");
        }
        if !confirm("Add this rule anyway?") {
            bail!("not added (pass --force to accept these risks)");
        }
    }
    let mut f = EnvFile::load(&ctx.paths, name)?;
    f.add_rule(&rule)?;
    env::reapply(ctx, name)?;
    Ok(())
}

pub fn allow(o: AllowOpts) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let rule = build_rule(&o)?;
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
    add_rule_checked(&ctx, &o.name, rule, o.force)?;
    println!(
        "allowed {summary} (rule {id}); revoke with `luoto revoke -e {} {id}`",
        o.name
    );
    Ok(ExitCode::SUCCESS)
}

pub fn revoke(name: &str, rule: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let mut f = EnvFile::load(&ctx.paths, name)?;
    let n = f.remove_rules(rule)?;
    if n == 0 {
        bail!(
            "no user rule with id or host `{rule}` (preset rules are changed by editing `presets`)"
        );
    }
    env::reapply(&ctx, name)?;
    println!("removed {n} rule(s)");
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

fn gate_requests(ctx: &Ctx, name: &str) -> Result<Vec<AccessRequest>> {
    ctl::gate(&ctx.rt, name, &GateCtl::Requests)
}

pub fn requests(name: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let envs = match name {
        Some(n) => vec![n.to_string()],
        None => config::list_envs(&ctx.paths)?,
    };
    let mut any = false;
    for e in envs {
        if ctx.rt.container_state(&names::gate(&e)).as_deref() != Some("running") {
            continue;
        }
        for r in gate_requests(&ctx, &e)? {
            if r.status != RequestStatus::Pending {
                continue;
            }
            any = true;
            println!(
                "{e} #{}  {} {:?}{}\n   reason (written by the sandbox, untrusted): {:?}\n   approve: luoto approve -e {e} {}   reject: luoto reject -e {e} {}",
                r.id,
                crate::text::display(&r.host),
                r.access,
                if r.paths.is_empty() {
                    String::new()
                } else {
                    format!(" paths {}", crate::text::display(&r.paths.join(",")))
                },
                r.reason,
                r.id,
                r.id
            );
        }
    }
    if !any {
        println!("no pending requests");
    }
    Ok(ExitCode::SUCCESS)
}

pub fn approve_request(
    ctx: &Ctx,
    name: &str,
    id: u64,
    ttl: Option<&str>,
    force: bool,
) -> Result<Rule> {
    let req = gate_requests(ctx, name)?
        .into_iter()
        .find(|r| r.id == id)
        .with_context(|| format!("no request #{id} in `{name}`"))?;
    if req.status != RequestStatus::Pending {
        bail!("request #{id} is already {:?}", req.status);
    }
    let rule = Rule {
        id: Some(new_rule_id()),
        host: req.host.clone(),
        access: Access::Level(req.access),
        paths: req.paths.clone(),
        expires: ttl.map(parse_ttl).transpose()?.map(|d| Utc::now() + d),
        note: Some(format!("approved request #{id}")),
        ..Default::default()
    };
    add_rule_checked(ctx, name, rule.clone(), force)?;
    ctl::gate::<AccessRequest>(
        &ctx.rt,
        name,
        &GateCtl::Resolve {
            id,
            approved: true,
            note: None,
        },
    )?;
    Ok(rule)
}

pub fn approve(name: &str, id: u64, ttl: Option<&str>, yes: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let req = gate_requests(&ctx, name)?
        .into_iter()
        .find(|r| r.id == id)
        .with_context(|| format!("no request #{id} in `{name}`"))?;
    println!(
        "request #{id}: {:?} access to {}{}\nreason (written by the sandbox — untrusted): {:?}",
        req.access,
        crate::text::display(&req.host),
        if req.paths.is_empty() {
            String::new()
        } else {
            format!(" paths {}", crate::text::display(&req.paths.join(",")))
        },
        req.reason
    );
    if !yes && !confirm("Approve?") {
        bail!("not approved (use --yes to skip the prompt)");
    }
    let rule = approve_request(&ctx, name, id, ttl, yes)?;
    println!("approved: {} {}", rule.host, rule.access.describe());
    Ok(ExitCode::SUCCESS)
}

pub fn reject(name: &str, id: u64, note: Option<String>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    ctl::gate::<AccessRequest>(
        &ctx.rt,
        name,
        &GateCtl::Resolve {
            id,
            approved: false,
            note,
        },
    )?;
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
    match env::reapply(&ctx, name)? {
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
    let n = env::unlock_all(&ctx)?;
    println!("vault unlocked; {n} env(s) registered");
    Ok(ExitCode::SUCCESS)
}

pub fn lock() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let failed = env::lock_all(&ctx)?;
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
    fn ttls() {
        assert_eq!(parse_ttl("30m").unwrap(), TimeDelta::minutes(30));
        assert_eq!(parse_ttl("2h").unwrap(), TimeDelta::hours(2));
        assert_eq!(parse_ttl("1d").unwrap(), TimeDelta::days(1));
        assert!(parse_ttl("1y").is_err());
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::*;

    #[test]
    fn github_origin_from_git_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://github.com/x/y\n[remote \"origin\"]\n\turl = git@github.com:Eetu/luoto.git\n",
        )
        .unwrap();
        let url = origin_url(dir.path()).unwrap();
        assert_eq!(github_repo(&url).as_deref(), Some("Eetu/luoto"));
    }

    #[test]
    fn credential_hint_follows_the_remote_form() {
        let none = config::Credentials::default();
        let https = credential_hint("e", "https://github.com/o/r.git", &none).unwrap();
        assert!(https.contains("[credentials.github]") && https.contains("repos = [\"o/r\"]"));
        let ssh = credential_hint("e", "git@github.com:o/r.git", &none).unwrap();
        assert!(ssh.contains("[credentials.ssh]") && ssh.contains("hosts = [\"github.com\"]"));
        let ado = credential_hint("e", "git@ssh.dev.azure.com:v3/org/P/r", &none).unwrap();
        assert!(ado.contains("hosts = [\"ssh.dev.azure.com\"]"));
        assert!(credential_hint("e", "https://gitlab.com/o/r", &none).is_none());

        // An HTTPS credential covers an SSH remote too (luoto sends it over HTTPS).
        let github: config::Credentials =
            toml::from_str("[github]\ntoken = \"env:T\"\nrepos = [\"o/r\"]").unwrap();
        assert!(credential_hint("e", "git@github.com:o/r.git", &github).is_none());
        let key: config::Credentials =
            toml::from_str("[ssh]\nkey = \"env:K\"\nhosts = [\"github.com\"]").unwrap();
        assert!(credential_hint("e", "git@github.com:o/r.git", &key).is_none());
        assert!(credential_hint("e", "https://github.com/o/r", &key).is_some());
    }

    #[test]
    fn a_missing_folder_is_proposed_as_is_and_made_on_creation() {
        let paths = crate::paths::Paths {
            config: tempfile::tempdir().unwrap().keep(),
            data: tempfile::tempdir().unwrap().keep(),
        };
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("new-app");
        let o = InitOpts {
            dir: Some(dir.display().to_string()),
            ..Default::default()
        };
        let mut p = propose(&paths, &o).unwrap();
        assert_eq!(p.name, "new-app");
        assert!(p.new_folder);
        assert!(!dir.exists(), "a proposal touches nothing");
        make_folder(&mut p).unwrap();
        assert!(dir.is_dir());
        let canonical = dir.canonicalize().unwrap().display().to_string();
        assert_eq!(p.cfg.workspace.dir.as_deref(), Some(canonical.as_str()));

        std::fs::write(dir.join("package.json"), "{}").unwrap();
        let p = propose(&paths, &o).unwrap();
        assert!(!p.new_folder);
        assert!(p.cfg.presets.contains(&"npm".to_string()));

        let o = InitOpts {
            dir: Some(parent.path().join("a/b").display().to_string()),
            ..Default::default()
        };
        assert!(propose(&paths, &o).is_err(), "no parent");
    }
}
