//! `luoto init` and the UI's new-env dialog: propose an env for a folder from what the folder
//! says about itself, or for a remote cloned inside the env (read there, never on the host),
//! then create and start it.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap_complete::engine::ArgValueCandidates;

use crate::config::{self, EnvConfig, EnvFile, Workspace};
use crate::env::{self, Ctx, UpOptions};
use crate::paths::Paths;
use crate::prompt::{ask, confirm};
use crate::text::display;
use crate::{complete, detect, names, project, repos, workspace};

#[derive(Default, clap::Args)]
pub struct InitOpts {
    /// The project folder, copied into the env (default: `.`; created when missing), or a
    /// remote cloned inside the env, with nothing on this machine: `owner/repo` on GitHub, an
    /// https or ssh URL, or user@host:path. `./owner/repo` is a folder.
    #[arg(value_name = "DIR|REMOTE")]
    pub dir: Option<String>,
    /// Env name (default: the folder's or repository's name).
    #[arg(long)]
    pub name: Option<String>,
    /// The branch a remote's clone checks out (default: the remote's).
    #[arg(long)]
    pub branch: Option<String>,
    #[arg(long)]
    pub image: Option<String>,
    /// Egress presets (repeatable), replacing the defaults and the detected ones:
    /// debian, github, github-releases, toolchains, npm, pypi, crates, go, maven, vscode, …
    #[arg(long = "preset", add = ArgValueCandidates::new(complete::presets))]
    pub presets: Vec<String>,
    /// Default toolchain (repeatable), e.g. `--tool node=24`; the project's own version
    /// files still win.
    #[arg(long = "tool", value_name = "TOOL=VERSION")]
    pub tools: Vec<String>,
    /// Coding agents to set up (repeatable): claude, opencode, codex, copilot, agy.
    #[arg(long = "agent", add = ArgValueCandidates::new(complete::agents))]
    pub agents: Vec<String>,
    /// An agent's credential without the prompt (repeatable): `KIND=REF`
    /// (`oauth_token=op://…`), `PROVIDER.KIND=REF`, or `login_inside`.
    #[arg(long = "credential", value_name = "KIND=REF")]
    pub credentials: Vec<String>,
    /// Dev-server ports to publish on 127.0.0.1 (repeatable).
    #[arg(long = "port")]
    pub ports: Vec<u16>,
    /// A repository beside the folder, at `/workspace/<name>` (repeatable): a host folder,
    /// copied in, or a remote (`owner/repo` on GitHub, an https or ssh URL), cloned in the env.
    #[arg(long = "repo", value_name = "FOLDER|REMOTE")]
    pub repos: Vec<String>,
    /// `gvisor` (default once `luoto setup` installed it): the env gets its own user-space
    /// kernel. `container`: it shares the VM's kernel, with builds about 1.6× faster.
    #[arg(long, value_enum)]
    pub isolation: Option<config::Isolation>,
    /// Let the env reach any HTTP(S) host for a while (`--open=2h`; default 1h) to see what
    /// it needs; `luoto egress keep` keeps that, `luoto egress close` ends it sooner.
    #[arg(
        long,
        value_name = "DURATION",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = crate::egress::WINDOW
    )]
    pub open: Option<String>,
    /// Only write the config.
    #[arg(long)]
    pub no_up: bool,
    /// Create without asking; accepts the folder's luoto.toml (`--no-project` ignores it). A
    /// remote's clone installs what it pins, and its luoto.toml waits for `luoto project apply`.
    #[arg(long, short)]
    pub yes: bool,
    /// Ignore the folder's luoto.toml.
    #[arg(long)]
    pub no_project: bool,
}

/// What `luoto init`'s argument names.
#[derive(Debug, PartialEq)]
pub enum Source {
    /// A host folder, which need not exist yet; `None` is the current one.
    Folder(Option<String>),
    /// A remote, cloned inside the env.
    Remote(String),
}

/// A folder when the argument looks like a path (starts with `/`, `~` or `.`, or holds a `\`),
/// exists, or has a parent that exists (a new folder); else a remote, if `repos::check_url`
/// takes it. Relative paths are read against `cwd`.
pub fn source(arg: Option<&str>, cwd: &Path) -> Result<Source> {
    let Some(a) = arg else {
        return Ok(Source::Folder(None));
    };
    let path_like = a.starts_with(['/', '~', '.']) || a.contains('\\');
    let path = cwd.join(workspace::expand(a));
    let parent = path.parent().unwrap_or(cwd);
    if path_like || path.exists() || parent.is_dir() {
        return Ok(Source::Folder(Some(a.to_string())));
    }
    if let Err(e) = repos::check_url(a) {
        bail!(
            "{e:#}; as a folder, {} does not exist (luoto creates only the last folder of a path)",
            parent.display()
        );
    }
    Ok(Source::Remote(a.to_string()))
}

/// The env whose workspace is cloned from `url`: the same clone URL in any case, or the same
/// GitHub repository however it is spelled.
pub fn env_cloned_from(paths: &Paths, url: &str) -> Result<Option<String>> {
    let want = repos::clone_url(url);
    let github = repos::github_repo(url).map(|r| r.to_lowercase());
    for name in config::list_envs(paths)? {
        let Ok(f) = EnvFile::load(paths, &name) else {
            continue;
        };
        let Some(have) = f.cfg.workspace.url else {
            continue;
        };
        if repos::clone_url(&have).eq_ignore_ascii_case(&want)
            || (github.is_some() && repos::github_repo(&have).map(|r| r.to_lowercase()) == github)
        {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// An env's name and workspace for a remote: nothing on the host, so nothing is read there.
fn remote_workspace(
    url: &str,
    branch: Option<&str>,
    name: Option<&str>,
) -> Result<(String, Workspace)> {
    if let Some(b) = branch {
        repos::check_branch(b)?;
    }
    let name = match name {
        Some(n) => n.to_string(),
        None => workspace::name_from(&repos::default_name(&repos::Source::Remote(url.into()))?),
    };
    config::validate_name(&name)
        .with_context(|| format!("pick a name with --name (derived `{name}` is not valid)"))?;
    Ok((
        name,
        Workspace {
            url: Some(url.to_string()),
            branch: branch.map(str::to_string),
            ..Default::default()
        },
    ))
}

/// Presets every new env starts with; the folder's files add more.
pub const DEFAULT_PRESETS: &[&str] = &["debian", "github", "github-releases", "toolchains"];

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
    /// How long the env's egress is open from its creation (`--open`).
    pub open: Option<String>,
}

/// Defaults plus what the folder says about itself; explicit options replace both. Touches
/// nothing on disk. A remote is read nowhere: its clone, inside the env, says what it needs
/// on the first `up`.
pub fn propose(paths: &Paths, o: &InitOpts) -> Result<Proposal> {
    let (name, mut workspace) = match source(o.dir.as_deref(), &std::env::current_dir()?)? {
        Source::Folder(dir) => {
            if o.branch.is_some() {
                bail!("--branch is for a remote; a folder is copied as it is");
            }
            new_workspace(paths, dir.as_deref(), o.name.as_deref())?
        }
        Source::Remote(url) => {
            if o.no_project {
                bail!(
                    "--no-project is for a folder: a remote's luoto.toml is shown on the first \
                     `up`, and applies only if you say yes"
                );
            }
            remote_workspace(&url, o.branch.as_deref(), o.name.as_deref())?
        }
    };
    let remote = workspace.url.is_some();
    let dir = std::path::PathBuf::from(workspace.dir.as_deref().unwrap_or_default());
    for spec in &o.repos {
        let src = repos::parse_source(spec)?;
        let repo_name = repos::default_name(&src)?;
        let repo = match src {
            repos::Source::Folder(d) => {
                repos::check_folder(workspace.dir.as_deref(), &d)?;
                config::Repo {
                    dir: Some(d.display().to_string()),
                    ..Default::default()
                }
            }
            repos::Source::Remote(u) => config::Repo {
                url: Some(u),
                ..Default::default()
            },
        };
        if workspace.repos.insert(repo_name.clone(), repo).is_some() {
            bail!(
                "two --repo are named `{repo_name}`; add one with `luoto repo add … --name` \
                 after init"
            );
        }
    }
    repos::check(&workspace)?;
    let new_folder = !remote && std::fs::read_dir(&dir).map_or(true, |mut d| d.next().is_none());
    let (project, project_error) = if o.no_project || new_folder || remote {
        (None, None)
    } else {
        match project::read_host(&dir)
            .and_then(|t| t.map(|t| project::parse(&t).map(|p| (t, p))).transpose())
        {
            Ok(p) => (p, None),
            Err(e) => (None, Some(format!("{e:#}"))),
        }
    };
    // The folder and the host folders of its repos, each repo's files under its name.
    let mut roots: Vec<(String, std::path::PathBuf)> = Vec::new();
    if !new_folder && !remote {
        roots.push((String::new(), dir.clone()));
    }
    roots.extend(
        workspace
            .repos
            .iter()
            .filter_map(|(n, r)| Some((n.clone(), r.dir.as_ref()?.into()))),
    );
    let found = detect::detect_roots(&roots);
    let presets = if o.presets.is_empty() {
        let mut p: Vec<String> = DEFAULT_PRESETS.iter().map(|s| s.to_string()).collect();
        config::extend_unique(&mut p, found.presets.iter().map(|(n, _)| n.clone()));
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
        agents: config::Agents::from_names(o.agents.clone()),
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
        open: o
            .open
            .as_deref()
            .map(|w| {
                crate::egress::parse_window(w)
                    .map(|_| w.trim().to_string())
                    .context("--open")
            })
            .transpose()?,
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
    crate::compile::compile(&p.name, &effective, None, &[])?;
    Ok(())
}

/// How each of the proposal's agents signs in once the env exists: what `--credential`
/// (`specs`) gives it, else what its first `up` does (asks, when it `asks`; else a login
/// inside where the provider allows one).
fn credential_rows(p: &Proposal, specs: &[String], asks: bool) -> Vec<String> {
    use luoto_shared::profiles;
    let mut rows = Vec::new();
    for name in p.cfg.agents.names() {
        let Some(a) = profiles::agent(name) else {
            continue;
        };
        if a.providers.is_empty() {
            continue;
        }
        let providers: Vec<profiles::Provider> = a
            .providers
            .iter()
            .filter_map(|n| profiles::provider(n))
            .collect();
        let given = specs.iter().find_map(|s| {
            let (key, r) = match s.split_once('=') {
                Some((k, r)) => (k.trim(), Some(r.trim())),
                None => (s.trim(), None),
            };
            let kind = key.rsplit('.').next().unwrap_or(key);
            providers.iter().find_map(|p| match r {
                Some(r) => p
                    .auth
                    .get(kind)
                    .map(|k| format!("{} = {}", k.label, crate::secrets::shown_ref(r))),
                None => (kind == "login_inside" && !p.login_hosts.is_empty())
                    .then(|| "log in inside the sandbox".to_string()),
            })
        });
        let login = providers.iter().any(|p| !p.login_hosts.is_empty());
        let how = match given {
            Some(g) => g,
            None if asks => "not set (asked at the first up)".into(),
            None if login => "log in inside the sandbox (no terminal to ask on)".into(),
            None => format!("not set (`luoto agent auth -e {} {name}`)", p.name),
        };
        rows.push(format!("{name}: {how}"));
    }
    rows
}

fn print_proposal(p: &Proposal, specs: &[String], asks: bool) {
    const INDENT: &str = "             ";
    let ws = &p.cfg.workspace;
    println!(
        "env `{}`{}",
        p.name,
        ws.dir
            .as_deref()
            .map(|d| format!(" from {d}"))
            .or_else(|| ws.url.as_deref().map(|u| format!(" from {}", display(u))))
            .unwrap_or_default()
    );
    let exists = ws.dir.as_deref().is_some_and(|d| Path::new(d).exists());
    if let Some(url) = &ws.url {
        println!(
            "  workspace  a remote: {}{} cloned in the env through the gate; nothing on this machine",
            display(url),
            ws.branch
                .as_deref()
                .map(|b| format!(" ({})", display(b)))
                .unwrap_or_default()
        );
    } else if exists {
        println!(
            "  workspace  copy: the env works on its own copy; changes leave by git push or `luoto pull`"
        );
    } else {
        println!(
            "  workspace  new folder, created now: the env starts empty, and `luoto pull` fills the folder"
        );
    }
    let mut repos: Vec<(String, String)> = ws
        .repos
        .iter()
        .map(|(n, r)| {
            let what = match (&r.dir, &r.url) {
                (Some(d), _) => format!("{d} (copied in)"),
                (None, Some(u)) => format!("{} (cloned in the env)", crate::text::display(u)),
                _ => String::new(),
            };
            (n.clone(), what)
        })
        .collect();
    if let Some((_, pc)) = &p.project {
        repos.extend(
            pc.repos
                .iter()
                .filter(|(n, _)| !ws.repos.keys().any(|o| o.eq_ignore_ascii_case(n)))
                .map(|(n, r)| {
                    (
                        crate::text::display(n),
                        format!(
                            "{} (cloned in the env, from luoto.toml)",
                            crate::text::display(&r.url)
                        ),
                    )
                }),
        );
    }
    if !repos.is_empty() {
        let width = repos.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        for (i, (n, what)) in repos.iter().enumerate() {
            let label = if i == 0 { "repos" } else { "" };
            println!("  {label:<10} {n:<width$}  {what}");
        }
        println!("{INDENT}each at /workspace/<name>");
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
                Some(t) => format!("default, from {}", crate::text::display(&t.source)),
                None => "--tool".into(),
            };
            tools.push(format!("{k} {v} ({why})"));
        }
    }
    if ws.url.is_some() {
        println!(
            "  toolchains and luoto.toml: read from the clone, shown before anything applies{}",
            if tools.is_empty() {
                String::new()
            } else {
                format!("\n{INDENT}defaults: {}", tools.join(", "))
            }
        );
    } else if tools.is_empty() {
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
        let names: Vec<&str> = p.cfg.agents.names().map(String::as_str).collect();
        println!("  agents     {}", names.join(", "));
    }
    for row in credential_rows(p, specs, asks) {
        println!("  credential {row}");
    }
    if !p.cfg.ports.is_empty() {
        let ports: Vec<String> = p.cfg.ports.iter().map(u16::to_string).collect();
        println!("  ports      {}", ports.join(", "));
    }
    if let Some(i) = &p.cfg.image {
        println!("  image      {i}");
    }
    if let Some(w) = &p.open {
        println!(
            "  egress     open for {w} to any HTTP(S) host no rule allows\n{INDENT}`luoto egress keep -e {}` keeps what it reaches",
            p.name
        );
    }
    if let Some((_, pc)) = &p.project {
        println!("  luoto.toml settings written in the repository, so review them:");
        project::print_entries(&project::summary(pc), "               ");
    }
    if let Some(e) = &p.project_error {
        println!("  luoto.toml not used: {}", crate::text::display(e));
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

/// The env whose folder is `dir` itself.
fn env_at(paths: &Paths, dir: &Path) -> Result<Option<String>> {
    for name in config::list_envs(paths)? {
        let Ok(f) = EnvFile::load(paths, &name) else {
            continue;
        };
        if f.cfg
            .workspace
            .dir
            .is_some_and(|d| workspace::canonical(&d).is_ok_and(|d| d == dir))
        {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// An env's name and workspace for a folder (default: the current one), which need not
/// exist yet: `make_folder` creates it once the env is wanted.
pub fn new_workspace(
    paths: &Paths,
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
    if let Some(other) = env_at(paths, &dir)? {
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
            ..Default::default()
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
    let path = Path::new(&dir);
    if !path.exists() {
        std::fs::create_dir(path).with_context(|| format!("create {dir}"))?;
        println!("created {dir}");
    }
    p.cfg.workspace.dir = Some(workspace::canonical(&dir)?.display().to_string());
    Ok(())
}

/// Create the proposed env: its folder, its config, and the answer to the folder's
/// luoto.toml (`accept_project`).
pub fn create(ctx: &Ctx, p: &mut Proposal, accept_project: bool, quiet: bool) -> Result<()> {
    if p.cfg.workspace.url.is_none() {
        make_folder(p)?;
    }
    // The window starts now, not when it was proposed.
    if let Some(w) = &p.open {
        p.cfg.egress.open_until = Some(crate::egress::until(crate::egress::parse_window(w)?));
    }
    let name = &p.name;
    let f = EnvFile::create(&ctx.paths, name, &p.cfg)?;
    if !quiet {
        println!("created env `{name}` ({})", f.path.display());
    }
    if let Some((text, _)) = &p.project {
        if accept_project {
            project::accept(ctx, name, text)?;
        } else {
            project::forget(ctx, name, Some(text))?;
            if !quiet {
                println!(
                    "luoto.toml not applied (`luoto project apply -e {name}` applies it later)"
                );
            }
        }
    }
    Ok(())
}

/// Start a new env: `up` asks for the credentials its agents and repos lack and installs the
/// agents. `accept_installs`: what a remote's clone pins installs without a question.
pub fn start(ctx: &Ctx, name: &str, quiet: bool, accept_installs: bool) -> Result<()> {
    env::up(
        ctx,
        name,
        &UpOptions {
            quiet,
            accept_installs,
            ..Default::default()
        },
    )
}

pub fn init(o: InitOpts) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if o.yes {
        // Nothing asks, `up` included: agents log in inside, repos get a hint.
        crate::prompt::never_ask();
    }
    // `init` again for an env's own folder or remote: detect anew and offer what is missing.
    if o.name.is_none() {
        match source(o.dir.as_deref(), &std::env::current_dir()?)? {
            Source::Folder(d) => {
                if let Some(dir) = match &d {
                    Some(d) => workspace::canonical(d).ok(),
                    None => std::env::current_dir()?.canonicalize().ok(),
                } && let Some(existing) = env_at(&ctx.paths, &dir)?
                {
                    return redetect(&ctx, &existing, Some(&dir), &o);
                }
            }
            Source::Remote(url) => {
                if let Some(existing) = env_cloned_from(&ctx.paths, &url)? {
                    return redetect(&ctx, &existing, None, &o);
                }
            }
        }
    }
    let mut p = propose(&ctx.paths, &o)?;
    let interactive = !o.yes && std::io::stdin().is_terminal();
    if interactive && p.new_folder {
        println!(
            "{} is {}, so there is nothing to detect: pick what the env needs.",
            p.cfg.workspace.dir.as_deref().unwrap_or_default(),
            if Path::new(p.cfg.workspace.dir.as_deref().unwrap_or_default()).exists() {
                "empty"
            } else {
                "new"
            }
        );
        crate::wizard::customize(&mut p)?;
        check(&p)?;
        println!();
    }
    print_proposal(&p, &o.credentials, interactive);
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
                    print_proposal(&p, &o.credentials, interactive);
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
    create(&ctx, &mut p, accept_project, false)?;
    let name = p.name.clone();
    if !o.credentials.is_empty() {
        let agents: Vec<String> = env::layered(&ctx, &name)?.agents.names().cloned().collect();
        crate::agents::set_credentials(&ctx, &name, &agents, &o.credentials).with_context(
            || {
                format!(
                    "env `{name}` is created without it; `luoto agent add -e {name} <agent> \
                 --credential …` sets it"
                )
            },
        )?;
    }
    crate::agents::login_inside_unless_set(&ctx, &name)?;
    if o.no_up {
        // `up` asks for the credentials the repos lack; until then, say what they are.
        let cfg = env::layered(&ctx, &name)?;
        if let Some(hint) =
            repos::credential_hint(&name, &repos::remotes(&cfg.workspace), &cfg.credentials)
        {
            println!("\n{hint}");
        }
        if cfg.workspace.url.is_some() {
            println!("\n`luoto up -e {name}` clones it");
        }
    } else {
        start(&ctx, &name, false, o.yes)?;
    }
    // The luoto.toml accepted by now: the folder's, or the clone's if `up` asked about it.
    if let Some((_, pc)) = project::accepted(&ctx, &name) {
        let cfg = EnvFile::load(&ctx.paths, &name)?.cfg;
        print_needs(&name, &project::missing_needs(&pc, &cfg));
    }
    println!(
        "\nYour settings for every env (shell rc files, .gitconfig, .claude/settings.json, …) go in \
         {}: copied in on each `up`, and readable by code in the env, so keep secrets out.",
        crate::ssh::tilde(&ctx.paths.home_files())
    );
    Ok(ExitCode::SUCCESS)
}

/// Offer what the project suggests now and the env's config lacks. The project is the env's
/// own copy while it runs (work happens there), else the folder; an env cloned from a remote
/// (`dir` is `None`) has only the copy, so it is started first.
fn redetect(ctx: &Ctx, name: &str, dir: Option<&Path>, o: &InitOpts) -> Result<ExitCode> {
    if let Some(w) = &o.open {
        let until = crate::egress::until(crate::egress::parse_window(w).context("--open")?);
        crate::egress::open(ctx, name, until)?;
        println!(
            "egress of `{name}` is open {}",
            crate::egress::until_text(Some(until))
        );
    }
    let up = UpOptions {
        accept_installs: o.yes,
        ..Default::default()
    };
    let mut inside = ctx.rt.is_running(&names::dev(name));
    let (found, source) = match dir {
        Some(dir) if !inside => (detect::detect(dir), dir.display().to_string()),
        _ => {
            if !inside {
                if o.no_up {
                    println!(
                        "env `{name}` exists for that remote, and its files are only in the env: \
                         `luoto up -e {name}` starts it, then `luoto init` again reads them"
                    );
                    return Ok(ExitCode::SUCCESS);
                }
                println!("env `{name}` exists for that remote; starting it to read its files");
                env::up(ctx, name, &up)?;
                inside = true;
            }
            (
                crate::deps::detect_in_env(ctx, name)?,
                "its workspace".to_string(),
            )
        }
    };
    let heading = format!("env `{name}` exists; {source} now suggests:");
    if !offer(ctx, name, &found, &heading, o.yes, inside)? {
        println!("env `{name}` already has what {source} suggests");
        return Ok(ExitCode::SUCCESS);
    }
    if !o.no_up {
        env::up(ctx, name, &up)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Offer what detection found and the env's config lacks: presets, and default toolchains
/// for runtimes, package managers and task runners the project doesn't pin. Only adds, and
/// only with `yes` or a yes on a terminal; without one it lists them. Files read `inside` the
/// env can be the sandbox's, so there Enter answers no. Whether the config changed.
pub fn offer(
    ctx: &Ctx,
    name: &str,
    found: &detect::Detected,
    heading: &str,
    yes: bool,
    inside: bool,
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
        println!("  preset    + {p} ({})", crate::text::display(f));
    }
    for t in &tools {
        println!(
            "  toolchain + {} {} (default, from {})",
            t.tool,
            t.version,
            crate::text::display(&t.source)
        );
    }
    if !yes && !crate::prompt::interactive() {
        match &file.cfg.workspace.url {
            Some(u) => println!("  `luoto init {} --yes` adds them", display(u)),
            None => println!("  `luoto init --yes` in the env's folder adds them"),
        }
        return Ok(false);
    }
    let added = yes
        || if inside {
            crate::prompt::confirm(&format!("Add them to `{name}`?"))
        } else {
            ask(&format!("Add them to `{name}`? [Y/n]"), 'y') != 'n'
        };
    if !added {
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

/// Show what the project's luoto.toml needs that only the user can add (`needs`: one entry
/// per credential, already worded).
pub fn print_needs(name: &str, needs: &[String]) {
    if !needs.is_empty() {
        println!(
            "\nThe project needs credentials only you can add (`luoto edit -e {name}`):\n\n{}\n",
            needs.join("\n\n")
        );
    }
}

/// The URL of a folder's `origin` remote, if any.
pub fn origin_url(dir: &Path) -> Option<String> {
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

#[cfg(test)]
mod tests {
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
        assert_eq!(repos::github_repo(&url).as_deref(), Some("Eetu/luoto"));
    }

    #[test]
    fn a_missing_folder_is_proposed_as_is_and_made_on_creation() {
        let paths = Paths {
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

    #[test]
    fn an_argument_is_a_folder_when_it_can_be_one_else_a_remote() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd = cwd.path();
        std::fs::create_dir_all(cwd.join("have/sub")).unwrap();
        let folder = |a: &str| Source::Folder(Some(a.to_string()));
        let remote = |a: &str| Source::Remote(a.to_string());
        for (arg, want) in [
            ("new-app", folder("new-app")),
            ("have", folder("have")),
            ("have/sub", folder("have/sub")),
            ("have/new", folder("have/new")),
            ("./acme/web", folder("./acme/web")),
            ("/abs/acme/web", folder("/abs/acme/web")),
            ("~/acme/web", folder("~/acme/web")),
            ("acme/web", remote("acme/web")),
            (
                "https://github.com/acme/web.git",
                remote("https://github.com/acme/web.git"),
            ),
            (
                "git@github.com:acme/web.git",
                remote("git@github.com:acme/web.git"),
            ),
            (
                "ssh://git@host.example:2222/x/y",
                remote("ssh://git@host.example:2222/x/y"),
            ),
            (
                "https://dev.azure.com/o/P/_git/web",
                remote("https://dev.azure.com/o/P/_git/web"),
            ),
        ] {
            assert_eq!(source(Some(arg), cwd).unwrap(), want, "{arg}");
        }
        assert_eq!(source(None, cwd).unwrap(), Source::Folder(None));
        for arg in ["acme/web/more", "file:///etc", "http://github.com/acme/web"] {
            let e = source(Some(arg), cwd).unwrap_err();
            assert!(format!("{e:#}").contains("as a folder"), "{arg}: {e:#}");
        }
    }

    fn paths() -> Paths {
        Paths {
            config: tempfile::tempdir().unwrap().keep(),
            data: tempfile::tempdir().unwrap().keep(),
        }
    }

    #[test]
    fn a_remote_is_proposed_without_reading_or_making_anything_here() {
        let paths = paths();
        let o = InitOpts {
            dir: Some("https://github.com/Acme/Web-App.git".into()),
            branch: Some("develop".into()),
            ..Default::default()
        };
        let p = propose(&paths, &o).unwrap();
        assert_eq!(p.name, "web-app");
        let ws = &p.cfg.workspace;
        assert_eq!(ws.dir, None);
        assert_eq!(ws.url.as_deref(), o.dir.as_deref());
        assert_eq!(ws.branch.as_deref(), Some("develop"));
        assert!(!p.new_folder && p.project.is_none() && p.project_error.is_none());
        assert!(p.found.presets.is_empty() && p.found.tools.is_empty());
        assert!(p.found.defaults.is_empty());
        assert_eq!(p.cfg.presets, DEFAULT_PRESETS);
        assert!(p.cfg.tools.is_empty());
        assert!(!paths.envs_dir().exists(), "a proposal writes nothing");
        assert!(!Path::new("Web-App").exists() && !Path::new("web-app").exists());

        let named = InitOpts {
            name: Some("site".into()),
            ..o
        };
        assert_eq!(propose(&paths, &named).unwrap().name, "site");
        let no_project = InitOpts {
            dir: Some("acme/web".into()),
            no_project: true,
            ..Default::default()
        };
        assert!(propose(&paths, &no_project).is_err());
        let folder = tempfile::tempdir().unwrap();
        let branch_on_folder = InitOpts {
            dir: Some(folder.path().display().to_string()),
            branch: Some("main".into()),
            ..Default::default()
        };
        assert!(propose(&paths, &branch_on_folder).is_err());
    }

    #[test]
    fn the_proposal_says_how_each_agent_will_sign_in() {
        let o = InitOpts {
            dir: Some(tempfile::tempdir().unwrap().keep().display().to_string()),
            agents: vec!["claude".into(), "copilot".into()],
            ..Default::default()
        };
        let p = propose(&paths(), &o).unwrap();
        assert_eq!(
            credential_rows(&p, &[], true),
            [
                "claude: not set (asked at the first up)",
                "copilot: not set (asked at the first up)"
            ]
        );
        let name = &p.name;
        assert_eq!(
            credential_rows(&p, &[], false),
            [
                "claude: log in inside the sandbox (no terminal to ask on)".to_string(),
                format!("copilot: not set (`luoto agent auth -e {name} copilot`)"),
            ]
        );
        assert_eq!(
            credential_rows(&p, &["oauth_token=env:T".into()], true)[0],
            "claude: Claude subscription token = env:T"
        );
    }

    #[test]
    fn the_same_remote_again_finds_its_env() {
        let paths = paths();
        let mut cfg = EnvConfig::default();
        cfg.workspace.url = Some("acme/web".into());
        EnvFile::create(&paths, "web", &cfg).unwrap();
        for same in [
            "acme/web",
            "ACME/Web",
            "https://github.com/acme/web.git",
            "https://github.com/acme/web",
            "git@github.com:Acme/web.git",
        ] {
            assert_eq!(
                env_cloned_from(&paths, same).unwrap().as_deref(),
                Some("web"),
                "{same}"
            );
        }
        for other in ["acme/api", "https://gitlab.com/acme/web.git"] {
            assert_eq!(env_cloned_from(&paths, other).unwrap(), None, "{other}");
        }
    }
}
