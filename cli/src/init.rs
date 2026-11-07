//! `luoto init` and the UI's new-env dialog: propose an env for a folder from what the folder
//! says about itself, then create and start it.

use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap_complete::engine::ArgValueCandidates;

use crate::config::{self, EnvConfig, EnvFile, Workspace};
use crate::env::{self, Ctx, UpOptions};
use crate::paths::Paths;
use crate::prompt::{ask, confirm};
use crate::{complete, detect, names, project, repos, workspace};

#[derive(Default, clap::Args)]
pub struct InitOpts {
    /// The project folder, copied into the env (default: `.`); created when missing.
    pub dir: Option<String>,
    /// Env name (default: the folder's name).
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub image: Option<String>,
    /// Egress presets (repeatable), replacing the defaults and the detected ones:
    /// debian, github, toolchains, npm, pypi, crates, go, maven, gradle, vscode, docs, …
    #[arg(long = "preset", add = ArgValueCandidates::new(complete::presets))]
    pub presets: Vec<String>,
    /// Default toolchain (repeatable), e.g. `--tool node=24`; the project's own version
    /// files still win.
    #[arg(long = "tool", value_name = "TOOL=VERSION")]
    pub tools: Vec<String>,
    /// Coding agents to set up (repeatable): claude, opencode, codex, copilot, agy.
    #[arg(long = "agent", add = ArgValueCandidates::new(complete::agents))]
    pub agents: Vec<String>,
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
    /// Only write the config.
    #[arg(long)]
    pub no_up: bool,
    /// Create without asking; accepts the folder's luoto.toml (`--no-project` ignores it).
    #[arg(long, short)]
    pub yes: bool,
    /// Ignore the folder's luoto.toml.
    #[arg(long)]
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
pub fn propose(paths: &Paths, o: &InitOpts) -> Result<Proposal> {
    let (name, mut workspace) = new_workspace(paths, o.dir.as_deref(), o.name.as_deref())?;
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
    // The folder and the host folders of its repos, each repo's files under its name.
    let mut roots: Vec<(String, std::path::PathBuf)> = Vec::new();
    if !new_folder {
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
    crate::compile::compile(&p.name, &effective, None, &[])?;
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
    let exists = ws.dir.as_deref().is_some_and(|d| Path::new(d).exists());
    if exists {
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
/// luoto.toml (`accept_project`). The agents the env gets, the accepted luoto.toml's
/// included.
pub fn create(
    ctx: &Ctx,
    p: &mut Proposal,
    accept_project: bool,
    quiet: bool,
) -> Result<Vec<String>> {
    make_folder(p)?;
    let name = &p.name;
    let f = EnvFile::create(&ctx.paths, name, &p.cfg)?;
    if !quiet {
        println!("created env `{name}` ({})", f.path.display());
    }
    let mut agents = p.cfg.agents.clone();
    if let Some((text, pc)) = &p.project {
        if accept_project {
            project::accept(ctx, name, text)?;
            config::extend_unique(&mut agents, pc.agents.iter().cloned());
        } else {
            project::forget(ctx, name, Some(text))?;
            if !quiet {
                println!(
                    "luoto.toml not applied (`luoto project apply -e {name}` applies it later)"
                );
            }
        }
    }
    Ok(agents)
}

/// Start a new env and install its agents.
pub fn start(ctx: &Ctx, name: &str, agents: &[String], quiet: bool) -> Result<()> {
    env::up(
        ctx,
        name,
        &UpOptions {
            quiet,
            ..Default::default()
        },
    )?;
    for a in agents {
        crate::agents::install(ctx, name, a)?;
    }
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
        && let Some(existing) = env_at(&ctx.paths, &dir)?
    {
        return redetect(&ctx, &existing, &dir, &o);
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
        crate::wizard::customize(&mut p, &ctx.global)?;
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
                    crate::wizard::customize(&mut p, &ctx.global)?;
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
    let agents = create(&ctx, &mut p, accept_project, false)?;
    let name = p.name.clone();
    if let Some(hint) = p
        .cfg
        .workspace
        .dir
        .as_deref()
        .and_then(|d| origin_url(Path::new(d)))
        .and_then(|u| credential_hint(&name, &u, &p.cfg.credentials))
    {
        println!("{hint}");
    }
    // Before `up`, so the env starts with them.
    crate::agents::credentials(&ctx, &name, &agents, interactive)?;
    if !o.no_up {
        start(&ctx, &name, &agents, false)?;
    }
    if let Some((_, pc)) = p.project.as_ref().filter(|_| accept_project) {
        let cfg = EnvFile::load(&ctx.paths, &name)?.cfg;
        print_needs(&name, &project::missing_needs(pc, &cfg));
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
fn redetect(ctx: &Ctx, name: &str, dir: &Path, o: &InitOpts) -> Result<ExitCode> {
    let (found, source) = if ctx.rt.is_running(&names::dev(name)) {
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
        env::up(ctx, name, &UpOptions::default())?;
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
            crate::text::display(&repo),
            "fine-grained PAT, or app_id + installation_id + private_key",
        )
    } else {
        let (r, _) = crate::azure::parse_url(url)?;
        let repo = format!(
            "{}/{}/{}",
            crate::text::display(&r.org),
            crate::text::display(&crate::azure::decode(&r.project)),
            crate::text::display(&crate::azure::decode(&r.name))
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
}
