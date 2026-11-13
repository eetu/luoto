//! Repositories beside an env's folder in its workspace, each at `/workspace/<name>`: from the
//! env's config (`[workspace.repos.<name>]`, a host folder or a remote) and from the accepted
//! luoto.toml (`[repos.<name>]`, remotes only: a repository can't name your folders). On the
//! first `up` that has one, a host folder is copied in and a remote is cloned inside the env,
//! through the gate and with the env's credentials.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::config::{
    Credentials, EnvConfig, EnvFile, GitCred, ListAs, Relisted, Repo, Workspace, extend_unique,
};
use crate::env::{Ctx, UID};
use crate::prompt::{Ask, menu_help};
use crate::runtime::exec;
use crate::state::EnvState;
use crate::text::{self, display, sh_quote};
use crate::wizard::{Mode, Question, Step};
use crate::{connect, env, names, project, workspace};

/// A folder name under `/workspace`: one plain component, not hidden.
pub fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 100
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && name != project::FILE;
    if !ok {
        bail!(
            "`{}` is not a repo name: a folder name of letters, digits, `.`, `_` and `-`, not \
             starting with `.` or `-`",
            display(name)
        );
    }
    Ok(())
}

fn plain(s: &str, extra: &[u8]) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

fn host_ok(h: &str) -> bool {
    plain(h, b".-") && !h.starts_with(['.', '-'])
}

fn path_ok(p: &str) -> bool {
    plain(p, b"._~%/+-") && !p.starts_with('-') && !p.split('/').any(|s| s == "..")
}

/// GitHub's `owner/repo`.
fn shorthand(url: &str) -> Option<(&str, &str)> {
    let (owner, repo) = url.split_once('/')?;
    (plain(owner, b"_.-")
        && !owner.starts_with(['.', '-'])
        && plain(repo, b"_.-")
        && !repo.starts_with('-')
        && repo != "."
        && repo != "..")
        .then_some((owner, repo))
}

/// The user name of an `https://` URL, which a token can stand in: its host and path too.
fn https_userinfo(url: &str) -> Option<(&str, &str, &str)> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (user, host) = authority.rsplit_once('@')?;
    Some((user, host, path))
}

/// Azure DevOps' own clone URL, `https://<org>@dev.azure.com/<org>/…`: its user name is the
/// organization the path names, not a secret.
fn azure_org_user(user: &str, host: &str, path: &str) -> bool {
    host.eq_ignore_ascii_case(crate::azure::HOST)
        && path
            .split('/')
            .next()
            .is_some_and(|org| org.eq_ignore_ascii_case(user))
}

/// The host a remote names, if it is one luoto clones: GitHub's `owner/repo`, an `https://` or
/// `ssh://` URL, or scp-like `user@host:path`. No local paths, `file://` or git's command
/// transports (`ext::`), and no password in the URL ([`check_url`] also refuses an
/// `https://` user name for what is typed or a `luoto.toml` names).
fn remote_host(url: &str) -> Option<&str> {
    if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("ssh://"))
    {
        let (authority, path) = rest.split_once('/')?;
        let (user, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (host, port) = match hostport.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        };
        let ok = user.is_none_or(|u| plain(u, b"._-"))
            && host_ok(host)
            && port.is_none_or(|p| plain(p, b"") && p.parse::<u16>().is_ok())
            && path_ok(path);
        return ok.then_some(host);
    }
    if url.contains("://") {
        return None;
    }
    if let Some((user_host, path)) = url.split_once(':') {
        let (user, host) = user_host.split_once('@')?;
        return (plain(user, b"._-") && host_ok(host) && path_ok(path)).then_some(host);
    }
    shorthand(url).map(|_| "github.com")
}

/// A remote an env's own config names: what [`check_url`] allows, and an `https://` user name,
/// which env files written before 0.4.0 may hold (Bitbucket's copied URLs carry one).
fn check_config_url(url: &str) -> Result<()> {
    match https_userinfo(url) {
        Some((user, host, path)) if !azure_org_user(user, host, path) => {
            if !plain(user, b"._-") {
                bail!("`https://…@{}/…`: no password in the URL", display(host));
            }
            check_url(&format!("https://{host}/{path}"))
        }
        _ => check_url(url),
    }
}

pub fn check_url(url: &str) -> Result<()> {
    if let Some((user, host, path)) = https_userinfo(url)
        && !azure_org_user(user, host, path)
    {
        bail!(
            "`https://…@{}/…`: give the remote's URL without a user name or token, which would \
             be kept in the env's config, its export and the env's git config; `luoto up` asks \
             for a credential, which the gate adds",
            display(host)
        );
    }
    let Some(host) = remote_host(url) else {
        bail!(
            "`{}` is not a remote luoto clones: `owner/repo` (GitHub), an https:// or ssh:// \
             URL, or user@host:path",
            display(url)
        );
    };
    if host.eq_ignore_ascii_case("github.com") && github_repo(url).is_none() {
        bail!(
            "`{}` names no GitHub repository (`owner/repo`)",
            display(url)
        );
    }
    if forge_host(host) == Some("Azure DevOps") && crate::azure::parse_url(url).is_none() {
        bail!("`{}` names no Azure DevOps repository", display(url));
    }
    Ok(())
}

/// A remote a repository's `luoto.toml` may name: also a host by its name, not an address or
/// `localhost`, which would point the env's git at your machine or network.
pub fn check_project_url(url: &str) -> Result<()> {
    check_url(url)?;
    let host = remote_host(url).unwrap_or_default().to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok()
        || !host.contains('.')
        || host.ends_with(".localhost")
    {
        bail!(
            "`{}`: a luoto.toml names a remote's host by its name, not an address or a local name",
            display(url)
        );
    }
    Ok(())
}

/// The forge with a credential of its own that `host` belongs to, if any.
fn forge_host(host: &str) -> Option<&'static str> {
    let h = host.to_ascii_lowercase();
    if h == "github.com" {
        Some("GitHub")
    } else if h == crate::azure::HOST
        || h == crate::azure::SSH_HOST
        || h == "vs-ssh.visualstudio.com"
        || h.ends_with(".visualstudio.com")
    {
        Some("Azure DevOps")
    } else {
        None
    }
}

pub fn check_branch(b: &str) -> Result<()> {
    if !plain(b, b"._/+-")
        || b.starts_with(['-', '/', '.'])
        || b.ends_with(['/', '.'])
        || b.contains("..")
        || b.contains("//")
        || b.ends_with(".lock")
    {
        bail!("`{}` is not a branch name", display(b));
    }
    Ok(())
}

/// What git clones: the URL, with GitHub's `owner/repo` spelled out.
pub fn clone_url(url: &str) -> String {
    match shorthand(url) {
        Some((owner, repo)) if !url.contains(':') => {
            let repo = repo.strip_suffix(".git").unwrap_or(repo);
            format!("https://github.com/{owner}/{repo}.git")
        }
        _ => url.to_string(),
    }
}

/// `owner/repo` when a remote is on GitHub.
pub fn github_repo(url: &str) -> Option<String> {
    let at_github = |authority: &str| {
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, h)| h)
            .eq_ignore_ascii_case("github.com")
    };
    let path = if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("ssh://"))
    {
        let (authority, p) = rest.split_once('/')?;
        at_github(authority).then_some(p)?
    } else if let Some((authority, p)) = url.split_once(':') {
        (!p.starts_with("//") && authority.contains('@') && at_github(authority)).then_some(p)?
    } else {
        url
    };
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    shorthand(path).map(|(o, r)| format!("{o}/{r}"))
}

/// The env config's workspace is well-formed: a host folder (`dir`) or a remote (`url`, maybe
/// with a `branch`), not both; and its repos have valid names that stay distinct on a
/// case-insensitive host, each a folder or a remote in the same way.
pub fn check(ws: &Workspace) -> Result<()> {
    let folders =
        ws.dir
            .iter()
            .map(|d| ("[workspace]".to_string(), d))
            .chain(ws.repos.iter().filter_map(|(n, r)| {
                Some((format!("[workspace.repos.{}]", display(n)), r.dir.as_ref()?))
            }));
    for (at, d) in folders {
        if workspace::network_path(d) {
            bail!(
                "{at}: `{}` is on another machine; `dir` is a folder on this one",
                display(d)
            );
        }
    }
    match (&ws.dir, &ws.url) {
        (Some(_), Some(_)) => {
            bail!("[workspace]: a host folder (`dir`) or a remote (`url`), not both")
        }
        (None, Some(u)) => check_url(u).context("[workspace]")?,
        _ => {}
    }
    if let Some(b) = &ws.branch {
        if ws.url.is_none() {
            bail!("[workspace]: `branch` is for a remote (`url`); a folder is copied as it is");
        }
        check_branch(b).context("[workspace]")?;
    }
    let mut folded: BTreeMap<String, &str> = BTreeMap::new();
    for (name, r) in &ws.repos {
        check_name(name).context("[workspace.repos]")?;
        if let Some(other) = folded.insert(name.to_lowercase(), name) {
            bail!("[workspace.repos]: `{other}` and `{name}` differ only by case");
        }
        match (&r.dir, &r.url) {
            (Some(_), Some(_)) => {
                bail!(
                    "[workspace.repos.{name}]: a host folder (`dir`) or a remote (`url`), not both"
                )
            }
            (None, None) => {
                bail!("[workspace.repos.{name}]: give a host folder (`dir`) or a remote (`url`)")
            }
            (Some(d), None) => {
                if !workspace::expand(d).is_absolute() {
                    bail!("[workspace.repos.{name}]: `dir` is an absolute path (got `{d}`)");
                }
                if r.branch.is_some() {
                    bail!(
                        "[workspace.repos.{name}]: `branch` is for remotes; a folder is copied as it is"
                    );
                }
            }
            (None, Some(u)) => {
                check_config_url(u).with_context(|| format!("[workspace.repos.{name}]"))?;
            }
        }
        if let Some(b) = &r.branch {
            check_branch(b).with_context(|| format!("[workspace.repos.{name}]"))?;
        }
    }
    Ok(())
}

/// What a `--repo` argument names.
#[derive(Debug, PartialEq)]
pub enum Source {
    Folder(PathBuf),
    Remote(String),
}

/// A host folder when the argument looks like a path (starts with `/`, `~` or `.`, or holds a
/// `\`) or names an existing folder; else a remote.
pub fn parse_source(s: &str) -> Result<Source> {
    let path_like = s.starts_with(['/', '~', '.']) || s.contains('\\');
    if path_like || workspace::expand(s).is_dir() {
        let dir = workspace::canonical(s)?;
        if !dir.is_dir() {
            bail!("{} is not a folder", dir.display());
        }
        return Ok(Source::Folder(dir));
    }
    check_url(s)?;
    Ok(Source::Remote(s.to_string()))
}

/// The repo's folder name in the workspace by default: the last part of its path or URL.
pub fn default_name(src: &Source) -> Result<String> {
    let full = match src {
        Source::Folder(d) => d.display().to_string(),
        Source::Remote(u) => u.clone(),
    };
    let last = full
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\', ':'])
        .next()
        .unwrap_or_default();
    let name = last.strip_suffix(".git").unwrap_or(last).to_string();
    check_name(&name).context("name it with --name")?;
    Ok(name)
}

/// A host folder can be a repo of the env with folder `root`: it is neither inside the env's
/// folder (copied in already) nor around it, and it doesn't hold your home folder.
pub fn check_folder(root: Option<&str>, dir: &Path) -> Result<()> {
    if let Some(root) = root.and_then(|r| workspace::canonical(r).ok()) {
        if dir.starts_with(&root) {
            bail!(
                "{} is inside the env's folder {}, which the env has already",
                dir.display(),
                root.display()
            );
        }
        if root.starts_with(dir) {
            bail!(
                "{} holds the env's folder {}",
                dir.display(),
                root.display()
            );
        }
    }
    // Canonical like `dir`: a symlinked home, and Windows' `\\?\` form.
    if let Some(home) = directories::BaseDirs::new().map(|b| {
        b.home_dir()
            .canonicalize()
            .unwrap_or_else(|_| b.home_dir().to_path_buf())
    }) && home.starts_with(dir)
    {
        bail!(
            "{} holds your home folder, which never goes into an env",
            dir.display()
        );
    }
    Ok(())
}

/// `p`'s names, to compare as text: `~` expanded, past any drive or root, each folded as
/// macOS and Windows compare names. `..` only the filesystem resolves.
fn text_names(p: &str) -> Result<Vec<String>> {
    let path = match directories::BaseDirs::new() {
        Some(b) if p == "~" => b.home_dir().to_path_buf(),
        _ => workspace::expand(p),
    };
    let mut out = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => out.push(workspace::fold(&n.to_string_lossy())),
            Component::ParentDir => bail!("`{}` names `..`", display(p)),
            _ => {}
        }
    }
    Ok(out)
}

/// [`check_folder`]'s rule for the folders of a config from elsewhere, on their text alone: a
/// lookup can reach another machine (an automounter, a share) before anyone said yes. None is
/// your home folder or holds it (as written, or as its links resolve), and no repo's is in or
/// around the env's.
pub fn check_folders_text(ws: &Workspace) -> Result<()> {
    let homes: Vec<Vec<String>> = directories::BaseDirs::new()
        .map(|b| {
            [
                Some(b.home_dir().to_path_buf()),
                b.home_dir().canonicalize().ok(),
            ]
        })
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|h| text_names(&h.to_string_lossy()).ok())
        .collect();
    let root = ws.dir.as_deref().map(text_names).transpose()?;
    let folders = ws.dir.iter().map(|d| (None, d)).chain(
        ws.repos
            .iter()
            .filter_map(|(n, r)| Some((Some(n), r.dir.as_ref()?))),
    );
    for (repo, d) in folders {
        let at = match repo {
            Some(n) => format!("[workspace.repos.{}]", display(n)),
            None => "[workspace]".to_string(),
        };
        let names = text_names(d).with_context(|| at.clone())?;
        if names.is_empty() {
            bail!("{at}: `{}` names no folder of its own", display(d));
        }
        if homes.iter().any(|h| h.starts_with(&names)) {
            bail!(
                "{at}: {} is your home folder or holds it, which never goes into an env",
                display(d)
            );
        }
        if let (Some(_), Some(root)) = (repo, &root) {
            if names.starts_with(root) {
                bail!("{at}: {} is inside the env's folder", display(d));
            }
            if root.starts_with(&names) {
                bail!("{at}: {} holds the env's folder", display(d));
            }
        }
    }
    Ok(())
}

/// Where a repo came from, for listings.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    Env,
    Project,
}

#[derive(Debug, Clone, Serialize)]
pub struct Listed {
    pub name: String,
    /// The host folder or the remote.
    pub source: String,
    /// `folder` (copied in) or `clone`.
    pub kind: &'static str,
    pub branch: Option<String>,
    pub origin: Origin,
    /// In the workspace already (copied, cloned or found there).
    pub present: bool,
}

/// The env's repos as `up` applies them: its own, then the accepted luoto.toml's it doesn't
/// name.
pub fn listed(ctx: &Ctx, env: &str) -> Result<Vec<Listed>> {
    let own = EnvFile::load(&ctx.paths, env)?.cfg.workspace.repos;
    let layered = env::layered(ctx, env)?.workspace.repos;
    let done = EnvState::load(&ctx.paths, env)?
        .map(|s| s.repos)
        .unwrap_or_default();
    Ok(layered
        .into_iter()
        .map(|(name, r)| Listed {
            source: r.dir.clone().or(r.url.clone()).unwrap_or_default(),
            kind: if r.dir.is_some() { "folder" } else { "clone" },
            branch: r.branch,
            origin: if own.contains_key(&name) {
                Origin::Env
            } else {
                Origin::Project
            },
            present: done.contains(&name),
            name,
        })
        .collect())
}

/// Which of `names` the workspace has a file or folder for.
fn present(ctx: &Ctx, env: &str, names: &[&str]) -> Result<BTreeSet<String>> {
    let dev = names::dev(env);
    let args = exec(&dev).user(UID).sh_with(
        r#"for d; do { [ -e "/workspace/$d" ] || [ -L "/workspace/$d" ]; } && printf '%s\n' "$d"; done; true"#,
        names,
    );
    let out = ctx.rt.run(&args).context("look for the repos in the env")?;
    Ok(out
        .lines()
        .filter(|l| names.contains(l))
        .map(str::to_string)
        .collect())
}

/// Copy in or clone each of `ws`'s repos that isn't in `done`, and return the names now in
/// the workspace. One the workspace has a folder for already is left as it is. A repo that
/// fails is a warning, and the next `up` tries it again.
/// The env's repos after [`seed`]: those in place, and why each of the others isn't, as
/// `name: why` with the command that fixes it.
pub struct Seeded {
    pub done: BTreeSet<String>,
    pub failed: Vec<String>,
}

impl Seeded {
    /// Each failure as a warning, for a command whose own summary doesn't list them.
    pub fn warn(&self) {
        for f in &self.failed {
            crate::progress::say(|| eprintln!("warning: repo {f}"));
        }
    }
}

pub fn seed(ctx: &Ctx, env: &str, cfg: &EnvConfig, done: &BTreeSet<String>) -> Seeded {
    let ws = &cfg.workspace;
    let mut failed = Vec::new();
    let mut now: BTreeSet<String> = done
        .iter()
        .filter(|n| ws.repos.contains_key(*n))
        .cloned()
        .collect();
    let pending: Vec<(&String, &Repo)> = ws
        .repos
        .iter()
        .filter(|(n, _)| !done.contains(*n))
        .collect();
    if pending.is_empty() {
        return Seeded { done: now, failed };
    }
    let names: Vec<&str> = pending.iter().map(|(n, _)| n.as_str()).collect();
    let found = match present(ctx, env, &names) {
        Ok(f) => f,
        Err(e) => {
            failed.push(format!(
                "{}: not set up ({e:#}); `luoto up -e {env}` tries again",
                names.join(", ")
            ));
            return Seeded { done: now, failed };
        }
    };
    let locked = pending.iter().any(|(_, r)| r.url.is_some()) && creds_locked(ctx, env);
    let mut added = Vec::new();
    // An entry of the env's own folder (or clone) by a repo's name would be taken for the
    // repo, and `pull` would then leave it out of the folder.
    let own = own_entries(ctx, env, ws);
    for (name, r) in pending {
        if own.contains(&name.to_lowercase()) {
            failed.push(format!(
                "{name}: left out, as the env's {} has its own `{name}`; give the repo another \
                 name",
                if ws.dir.is_some() { "folder" } else { "clone" }
            ));
            continue;
        }
        if found.contains(name) {
            println!(
                "repo {name}: /workspace/{name} is there already (from the env's folder or an \
                 earlier repo of that name) and is left as it is; to start it over, delete it \
                 in the env and `luoto up`"
            );
            now.insert(name.clone());
            continue;
        }
        let result = match (&r.dir, &r.url) {
            (Some(dir), _) => copy_in(ctx, env, ws, name, dir),
            (None, Some(url)) if waits(env, url) => continue,
            (None, Some(url)) => clone(ctx, env, name, url, r.branch.as_deref(), locked, cfg),
            (None, None) => continue,
        };
        match result {
            Ok(()) => {
                now.insert(name.clone());
                added.push(name.as_str());
            }
            Err(e) => failed.push(format!("{name}: {e:#}")),
        }
    }
    if let Err(e) = exclude_from_folder(ctx, env, &added) {
        eprintln!("warning: repos not added to the folder's .git/info/exclude ({e:#})");
    }
    Seeded { done: now, failed }
}

/// Whether some of the env's credentials didn't load (the vault is locked, or a reference
/// doesn't resolve): clones then fail with 403s whose cause is that, not a missing credential.
pub fn creds_locked(ctx: &Ctx, env: &str) -> bool {
    crate::ctl::vault_status(&ctx.rt)
        .is_ok_and(|s| s.locked || s.envs.iter().any(|e| e.env == env && !e.missing.is_empty()))
}

/// The top-level names of the env's own workspace, lowercased: its host folder's entries, or
/// what its clone tracks (`git ls-tree` in the env; the host has no copy).
fn own_entries(ctx: &Ctx, env: &str, ws: &Workspace) -> BTreeSet<String> {
    if let Some(d) = &ws.dir {
        return std::fs::read_dir(d)
            .into_iter()
            .flatten()
            .filter_map(|e| Some(e.ok()?.file_name().to_str()?.to_lowercase()))
            .collect();
    }
    if ws.url.is_none() {
        return BTreeSet::new();
    }
    let dev = names::dev(env);
    ctx.rt
        .run(exec(&dev).user(UID).argv([
            "git",
            "-c",
            "core.fsmonitor=false",
            "-C",
            "/workspace",
            "ls-tree",
            "-z",
            "--name-only",
            "HEAD",
        ]))
        .unwrap_or_default()
        .split('\0')
        .filter(|n| !n.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The start of the folder the env's own remote is cloned into before its entries move into
/// `/workspace`; a random suffix ends it, so no entry of the repository has its name.
const WORKSPACE_CLONE: &str = ".luoto-clone-";

/// What [`clone_workspace`] runs as the dev user: the env's remote cloned into a hidden folder
/// of `/workspace`, its entries moved up only once the clone is whole, so a clone cut short
/// leaves nothing an `up` would take as the workspace. No prompts, no submodules, and LFS
/// files stay pointers (no filter runs). Exits 3, touching nothing, when `/workspace` holds
/// anything but such folders.
pub fn workspace_clone_script(url: &str, branch: Option<&str>, progress: bool) -> String {
    format!(
        r#"export GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND='ssh -o BatchMode=yes' GIT_LFS_SKIP_SMUDGE=1
cd /workspace || exit 1
for f in * .[!.]* ..?*; do
  {{ [ -e "$f" ] || [ -L "$f" ]; }} || continue
  case "$f" in {tmp}*) ;; *) exit 3 ;; esac
done
rm -rf -- {tmp}*
t=/workspace/{tmp}{suffix}
mkdir -- "$t" && git clone --no-recurse-submodules{progress}{branch} -- {url} "$t" || {{ rm -rf -- "$t"; exit 1; }}
for f in "$t"/* "$t"/.[!.]* "$t"/..?*; do
  {{ [ -e "$f" ] || [ -L "$f" ]; }} || continue
  mv -- "$f" /workspace/ || exit 1
done
rmdir -- "$t""#,
        tmp = WORKSPACE_CLONE,
        suffix = hex::encode(rand::random::<[u8; 8]>()),
        progress = if progress { " --progress" } else { "" },
        branch = branch
            .map(|b| format!(" --branch {}", sh_quote(b)))
            .unwrap_or_default(),
        url = sh_quote(&clone_url(url)),
    )
}

/// Clone the env's own remote (`[workspace] url`) into `/workspace`, inside the env and
/// through the gate, as the dev user. `locked`: some of the env's credentials didn't load.
pub fn clone_workspace(
    ctx: &Ctx,
    env: &str,
    url: &str,
    branch: Option<&str>,
    locked: bool,
    cfg: &EnvConfig,
) -> Result<()> {
    let what = format!(
        "cloning {}{} into the env",
        display(url),
        branch
            .map(|b| format!(" ({})", display(b)))
            .unwrap_or_default()
    );
    let script = workspace_clone_script(url, branch, git_progress());
    let dev = names::dev(env);
    let status = crate::progress::step(&what, || {
        quiet_git(
            ctx,
            &exec(&dev)
                .user(UID)
                .cwd("/")
                .argv(["sh", "-c", connect::LOGIN, &script]),
        )
    })?;
    if status.code() == Some(3) {
        bail!(
            "/workspace in the env has files, but no clone into it finished (an `up` cut short, \
             or files written in the env since): see them with `luoto shell -e {env}`; to clone \
             it again, empty /workspace there (`find /workspace -mindepth 1 -delete`) and \
             `luoto up -e {env}`"
        );
    }
    clone_failed(env, url, status.success(), locked, cfg)
}

/// Why a clone of `url` failed, and what to run next: unlock the env's credentials, or give
/// the repo access, then `up` again. With a credential for the repo, the remote refused it:
/// a token for another forge or account, or one that expired.
fn clone_failed(env: &str, url: &str, ok: bool, locked: bool, cfg: &EnvConfig) -> Result<()> {
    if ok {
        return Ok(());
    }
    if locked {
        bail!(
            "git clone failed: some of the env's credentials are locked (see the warning about \
             secrets above); once `luoto vault unlock` loads them, `luoto up -e {env}` clones it"
        );
    }
    let repo = forge_repo(url).map_or_else(|| display(url), |(_, r)| display(&r));
    if uncovered(&[url.to_string()], &cfg.credentials).is_empty() && !is_ssh(url) {
        bail!(
            "the remote refused the env's credential for {repo}: a token for another forge or \
             account, or one that expired\n`luoto repo auth -e {env} {repo}` gives it another, \
             then `luoto up -e {env}`"
        );
    }
    bail!(
        "git clone failed\n  if private, a token: `luoto repo auth -e {env} {repo}`\n  what the \
         gate blocked: `luoto egress -e {env} --denied --since 10m`\n  `luoto up -e {env}` tries \
         again"
    )
}

/// Run git `args` in the env ([`crate::progress::git`]): its output carries the remote's
/// messages and the sandbox's own text, so it reaches the terminal escaped, and only with
/// `--verbose` or, its errors, when the clone fails.
fn quiet_git(ctx: &Ctx, args: &[String]) -> Result<std::process::ExitStatus> {
    crate::progress::git(&ctx.rt, args)
}

/// git's progress lines, only where they are shown as they come.
fn git_progress() -> bool {
    crate::progress::verbose() && std::io::stderr().is_terminal()
}

/// What a repo in the env holds that no remote has.
#[derive(Debug, PartialEq)]
pub struct Unpushed {
    /// `/workspace` or `/workspace/<name>`.
    pub path: String,
    /// Files changed and not committed.
    pub changed: usize,
    /// Commits on a local branch or HEAD and on no remote-tracking one.
    pub commits: usize,
    pub stashes: usize,
    /// A repo git couldn't read: what it holds is unknown.
    pub unread: bool,
}

impl fmt::Display for Unpushed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.unread {
            return write!(
                f,
                "{}: git couldn't read it; look before removing",
                self.path
            );
        }
        let n = |k: usize, one: &str, many: &str| match k {
            0 => None,
            1 => Some(format!("1 {one}")),
            k => Some(format!("{k} {many}")),
        };
        let parts: Vec<String> = [
            n(self.changed, "file changed", "files changed"),
            n(self.commits, "commit not pushed", "commits not pushed"),
            n(self.stashes, "stash", "stashes"),
        ]
        .into_iter()
        .flatten()
        .collect();
        write!(f, "{}: {}", self.path, parts.join(", "))
    }
}

/// Counts per repo, one line each: a git work tree whose top is the folder given. Commits count
/// from HEAD too (a detached one, after checking out a tag); a folder with a `.git` that git
/// can't read is a line of `?`.
const UNPUSHED_SCRIPT: &str = r#"for d; do
  if [ "$(git -C "$d" rev-parse --show-toplevel 2>/dev/null)" != "$d" ]; then
    { [ -e "$d/.git" ] || [ -L "$d/.git" ]; } && printf '%s\t?\n' "$d"
    continue
  fi
  h=; git -C "$d" rev-parse -q --verify HEAD >/dev/null 2>&1 && h=HEAD
  c=$(git -c core.fsmonitor=false -C "$d" status --porcelain 2>/dev/null | wc -l)
  u=$(git -C "$d" rev-list --count $h --branches --not --remotes 2>/dev/null) || u='?'
  s=$(git -C "$d" stash list 2>/dev/null | wc -l)
  printf '%s\t%s\t%s\t%s\n' "$d" "$c" "$u" "$s"
done; true"#;

/// The repos in the env (`/workspace` and its seeded `repos`) holding work no remote has, run
/// as the dev user in one call. The sandbox decides how long git takes (a clean filter it
/// configured runs) and what the script prints, so both are bounded and only lines naming a
/// folder asked about are read.
pub fn unpushed(ctx: &Ctx, env: &str, repos: &BTreeSet<String>) -> Result<Vec<Unpushed>> {
    let _waiting = crate::progress::waiting("checking the env's repos for work not pushed");
    let dev = names::dev(env);
    let dirs: Vec<String> = std::iter::once("/workspace".to_string())
        .chain(repos.iter().map(|r| format!("/workspace/{r}")))
        .collect();
    let args = exec(&dev).user(UID).sh_with(UNPUSHED_SCRIPT, &dirs);
    let out = ctx.rt.run_limited(&args, STATUS_LIMIT, STATUS_CAP)?;
    Ok(parse_unpushed(&out, &dirs))
}

/// How long the repos' `git status` in the env may take before `rm` goes on without it.
const STATUS_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);
/// A line per repo.
const STATUS_CAP: usize = 64 << 10;

/// The script's lines for `dirs`, the first for each; one whose counts aren't all numbers is a
/// repo git couldn't read.
fn parse_unpushed(out: &str, dirs: &[String]) -> Vec<Unpushed> {
    let mut found: Vec<Unpushed> = Vec::new();
    for l in out.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        let Some(path) = dirs.iter().find(|d| **d == f[0]) else {
            continue;
        };
        if found.iter().any(|w| w.path == *path) {
            continue;
        }
        let n = |i: usize| f.get(i).and_then(|x| x.trim().parse::<usize>().ok());
        let counts = match (f.len(), n(1), n(2), n(3)) {
            (4, Some(c), Some(u), Some(s)) => Some((c, u, s)),
            _ => None,
        };
        let (changed, commits, stashes) = counts.unwrap_or_default();
        found.push(Unpushed {
            path: path.clone(),
            changed,
            commits,
            stashes,
            unread: counts.is_none(),
        });
    }
    found.retain(|w| w.unread || w.changed + w.commits + w.stashes > 0);
    found
}

/// Forget that `url` was answered as public, so the next `up` asks for its access again:
/// for a remote that failed to clone. Whether it had been.
pub fn undecline(ctx: &Ctx, env: &str, url: &str) -> Result<bool> {
    let keys: BTreeSet<String> = uncovered(&[clone_url(url)], &Credentials::default())
        .iter()
        .flat_map(|(f, repos)| repos.iter().map(|r| f.key(r)))
        .collect();
    let mut skip = declined(ctx, env);
    let before = skip.len();
    skip.retain(|k| !keys.contains(k));
    if skip.len() == before {
        return Ok(false);
    }
    let text: String = skip.iter().map(|k| format!("{k}\n")).collect();
    crate::paths::write_private(&declined_path(ctx, env), text.as_bytes())?;
    Ok(true)
}

fn copy_in(ctx: &Ctx, env: &str, ws: &Workspace, name: &str, dir: &str) -> Result<()> {
    let dir = workspace::canonical(dir)?;
    check_folder(ws.dir.as_deref(), &dir)?;
    let n = crate::progress::step(
        &format!("copying {} into /workspace/{name}", dir.display()),
        || workspace::push(ctx, env, &dir, Some(name)),
    )?;
    println!("copied {n} file(s)");
    Ok(())
}

fn clone(
    ctx: &Ctx,
    env: &str,
    name: &str,
    url: &str,
    branch: Option<&str>,
    locked: bool,
    cfg: &EnvConfig,
) -> Result<()> {
    let what = format!("cloning {} into /workspace/{name}", display(url));
    // No prompts: a remote that wants a password or an unknown host key fails instead.
    // Into a hidden folder first, moved into place only when the clone is whole: one cut
    // short leaves nothing the next `up` would take as done.
    let tmp = sh_quote(&format!("/workspace/.{name}.luoto-clone"));
    let script = format!(
        "export GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND='ssh -o BatchMode=yes'\n\
         rm -rf {tmp} && git clone{}{} -- {} {tmp} && mv {tmp} {} || {{ rm -rf {tmp}; exit 1; }}",
        if git_progress() { " --progress" } else { "" },
        branch
            .map(|b| format!(" --branch {}", sh_quote(b)))
            .unwrap_or_default(),
        sh_quote(&clone_url(url)),
        sh_quote(&format!("/workspace/{name}")),
    );
    let dev = names::dev(env);
    let status = crate::progress::step(&what, || {
        quiet_git(
            ctx,
            &exec(&dev)
                .user(UID)
                .cwd("/workspace")
                .argv(["sh", "-c", connect::LOGIN, &script]),
        )
    })?;
    clone_failed(env, url, status.success(), locked, cfg)
}

/// Keep the repos out of `git status` in the env's folder when it is a repository itself (a
/// launchpad that lists them), in its `.git/info/exclude`, which is never committed.
fn exclude_from_folder(ctx: &Ctx, env: &str, added: &[&str]) -> Result<()> {
    if added.is_empty() {
        return Ok(());
    }
    const SCRIPT: &str = r#"cd /workspace || exit 0
[ "$(git rev-parse --show-toplevel 2>/dev/null)" = /workspace ] || exit 0
x=$(git rev-parse --git-path info/exclude) || exit 0
mkdir -p "$(dirname "$x")"
for d; do grep -qxF "/$d/" "$x" 2>/dev/null || printf '/%s/\n' "$d" >> "$x"; done"#;
    let dev = names::dev(env);
    ctx.rt.run(exec(&dev).user(UID).sh_with(SCRIPT, added))?;
    Ok(())
}

/// Whether a remote goes over SSH (`ssh://…` or `user@host:path`).
fn is_ssh(url: &str) -> bool {
    url.starts_with("ssh://") || (!url.contains("://") && url.contains(':'))
}

/// A forge account a credential reaches: a GitHub owner (a token or App installation reaches
/// one owner's repos), or an Azure DevOps organization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Forge {
    Github(String),
    Azure(String),
    /// Any other git host (`host` or `host:port`), with `[[credentials.git]]`.
    Git(String),
}

impl Forge {
    /// How a repo of it is remembered as needing no credential.
    pub(crate) fn key(&self, repo: &str) -> String {
        match self {
            Forge::Github(_) => format!("github:{}", repo.to_lowercase()),
            Forge::Azure(_) => format!("azure_devops:{}", repo.to_lowercase()),
            Forge::Git(h) => format!("git:{}/{}", h.to_lowercase(), repo.to_lowercase()),
        }
    }
}

/// Every remote the env works with: its folder's origin or the remote its workspace is cloned
/// from, and its repos' (a folder's origin, or the remote it clones).
pub fn remotes(ws: &Workspace) -> Vec<String> {
    ws.dir
        .iter()
        .chain(ws.repos.values().filter_map(|r| r.dir.as_ref()))
        .filter_map(|d| crate::init::origin_url(Path::new(d)))
        .chain(
            ws.url
                .iter()
                .chain(ws.repos.values().filter_map(|r| r.url.as_ref()))
                .map(|u| clone_url(u)),
        )
        .collect()
}

/// A remote on any other git host: the host as a credential names it (`host`, or `host:port`
/// for HTTPS on another port), the host its SSH would log in to, and the repository path
/// (`group/sub/repo`, no `.git`).
fn other_remote(url: &str) -> Option<(String, String, String)> {
    if forge_host(remote_host(url)?).is_some() {
        return None;
    }
    let (host, path) = if let Some(rest) = url.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/')?;
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        (hostport.to_string(), path)
    } else if let Some(rest) = url.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/')?;
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        (hostport.split(':').next()?.to_string(), path)
    } else {
        let (user_host, path) = url.split_once(':')?;
        (user_host.split_once('@')?.1.to_string(), path)
    };
    let name = host.split(':').next()?.to_string();
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    (!path.is_empty() && path.contains('/'))
        .then(|| (host.to_lowercase(), name.to_lowercase(), path.to_string()))
}

/// The repos among `remotes` that no credential of `creds` covers, by forge account, as
/// credentials list them (`owner/repo`, `org/project/repo`). An SSH remote whose host the
/// env's SSH key logs in to is covered.
pub fn uncovered(remotes: &[String], creds: &Credentials) -> BTreeMap<Forge, Vec<String>> {
    let ssh_hosts: Vec<&str> = creds
        .ssh
        .iter()
        .flat_map(|s| s.hosts.iter().map(String::as_str))
        .collect();
    let by_ssh = |url: &str, host: &str| is_ssh(url) && ssh_hosts.contains(&host);
    let azure_covered: Vec<String> = creds
        .azure_devops
        .iter()
        .flat_map(|c| c.repos.iter().chain(&c.read_repos))
        .filter_map(|r| crate::azure::parse_repo(r).ok())
        .map(|r| r.key())
        .collect();
    let mut out: BTreeMap<Forge, Vec<String>> = BTreeMap::new();
    for url in remotes {
        if let Some(repo) = github_repo(url) {
            if !creds.github.covers(&repo, false) && !by_ssh(url, "github.com") {
                let owner = repo.split('/').next().unwrap_or_default().to_string();
                extend_unique(out.entry(Forge::Github(owner)).or_default(), [repo]);
            }
        } else if let Some((r, _)) = crate::azure::parse_url(url) {
            if !azure_covered.contains(&r.key()) && !by_ssh(url, crate::azure::SSH_HOST) {
                let shown = format!(
                    "{}/{}/{}",
                    r.org,
                    crate::azure::decode(&r.project),
                    crate::azure::decode(&r.name)
                );
                extend_unique(out.entry(Forge::Azure(r.org.clone())).or_default(), [shown]);
            }
        } else if let Some((host, name, path)) = other_remote(url) {
            let cred = creds.git.iter().find(|c| {
                let h = c.host.to_lowercase();
                h == host || (is_ssh(url) && h.split(':').next() == Some(name.as_str()))
            });
            let covered = cred.is_some_and(|c| {
                c.repos.iter().chain(&c.read_repos).any(|r| {
                    r.trim_matches('/')
                        .trim_end_matches(".git")
                        .eq_ignore_ascii_case(&path)
                })
            });
            if !covered && !by_ssh(url, &name) {
                let host = cred.map_or(host, |c| c.host.to_lowercase());
                extend_unique(out.entry(Forge::Git(host)).or_default(), [path]);
            }
        }
    }
    out
}

/// What the env needs to fetch and push `remotes` and no credential of `creds` covers, as
/// config text with the advice around it.
pub fn credential_hint(env: &str, remotes: &[String], creds: &Credentials) -> Option<String> {
    hint(
        env,
        &uncovered(remotes, creds),
        creds,
        remotes.iter().any(|u| is_ssh(u)),
    )
}

fn hint(
    env: &str,
    needs: &BTreeMap<Forge, Vec<String>>,
    creds: &Credentials,
    ssh: bool,
) -> Option<String> {
    if needs.is_empty() {
        return None;
    }
    let list = |repos: &[String]| {
        repos
            .iter()
            .map(|r| format!("\"{}\"", display(r)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let github: Vec<(&String, &Vec<String>)> = needs
        .iter()
        .filter_map(|(f, r)| match f {
            Forge::Github(o) => Some((o, r)),
            _ => None,
        })
        .collect();
    let azure: Vec<String> = needs
        .iter()
        .filter(|(f, _)| matches!(f, Forge::Azure(_)))
        .flat_map(|(_, r)| r.clone())
        .collect();
    let mut blocks = Vec::new();
    if creds.github.is_empty() {
        let header = if github.len() > 1 {
            "[[credentials.github]]"
        } else {
            "[credentials.github]"
        };
        for (owner, repos) in &github {
            blocks.push(format!(
                "{header}\ntoken = \"op://<vault>/<item>/<field>\"   # fine-grained token for {}, or an App\nrepos = [{}]   # read and write: push, pull requests\n# read_repos = []   # private repos it only reads",
                display(owner),
                list(repos)
            ));
        }
    } else if !github.is_empty() {
        let all: Vec<String> = github.iter().flat_map(|(_, r)| r.iter().cloned()).collect();
        blocks.push(format!(
            "# [credentials.github] doesn't list {}: add each to `repos` (read and write) or\n\
             # `read_repos`; another owner's need a credential of their own, one\n\
             # [[credentials.github]] each (the existing table becomes one too)",
            list(&all)
        ));
    }
    if !azure.is_empty() {
        blocks.push(match &creds.azure_devops {
            None => format!(
                "[credentials.azure_devops]\ntoken = \"op://<vault>/<item>/<field>\"   # PAT with Code (Read & write)\nrepos = [{}]\n# read_repos = []",
                list(&azure)
            ),
            Some(_) => format!(
                "# [credentials.azure_devops] doesn't list {}: add each to `repos` or `read_repos`",
                list(&azure)
            ),
        });
    }
    for (forge, repos) in needs {
        let Forge::Git(host) = forge else { continue };
        let existing = creds.git.iter().any(|c| c.host.eq_ignore_ascii_case(host));
        blocks.push(if existing {
            format!(
                "# [[credentials.git]] for {} doesn't list {}: add each to `repos` or `read_repos`",
                display(host),
                list(repos)
            )
        } else {
            format!(
                "[[credentials.git]]\nhost = \"{}\"\ntoken = \"op://<vault>/<item>/<field>\"   # read and write access to the repos\nusername = \"oauth2\"   # GitLab; Forgejo and Gitea: the token's owner\nrepos = [{}]\n# read_repos = []   # fetch only; without a token, public ones\n# private = true   # a host on a private network\n# ca = \"~/certs/ca.pem\"   # its internal CA",
                display(host),
                list(repos)
            )
        });
    }
    let ssh_note = if ssh {
        "\n\nSSH remotes work with these as they are: the env sends them over HTTPS. \
         [credentials.ssh] keeps them on SSH, with a key that reaches every repo it can and \
         that luoto can't limit."
    } else {
        ""
    };
    Some(format!(
        "Public repos need none of these. For a private one, or to push from the env, give it \
         HTTPS credentials (`luoto repo auth -e {env} <repo>` on a terminal, or `luoto edit -e \
         {env}`); each reaches only the repos it lists:\n\n{}{ssh_note}",
        blocks
            .iter()
            .map(|b| format!("  {}", b.replace('\n', "\n  ")))
            .collect::<Vec<_>>()
            .join("\n\n")
    ))
}

/// Repos answered as public, needing no credential, as [`Forge::key`] writes them.
pub fn declined_path(ctx: &Ctx, env: &str) -> PathBuf {
    ctx.paths.env_state(env).join("credentials.declined")
}

pub fn declined(ctx: &Ctx, env: &str) -> BTreeSet<String> {
    std::fs::read_to_string(declined_path(ctx, env))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// Whether `host` (or `host:port`) resolves only to private addresses here: a self-hosted
/// forge on a private network, which the gate reaches only when its credential says so.
fn private_host(host: &str) -> bool {
    use std::net::ToSocketAddrs;
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => (n, p.parse().unwrap_or(443)),
        None => (host, 443),
    };
    let addrs: Vec<std::net::IpAddr> = (name, port)
        .to_socket_addrs()
        .map(|a| a.map(|s| s.ip()).collect())
        .unwrap_or_default();
    !addrs.is_empty() && addrs.iter().all(|ip| luoto_shared::host::is_private(*ip))
}

/// The user name a new git host credential sends with its token, and, for a host on a private
/// network, the CA its certificate may be signed by.
/// Whether the env may reach `host` on a private network: asked when it resolves only to
/// private addresses here. The host comes from a remote, maybe one a team's luoto.toml named,
/// so the address alone never decides it.
fn ask_private(host: &str) -> bool {
    private_host(host)
        && crate::prompt::confirm(&format!(
            "  {} resolves to private addresses here. Let the env reach it there \
             (`private = true`)?",
            display(host)
        ))
}

fn git_details(host: &str, private: bool, ca: &mut Option<String>) -> Result<String> {
    if private {
        let question = format!(
            "The CA certificate (a PEM file) of {}, if an internal CA signs it:",
            display(host)
        );
        let path = inquire::Text::new(&question)
            .with_help_message("empty when its certificate is public")
            .ask()?
            .unwrap_or_default();
        let path = path.trim();
        if !path.is_empty() {
            *ca = Some(path.to_string());
        }
    }
    Ok(inquire::Text::new("User name sent with the token:")
        .with_default("oauth2")
        .with_help_message("GitLab takes oauth2; Forgejo and Gitea, the token's owner")
        .ask()?
        .unwrap_or_else(|| "oauth2".into()))
}

/// Repos whose access was left for later in this command, as [`Forge::key`] writes them: not
/// asked again, and not cloned, which would only fail.
static LATER: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

pub(crate) fn left_for_later(key: &str) -> bool {
    LATER.lock().is_ok_and(|s| s.contains(key))
}

/// A remote's forge account and its repo as credentials list it (`owner/repo`,
/// `org/project/repo`, `group/sub/repo`).
fn forge_repo(url: &str) -> Option<(Forge, String)> {
    uncovered(&[clone_url(url)], &Credentials::default())
        .into_iter()
        .find_map(|(f, r)| Some((f, r.into_iter().next()?)))
}

/// Whether `url`'s access was left for later in this command; if so, says that it isn't
/// cloned.
pub fn waits(env: &str, url: &str) -> bool {
    let Some((forge, repo)) = forge_repo(url) else {
        return false;
    };
    if !left_for_later(&forge.key(&repo)) {
        return false;
    }
    let repo = display(&repo);
    let line = crate::prompt::with_command(
        &format!("not cloned yet: {repo} needs a token or to be public"),
        &format!("luoto repo auth -e {env} {repo}"),
        text::columns(),
    );
    println!("{line}");
    true
}

/// What the env may do with a repo of a forge.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Access {
    /// Fetch it without a token.
    Public,
    /// Fetch it with a token.
    Read,
    /// Fetch and push with a token, and on GitHub open pull requests.
    Push,
}

impl Forge {
    fn name(&self) -> String {
        match self {
            Forge::Github(_) => "GitHub".into(),
            Forge::Azure(_) => "Azure DevOps".into(),
            Forge::Git(h) => display(h),
        }
    }

    /// The forge account, as people name it: "GitHub acme", "Azure DevOps org", a host.
    fn account(&self) -> String {
        match self {
            Forge::Github(o) | Forge::Azure(o) => format!("{} {}", self.name(), display(o)),
            Forge::Git(h) => display(h),
        }
    }

    /// Where its credentials are, as `relist_repo` takes them.
    fn table(&self) -> (&'static str, Option<&str>) {
        match self {
            Forge::Github(_) => ("github", None),
            Forge::Azure(_) => ("azure_devops", None),
            Forge::Git(h) => ("git", Some(h)),
        }
    }

    /// Whether `entry`, as a credential of it lists repos, is `repo`.
    fn same(&self, entry: &str, repo: &str) -> bool {
        match self {
            Forge::Github(_) => entry.eq_ignore_ascii_case(repo),
            Forge::Azure(_) => {
                let key = |r: &str| crate::azure::parse_repo(r).ok().map(|r| r.key());
                key(entry).is_some() && key(entry) == key(repo)
            }
            Forge::Git(_) => entry
                .trim_matches('/')
                .trim_end_matches(".git")
                .eq_ignore_ascii_case(repo),
        }
    }
}

/// The access menu's entries for a repo of `forge`, least privilege first, each with what it
/// needs of a token in the forge's terms.
fn access_rows(forge: &Forge) -> Vec<(Access, String, String)> {
    let (push, read, write) = match forge {
        Forge::Github(_) => (
            "Read and push, open pull requests",
            "token with Contents: read",
            "token with Contents + Pull requests: write",
        ),
        Forge::Azure(_) => (
            "Read and push",
            "PAT with Code: read",
            "PAT with Code: read & write",
        ),
        Forge::Git(h) if h.contains("gitlab") => (
            "Read and push",
            "token with read_repository",
            "token with write_repository",
        ),
        Forge::Git(_) => (
            "Read and push",
            "token that reads it",
            "token that reads and writes it",
        ),
    };
    vec![
        (
            Access::Public,
            "Fetch only, it's public".into(),
            "no token".into(),
        ),
        (Access::Read, "Read it, it's private".into(), read.into()),
        (Access::Push, push.into(), write.into()),
    ]
}

/// The access question for `repo`: what the env has marked `(current)` and opened on, else
/// the least privilege; "Later" (`None`) when it may wait.
fn access_question(
    forge: &Forge,
    repo: &str,
    current: Option<Access>,
    mode: Mode,
) -> Question<Option<Access>> {
    let mut rows: Vec<(Option<Access>, String, String)> = access_rows(forge)
        .into_iter()
        .map(|(a, label, desc)| {
            let label = if Some(a) == current {
                format!("{label} (current)")
            } else {
                label
            };
            (Some(a), label, desc)
        })
        .collect();
    if mode == Mode::Missing {
        rows.push((None, "Later".into(), String::new()));
    }
    let at = rows
        .iter()
        .position(|(a, _, _)| a.is_some() && *a == current)
        .unwrap_or(0);
    Question {
        text: format!("What can the env do with {}?", display(repo)),
        rows,
        at,
        help: menu_help(mode.esc()),
    }
}

/// What `creds`, and the repos answered as public (`declined`), let the env do with `repo` of
/// `forge`, and the token that does it.
fn access_of(
    creds: &Credentials,
    declined: &BTreeSet<String>,
    forge: &Forge,
    repo: &str,
) -> Option<(Access, Option<String>)> {
    let has = |list: &[String]| list.iter().any(|r| forge.same(r, repo));
    let lists: Vec<(&[String], &[String], Option<&String>)> = match forge {
        Forge::Github(_) => creds
            .github
            .0
            .iter()
            .map(|c| (&c.repos[..], &c.read_repos[..], c.token.as_ref()))
            .collect(),
        Forge::Azure(_) => creds
            .azure_devops
            .iter()
            .map(|c| (&c.repos[..], &c.read_repos[..], Some(&c.token)))
            .collect(),
        Forge::Git(h) => creds
            .git
            .iter()
            .filter(|c| c.host.eq_ignore_ascii_case(h))
            .map(|c| (&c.repos[..], &c.read_repos[..], c.token.as_ref()))
            .collect(),
    };
    for (repos, read, token) in lists {
        if has(repos) {
            return Some((Access::Push, token.cloned()));
        }
        if has(read) {
            let access = if token.is_some() || !matches!(forge, Forge::Git(_)) {
                Access::Read
            } else {
                Access::Public
            };
            return Some((access, token.cloned()));
        }
    }
    declined
        .contains(&forge.key(repo))
        .then_some((Access::Public, None))
}

/// The closing summary of a repo's access step; `replaced`, the token it had before.
fn access_summary(
    env: &str,
    forge: &Forge,
    repo: &str,
    now: Option<&(Access, Option<String>)>,
    replaced: Option<&str>,
) -> String {
    let token = |t: &Option<String>| match (t, forge) {
        (Some(t), _) => format!("token {}", crate::wizard::shown_ref(t)),
        (None, Forge::Github(_)) => "with the GitHub App".into(),
        (None, _) => "no token".into(),
    };
    let access = match now {
        None => "none yet".to_string(),
        Some((Access::Public, _)) => "fetch only (public)".into(),
        Some((Access::Read, t)) => format!("read, {}", token(t)),
        Some((Access::Push, t)) => format!("read and push, {}", token(t)),
    };
    let repo = display(repo);
    let mut rows = vec![("access", access)];
    if let Some(r) = replaced {
        rows.push(("replaces", format!("token {}", crate::wizard::shown_ref(r))));
    }
    rows.push(("change it", format!("luoto repo auth -e {env} {repo}")));
    crate::prompt::summary(&repo, &rows)
}

/// The token `before` had that `after` replaced: a token gone for another, not one added or
/// dropped.
fn replaced<'a>(
    before: Option<&'a (Access, Option<String>)>,
    after: Option<&(Access, Option<String>)>,
) -> Option<&'a str> {
    let old = before?.1.as_deref()?;
    let new = after?.1.as_deref()?;
    (old != new).then_some(old)
}

/// A GitHub token's documented prefixes (fine-grained, classic, OAuth, user-to-server,
/// server-to-server, refresh).
const GITHUB_TOKEN: crate::wizard::Shape<'static> = crate::wizard::Shape {
    what: "a GitHub token",
    prefixes: &["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
    hint: "github_pat_ or ghp_",
};

/// The line before the first repo's question when there are several: how many, by account.
fn overview(needs: &BTreeMap<Forge, Vec<String>>) -> Option<String> {
    let total: usize = needs.values().map(Vec::len).sum();
    if total < 2 {
        return None;
    }
    let accounts: Vec<String> = needs
        .iter()
        .map(|(f, r)| format!("{} ({})", f.account(), r.len()))
        .collect();
    Some(format!(
        "{total} repos need access: {}",
        accounts.join(", ")
    ))
}

/// The line before a repo's question in [`ask_missing`]: `n` of `total`, when there are several.
fn missing_line(n: usize, total: usize, repo: &str, forge: &Forge, note: &str) -> String {
    let count = if total > 1 {
        format!("({n}/{total}) ")
    } else {
        String::new()
    };
    format!(
        "{count}{} ({}{note}) has no credential, so the env can only fetch it if it is public.",
        display(repo),
        forge.name()
    )
}

/// Note `key` as answered public, or not.
fn set_declined(ctx: &Ctx, env: &str, key: &str, public: bool) -> Result<()> {
    let mut keys = declined(ctx, env);
    let changed = if public {
        keys.insert(key.to_string())
    } else {
        keys.remove(key)
    };
    if changed {
        let text: String = keys.iter().map(|k| format!("{k}\n")).collect();
        crate::paths::write_private(&declined_path(ctx, env), text.as_bytes())?;
    }
    Ok(())
}

/// Write `access` for `repo` of `forge` into the env's config: it moves within the credential
/// that lists it, or joins the forge account's (a new one with `token`, for a repo it can't
/// reach yet). `token` replaces the credential's own; `git` holds what a new
/// `[[credentials.git]]` takes. A public repo on GitHub or Azure DevOps is noted by the
/// caller ([`set_declined`]).
fn write_access(
    f: &mut EnvFile,
    forge: &Forge,
    repo: &str,
    access: Access,
    token: Option<&str>,
    git: &GitCred,
) -> Result<()> {
    let (table, host) = forge.table();
    let same = |e: &str| forge.same(e, repo);
    let repos = [repo.to_string()];
    let to = match access {
        Access::Public => ListAs::Nowhere,
        Access::Read => ListAs::Read,
        Access::Push => ListAs::Write,
    };
    let read = access != Access::Push;
    if let Forge::Git(_) = forge {
        // Another host's public repos still need a rule to be fetched: they stay in its
        // credential's `read_repos`, without a token when it has none. Its own settings
        // (`username`, `private`, `ca`) stay as they are.
        let new = GitCred {
            token: token.map(str::to_string),
            ..git.clone()
        };
        f.add_git_repos(&new, &repos, read)?;
        let to = if read { ListAs::Read } else { ListAs::Write };
        f.relist_repo(table, host, &same, to, token)?;
        return Ok(());
    }
    match f.relist_repo(table, host, &same, to, token)? {
        Relisted::Emptied => println!(
            "  the {} credential had no other repo, so it is removed (not its token)",
            forge.name()
        ),
        Relisted::Moved => {}
        Relisted::No if access == Access::Public => {}
        Relisted::No => {
            match forge {
                Forge::Github(o) => f.add_github_repos(o, token, &repos, read)?,
                Forge::Azure(_) => f.add_azure_repos(token, &repos, read)?,
                Forge::Git(_) => {}
            }
            // The account's credential, found by its other repos, takes the token given.
            if token.is_some() {
                f.relist_repo(table, host, &same, to, token)?;
            }
        }
    }
    Ok(())
}

/// The token the credential of `repo`'s forge account has (the owner's on GitHub, the
/// organization's on Azure DevOps, the host's), and whether it is a GitHub App instead.
fn account_token(creds: &Credentials, forge: &Forge) -> (Option<String>, bool) {
    match forge {
        Forge::Github(o) => {
            let owns = |c: &&crate::config::GithubCred| {
                c.repos.iter().chain(&c.read_repos).any(|r| {
                    r.split('/')
                        .next()
                        .is_some_and(|x| x.eq_ignore_ascii_case(o))
                })
            };
            match creds.github.0.iter().find(owns) {
                Some(c) => (c.token.clone(), c.token.is_none()),
                None => (None, false),
            }
        }
        Forge::Azure(_) => (creds.azure_devops.as_ref().map(|c| c.token.clone()), false),
        Forge::Git(h) => (
            creds
                .git
                .iter()
                .find(|c| c.host.eq_ignore_ascii_case(h))
                .and_then(|c| c.token.clone()),
            false,
        ),
    }
}

/// The other repos the token of `repo`'s forge account reaches: a new token for `repo` is
/// theirs too.
fn token_shared_with(creds: &Credentials, forge: &Forge, repo: &str) -> Vec<String> {
    let lists: Vec<&Vec<String>> = match forge {
        Forge::Github(o) => creds
            .github
            .0
            .iter()
            .filter(|c| c.token.is_some())
            .find(|c| {
                c.repos.iter().chain(&c.read_repos).any(|r| {
                    r.split('/')
                        .next()
                        .is_some_and(|x| x.eq_ignore_ascii_case(o))
                })
            })
            .map(|c| vec![&c.repos, &c.read_repos])
            .unwrap_or_default(),
        Forge::Azure(_) => creds
            .azure_devops
            .as_ref()
            .map(|c| vec![&c.repos, &c.read_repos])
            .unwrap_or_default(),
        Forge::Git(h) => creds
            .git
            .iter()
            .filter(|c| c.token.is_some())
            .find(|c| c.host.eq_ignore_ascii_case(h))
            .map(|c| vec![&c.repos, &c.read_repos])
            .unwrap_or_default(),
    };
    lists
        .into_iter()
        .flatten()
        .filter(|r| !forge.same(r, repo))
        .map(|r| display(r))
        .collect()
}

/// Where a token for `forge` is kept and fetched, and what it must allow, for `repo`.
fn token_ask(forge: &Forge, repo: &str, read: bool) -> (String, String, String) {
    let shown = display(repo);
    match forge {
        Forge::Github(o) => (
            format!("GitHub token for {o}"),
            format!("github.{o}"),
            format!(
                "A fine-grained token (github.com/settings/personal-access-tokens), resource \
                 owner {o}, for {shown}: Contents{}.",
                if read {
                    " read-only"
                } else {
                    " and Pull requests, read and write"
                }
            ),
        ),
        Forge::Azure(o) => (
            format!("Azure DevOps PAT for {o}"),
            format!("azure_devops.{o}"),
            format!(
                "A PAT (dev.azure.com/{o}/_usersSettings/tokens) with Code ({}).",
                if read { "Read" } else { "Read & write" }
            ),
        ),
        Forge::Git(h) => (
            format!("token for {h}"),
            format!("git.{h}"),
            format!(
                "An access token for {h} that {} the repo (GitLab: read_repository{}; Forgejo \
                 and Gitea: repository {}).",
                if read { "reads" } else { "reads and writes" },
                if read { "" } else { " and write_repository" },
                if read { "read" } else { "read and write" }
            ),
        ),
    }
}

/// References the config has for `forge`'s other accounts: one token often serves several (a
/// classic GitHub token, a GitLab group's).
fn known_tokens(creds: &Credentials, forge: &Forge) -> Vec<(String, String)> {
    let mut known: Vec<(String, String)> = Vec::new();
    let mut offer = |what: String, r: &Option<String>| {
        if let Some(r) = r
            && !known.iter().any(|(_, k)| k == r)
        {
            known.push((what, r.clone()));
        }
    };
    match forge {
        Forge::Github(_) => {
            for c in &creds.github.0 {
                let owners: BTreeSet<&str> = c
                    .repos
                    .iter()
                    .chain(&c.read_repos)
                    .filter_map(|r| r.split('/').next())
                    .collect();
                offer(
                    owners.into_iter().collect::<Vec<_>>().join(" and "),
                    &c.token,
                );
            }
        }
        // Another host's token would go to this host's server.
        Forge::Git(h) => {
            let name = |x: &str| x.split(':').next().unwrap_or(x).to_ascii_lowercase();
            for c in &creds.git {
                if name(&c.host) == name(h) {
                    offer(c.host.clone(), &c.token);
                }
            }
        }
        Forge::Azure(_) => {}
    }
    known
}

/// Ask what the env may do with `repo` (`Missing`: it has no access; `Change`: `repo auth`),
/// then, for a private one, its token, and write the answer. Ends with the repo's summary, or
/// `unchanged`. Whether the config changed.
pub(crate) fn ask_repo(
    ctx: &Ctx,
    env: &str,
    forge: &Forge,
    repo: &str,
    mode: Mode,
) -> Result<bool> {
    Ok(matches!(
        ask_repo_step(ctx, env, forge, repo, mode, false)?,
        Step::Got(true)
    ))
}

/// [`ask_repo`]; with `back`, another repo's question came before this one, so Esc at its
/// first question is `Back` instead of "later".
fn ask_repo_step(
    ctx: &Ctx,
    env: &str,
    forge: &Forge,
    repo: &str,
    mode: Mode,
    back: bool,
) -> Result<Step<bool>> {
    let f = EnvFile::load(&ctx.paths, env)?;
    let now = access_of(&f.cfg.credentials, &declined(ctx, env), forge, repo);
    let later = || -> Result<Step<bool>> {
        if let Ok(mut s) = LATER.lock() {
            s.insert(forge.key(repo));
        }
        println!("{}", access_summary(env, forge, repo, None, None));
        Ok(Step::Got(false))
    };
    // Back from where its token is kept, the menu opens on what was picked.
    let mut picked: Option<Access> = None;
    loop {
        let mut q = access_question(forge, repo, now.as_ref().map(|n| n.0), mode);
        if back {
            q.help = menu_help("back");
        }
        if let Some(i) = q
            .rows
            .iter()
            .position(|(a, _, _)| picked.is_some() && *a == picked)
        {
            q.at = i;
        }
        let access = match crate::wizard::ask_menu(q)? {
            Some(Some(a)) => {
                picked = Some(a);
                a
            }
            Some(None) => return later(),
            None if back => return Ok(Step::Back),
            None if mode == Mode::Missing => return later(),
            None => {
                println!("unchanged");
                return Ok(Step::Got(false));
            }
        };
        let mut f = EnvFile::load(&ctx.paths, env)?;
        let mut git = GitCred::default();
        if let Forge::Git(h) = forge {
            git.host = h.clone();
            git.private = ask_private(h);
        }
        let (have, app) = account_token(&f.cfg.credentials, forge);
        let token = if access == Access::Public || app {
            None
        } else if let Some(t) = have.as_deref().filter(|_| mode == Mode::Missing) {
            let line = format!(
                "the {} credential you have now reaches {} too, with its token {}",
                forge.name(),
                display(repo),
                crate::wizard::shown_ref(t)
            );
            println!("{}", text::wrap(&line, "  ", text::columns()));
            None
        } else {
            let read = access == Access::Read;
            let (label, acct, how) = token_ask(forge, repo, read);
            let mut how = text::wrap(&display(&how), "  ", text::columns());
            let shared = token_shared_with(&f.cfg.credentials, forge, repo);
            if !shared.is_empty() {
                let note = format!(
                    "The {} credential's token also reaches {}: another token replaces it for \
                     them too, so it must cover them.",
                    forge.name(),
                    shared.join(", ")
                );
                how = format!("{how}\n{}", text::wrap(&note, "  ", text::columns()));
            }
            let title = format!("luoto {label}");
            let known = known_tokens(&f.cfg.credentials, forge);
            let help = menu_help("back");
            let ask = crate::wizard::SecretAsk {
                label: &label,
                acct: &acct,
                title: &title,
                later: false,
                known: &known,
                current: have.as_deref(),
                help: &help,
                kind: None,
                how: Some(&how),
                shape: matches!(forge, Forge::Github(_)).then_some(GITHUB_TOKEN),
            };
            match crate::wizard::secret(&ask, &ctx.global)? {
                Step::Got(crate::wizard::Secret::Ref(r)) => Some(r),
                _ => continue,
            }
        };
        if token.is_some() && have.is_none() && matches!(forge, Forge::Git(_)) {
            git.username = git_details(&git.host, git.private, &mut git.ca)?;
        }
        if now
            .as_ref()
            .is_some_and(|(a, t)| *a == access && (token.is_none() || *t == token))
        {
            println!("{}", access_summary(env, forge, repo, now.as_ref(), None));
            return Ok(Step::Got(false));
        }
        let public = access == Access::Public && !matches!(forge, Forge::Git(_));
        set_declined(ctx, env, &forge.key(repo), public)?;
        write_access(&mut f, forge, repo, access, token.as_deref(), &git)?;
        // Answered now, so `up` clones it after all.
        if let Ok(mut s) = LATER.lock() {
            s.remove(&forge.key(repo));
        }
        let after = access_of(&f.cfg.credentials, &declined(ctx, env), forge, repo);
        let was = replaced(now.as_ref(), after.as_ref());
        println!("{}", access_summary(env, forge, repo, after.as_ref(), was));
        return Ok(Step::Got(true));
    }
}

/// For each repo no credential covers: on a terminal, ask what the env may do with it (and
/// for a private one, where its token is kept) and write it into the env's config, or note it
/// as public so it isn't asked again; without one, say what to add. Esc at a repo after the
/// first goes back to the one before, asked again from what it has now. Whether the config
/// changed.
pub fn ask_missing(ctx: &Ctx, env: &str, cfg: &EnvConfig) -> Result<bool> {
    let all = remotes(&cfg.workspace);
    let skip = declined(ctx, env);
    let mut needs = uncovered(&all, &cfg.credentials);
    for (forge, repos) in needs.iter_mut() {
        repos.retain(|r| !skip.contains(&forge.key(r)) && !left_for_later(&forge.key(r)));
    }
    needs.retain(|_, r| !r.is_empty());
    if needs.is_empty() {
        return Ok(false);
    }
    if !crate::prompt::interactive() {
        if let Some(h) = hint(env, &needs, &cfg.credentials, all.iter().any(|u| is_ssh(u))) {
            println!("\n{h}");
        }
        return Ok(false);
    }
    // Repos a repository's luoto.toml named, not the env's own config: whoever writes that
    // repository chose them.
    let own_ws = EnvFile::load(&ctx.paths, env)?.cfg.workspace;
    let own = uncovered(&remotes(&own_ws), &cfg.credentials);
    let cloned_from = uncovered(
        &own_ws.url.iter().map(|u| clone_url(u)).collect::<Vec<_>>(),
        &cfg.credentials,
    );
    if let Some(o) = overview(&needs) {
        println!("\n{}", text::wrap(&o, "", text::columns()));
    }
    let items: Vec<(Forge, String)> = needs
        .into_iter()
        .flat_map(|(f, repos)| repos.into_iter().map(move |r| (f.clone(), r)))
        .collect();
    let total = items.len();
    let mut changed = false;
    let mut i = 0;
    while let Some((forge, repo)) = items.get(i) {
        let note = if !own.get(forge).is_some_and(|o| o.contains(repo)) {
            ", named by the project's luoto.toml"
        } else if cloned_from.get(forge).is_some_and(|w| w.contains(repo)) {
            ", the env is cloned from it"
        } else {
            ""
        };
        let line = missing_line(i + 1, total, repo, forge, note);
        println!("\n{}", text::wrap(&line, "", text::columns()));
        match ask_repo_step(ctx, env, forge, repo, Mode::Missing, i > 0)? {
            Step::Got(c) => {
                changed |= c;
                i += 1;
            }
            // The one before, from what it has now; then this one again.
            Step::Back => {
                let Some((prev, prev_repo)) = i.checked_sub(1).and_then(|p| items.get(p)) else {
                    continue;
                };
                println!("\nback to {} ({i}/{total})", display(prev_repo));
                changed |= ask_repo(ctx, env, prev, prev_repo, Mode::Change)?;
            }
        }
    }
    Ok(changed)
}

/// `luoto repo add`: add a host folder or a remote to the env, and copy or clone it now when
/// the env runs.
pub fn add(
    env_name: &str,
    spec: &str,
    name: Option<&str>,
    branch: Option<&str>,
) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    let src = parse_source(spec)?;
    let name = match name {
        Some(n) => n.to_string(),
        None => default_name(&src)?,
    };
    check_name(&name)?;
    if f.cfg.workspace.repos.contains_key(&name) {
        bail!(
            "env `{env_name}` has a repo `{name}` already (`luoto repo rm {name}` first, or pick \
             another --name)"
        );
    }
    let repo = match &src {
        Source::Folder(d) => {
            if branch.is_some() {
                bail!("--branch is for remotes; a folder is copied as it is");
            }
            check_folder(f.cfg.workspace.dir.as_deref(), d)?;
            Repo {
                dir: Some(d.display().to_string()),
                ..Default::default()
            }
        }
        Source::Remote(u) => {
            if let Some(b) = branch {
                check_branch(b)?;
            }
            Repo {
                url: Some(u.clone()),
                branch: branch.map(str::to_string),
                ..Default::default()
            }
        }
    };
    let mut ws = f.cfg.workspace.clone();
    ws.repos.insert(name.clone(), repo.clone());
    check(&ws)?;
    f.set_repo(&name, &repo)?;
    println!("added repo `{name}` to env `{env_name}`, at /workspace/{name}");
    if project::accepted(&ctx, env_name).is_some_and(|(_, p)| p.repos.contains_key(&name)) {
        println!("  it replaces luoto.toml's repo `{name}` in this env");
    }
    let running = ctx.rt.is_running(&names::dev(env_name));
    // Its credential before its clone, which needs it.
    if ask_missing(&ctx, env_name, &env::layered(&ctx, env_name)?)? && running {
        crate::sync::reapply(&ctx, env_name)?;
    }
    let cfg = env::layered(&ctx, env_name)?;
    if running {
        let done = EnvState::load(&ctx.paths, env_name)?
            .map(|s| s.repos)
            .unwrap_or_default();
        let now = seed(&ctx, env_name, &cfg, &done);
        now.warn();
        EnvState::update(&ctx.paths, env_name, |s| s.repos = now.done)?;
    } else {
        println!(
            "`luoto up -e {env_name}` {} it",
            if repo.dir.is_some() {
                "copies in"
            } else {
                "clones"
            }
        );
    }
    if let Some(u) = &repo.url {
        println!(
            "\nTo give the team the same repo, add it to the folder's luoto.toml:\n\n[repos.{name}]\nurl = \"{u}\"{}",
            repo.branch
                .as_deref()
                .map(|b| format!("\nbranch = \"{b}\""))
                .unwrap_or_default()
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// `luoto repo rm`: drop a repo from the env's config; its copy in the env stays.
pub fn rm(env_name: &str, name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let mut f = EnvFile::load(&ctx.paths, env_name)?;
    let in_project =
        project::accepted(&ctx, env_name).is_some_and(|(_, p)| p.repos.contains_key(name));
    if !f.cfg.workspace.repos.contains_key(name) {
        if in_project {
            bail!(
                "`{}` comes from the team's luoto.toml; `luoto project ignore` stops applying \
                 that file",
                display(name)
            );
        }
        bail!("env `{env_name}` has no repo `{}`", display(name));
    }
    f.remove_repo(name)?;
    let mut was_there = false;
    EnvState::update(&ctx.paths, env_name, |s| was_there = s.repos.remove(name))?;
    println!("removed repo `{name}` from env `{env_name}`");
    if was_there {
        println!("its copy stays at /workspace/{name} in the env until you delete it there");
    }
    if in_project {
        println!("luoto.toml lists `{name}` too, and applies again");
    }
    Ok(ExitCode::SUCCESS)
}

/// The forge account and repo `which` names among the env's remotes: a repo by its name in
/// the workspace, or a remote by its path on the forge (`acme/api`) or its URL.
fn find(ws: &Workspace, which: &str) -> Option<(Forge, String, String)> {
    let by_name = ws
        .repos
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(which))
        .and_then(|(_, r)| {
            r.url
                .as_deref()
                .map(clone_url)
                .or_else(|| crate::init::origin_url(Path::new(r.dir.as_deref()?)))
        });
    let key = |u: &str| forge_repo(u).map(|(f, r)| f.key(&r));
    let want = key(which);
    by_name
        .into_iter()
        .chain(remotes(ws).into_iter().filter(|u| {
            (want.is_some() && key(u) == want)
                || forge_repo(u).is_some_and(|(f, r)| f.same(&r, which))
        }))
        .find_map(|u| forge_repo(&u).map(|(f, r)| (f, r, u)))
}

/// `luoto repo auth`: the access question again for one of the env's repos, opening on what
/// the env has. A running env takes the answer at once, and clones a repo that waited for it.
pub fn auth(env_name: &str, which: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let cfg = env::layered(&ctx, env_name)?;
    let Some((forge, repo, url)) = find(&cfg.workspace, which) else {
        let which = display(which);
        bail!(
            "env `{env_name}` has no repo `{which}`; `luoto repo add -e {env_name} {which}` adds it"
        );
    };
    let ssh_host = match &forge {
        Forge::Github(_) => "github.com".to_string(),
        Forge::Azure(_) => crate::azure::SSH_HOST.to_string(),
        Forge::Git(h) => h.split(':').next().unwrap_or(h).to_string(),
    };
    if is_ssh(&url)
        && cfg
            .credentials
            .ssh
            .as_ref()
            .is_some_and(|s| s.hosts.iter().any(|h| h.eq_ignore_ascii_case(&ssh_host)))
    {
        println!(
            "{} goes over SSH with the env's key ([credentials.ssh]), which reaches every repo \
             the key can: there is no access to choose",
            display(&repo)
        );
        return Ok(ExitCode::SUCCESS);
    }
    if !crate::prompt::interactive() {
        bail!(
            "repo auth needs a terminal; without one, `luoto edit -e {env_name}` sets a repo's \
             access in its [credentials]"
        );
    }
    if !ask_repo(&ctx, env_name, &forge, &repo, Mode::Change)? {
        return Ok(ExitCode::SUCCESS);
    }
    let state = EnvState::load(&ctx.paths, env_name)?;
    // The env's own remote is cloned by `up` alone, which this one waits for.
    let own = cfg.workspace.url.as_deref().map(clone_url) == Some(url);
    if own && !state.as_ref().is_some_and(|s| s.seeded) {
        println!("`luoto up -e {env_name}` clones it");
    }
    if !ctx.rt.is_running(&names::dev(env_name)) {
        return Ok(ExitCode::SUCCESS);
    }
    crate::sync::reapply(&ctx, env_name)?;
    let cfg = env::layered(&ctx, env_name)?;
    let done = state.map(|s| s.repos).unwrap_or_default();
    let now = seed(&ctx, env_name, &cfg, &done);
    now.warn();
    if now.done != done {
        EnvState::update(&ctx.paths, env_name, |s| s.repos = now.done)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// `luoto repo list`.
pub fn list(env_name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let repos = listed(&ctx, env_name)?;
    if repos.is_empty() {
        println!(
            "env `{env_name}` has no repos besides its folder (`luoto repo add <folder|owner/repo|url>`)"
        );
        return Ok(ExitCode::SUCCESS);
    }
    let width = repos.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for r in &repos {
        let from = match r.origin {
            Origin::Env => "",
            Origin::Project => ", from luoto.toml",
        };
        let what = match r.kind {
            "folder" => format!("copied in from {}", display(&r.source)),
            _ => format!(
                "cloned from {}{}",
                display(&r.source),
                r.branch
                    .as_deref()
                    .map(|b| format!(" ({})", display(b)))
                    .unwrap_or_default()
            ),
        };
        let state = if r.present {
            ""
        } else {
            " (not yet: `luoto up`)"
        };
        println!("{:<width$}  {what}{from}{state}", r.name);
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_token_names_the_other_repos_it_replaces_the_token_for() {
        let cfg: crate::config::EnvConfig = toml::from_str(
            r#"
[workspace]
dir = "/w"
[[credentials.github]]
token = "op://Dev/acme/token"
repos = ["acme/api", "acme/web"]
read_repos = ["acme/docs"]
[[credentials.github]]
repos = ["other/app"]
"#,
        )
        .unwrap();
        let acme = Forge::Github("acme".into());
        assert_eq!(
            token_shared_with(&cfg.credentials, &acme, "ACME/api"),
            ["acme/web", "acme/docs"]
        );
        let other = Forge::Github("other".into());
        assert!(token_shared_with(&cfg.credentials, &other, "other/app").is_empty());
    }

    #[test]
    fn an_env_file_from_before_keeps_its_https_user_name() {
        let url = "https://alice@bitbucket.org/acme/api.git";
        assert!(check_url(url).is_err());
        check_config_url(url).unwrap();
        assert!(check_config_url("https://alice:pw@bitbucket.org/acme/api.git").is_err());
        assert!(check_config_url("file:///etc").is_err());
    }

    #[test]
    fn remotes_luoto_clones() {
        for u in [
            "acme/api",
            "acme/.github",
            "https://github.com/acme/api.git",
            "https://org@dev.azure.com/org/Data%20Team/_git/api",
            "ssh://git@github.com/acme/api.git",
            "ssh://git@host.example:2222/x/y",
            "git@github.com:acme/api.git",
            "git@ssh.dev.azure.com:v3/org/project/api",
            "git@my-azure:v3/org/project/api",
        ] {
            assert!(check_url(u).is_ok(), "{u}");
        }
        for u in [
            "-uacme/api",
            "acme/../api",
            "acme/api/more",
            "https://user:secret@github.com/acme/api",
            "http://github.com/acme/api",
            "file:///etc",
            "ext::sh -c touch% /tmp/x",
            "/home/dev/api",
            "host:path",
            "git@github.com:--upload-pack=x",
            "https://github.com/acme/a b",
            "https://-x/a",
            "https://github.com/acme/api/more",
            "https://dev.azure.com/org/project/api",
            "",
        ] {
            assert!(check_url(u).is_err(), "{u}");
        }
        for u in [
            "https://ghp_secret@github.com/acme/api",
            "https://glpat-secret@gitlab.com/group/api.git",
            "https://other@dev.azure.com/org/Data%20Team/_git/api",
            "https://x@forge.example",
        ] {
            assert!(check_url(u).is_err(), "{u}");
        }
        // A token in the URL would be kept wherever the URL is: the error doesn't repeat it.
        let e = check_url("https://ghp_secret@github.com/acme/api").unwrap_err();
        assert!(!e.to_string().contains("ghp_secret"), "{e}");
        assert!(e.to_string().contains("github.com"), "{e}");
    }

    #[test]
    fn folders_on_other_machines_are_refused() {
        let ws = |dir: &str, repo: &str| Workspace {
            dir: Some(dir.into()),
            repos: BTreeMap::from([(
                "api".to_string(),
                Repo {
                    dir: Some(repo.into()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        // Absolute here: a drive on Windows.
        let (p, q) = if cfg!(windows) {
            (r"C:\p", r"C:\q")
        } else {
            ("/p", "/q")
        };
        assert!(check(&ws(p, q)).is_ok());
        for bad in [
            r"\\attacker\share",
            "//attacker/share",
            r"\\?\UNC\attacker\s",
            "/net/h/x",
        ] {
            let e = check(&ws(bad, q)).unwrap_err();
            assert!(format!("{e:#}").contains("another machine"), "{e:#}");
            let e = check(&ws("/p", bad)).unwrap_err();
            assert!(format!("{e:#}").contains("[workspace.repos.api]"), "{e:#}");
        }
    }

    #[test]
    fn an_imported_configs_folders_are_judged_as_text() {
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();
        let h = home.display().to_string();
        let ws = |dir: &str, repo: Option<&str>| Workspace {
            dir: Some(dir.into()),
            repos: repo
                .map(|r| {
                    (
                        "api".to_string(),
                        Repo {
                            dir: Some(r.into()),
                            ..Default::default()
                        },
                    )
                })
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let parent = home.parent().unwrap().display().to_string();
        for bad in [
            ws(&h, None),
            ws("~", None),
            ws(&format!("{h}/"), None),
            ws(&h.to_uppercase(), None),
            ws(&parent, None),
            ws("/", None),
            ws(".", None),
            ws(&format!("{h}/proj/.."), None),
            ws("/nonexistent/luoto-p", Some(&parent)),
            ws("/nonexistent/luoto-p", Some("~")),
            ws("/nonexistent/luoto-p", Some("/nonexistent/luoto-p/api")),
            ws("/nonexistent/luoto-p/web", Some("/nonexistent/luoto-p")),
        ] {
            assert!(check_folders_text(&bad).is_err(), "{bad:?}");
        }
        assert!(check_folders_text(&ws("/nonexistent/luoto-p", Some("/nonexistent/x"))).is_ok());
        // A folder in your home is a folder like any: the import lists it.
        assert!(check_folders_text(&ws("~/dev/proj", Some("~/.ssh"))).is_ok());
    }

    #[test]
    fn github_is_found_in_any_spelling() {
        for u in [
            "https://GitHub.com/acme/api",
            "https://me@github.com/acme/api.git",
            "ssh://git@GITHUB.com/acme/api",
            "git@github.com:acme/api",
        ] {
            assert_eq!(github_repo(u).as_deref(), Some("acme/api"), "{u}");
            assert!(other_remote(u).is_none(), "{u}");
        }
        assert!(github_repo("https://github.example/acme/api").is_none());
    }

    #[test]
    fn a_project_names_hosts_not_addresses() {
        assert!(check_project_url("https://git.acme.example/a/b").is_ok());
        assert!(check_project_url("acme/api").is_ok());
        for u in [
            "https://192.168.1.10/a/b",
            "https://127.0.0.1:8080/a/b",
            "https://localhost/a/b",
            "https://forge/a/b",
            "git@x.localhost:a/b",
        ] {
            assert!(check_project_url(u).is_err(), "{u}");
        }
    }

    #[test]
    fn shorthand_clones_from_github() {
        assert_eq!(clone_url("acme/api"), "https://github.com/acme/api.git");
        assert_eq!(clone_url("acme/api.git"), "https://github.com/acme/api.git");
        assert_eq!(
            clone_url("git@github.com:acme/api"),
            "git@github.com:acme/api"
        );
        assert_eq!(github_repo("acme/api").as_deref(), Some("acme/api"));
        assert_eq!(
            github_repo("https://github.com/acme/api.git").as_deref(),
            Some("acme/api")
        );
        assert_eq!(
            github_repo("git@github.com:acme/api.git").as_deref(),
            Some("acme/api")
        );
        assert_eq!(github_repo("git@ssh.dev.azure.com:v3/o/p/r"), None);
    }

    #[test]
    fn names_are_plain_folders() {
        for n in ["api", "web-app", "lib_2", "x.y"] {
            assert!(check_name(n).is_ok(), "{n}");
        }
        for n in [".git", "-x", "a/b", "..", "", "luoto.toml", "a b"] {
            assert!(check_name(n).is_err(), "{n}");
        }
        assert!(check_branch("feature/x-1").is_ok());
        for b in ["-b", "a..b", "x.lock", "/x", "a b"] {
            assert!(check_branch(b).is_err(), "{b}");
        }
    }

    #[test]
    fn default_names_come_from_the_last_part() {
        let remote = |u: &str| default_name(&Source::Remote(u.into())).unwrap();
        assert_eq!(remote("acme/api"), "api");
        assert_eq!(remote("git@github.com:acme/web.git"), "web");
        assert_eq!(remote("https://dev.azure.com/o/p/_git/infra"), "infra");
        assert_eq!(
            default_name(&Source::Folder("/home/me/dev/lib".into())).unwrap(),
            "lib"
        );
    }

    #[test]
    fn config_repos_are_a_folder_or_a_remote() {
        let ws = |repos: &[(&str, Repo)]| Workspace {
            dir: Some("/p".into()),
            repos: repos
                .iter()
                .map(|(n, r)| (n.to_string(), r.clone()))
                .collect(),
            ..Default::default()
        };
        let url = |u: &str| Repo {
            url: Some(u.into()),
            ..Default::default()
        };
        assert!(check(&ws(&[("api", url("acme/api"))])).is_ok());
        let both = Repo {
            dir: Some("/x".into()),
            url: Some("acme/api".into()),
            branch: None,
        };
        assert!(check(&ws(&[("api", both)])).is_err());
        assert!(check(&ws(&[("api", Repo::default())])).is_err());
        let relative = Repo {
            dir: Some("x".into()),
            ..Default::default()
        };
        assert!(check(&ws(&[("api", relative)])).is_err());
        assert!(check(&ws(&[("Api", url("acme/a")), ("api", url("acme/b"))])).is_err());
    }

    #[test]
    fn a_workspace_is_a_folder_or_a_remote() {
        let ws = |dir: Option<&str>, url: Option<&str>, branch: Option<&str>| Workspace {
            dir: dir.map(String::from),
            url: url.map(String::from),
            branch: branch.map(String::from),
            ..Default::default()
        };
        assert!(check(&ws(Some("/p"), None, None)).is_ok());
        assert!(check(&ws(None, Some("acme/web"), Some("develop"))).is_ok());
        assert!(
            check(&ws(None, None, None)).is_ok(),
            "`up` says what to set"
        );
        let both = check(&ws(Some("/p"), Some("acme/web"), None)).unwrap_err();
        assert!(format!("{both:#}").contains("not both"), "{both:#}");
        assert!(check(&ws(Some("/p"), None, Some("main"))).is_err());
        assert!(check(&ws(None, Some("file:///etc"), None)).is_err());
        assert!(check(&ws(None, Some("acme/web"), Some("--upload-pack=x"))).is_err());
    }

    #[test]
    fn the_cloned_remote_is_one_the_env_needs_access_to() {
        let ws = Workspace {
            url: Some("acme/web".into()),
            repos: BTreeMap::from([(
                "api".to_string(),
                Repo {
                    url: Some("git@gitlab.com:acme/api.git".into()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let all = remotes(&ws);
        assert_eq!(
            all,
            [
                "https://github.com/acme/web.git",
                "git@gitlab.com:acme/api.git"
            ]
        );
        let needs = uncovered(&all, &Credentials::default());
        assert_eq!(needs[&Forge::Github("acme".into())], ["acme/web"]);
        let have: Credentials =
            toml::from_str("[github]\ntoken = \"env:T\"\nread_repos = [\"acme/web\"]\n").unwrap();
        assert!(!uncovered(&all, &have).contains_key(&Forge::Github("acme".into())));
    }

    #[cfg(unix)]
    #[test]
    fn the_workspace_clone_moves_in_whole_and_runs_nothing_it_brings() {
        let script = workspace_clone_script("acme/web", Some("dev"), false);
        assert!(script.contains("GIT_LFS_SKIP_SMUDGE=1"));
        assert!(script.contains(
            "--no-recurse-submodules --branch dev -- https://github.com/acme/web.git \"$t\""
        ));
        assert!(
            workspace_clone_script("x/y", Some("a'b"), true)
                .contains("--progress --branch 'a'\\''b' --")
        );
        // The script against a stand-in for git, with a temporary folder as /workspace.
        let root = tempfile::tempdir().unwrap();
        let ws = root.path().join("workspace");
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let fake = r#"#!/bin/sh
[ "$GIT_LFS_SKIP_SMUDGE" = 1 ] || exit 9
for last; do :; done
[ -n "$FAIL" ] && { mkdir -p "$last"; echo half > "$last/a"; exit 128; }
mkdir -p "$last/.git" "$last/src" "$last/.luoto-clone" && echo x > "$last/src/main.rs" && echo y > "$last/.envrc"
"#;
        std::fs::write(bin.join("git"), fake).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(bin.join("git"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let run = |fail: bool| {
            let s = script.replace("/workspace", &ws.display().to_string());
            let mut c = std::process::Command::new("sh");
            c.args(["-c", &s]).env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            );
            if fail {
                c.env("FAIL", "1");
            }
            c.status().unwrap().code()
        };
        let names = || {
            let mut n: Vec<String> = std::fs::read_dir(&ws)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            n.sort();
            n
        };
        assert_eq!(run(true), Some(1));
        assert!(names().is_empty(), "a failed clone leaves nothing");
        // What a clone cut short by more than an error left is cleared.
        std::fs::create_dir_all(ws.join(".luoto-clone-0123456789abcdef/.git")).unwrap();
        // The repository's own `.luoto-clone` moves in like any entry.
        assert_eq!(run(false), Some(0));
        assert_eq!(names(), [".envrc", ".git", ".luoto-clone", "src"]);
        assert_eq!(run(false), Some(3), "a workspace with files is left alone");
        assert_eq!(names(), [".envrc", ".git", ".luoto-clone", "src"]);
        assert_ne!(
            workspace_clone_script("x/y", None, false),
            workspace_clone_script("x/y", None, false),
            "each clone's folder is its own"
        );
    }

    #[test]
    fn only_repos_with_work_no_remote_has_are_named() {
        let dirs = [
            "/workspace".to_string(),
            "/workspace/api".to_string(),
            "/workspace/web".to_string(),
        ];
        let out = "/workspace\t2\t0\t0\n\
                   /workspace/api\t      0\t0\t0\n\
                   /etc\t1\t1\t1\n\
                   /workspace/api\x1b[2K\t1\t1\t1\n\
                   /workspace/api\t1\t1\t1\n\
                   /workspace/web\t?\n";
        let found = parse_unpushed(out, &dirs);
        let shown: Vec<String> = found.iter().map(ToString::to_string).collect();
        assert_eq!(
            shown,
            [
                "/workspace: 2 files changed",
                "/workspace/web: git couldn't read it; look before removing",
            ],
            "the first line for a folder counts; a clean repo goes unnamed"
        );
        let all = Unpushed {
            path: "/workspace/api".into(),
            changed: 1,
            commits: 3,
            stashes: 1,
            unread: false,
        };
        assert_eq!(
            all.to_string(),
            "/workspace/api: 1 file changed, 3 commits not pushed, 1 stash"
        );
        assert_eq!(
            parse_unpushed("/workspace\t0\t?\t0\n", &dirs)[0].to_string(),
            "/workspace: git couldn't read it; look before removing"
        );
    }

    #[test]
    fn folders_stay_outside_the_env_folder() {
        let root = tempfile::tempdir().unwrap();
        let inner = root.path().join("api");
        std::fs::create_dir(&inner).unwrap();
        let root_s = root.path().display().to_string();
        let inner = inner.canonicalize().unwrap();
        assert!(check_folder(Some(&root_s), &inner).is_err());
        let canon = root.path().canonicalize().unwrap();
        assert!(check_folder(Some(&inner.display().to_string()), &canon).is_err());
        let other = tempfile::tempdir().unwrap();
        assert!(check_folder(Some(&root_s), &other.path().canonicalize().unwrap()).is_ok());
        // The root of home's drive, canonical as `dir` arrives (`\\?\C:\` on Windows).
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();
        let top = home.ancestors().last().unwrap().canonicalize().unwrap();
        assert!(check_folder(None, &top).is_err());
    }

    #[test]
    fn hints_ask_for_https_credentials_per_owner() {
        let none = Credentials::default();
        let remotes: Vec<String> = [
            "git@github.com:globex/infra-dev.git",
            "https://github.com/initech/portal",
            "git@azure-fabrikam:v3/fabrikam/Infra/agent",
            "https://gitlab.com/o/r",
        ]
        .map(String::from)
        .to_vec();
        let hint = credential_hint("e", &remotes, &none).unwrap();
        assert_eq!(hint.matches("[[credentials.github]]").count(), 2);
        assert!(hint.contains("repos = [\"globex/infra-dev\"]"));
        assert!(hint.contains("[credentials.azure_devops]"));
        assert!(hint.contains("fabrikam/Infra/agent"));
        assert!(hint.contains("SSH remotes work"));
        let one = credential_hint("e", &remotes[1..2], &none).unwrap();
        assert!(one.contains("[credentials.github]\n") && !one.contains("SSH"));

        let have: Credentials = toml::from_str(
            "[github]\ntoken = \"env:T\"\nread_repos = [\"initech/portal\"]\n\
             [azure_devops]\ntoken = \"env:A\"\nrepos = [\"fabrikam/Infra/agent\"]\n\
             [ssh]\nkey = \"env:K\"\nhosts = [\"github.com\"]\n",
        )
        .unwrap();
        // Covered over HTTPS, or an SSH remote whose host the key logs in to; GitLab's needs
        // a credential of its own.
        assert!(credential_hint("e", &remotes[..3], &have).is_none());
        assert!(
            credential_hint("e", &remotes, &have)
                .unwrap()
                .contains("host = \"gitlab.com\"")
        );
        let other = ["https://github.com/acme/x".to_string()];
        assert!(
            credential_hint("e", &other, &have)
                .unwrap()
                .contains("doesn't list \"acme/x\"")
        );
    }

    #[test]
    fn other_hosts_ask_for_a_git_credential() {
        assert_eq!(
            other_remote("https://forge.internal:3000/infra/api.git"),
            Some((
                "forge.internal:3000".into(),
                "forge.internal".into(),
                "infra/api".into()
            ))
        );
        assert_eq!(
            other_remote("git@gitlab.com:group/sub/repo.git"),
            Some((
                "gitlab.com".into(),
                "gitlab.com".into(),
                "group/sub/repo".into()
            ))
        );
        let remotes = ["https://gitlab.com/group/api.git".to_string()];
        let none = Credentials::default();
        let needs = uncovered(&remotes, &none);
        assert_eq!(needs[&Forge::Git("gitlab.com".into())], ["group/api"]);
        assert!(
            credential_hint("e", &remotes, &none)
                .unwrap()
                .contains("[[credentials.git]]")
        );
        let have: Credentials = toml::from_str(
            "[[git]]\nhost = \"gitlab.com\"\ntoken = \"env:T\"\nrepos = [\"Group/API\"]\n",
        )
        .unwrap();
        assert!(uncovered(&remotes, &have).is_empty());
        // An SSH remote of the host is covered by its HTTPS credential.
        let ssh = ["git@gitlab.com:group/api.git".to_string()];
        assert!(uncovered(&ssh, &have).is_empty());
    }

    #[test]
    fn the_access_question_starts_at_the_least_privilege_in_the_forges_terms() {
        let gh = Forge::Github("acme".into());
        let q = access_question(&gh, "acme/api", None, Mode::Missing);
        assert_eq!(q.text, "What can the env do with acme/api?");
        assert_eq!(q.help, "↑↓ to move, Enter to pick, Esc: later");
        assert_eq!(q.at, 0);
        let rows: Vec<(Option<Access>, &str, &str)> = q
            .rows
            .iter()
            .map(|(a, l, d)| (*a, l.as_str(), d.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                (Some(Access::Public), "Fetch only, it's public", "no token"),
                (
                    Some(Access::Read),
                    "Read it, it's private",
                    "token with Contents: read"
                ),
                (
                    Some(Access::Push),
                    "Read and push, open pull requests",
                    "token with Contents + Pull requests: write"
                ),
                (None, "Later", ""),
            ]
        );
        let shown = crate::prompt::menu_rows(
            &q.rows
                .iter()
                .map(|(_, l, d)| (l.clone(), d.clone()))
                .collect::<Vec<_>>(),
            79,
        );
        assert!(
            shown.iter().all(|l| l.chars().count() + 2 <= 79),
            "{shown:?}"
        );
        let azure = access_rows(&Forge::Azure("o".into()));
        assert_eq!(
            (azure[1].2.as_str(), azure[2].2.as_str()),
            ("PAT with Code: read", "PAT with Code: read & write")
        );
        let gitlab = access_rows(&Forge::Git("gitlab.com".into()));
        assert_eq!(
            (gitlab[1].2.as_str(), gitlab[2].2.as_str()),
            ("token with read_repository", "token with write_repository")
        );
        // Changing it: what the env has, marked and opened on; Esc keeps it, no Later.
        let q = access_question(&gh, "acme/api", Some(Access::Read), Mode::Change);
        assert_eq!(q.at, 1);
        assert_eq!(q.rows[1].1, "Read it, it's private (current)");
        assert_eq!(q.rows.len(), 3);
        assert_eq!(q.help, "↑↓ to move, Enter to pick, Esc: unchanged");
    }

    #[test]
    fn a_repos_access_is_read_from_the_list_that_names_it() {
        let creds: Credentials = toml::from_str(
            "[[github]]\ntoken = \"env:A\"\nrepos = [\"acme/web\"]\nread_repos = [\"Acme/API\"]\n\
             [[github]]\napp_id = \"1\"\ninstallation_id = 2\nprivate_key = \"env:K\"\n\
             repos = [\"other/x\"]\n\
             [azure_devops]\ntoken = \"env:P\"\nread_repos = [\"org/Data Team/infra\"]\n\
             [[git]]\nhost = \"gitlab.com\"\nread_repos = [\"group/pub\"]\n\
             [[git]]\nhost = \"forge.example\"\ntoken = \"env:F\"\nread_repos = [\"t/priv.git\"]\n",
        )
        .unwrap();
        let gh = Forge::Github("acme".into());
        let none = BTreeSet::new();
        let of = |f: &Forge, r: &str| access_of(&creds, &none, f, r);
        assert_eq!(
            of(&gh, "acme/api"),
            Some((Access::Read, Some("env:A".into())))
        );
        assert_eq!(
            of(&gh, "acme/web"),
            Some((Access::Push, Some("env:A".into())))
        );
        assert_eq!(
            of(&Forge::Github("other".into()), "other/x"),
            Some((Access::Push, None))
        );
        assert_eq!(of(&gh, "acme/new"), None);
        let public = BTreeSet::from([gh.key("acme/new")]);
        assert_eq!(
            access_of(&creds, &public, &gh, "acme/new"),
            Some((Access::Public, None))
        );
        assert_eq!(
            of(&Forge::Azure("org".into()), "org/Data%20Team/infra"),
            Some((Access::Read, Some("env:P".into())))
        );
        // Another host's repos without a token are public; with one, private.
        assert_eq!(
            of(&Forge::Git("gitlab.com".into()), "group/pub"),
            Some((Access::Public, None))
        );
        assert_eq!(
            of(&Forge::Git("forge.example".into()), "t/priv"),
            Some((Access::Read, Some("env:F".into())))
        );
        assert_eq!(account_token(&creds, &gh), (Some("env:A".into()), false));
        assert_eq!(
            account_token(&creds, &Forge::Github("other".into())),
            (None, true)
        );
    }

    #[test]
    fn a_repo_step_ends_with_its_summary() {
        let gh = Forge::Github("acme".into());
        let token = Some("keyring:luoto/github.acme".to_string());
        assert_eq!(
            access_summary(
                "web",
                &gh,
                "acme/api",
                Some(&(Access::Read, token.clone())),
                None
            ),
            "acme/api\n  access       read, token keyring:luoto/github.acme\n  \
             change it    luoto repo auth -e web acme/api"
        );
        assert_eq!(
            access_summary("web", &gh, "acme/api", Some(&(Access::Push, token)), None),
            "acme/api\n  access       read and push, token keyring:luoto/github.acme\n  \
             change it    luoto repo auth -e web acme/api"
        );
        assert!(
            access_summary("web", &gh, "acme/api", Some(&(Access::Public, None)), None)
                .contains("access       fetch only (public)\n")
        );
        assert!(
            access_summary("web", &gh, "acme/api", None, None).contains("access       none yet\n")
        );
    }

    #[test]
    fn a_new_token_names_the_one_it_replaces() {
        let gh = Forge::Github("acme".into());
        let old = (Access::Push, Some("env:OLD".to_string()));
        let new = (Access::Push, Some("env:NEW".to_string()));
        let was = replaced(Some(&old), Some(&new));
        assert_eq!(was, Some("env:OLD"));
        assert_eq!(
            access_summary("web", &gh, "acme/api", Some(&new), was),
            "acme/api\n  access       read and push, token env:NEW\n  \
             replaces     token env:OLD\n  \
             change it    luoto repo auth -e web acme/api"
        );
        // Kept, added or dropped: nothing replaced.
        assert_eq!(replaced(Some(&old), Some(&old)), None);
        assert_eq!(replaced(None, Some(&new)), None);
        assert_eq!(replaced(Some(&old), Some(&(Access::Public, None))), None);
    }

    #[test]
    fn several_repos_are_counted_by_account_before_the_first() {
        let mut needs: BTreeMap<Forge, Vec<String>> = BTreeMap::new();
        needs.insert(Forge::Azure("org".into()), vec!["org/p/r".into()]);
        assert_eq!(overview(&needs), None);
        needs.insert(
            Forge::Github("acme".into()),
            vec!["acme/api".into(), "acme/web".into()],
        );
        needs.insert(Forge::Github("beta".into()), vec!["beta/x".into()]);
        assert_eq!(
            overview(&needs).as_deref(),
            Some("4 repos need access: GitHub acme (2), GitHub beta (1), Azure DevOps org (1)")
        );
        let gh = Forge::Github("acme".into());
        assert_eq!(
            missing_line(2, 4, "acme/web", &gh, ""),
            "(2/4) acme/web (GitHub) has no credential, so the env can only fetch it if it is \
             public."
        );
        assert!(missing_line(1, 1, "acme/web", &gh, "").starts_with("acme/web (GitHub)"));
    }

    #[test]
    fn a_github_token_is_known_by_its_prefix() {
        let fits = |v: &str| GITHUB_TOKEN.fits(v);
        assert!(fits("github_pat_11ABC"));
        assert!(fits("ghp_abc"));
        assert!(fits("ghs_abc"));
        // An Azure DevOps PAT has no such prefix.
        assert!(!fits("3x7kq2abcdefghijklmnopqrstuvwxyz0123456789abcdefgh"));
    }

    #[test]
    fn repo_auth_finds_a_repo_by_name_path_or_url() {
        let ws = Workspace {
            url: Some("acme/web".into()),
            repos: BTreeMap::from([(
                "api".to_string(),
                Repo {
                    url: Some("https://gitlab.com/group/api.git".into()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let found = |w: &str| find(&ws, w).map(|(f, r, _)| (f, r));
        let gitlab = Some((Forge::Git("gitlab.com".into()), "group/api".to_string()));
        assert_eq!(found("api"), gitlab);
        assert_eq!(found("group/api"), gitlab);
        assert_eq!(found("https://gitlab.com/group/api.git"), gitlab);
        let web = Some((Forge::Github("acme".into()), "acme/web".to_string()));
        assert_eq!(found("ACME/web"), web);
        assert_eq!(found("https://github.com/acme/web"), web);
        assert_eq!(found("acme/other"), None);
    }
}
