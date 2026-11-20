//! Pulling with nobody reviewing: an env whose `[workspace] dangerously_pull_on_stop` is set
//! (or a `luoto run --dangerously-pull`) has its files written into its folder when it stops.
//! `stop` is the one way an env stops: the CLI, the UI and the watcher call it.
//!
//! The pull reads the stopped env's `work` volume through a container of luoto's tools image
//! (no network, read-only), never the running env: code there could stall the read or change
//! files after they were judged. It writes only what the three-way rule gives the env
//! (`base::judge`), less what `workspace::risky` and `unattended` hold back, within `CAPS`.
//! What it plans is journaled before the first write, so a pull cut short (a crash, a power
//! cut) is told apart from a finished one, and `recover` cleans up after it.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::base::{self, Base, Host, Print};
use crate::config::{self, EnvFile, Workspace};
use crate::env::{self, Ctx};
use crate::paths::Paths;
use crate::state::EnvState;
use crate::text::display;
use crate::transfer::{MOUNT, VolumeBox};
use crate::workspace::{self, PullPlan, PullTarget, TarError, TarRead};
use crate::{names, notify};

/// `luoto run`'s exit code when the agent succeeded and its unattended pull left something
/// out (sysexits' EX_TEMPFAIL: look, then try again).
pub const INCOMPLETE: u8 = 75;

/// How many times a pull that couldn't run is tried again on its own.
const MAX_ATTEMPTS: u32 = 3;

/// How long reading one folder of a stopped env may take.
const READ_LIMIT: Duration = Duration::from_secs(600);
/// How long, and how much, listing what no pull takes may take.
const FIND_LIMIT: Duration = Duration::from_secs(60);
const FIND_CAP: usize = 256 << 10;

/// The most an unattended pull reads and writes for one folder. Over one, nothing is written.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// The env's files as a tar, held in memory while they are judged.
    pub read: u64,
    /// Bytes written.
    pub bytes: u64,
    /// Files written.
    pub files: usize,
    /// One file.
    pub file: u64,
    /// Free space left on the folder's disk afterwards.
    pub spare: u64,
}

pub const CAPS: Caps = Caps {
    read: 512 << 20,
    bytes: 256 << 20,
    files: 5000,
    file: 64 << 20,
    spare: 256 << 20,
};

/// Why `sizes` (the files a pull would write) are more than `caps` allows with `free` bytes
/// on the disk, if they are.
pub fn over(caps: &Caps, sizes: &[u64], free: Option<u64>) -> Option<String> {
    let human = crate::disk::human;
    let total: u64 = sizes.iter().sum();
    if sizes.is_empty() {
        return None;
    }
    if sizes.len() > caps.files {
        return Some(format!(
            "{} files changed, more than the {} an unattended pull writes",
            sizes.len(),
            caps.files
        ));
    }
    if let Some(big) = sizes.iter().max().filter(|s| **s > caps.file) {
        return Some(format!(
            "a file of {} changed, more than the {} an unattended pull writes",
            human(*big),
            human(caps.file)
        ));
    }
    if total > caps.bytes {
        return Some(format!(
            "{} changed, more than the {} an unattended pull writes",
            human(total),
            human(caps.bytes)
        ));
    }
    if let Some(free) = free.filter(|f| *f < total.saturating_add(caps.spare)) {
        return Some(format!(
            "the folder's disk has {} free, too little to write {} safely",
            human(free),
            human(total)
        ));
    }
    None
}

/// Free bytes on the disk that holds `dir`, where the system says.
fn free_space(dir: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        // SAFETY: `path` is a NUL-terminated string and `s` a statvfs the call fills in.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
            return None;
        }
        #[allow(clippy::unnecessary_cast)]
        Some((s.f_bavail as u64).saturating_mul(s.f_frsize as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

/// JavaScript as a tool loads it: its config files are programs.
const SCRIPT_EXTS: &[&str] = &["js", "cjs", "mjs", "ts", "cts", "mts"];

/// Files that are code a tool on the host loads by itself: an editor or language server
/// opening the folder, a test runner collecting tests. Named without their folder.
const LOADED_BY_NAME: &[(&str, &str)] = &[
    ("build.rs", "a build script: rust-analyzer runs it"),
    ("conftest.py", "pytest and editors' test discovery run it"),
    ("sitecustomize.py", "Python runs it at start"),
    ("usercustomize.py", "Python runs it at start"),
    ("gemfile", "Ruby tools evaluate it"),
    ("rakefile", "Ruby tools evaluate it"),
    (
        "build.gradle",
        "a Gradle build script: an IDE's import runs it",
    ),
    (
        "build.gradle.kts",
        "a Gradle build script: an IDE's import runs it",
    ),
    (
        "settings.gradle",
        "a Gradle build script: an IDE's import runs it",
    ),
    (
        "settings.gradle.kts",
        "a Gradle build script: an IDE's import runs it",
    ),
    ("flake.nix", "direnv and nix tools evaluate it"),
    ("shell.nix", "direnv and nix tools evaluate it"),
    (".pnp.cjs", "node loads it for every yarn command"),
    (".pnp.loader.mjs", "node loads it for every yarn command"),
    (
        "nodemon.json",
        "a running nodemon runs the command it names",
    ),
];

/// What an unattended pull holds back beyond `workspace::risky`: files nobody runs by hand,
/// which run all the same once they are in the folder. `rel` in the folder or any folder
/// within it, compared as the filesystem compares names.
pub fn unattended(rel: &str) -> Option<&'static str> {
    let parts: Vec<String> = rel.split('/').map(workspace::fold).collect();
    let name = parts.last()?.as_str();
    if let Some((_, why)) = LOADED_BY_NAME.iter().find(|(n, _)| *n == name) {
        return Some(why);
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        let script = SCRIPT_EXTS.contains(&ext);
        if script && stem.ends_with(".config") {
            return Some("a tool's config that is code: editors and dev servers load it");
        }
        if script && matches!(stem, ".eslintrc" | ".prettierrc") {
            return Some("a tool's config that is code: editors and dev servers load it");
        }
        if ext == "gemspec" {
            return Some("Ruby tools evaluate it");
        }
    }
    let yarn = parts
        .windows(2)
        .any(|w| w[0] == ".yarn" && matches!(w[1].as_str(), "releases" | "plugins" | "sdks"));
    if yarn && parts.len() > 2 {
        return Some("yarn's own code: every yarn command runs it");
    }
    None
}

/// The folders among the env's files laid out as a git repository without a work tree
/// (`HEAD`, `config`, `objects/`, `refs/`): git run inside one, by a prompt or an editor,
/// takes its `config` as the repository's, hooks and all. `""` is the folder itself.
pub fn bare_roots(present: &BTreeSet<String>, folders: &BTreeSet<String>) -> Vec<String> {
    let under = |root: &str, name: &str| {
        if root.is_empty() {
            name.to_string()
        } else {
            format!("{root}/{name}")
        }
    };
    present
        .iter()
        .filter_map(|p| match p.rsplit_once('/') {
            Some((root, "HEAD")) => Some(root.to_string()),
            None if p == "HEAD" => Some(String::new()),
            _ => None,
        })
        .filter(|root| {
            present.contains(&under(root, "config"))
                && folders.contains(&under(root, "objects"))
                && folders.contains(&under(root, "refs"))
        })
        .collect()
}

/// Whether `rel` is `folder` or in it; everything is in `""`.
fn within(rel: &str, folder: &str) -> bool {
    folder.is_empty()
        || rel
            .strip_prefix(folder)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The folder of `dest` its repository runs hooks from (`core.hooksPath`), when it is inside.
fn hooks_path(dest: &Path) -> Option<String> {
    if !dest.join(".git").exists() {
        return None;
    }
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dest)
        .args(["config", "--get", "core.hooksPath"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let set = String::from_utf8_lossy(&out.stdout).trim().to_string();
    hooks_rel(dest, &set)
}

/// `core.hooksPath` as a path in the folder: a relative one counts from the repository's top.
fn hooks_rel(dest: &Path, set: &str) -> Option<String> {
    if set.is_empty() {
        return None;
    }
    let rel = match Path::new(set).strip_prefix(dest) {
        Ok(rel) => rel.to_path_buf(),
        Err(_) if Path::new(set).is_absolute() || set.starts_with('~') => return None,
        Err(_) => PathBuf::from(set),
    };
    let parts: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(Some(n.to_string_lossy().into_owned())),
            std::path::Component::CurDir => None,
            _ => Some(None),
        })
        .collect::<Option<_>>()?;
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// What the repository whose root is `dest` is in the middle of, if anything: a pull then
/// would write under a merge or a rebase.
pub fn mid_operation(dest: &Path) -> Option<&'static str> {
    let dot = dest.join(".git");
    let git = if dot.is_dir() {
        dot
    } else {
        // A work tree of another repository: `.git` is a file naming its own folder there.
        let text = std::fs::read_to_string(&dot).ok()?;
        let named = text.lines().next()?.strip_prefix("gitdir:")?.trim();
        dest.join(named)
    };
    [
        ("index.lock", "git is running in it"),
        ("rebase-merge", "a rebase is under way in it"),
        ("rebase-apply", "a rebase is under way in it"),
        ("MERGE_HEAD", "a merge is under way in it"),
        ("CHERRY_PICK_HEAD", "a cherry-pick is under way in it"),
        ("REVERT_HEAD", "a revert is under way in it"),
        ("BISECT_LOG", "a bisect is under way in it"),
    ]
    .into_iter()
    .find(|(f, _)| git.join(f).exists())
    .map(|(_, why)| why)
}

/// What the folder's own tools say about a plan's entries.
#[derive(Debug, Default)]
pub struct Facts {
    /// Paths the folder's repository ignores.
    pub ignored: BTreeSet<String>,
    /// Where it runs hooks from.
    pub hooks: Option<String>,
}

/// What an unattended pull does with a plan's entries.
#[derive(Debug, Default, PartialEq)]
pub struct Decided {
    pub write: Vec<String>,
    /// Held back for a person, and why.
    pub held: Vec<(String, String)>,
    pub conflicts: Vec<String>,
    /// Left in the env: the folder's repository ignores them.
    pub ignored: usize,
}

/// Sort `plan`'s entries: a conflict is never written, nor what the folder's repository
/// ignores; what a host tool runs by itself is held back; the rest is written.
pub fn decide(plan: &PullPlan, facts: &Facts) -> Decided {
    let bare = bare_roots(&plan.present, &plan.folders);
    let mut d = Decided::default();
    for e in &plan.entries {
        let rel = e.path.as_str();
        let why = if let Some(r) = &e.risky {
            Some(r.clone())
        } else if let Some(r) = unattended(rel) {
            Some(r.to_string())
        } else if e.executable {
            Some("an executable file".to_string())
        } else if facts.hooks.as_deref().is_some_and(|h| within(rel, h)) {
            Some("your repository runs its hooks from this folder".to_string())
        } else if bare.iter().any(|root| within(rel, root)) {
            Some("laid out as a git repository: git run there takes its config".to_string())
        } else {
            None
        };
        if facts.ignored.contains(rel) {
            d.ignored += 1;
        } else if e.conflict() {
            d.conflicts.push(e.path.clone());
        } else if let Some(why) = why {
            d.held.push((e.path.clone(), why));
        } else {
            d.write.push(e.path.clone());
        }
    }
    d
}

/// Where luoto keeps an env's pulls: outside its state, which goes with the env.
fn dir(paths: &Paths, env: &str) -> PathBuf {
    paths.data.join("pulls").join(env)
}

/// The report of the env's last unattended pull.
pub fn report_file(paths: &Paths, env: &str) -> PathBuf {
    dir(paths, env).join("report.json")
}

/// Held while an env is pulled or stopped, or starts: one at a time.
pub struct Lock(#[allow(dead_code)] File);

fn lock_file(paths: &Paths, env: &str) -> Result<File> {
    let dir = dir(paths, env);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(File::create(dir.join("lock"))?)
}

/// Wait for the env's pull lock.
pub fn lock(paths: &Paths, env: &str) -> Result<Lock> {
    let f = lock_file(paths, env)?;
    if f.try_lock().is_err() {
        let _waiting = crate::progress::waiting(&format!(
            "waiting for another luoto to be done with `{env}`"
        ));
        f.lock().context("lock the env's pulls")?;
    }
    Ok(Lock(f))
}

/// The env's pull lock, unless someone holds it.
fn try_lock(paths: &Paths, env: &str) -> Option<Lock> {
    let f = lock_file(paths, env).ok()?;
    f.try_lock().ok().map(|()| Lock(f))
}

/// What is owed to an env's folder, written before it is acted on so a crash leaves it said.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Pending {
    /// A stop or a run is under way that ends in an unattended pull.
    #[serde(default)]
    pub pull: bool,
    /// The run was to remove its env afterwards. Never acted on later: a removal is not
    /// resumed.
    #[serde(default)]
    pub rm: bool,
    /// The env started with pull-on-stop set and hasn't been pulled since.
    #[serde(default)]
    pub dirty: bool,
    /// An interrupted run left its files half done: no unattended pull until a person has
    /// reviewed one.
    #[serde(default)]
    pub hold: bool,
    /// How often a pull that was owed was tried and couldn't run.
    #[serde(default)]
    pub attempts: u32,
}

impl Pending {
    fn file(paths: &Paths, env: &str) -> PathBuf {
        dir(paths, env).join("pending.json")
    }

    pub fn load(paths: &Paths, env: &str) -> Pending {
        std::fs::read(Self::file(paths, env))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Whether a pull is still to be done.
    pub fn owed(&self) -> bool {
        self.pull || self.dirty
    }

    /// Change what is recorded with `f`; nothing left to say removes the record.
    pub fn update(paths: &Paths, env: &str, f: impl FnOnce(&mut Pending)) -> Result<()> {
        let was = Self::load(paths, env);
        let mut now = was.clone();
        f(&mut now);
        if now == was {
            return Ok(());
        }
        let file = Self::file(paths, env);
        if now == Pending::default() {
            return match std::fs::remove_file(&file) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            };
        }
        base::write_synced(&file, &serde_json::to_vec(&now)?)
    }

    /// The pull that was owed is over, done or not.
    fn settled(&mut self, again: bool) {
        self.rm = false;
        if again {
            self.pull = true;
            self.attempts += 1;
        } else {
            self.pull = false;
            self.dirty = false;
            self.attempts = 0;
        }
    }
}

/// Whether the env's own file sets pull-on-stop.
pub fn on(paths: &Paths, env: &str) -> bool {
    EnvFile::load(paths, env).is_ok_and(|f| f.cfg.workspace.dangerously_pull_on_stop)
}

/// `up` started an env with pull-on-stop: from here a stop it doesn't see (a crash, a
/// restart of the machine) leaves a pull owed.
pub fn started(paths: &Paths, env: &str) {
    if on(paths, env) {
        let _ = Pending::update(paths, env, |p| p.dirty = true);
    }
}

/// Pull-on-stop was turned off: no pull is owed to the env's folder any more.
pub fn turned_off(paths: &Paths, env: &str) {
    let _ = Pending::update(paths, env, |p| p.settled(false));
}

/// A person reviewed a pull of the env: unattended pulls go on.
pub fn reviewed(paths: &Paths, env: &str) {
    let _ = Pending::update(paths, env, |p| p.hold = false);
}

/// A run of the env was interrupted: its files wait for a reviewed pull, and no pull is
/// owed until then (the run says so).
pub fn hold(paths: &Paths, env: &str) {
    let _ = Pending::update(paths, env, |p| {
        p.settled(false);
        p.hold = true;
    });
}

/// A run that ends in an unattended pull starts.
pub fn expect(paths: &Paths, env: &str, rm: bool) -> Result<()> {
    Pending::update(paths, env, |p| {
        p.pull = true;
        p.rm = rm;
    })
}

/// Forget what was owed to a removed env's folder; the last report stays.
pub fn forget(paths: &Paths, env: &str) {
    for f in ["pending.json", "journal.json", "lock"] {
        let _ = std::fs::remove_file(dir(paths, env).join(f));
    }
}

/// One file a pull is about to write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Planned {
    pub path: String,
    /// The temporary file it is written through, beside it.
    pub tmp: String,
    pub new: Print,
    /// What the folder held; None for nothing.
    pub was: Option<Print>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedFolder {
    pub dir: String,
    pub entries: Vec<Planned>,
}

/// What a pull planned, on disk before its first write; `complete` once every file is
/// written, synced and in the base.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Journal {
    pub complete: bool,
    pub folders: Vec<PlannedFolder>,
}

impl Journal {
    fn file(paths: &Paths, env: &str) -> PathBuf {
        dir(paths, env).join("journal.json")
    }

    fn load(paths: &Paths, env: &str) -> Option<Journal> {
        serde_json::from_slice(&std::fs::read(Self::file(paths, env)).ok()?).ok()
    }

    fn save(&self, paths: &Paths, env: &str) -> Result<()> {
        base::write_synced(&Self::file(paths, env), &serde_json::to_vec(self)?)
    }
}

/// What became of a planned write that a crash may have cut short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// The folder holds the new file.
    Done,
    /// It holds what it held before.
    NotDone,
    /// It holds something else: someone changed it since.
    Changed,
}

/// Tell a planned write's fate from what the folder holds `now`.
pub fn fate(new: &Print, was: Option<&Print>, now: &Host) -> Fate {
    match (now, was) {
        (Host::Is(p), _) if p == new => Fate::Done,
        (Host::Is(p), Some(w)) if p == w => Fate::NotDone,
        (Host::Absent, None) => Fate::NotDone,
        _ => Fate::Changed,
    }
}

/// What cleaning up after a pull cut short found.
#[derive(Debug, Default, PartialEq)]
pub struct Recovered {
    pub done: usize,
    pub not_done: usize,
    pub changed: usize,
    /// Half-written temporary files removed.
    pub temps: usize,
}

/// A temporary file's name as `workspace::temp_name` makes them: nothing else is removed.
fn temp_named(name: &str) -> bool {
    name.strip_prefix(".luoto-")
        .and_then(|n| n.strip_suffix(".tmp"))
        .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Clean up after a pull that never marked its journal complete: remove the temporary files
/// it named and count what became of each planned write. None when no pull was cut short.
pub fn recover_journal(paths: &Paths, env: &str) -> Option<Recovered> {
    let journal = Journal::load(paths, env).filter(|j| !j.complete)?;
    let mut r = Recovered::default();
    for folder in &journal.folders {
        let dest = Path::new(&folder.dir);
        for e in &folder.entries {
            let target = dest.join(&e.path);
            // The journal's paths were the sandbox's names: judged again before any is used.
            if !workspace::plain_inside(dest, &target) {
                r.changed += 1;
                continue;
            }
            if temp_named(&e.tmp)
                && let Some(parent) = target.parent()
                && std::fs::symlink_metadata(parent.join(&e.tmp)).is_ok_and(|m| !m.is_dir())
                && std::fs::remove_file(parent.join(&e.tmp)).is_ok()
            {
                r.temps += 1;
            }
            match fate(&e.new, e.was.as_ref(), &Host::at(&target)) {
                Fate::Done => r.done += 1,
                Fate::NotDone => r.not_done += 1,
                Fate::Changed => r.changed += 1,
            }
        }
    }
    let _ = std::fs::remove_file(Journal::file(paths, env));
    Some(r)
}

/// What an unattended pull did for one folder.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FolderReport {
    pub dir: String,
    /// The repo, or None for the env's own folder.
    pub repo: Option<String>,
    pub written: Vec<String>,
    /// Left for a person, and why: what host tools run by themselves, and files that couldn't
    /// be written.
    pub held: Vec<(String, String)>,
    /// Changed in the folder too: the folder's are kept.
    pub conflicts: Vec<String>,
    /// Deleted in the env; kept in the folder.
    pub deleted: Vec<String>,
    pub refused: Vec<(String, String)>,
    /// Files the folder's repository ignores, left in the env.
    pub ignored: usize,
    /// What no pull takes (`node_modules`, …) and the folder's repository doesn't ignore.
    pub never_copied: Vec<String>,
    pub unchanged: usize,
    /// Changed only in the folder.
    pub yours: usize,
    /// Why the env's files weren't all read.
    pub unread: Option<String>,
    /// Why nothing was written for this folder.
    pub deferred: Option<String>,
    /// The folder's git HEAD at the env's copy, and now, when it moved.
    pub head_moved: Option<(String, String)>,
    /// Everything written is synced to disk and in the base.
    pub complete: bool,
    /// Trying again by itself may help (the folder was mid-merge, the runtime failed).
    #[serde(skip)]
    retry: bool,
}

impl FolderReport {
    /// Whether something the env holds for this folder didn't land in it.
    fn incomplete(&self) -> bool {
        !self.complete
            || !self.held.is_empty()
            || !self.conflicts.is_empty()
            || !self.refused.is_empty()
            || self.unread.is_some()
            || self.deferred.is_some()
    }
}

/// `s` in lines the terminal holds, those after the first indented.
fn wrapped(s: &str) -> String {
    let w = crate::text::wrap(s, "  ", crate::text::columns());
    w.strip_prefix("  ").unwrap_or(&w).to_string()
}

/// What an unattended pull did.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub env: String,
    pub at: Option<DateTime<Utc>>,
    /// `down`, `idle`, `run`, `ui` or `recovery`.
    pub why: String,
    pub folders: Vec<FolderReport>,
    /// Why no folder was pulled at all.
    pub error: Option<String>,
    /// Not pulled: an interrupted run's files wait for a reviewed pull.
    pub held: bool,
}

impl Report {
    /// Whether something the env holds didn't land: files held back, in conflict, refused or
    /// unread, or a folder not pulled.
    pub fn incomplete(&self) -> bool {
        self.error.is_some() || self.held || self.folders.iter().any(FolderReport::incomplete)
    }

    /// Whether the env holds nothing its folders lack, as far as a pull can tell: `--rm`
    /// removes only then.
    pub fn removable(&self) -> bool {
        !self.incomplete() && self.folders.iter().all(|f| f.never_copied.is_empty())
    }

    fn retry(&self) -> bool {
        self.error.is_some() || self.folders.iter().any(|f| f.retry)
    }

    pub fn written(&self) -> usize {
        self.folders.iter().map(|f| f.written.len()).sum()
    }

    /// Files left for a person: held back, in conflict or refused.
    pub fn left(&self) -> usize {
        self.folders
            .iter()
            .map(|f| f.held.len() + f.conflicts.len() + f.refused.len())
            .sum()
    }

    fn folders_text(&self) -> String {
        self.folders
            .iter()
            .map(|f| crate::ssh::tilde(Path::new(&f.dir)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// One line of what the pull came to, for the watcher's log and a run's end.
    pub fn line(&self) -> String {
        let env = &self.env;
        if self.held {
            return format!(
                "nothing pulled from `{env}`: an interrupted run left its files half done; \
                 `luoto pull -e {env}` reviews them"
            );
        }
        if let Some(e) = &self.error {
            return format!("nothing pulled from `{env}`: {e}");
        }
        let mut s = format!(
            "pulled {} file(s) from `{env}` into {}",
            self.written(),
            self.folders_text()
        );
        let left = self.left();
        if left > 0 {
            s.push_str(&format!("; {left} left for you"));
        }
        let waiting = self
            .folders
            .iter()
            .filter(|f| f.deferred.is_some() || f.unread.is_some() || !f.complete)
            .count();
        if waiting > 0 {
            s.push_str(&format!("; {waiting} folder(s) not pulled whole"));
        }
        if left + waiting > 0 {
            s.push_str(&format!(": `luoto pull -e {env}` reviews"));
        }
        s
    }

    /// The desktop notification of a pull: counts and the folders, which are yours. No file
    /// name, which the sandbox chose. None when there is nothing to tell.
    pub fn note(&self) -> Option<notify::Note> {
        if self.written() == 0 && !self.incomplete() {
            return None;
        }
        let env = &self.env;
        let title = match self.written() {
            0 => format!("luoto pulled nothing from `{env}`"),
            1 => format!("luoto pulled 1 file from `{env}`"),
            n => format!("luoto pulled {n} files from `{env}`"),
        };
        let mut body = match self.folders.is_empty() {
            true => String::new(),
            false => format!("into {}", self.folders_text()),
        };
        if self.incomplete() {
            let left = match self.left() {
                0 => "not all of it could be pulled".to_string(),
                n => format!("{n} held back"),
            };
            if !body.is_empty() {
                body.push_str("; ");
            }
            body.push_str(&format!("{left}: `luoto pull -e {env}`"));
        }
        Some(notify::Note { title, body })
    }

    /// The whole of it for a terminal or a log, at most `cap` names per list, the names the
    /// sandbox chose escaped.
    pub fn print(&self, w: &mut impl Write, style: crate::style::Style, cap: usize) {
        let _ = self.write(w, style, cap);
    }

    fn write(
        &self,
        w: &mut impl Write,
        style: crate::style::Style,
        cap: usize,
    ) -> std::io::Result<()> {
        if self.held || self.error.is_some() {
            return writeln!(w, "{}", style.commands(&wrapped(&self.line())));
        }
        let env = &self.env;
        let list = |w: &mut dyn Write, head: &str, items: &[String]| -> std::io::Result<()> {
            if items.is_empty() {
                return Ok(());
            }
            writeln!(w, "{}", style.commands(head))?;
            for i in items.iter().take(cap) {
                writeln!(w, "  {i}")?;
            }
            if items.len() > cap {
                writeln!(w, "  … and {} more", items.len() - cap)?;
            }
            Ok(())
        };
        let names = |v: &[String]| v.iter().map(|p| display(p)).collect::<Vec<_>>();
        let whys = |v: &[(String, String)]| {
            v.iter()
                .map(|(p, why)| format!("{} — {}", display(p), display(why)))
                .collect::<Vec<_>>()
        };
        for f in &self.folders {
            let to = crate::ssh::tilde(Path::new(&f.dir));
            if let Some(why) = &f.deferred {
                let head = format!("nothing pulled into {to}: {}", display(why));
                writeln!(w, "{}", style.commands(&wrapped(&head)))?;
                continue;
            }
            let head = format!(
                "pulled {} file(s) from `{env}` into {to}{}",
                f.written.len(),
                if f.complete {
                    ""
                } else {
                    " (not synced to disk)"
                }
            );
            writeln!(w, "{}", style.head(&wrapped(&head)))?;
            list(w, "wrote:", &names(&f.written))?;
            let held = format!("held back (`luoto pull -e {env}` reviews them):");
            list(w, &held, &whys(&f.held))?;
            list(
                w,
                "changed here and in the env (yours kept):",
                &names(&f.conflicts),
            )?;
            list(w, "deleted in the env, kept here:", &names(&f.deleted))?;
            list(w, "refused:", &whys(&f.refused))?;
            list(
                w,
                "never copied, so only in the env:",
                &names(&f.never_copied),
            )?;
            if f.ignored > 0 {
                writeln!(
                    w,
                    "{} file(s) your .gitignore ignores stay in the env",
                    f.ignored
                )?;
            }
            if let Some((then, now)) = &f.head_moved {
                writeln!(
                    w,
                    "your folder's HEAD moved since the env's copy ({then} → {now})"
                )?;
            }
            if let Some(why) = &f.unread {
                let first = why.lines().next().unwrap_or_default();
                writeln!(w, "not all of the env's files could be read: {first}")?;
            }
        }
        Ok(())
    }

    fn save(&self, paths: &Paths, env: &str) {
        let saved = serde_json::to_vec_pretty(self)
            .map_err(anyhow::Error::from)
            .and_then(|b| base::write_synced(&report_file(paths, env), &b));
        if let Err(e) = saved {
            crate::progress::warn(&format!("the pull's report wasn't saved ({e:#})"));
        }
    }

    /// The env's last report, if it was made at or after `since`.
    pub fn last(paths: &Paths, env: &str, since: DateTime<Utc>) -> Option<Report> {
        let r: Report =
            serde_json::from_slice(&std::fs::read(report_file(paths, env)).ok()?).ok()?;
        r.at.is_some_and(|at| at >= since).then_some(r)
    }
}

/// The folders of this machine an unattended pull of the env writes: its own and its repos'
/// copied in from one, as its own file names them.
fn folders(ws: &Workspace, present: &BTreeSet<String>) -> Result<Vec<PullTarget>> {
    let mut all = Vec::new();
    if ws.dir.is_some() {
        all = workspace::pull_targets(ws, None, None, present)?;
    } else {
        for (name, r) in &ws.repos {
            if r.dir.is_some() && present.contains(name) {
                all.extend(workspace::pull_targets(ws, None, Some(name), present)?);
            }
        }
    }
    Ok(all.into_iter().filter(|t| t.home).collect())
}

/// A folder's part of an unattended pull, planned.
struct Work {
    target: PullTarget,
    plan: PullPlan,
    write: Vec<String>,
    old: Base,
}

/// tar's output for `target` from the stopped env's volume.
fn read_stopped(
    ctx: &Ctx,
    vol: &VolumeBox,
    env: &str,
    target: &PullTarget,
) -> std::result::Result<TarRead, TarError> {
    let root = match &target.repo {
        Some(name) => format!("{MOUNT}/{name}"),
        None => MOUNT.to_string(),
    };
    let name = format!("{}.pull", names::dev(env));
    let args = vol.args_named(&name, workspace::tar_args(&root, &target.skip, false));
    let child = ctx
        .rt
        .command()
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(TarError::Io)?;
    let read = workspace::read_tar(child, CAPS.read, Some(READ_LIMIT));
    if read.is_err() {
        // Its client was ended; a container of its own would read on.
        vol.forget(&name);
    }
    read
}

/// What the stopped env holds under `target` that no pull takes.
fn never_copied(ctx: &Ctx, vol: &VolumeBox, env: &str, target: &PullTarget) -> Result<Vec<String>> {
    let root = match &target.repo {
        Some(name) => format!("{MOUNT}/{name}"),
        None => MOUNT.to_string(),
    };
    let mut argv = vec![
        "sh".to_string(),
        "-c".into(),
        r#"cd "$0" && exec find "$@""#.into(),
        root,
    ];
    argv.extend(workspace::never_copied_find(&target.skip));
    let name = format!("{}.find", names::dev(env));
    let out = ctx
        .rt
        .run_limited(vol.args_named(&name, argv), FIND_LIMIT, FIND_CAP);
    if out.is_err() {
        vol.forget(&name);
    }
    Ok(workspace::never_copied_lines(&out?))
}

/// What stopped env `env` holds that its folders don't have, read from its volume as an
/// unattended pull reads it: `commands::unpulled` for an env that can't be asked. Nothing for
/// an env with no folder here.
pub fn unpulled_stopped(ctx: &Ctx, env: &str) -> Result<Vec<workspace::Unpulled>> {
    let ws = EnvFile::load(&ctx.paths, env)?.cfg.workspace;
    let Some(state) = EnvState::load(&ctx.paths, env)? else {
        return Ok(Vec::new());
    };
    let targets = folders(&ws, &state.repos)?;
    if targets.is_empty() || !ctx.rt.volume_exists(&names::volume(env, "work")) {
        return Ok(Vec::new());
    }
    if ctx.rt.is_running(&names::dev(env)) {
        bail!("env `{env}` is running");
    }
    let id_map = env::dev_id_map(&ctx.rt, state.octet);
    let vol = VolumeBox::open(ctx, env, "work", id_map, false)?;
    let mut found = Vec::new();
    for t in &targets {
        let read = read_stopped(ctx, &vol, env, t).map_err(|e| match e {
            TarError::TooLarge => anyhow::anyhow!(
                "the env's files are more than the {} read from a stopped env",
                crate::disk::human(CAPS.read)
            ),
            e => anyhow::anyhow!("the env's files couldn't be read ({e})"),
        })?;
        let never = never_copied(ctx, &vol, env, t)?;
        let base = t.base(&ctx.paths, env);
        let plan = workspace::build_plan(&read, &t.dest, &t.skip, base.as_ref())?;
        let u = workspace::Unpulled::of(&plan, t, never);
        if u.any() {
            found.push(u);
        }
    }
    Ok(found)
}

/// Plan one folder: read the env's side, judge it, and fill in `report`. None when nothing
/// is to be written for it, which `report.deferred` then explains.
fn plan_folder(
    ctx: &Ctx,
    vol: &VolumeBox,
    env: &str,
    target: &PullTarget,
    report: &mut FolderReport,
) -> Option<Work> {
    let Some(old) = target.base(&ctx.paths, env) else {
        report.deferred = Some(format!(
            "luoto has no record of what the env's copy started from (an env made before it \
             kept one, or imported); `luoto pull -e {env}` reviews its files and starts one"
        ));
        return None;
    };
    if let Some(op) = mid_operation(&target.dest) {
        report.deferred = Some(format!("{op}; `luoto down -e {env}` tries again"));
        report.retry = true;
        return None;
    }
    let read = match read_stopped(ctx, vol, env, target) {
        Ok(r) => r,
        Err(e) => {
            report.retry = !matches!(e, TarError::TooLarge);
            report.deferred = Some(match e {
                TarError::TooLarge => format!(
                    "the env's files are more than the {} an unattended pull reads",
                    crate::disk::human(CAPS.read)
                ),
                e => format!("the env's files couldn't be read ({e})"),
            });
            return None;
        }
    };
    let found = never_copied(ctx, vol, env, target);
    let plan = workspace::build_plan(&read, &target.dest, &target.skip, Some(&old));
    let (plan, found) = match (plan, found) {
        (Ok(p), Ok(f)) => (p, f),
        (Err(e), _) | (_, Err(e)) => {
            report.deferred = Some(format!("the env's files couldn't be read ({e:#})"));
            report.retry = true;
            return None;
        }
    };
    let mut asked: Vec<String> = plan.entries.iter().map(|e| e.path.clone()).collect();
    asked.extend(found.iter().cloned());
    let facts = Facts {
        ignored: workspace::host_ignored(&target.dest, &asked),
        hooks: hooks_path(&target.dest),
    };
    let decided = decide(&plan, &facts);
    report.unchanged = plan.unchanged;
    report.yours = plan.yours;
    report.deleted = plan.deleted.clone();
    report.refused = plan.refused.clone();
    report.unread = plan.unread.clone();
    report.head_moved = plan.head_moved.clone();
    report.conflicts = decided.conflicts;
    report.held = decided.held;
    report.ignored = decided.ignored;
    report.never_copied = found
        .into_iter()
        .filter(|p| !facts.ignored.contains(p))
        .collect();
    let sizes: Vec<u64> = plan
        .entries
        .iter()
        .filter(|e| decided.write.contains(&e.path))
        .map(|e| e.size)
        .collect();
    if let Some(why) = over(&CAPS, &sizes, free_space(&target.dest)) {
        report.deferred = Some(format!("{why}; `luoto pull -e {env}` reviews them"));
        return None;
    }
    Some(Work {
        target: target.clone(),
        plan,
        write: decided.write,
        old,
    })
}

/// Pull the stopped env's files into its folders.
fn pull_stopped(ctx: &Ctx, env: &str, report: &mut Report) -> Result<()> {
    let ws = EnvFile::load(&ctx.paths, env)?.cfg.workspace;
    let state = EnvState::load(&ctx.paths, env)?
        .with_context(|| format!("env `{env}` has never started"))?;
    let targets = folders(&ws, &state.repos)?;
    if targets.is_empty() {
        bail!("env `{env}` has no folder on this machine to pull into");
    }
    env::ensure_vm(ctx)?;
    // Never from a running env: code in it could stall the read or write after it.
    if ctx.rt.is_running(&names::dev(env)) {
        bail!("env `{env}` is running");
    }
    env::ensure_image(ctx, &ctx.image("tools"))?;
    report.folders = targets
        .iter()
        .map(|t| FolderReport {
            dir: t.dest.display().to_string(),
            repo: t.repo.clone(),
            ..Default::default()
        })
        .collect();
    let mut work: Vec<Option<Work>> = Vec::new();
    {
        let _reading = crate::progress::waiting(&format!("reading the files of `{env}`"));
        let id_map = env::dev_id_map(&ctx.rt, state.octet);
        let vol = VolumeBox::open(ctx, env, "work", id_map, false)?;
        for (t, r) in targets.iter().zip(&mut report.folders) {
            work.push(plan_folder(ctx, &vol, env, t, r));
        }
    }
    // What is about to be written, on disk before any of it is.
    let journal = Journal {
        complete: false,
        folders: work
            .iter()
            .flatten()
            .map(|w| PlannedFolder {
                dir: w.plan.dir.clone(),
                entries: w
                    .write
                    .iter()
                    .filter_map(|rel| {
                        Some(Planned {
                            path: rel.clone(),
                            tmp: workspace::temp_name(),
                            new: w.plan.prints.get(rel)?.clone(),
                            was: w.plan.was(rel),
                        })
                    })
                    .collect(),
            })
            .collect(),
    };
    journal.save(&ctx.paths, env)?;
    let _writing = crate::progress::waiting("writing");
    let mut planned = journal.folders.iter();
    for (w, r) in work.iter().zip(&mut report.folders) {
        let (Some(w), Some(folder)) = (w, w.as_ref().and_then(|_| planned.next())) else {
            continue;
        };
        let picked: Vec<(String, String)> = folder
            .entries
            .iter()
            .map(|e| (e.path.clone(), e.tmp.clone()))
            .collect();
        let done = w.plan.write(&picked);
        r.held.extend(done.failed);
        r.written = done.written;
        if let Some(why) = done.unsynced {
            r.deferred = Some(format!("what was written isn't synced to disk ({why})"));
            continue;
        }
        let new = w.plan.rebased(Some(&w.old), &r.written);
        match new.save(&ctx.paths, env, w.target.repo.as_deref()) {
            Ok(()) => r.complete = true,
            Err(e) => r.deferred = Some(format!("what was pulled isn't recorded ({e:#})")),
        }
    }
    // A folder with nothing to write is as done as one written: only a failed sync or base
    // leaves the journal open.
    let open = work
        .iter()
        .zip(&report.folders)
        .any(|(w, r)| w.is_some() && !r.complete);
    if !open {
        Journal {
            complete: true,
            ..journal
        }
        .save(&ctx.paths, env)?;
    }
    Ok(())
}

/// Why an env stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// `luoto down`.
    Down,
    /// The watcher, after `idle_stop`.
    Idle,
    /// A `luoto run` ended (`--down`, `--rm`, `--dangerously-pull`).
    Run,
    /// The UI's stop.
    Ui,
    /// It stopped without its pull: a crash, a restart of the machine.
    Recovery,
}

impl Why {
    fn name(self) -> &'static str {
        match self {
            Why::Down => "down",
            Why::Idle => "idle",
            Why::Run => "run",
            Why::Ui => "ui",
            Why::Recovery => "recovery",
        }
    }
}

/// What an unattended pull does at a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pull {
    No,
    /// An interrupted run's files wait for a reviewed pull.
    Held,
    Yes,
}

/// Whether a stop pulls: with the env's setting or when its run asked (`asked`), unless an
/// interrupted run put its files on hold.
pub fn pull_at_stop(setting: bool, asked: bool, hold: bool) -> Pull {
    match (setting || asked, hold) {
        (false, _) => Pull::No,
        (true, true) => Pull::Held,
        (true, false) => Pull::Yes,
    }
}

/// What stopping an env did.
pub struct Stopped {
    pub was_running: bool,
    /// The unattended pull's report, when the stop pulled (or would have).
    pub report: Option<Report>,
}

/// Stop the env, and pull its files into its folders first when its own file says so
/// (`dangerously_pull_on_stop`) or `asked` (`luoto run --dangerously-pull`): from its volume,
/// once it has stopped. An env that wasn't running is pulled when a pull is owed to it.
pub fn stop(ctx: &Ctx, env: &str, why: Why, asked: bool) -> Result<Stopped> {
    if !asked && !on(&ctx.paths, env) {
        return Ok(Stopped {
            was_running: env::down(ctx, env)?,
            report: None,
        });
    }
    let _lock = lock(&ctx.paths, env)?;
    stop_locked(ctx, env, why, asked)
}

/// [`stop`] for an env that pulls, under its lock: what is owed is read only now, so two
/// stops of one env never both pull for the same reason.
fn stop_locked(ctx: &Ctx, env: &str, why: Why, asked: bool) -> Result<Stopped> {
    let pending = Pending::load(&ctx.paths, env);
    let pull = pull_at_stop(on(&ctx.paths, env), asked, pending.hold);
    if pull == Pull::Yes {
        Pending::update(&ctx.paths, env, |p| p.pull = true)?;
    }
    let was_running = env::down(ctx, env)?;
    let mut report = Report {
        env: env.to_string(),
        at: Some(Utc::now()),
        why: why.name().to_string(),
        ..Default::default()
    };
    match pull {
        Pull::Yes => {}
        Pull::Held => {
            report.held = true;
            report.save(&ctx.paths, env);
            // Said here: nothing is owed until a reviewed pull.
            Pending::update(&ctx.paths, env, |p| p.settled(false))?;
            return Ok(Stopped {
                was_running,
                report: Some(report),
            });
        }
        Pull::No => {
            return Ok(Stopped {
                was_running,
                report: None,
            });
        }
    }
    if !was_running && !asked && !pending.owed() {
        // Stopped and pulled already.
        Pending::update(&ctx.paths, env, |p| p.pull = false)?;
        return Ok(Stopped {
            was_running,
            report: None,
        });
    }
    if let Err(e) = pull_stopped(ctx, env, &mut report) {
        report.error = Some(crate::text::lines(&format!("{e:#}")));
    }
    report.save(&ctx.paths, env);
    let again = report.retry();
    Pending::update(&ctx.paths, env, |p| p.settled(again))?;
    Ok(Stopped {
        was_running,
        report: Some(report),
    })
}

/// The envs with something owed to their folder, or a pull cut short.
fn owing(paths: &Paths) -> Vec<String> {
    let Ok(dirs) = std::fs::read_dir(paths.data.join("pulls")) else {
        return Vec::new();
    };
    dirs.flatten()
        .filter_map(|d| d.file_name().into_string().ok())
        .filter(|n| config::validate_name(n).is_ok())
        .filter(|n| {
            Pending::load(paths, n).owed() || Journal::load(paths, n).is_some_and(|j| !j.complete)
        })
        .collect()
}

/// Whether any env has a pull to recover: cheap, for every command to ask.
pub fn any_owing(paths: &Paths) -> bool {
    !owing(paths).is_empty()
}

/// What `recover` does about an env's pending record.
#[derive(Debug, PartialEq, Eq)]
enum Owed {
    /// Nothing to do now: nothing is owed, or it was tried often enough and waits for
    /// `luoto down`.
    Nothing,
    /// Pull it, if it has stopped.
    Pull,
    /// Say that it stopped unpulled, if it has: its file no longer says to pull, or an
    /// interrupted run's files wait for a review.
    Tell,
}

fn owed(pending: &Pending, setting: bool) -> Owed {
    if !pending.owed() {
        Owed::Nothing
    } else if !setting || pending.hold {
        Owed::Tell
    } else if pending.attempts >= MAX_ATTEMPTS {
        Owed::Nothing
    } else {
        Owed::Pull
    }
}

/// Finish what a crash or a stop luoto didn't see left undone, for every env: clean up after
/// a pull cut short, and pull an env that stopped with one owed, when its file still says to
/// (else say so). On stderr. A removal that was to follow is never done here.
pub fn recover(ctx: &Ctx) {
    for env in owing(&ctx.paths) {
        if !ctx.paths.env_config(&env).exists() {
            forget(&ctx.paths, &env);
            continue;
        }
        // Whoever holds the lock is at it.
        let Some(_lock) = try_lock(&ctx.paths, &env) else {
            continue;
        };
        let note = |msg: String| crate::progress::note(&msg);
        if crate::machine::stopped(&ctx.rt) {
            note(format!(
                "env `{env}` stopped before its files were pulled: `luoto down -e {env}` pulls \
                 them"
            ));
            continue;
        }
        if let Some(r) = recover_journal(&ctx.paths, &env) {
            note(format!(
                "a pull of `{env}` was cut short: {} file(s) had been written, {} had not, {} \
                 changed since",
                r.done, r.not_done, r.changed
            ));
        }
        let pending = Pending::load(&ctx.paths, &env);
        let todo = owed(&pending, on(&ctx.paths, &env));
        // A running env is pulled when it stops.
        if todo == Owed::Nothing || ctx.rt.is_running(&names::dev(&env)) {
            continue;
        }
        // Said, never done: a removal is not resumed.
        let removal = match pending.rm {
            true => format!(" Its run was to remove it afterwards: `luoto rm -e {env}` does."),
            false => String::new(),
        };
        if todo == Owed::Tell {
            let _ = Pending::update(&ctx.paths, &env, |p| p.settled(false));
            note(format!(
                "env `{env}` stopped before its files were pulled: `luoto up -e {env}`, then \
                 `luoto pull -e {env}` reviews them.{removal}"
            ));
            continue;
        }
        note(format!(
            "env `{env}` stopped before its files were pulled: pulling them now.{removal}"
        ));
        match stop_locked(ctx, &env, Why::Recovery, false) {
            Ok(Stopped {
                report: Some(r), ..
            }) => r.print(&mut std::io::stderr(), crate::style::err(), 30),
            Ok(_) => {}
            Err(e) => crate::progress::warn(&format!("`{env}` not pulled ({e:#})")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::PlanEntry;

    fn paths(dir: &Path) -> Paths {
        Paths {
            config: dir.join("config"),
            data: dir.join("data"),
        }
    }

    #[test]
    fn tool_configs_that_are_code_are_held_back_at_any_depth() {
        for p in [
            "vite.config.ts",
            "web/eslint.config.mjs",
            "packages/app/tailwind.config.js",
            "Vite.Config.TS",
            ".eslintrc.cjs",
            ".prettierrc.js",
            "build.rs",
            "crates/core/build.rs",
            "tests/conftest.py",
            "Gemfile",
            "tool.gemspec",
            "android/build.gradle.kts",
            "flake.nix",
            ".pnp.cjs",
            ".yarn/releases/yarn-4.5.0.cjs",
            "web/.yarn/plugins/x.cjs",
            "nodemon.json",
        ] {
            assert!(unattended(p).is_some(), "{p}");
        }
        for p in [
            "src/main.rs",
            "src/config.ts",
            "docs/vite.config.md",
            "app.config.json",
            ".eslintrc.json",
            "src/build.rs.txt",
            ".yarn/cache/x.zip",
            "yarn/releases/x.cjs",
            "README.md",
        ] {
            assert!(unattended(p).is_none(), "{p}");
        }
    }

    #[test]
    fn a_folder_laid_out_as_a_repository_is_found() {
        let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        let files = set(&[
            "vendor/x/HEAD",
            "vendor/x/config",
            "vendor/x/description",
            "docs/HEAD",
            "docs/config",
            "HEAD",
        ]);
        let folders = set(&["vendor/x/objects", "vendor/x/refs", "docs/objects"]);
        assert_eq!(bare_roots(&files, &folders), ["vendor/x"]);
        let top = set(&["HEAD", "config"]);
        assert_eq!(bare_roots(&top, &set(&["objects", "refs"])), [""]);
        assert!(within("vendor/x/config", "vendor/x") && within("vendor/x", "vendor/x"));
        assert!(!within("vendor/xy/config", "vendor/x"));
        assert!(within("anything", ""));
    }

    #[test]
    fn the_hooks_folder_is_read_as_a_path_in_the_folder() {
        let dest = Path::new("/srv/web");
        assert_eq!(hooks_rel(dest, ".githooks"), Some(".githooks".into()));
        assert_eq!(
            hooks_rel(dest, "./tools/hooks/"),
            Some("tools/hooks".into())
        );
        assert_eq!(hooks_rel(dest, "/srv/web/hooks"), Some("hooks".into()));
        for outside in ["", "/usr/share/hooks", "~/hooks", "../hooks", "/srv/web"] {
            assert_eq!(hooks_rel(dest, outside), None, "{outside}");
        }
    }

    #[test]
    fn a_repository_mid_operation_is_told() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(mid_operation(d), None, "no repository");
        std::fs::create_dir(d.join(".git")).unwrap();
        assert_eq!(mid_operation(d), None);
        for (file, word) in [
            ("MERGE_HEAD", "merge"),
            ("index.lock", "git is running"),
            ("CHERRY_PICK_HEAD", "cherry-pick"),
        ] {
            std::fs::write(d.join(".git").join(file), b"").unwrap();
            assert!(mid_operation(d).unwrap().contains(word), "{file}");
            std::fs::remove_file(d.join(".git").join(file)).unwrap();
        }
        std::fs::create_dir(d.join(".git/rebase-merge")).unwrap();
        assert!(mid_operation(d).unwrap().contains("rebase"));
        // A work tree whose `.git` names the repository's folder for it.
        let tree = tempfile::tempdir().unwrap();
        let text = format!("gitdir: {}\n", d.join(".git").display());
        std::fs::write(tree.path().join(".git"), text).unwrap();
        assert!(mid_operation(tree.path()).unwrap().contains("rebase"));
    }

    #[test]
    fn over_a_cap_nothing_is_written() {
        let caps = Caps {
            read: 1000,
            bytes: 100,
            files: 3,
            file: 60,
            spare: 50,
        };
        assert_eq!(over(&caps, &[10, 20, 30], Some(1000)), None);
        assert_eq!(
            over(&caps, &[], Some(0)),
            None,
            "nothing to write needs no room"
        );
        assert!(
            over(&caps, &[1, 1, 1, 1], None)
                .unwrap()
                .contains("4 files")
        );
        assert!(over(&caps, &[61], None).unwrap().contains("a file of 61 B"));
        assert!(
            over(&caps, &[50, 51], None)
                .unwrap()
                .contains("101 B changed")
        );
        assert!(
            over(&caps, &[40, 40], Some(129))
                .unwrap()
                .contains("129 B free")
        );
        assert_eq!(over(&caps, &[40, 40], Some(130)), None);
        assert_eq!(
            over(&caps, &[40, 40], None),
            None,
            "a disk that doesn't say"
        );
    }

    fn entry(path: &str, change: &str, risky: Option<&str>, executable: bool) -> PlanEntry {
        PlanEntry {
            path: path.into(),
            change: change.into(),
            size: 1,
            executable,
            risky: risky.map(str::to_string),
        }
    }

    #[test]
    fn an_unattended_pull_writes_only_what_nothing_runs_by_itself() {
        let dest = tempfile::tempdir().unwrap();
        let mut plan = workspace::build_plan(
            &TarRead {
                raw: Vec::new(),
                failed: None,
            },
            dest.path(),
            &[],
            None,
        )
        .unwrap();
        plan.entries = vec![
            entry("src/a.rs", "changed", None, false),
            entry("src/new.rs", "new", None, false),
            entry("src/both.rs", "conflict", None, false),
            entry(".envrc", "new", Some("direnv loads it"), false),
            entry("vite.config.ts", "changed", None, false),
            entry("scripts/run.sh", "changed", None, true),
            entry(".githooks/pre-commit", "changed", None, false),
            entry("vendor/x/config", "new", None, false),
            entry("dist/app.js", "new", None, false),
            entry("dist/vite.config.js", "new", None, false),
        ];
        plan.present = ["vendor/x/HEAD", "vendor/x/config"]
            .map(String::from)
            .into();
        plan.folders = ["vendor/x/objects", "vendor/x/refs"]
            .map(String::from)
            .into();
        let facts = Facts {
            ignored: ["dist/app.js", "dist/vite.config.js"]
                .map(String::from)
                .into(),
            hooks: Some(".githooks".into()),
        };
        let d = decide(&plan, &facts);
        assert_eq!(d.write, ["src/a.rs", "src/new.rs"]);
        assert_eq!(d.conflicts, ["src/both.rs"]);
        assert_eq!(d.ignored, 2);
        let held: Vec<&str> = d.held.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            held,
            [
                ".envrc",
                "vite.config.ts",
                "scripts/run.sh",
                ".githooks/pre-commit",
                "vendor/x/config"
            ]
        );
        assert!(d.held[2].1.contains("executable"));
        assert!(d.held[3].1.contains("hooks"));
        assert!(d.held[4].1.contains("git repository"));
    }

    #[test]
    fn a_stop_pulls_with_the_setting_or_when_its_run_asked_unless_on_hold() {
        // (setting, asked, hold)
        assert_eq!(pull_at_stop(false, false, false), Pull::No);
        assert_eq!(pull_at_stop(false, false, true), Pull::No);
        // `luoto down`, the UI's stop and the idle stop: only the setting.
        assert_eq!(pull_at_stop(true, false, false), Pull::Yes);
        // `luoto run --dangerously-pull`, with or without it.
        assert_eq!(pull_at_stop(false, true, false), Pull::Yes);
        assert_eq!(pull_at_stop(true, true, false), Pull::Yes);
        // After an interrupted run nothing lands unreviewed.
        assert_eq!(pull_at_stop(true, false, true), Pull::Held);
        assert_eq!(pull_at_stop(false, true, true), Pull::Held);
    }

    #[test]
    fn what_is_owed_is_recorded_until_it_is_settled() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        assert!(!Pending::load(&p, "web").owed());
        assert!(!any_owing(&p));
        expect(&p, "web", true).unwrap();
        let now = Pending::load(&p, "web");
        assert!(now.owed() && now.pull && now.rm);
        assert!(any_owing(&p));
        // A pull that couldn't run stays owed, counted.
        Pending::update(&p, "web", |x| x.settled(true)).unwrap();
        let now = Pending::load(&p, "web");
        assert_eq!((now.pull, now.rm, now.attempts), (true, false, 1));
        // One that ran leaves nothing, and no file.
        Pending::update(&p, "web", |x| x.settled(false)).unwrap();
        assert_eq!(Pending::load(&p, "web"), Pending::default());
        assert!(!Pending::file(&p, "web").exists());
        // An interrupted run: on hold, with no pull owed, until a reviewed pull.
        expect(&p, "web", false).unwrap();
        Pending::update(&p, "web", |x| x.dirty = true).unwrap();
        hold(&p, "web");
        let held = Pending::load(&p, "web");
        assert!(held.hold && !held.owed());
        reviewed(&p, "web");
        assert!(!Pending::load(&p, "web").hold);
        // A removed env's records go; its report stays.
        expect(&p, "web", false).unwrap();
        std::fs::write(report_file(&p, "web"), b"{}").unwrap();
        forget(&p, "web");
        assert!(!any_owing(&p) && report_file(&p, "web").exists());
    }

    #[test]
    fn a_pull_owed_is_done_while_the_file_says_so_and_only_a_few_times_unasked() {
        let pending = |f: &dyn Fn(&mut Pending)| {
            let mut p = Pending::default();
            f(&mut p);
            p
        };
        assert_eq!(owed(&Pending::default(), true), Owed::Nothing);
        // The env started with the setting and was never seen to stop; or its stop was cut.
        assert_eq!(owed(&pending(&|p| p.dirty = true), true), Owed::Pull);
        assert_eq!(owed(&pending(&|p| p.pull = true), true), Owed::Pull);
        // A run's one-off pull, or a setting turned off since: only a person's review now.
        assert_eq!(owed(&pending(&|p| p.pull = true), false), Owed::Tell);
        let held = pending(&|p| {
            p.dirty = true;
            p.hold = true;
        });
        assert_eq!(owed(&held, true), Owed::Tell);
        // Tried and deferred three times: it waits for `luoto down`.
        let tried = pending(&|p| {
            p.pull = true;
            p.attempts = MAX_ATTEMPTS;
        });
        assert_eq!(owed(&tried, true), Owed::Nothing);
        // An interrupted run's hold alone owes nothing.
        assert_eq!(owed(&pending(&|p| p.hold = true), true), Owed::Nothing);
    }

    #[test]
    fn a_planned_writes_fate_is_told_by_its_fingerprint() {
        let (old, new, other) = (
            Print::of_bytes(b"old", false),
            Print::of_bytes(b"new", false),
            Print::of_bytes(b"other", false),
        );
        let is = |p: &Print| Host::Is(p.clone());
        assert_eq!(fate(&new, Some(&old), &is(&new)), Fate::Done);
        assert_eq!(fate(&new, None, &is(&new)), Fate::Done);
        assert_eq!(fate(&new, Some(&old), &is(&old)), Fate::NotDone);
        assert_eq!(fate(&new, None, &Host::Absent), Fate::NotDone);
        assert_eq!(fate(&new, Some(&old), &is(&other)), Fate::Changed);
        assert_eq!(fate(&new, Some(&old), &Host::Absent), Fate::Changed);
        assert_eq!(fate(&new, None, &is(&other)), Fate::Changed);
        assert_eq!(fate(&new, Some(&old), &Host::Other), Fate::Changed);
    }

    #[test]
    fn a_pull_cut_short_is_cleaned_up_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths(dir.path());
        let dest = tempfile::tempdir().unwrap();
        let d = dest.path();
        assert_eq!(recover_journal(&p, "web"), None, "no journal");
        let print = |s: &str| Print::of_bytes(s.as_bytes(), false);
        let plan = |path: &str, tmp: &str, new: &str, was: Option<&str>| Planned {
            path: path.into(),
            tmp: tmp.into(),
            new: print(new),
            was: was.map(print),
        };
        // Written, not yet written (its temp file half made), changed by someone since, a
        // new file never written, and names no pull would have journaled.
        std::fs::write(d.join("done.txt"), "new").unwrap();
        std::fs::write(d.join("todo.txt"), "old").unwrap();
        std::fs::write(d.join(".luoto-00112233aabbccdd.tmp"), "ne").unwrap();
        std::fs::write(d.join("edited.txt"), "mine").unwrap();
        std::fs::write(d.join("keep.tmp"), "mine").unwrap();
        let journal = Journal {
            complete: false,
            folders: vec![PlannedFolder {
                dir: d.display().to_string(),
                entries: vec![
                    plan(
                        "done.txt",
                        ".luoto-0000000000000001.tmp",
                        "new",
                        Some("old"),
                    ),
                    plan(
                        "todo.txt",
                        ".luoto-00112233aabbccdd.tmp",
                        "new",
                        Some("old"),
                    ),
                    plan(
                        "edited.txt",
                        ".luoto-0000000000000002.tmp",
                        "new",
                        Some("old"),
                    ),
                    plan("fresh.txt", ".luoto-0000000000000003.tmp", "new", None),
                    plan("x.txt", "keep.tmp", "new", None),
                    plan("../outside.txt", ".luoto-0000000000000004.tmp", "new", None),
                ],
            }],
        };
        journal.save(&p, "web").unwrap();
        assert!(any_owing(&p));
        assert_eq!(
            recover_journal(&p, "web"),
            Some(Recovered {
                done: 1,
                not_done: 3,
                changed: 2,
                temps: 1
            })
        );
        assert!(!d.join(".luoto-00112233aabbccdd.tmp").exists());
        assert!(
            d.join("keep.tmp").exists(),
            "only luoto's own temp names go"
        );
        assert_eq!(recover_journal(&p, "web"), None, "once");
        // A journal marked complete is nothing to recover.
        Journal {
            complete: true,
            ..journal
        }
        .save(&p, "web")
        .unwrap();
        assert!(!any_owing(&p));
        assert_eq!(recover_journal(&p, "web"), None);
    }

    fn folder(written: usize) -> FolderReport {
        FolderReport {
            dir: "/srv/work/web".into(),
            written: (0..written).map(|i| format!("f{i}")).collect(),
            complete: true,
            ..Default::default()
        }
    }

    fn report(folders: Vec<FolderReport>) -> Report {
        Report {
            env: "web".into(),
            folders,
            ..Default::default()
        }
    }

    #[test]
    fn an_env_is_removable_only_when_everything_landed() {
        let clean = report(vec![folder(3)]);
        assert!(!clean.incomplete() && clean.removable());
        let with = |f: &dyn Fn(&mut FolderReport)| {
            let mut one = folder(1);
            f(&mut one);
            report(vec![folder(2), one])
        };
        for r in [
            with(&|f| f.held.push((".envrc".into(), "direnv".into()))),
            with(&|f| f.conflicts.push("a".into())),
            with(&|f| f.refused.push(("l".into(), "leaves".into()))),
            with(&|f| f.unread = Some("tar: x".into())),
            with(&|f| f.deferred = Some("a merge".into())),
            with(&|f| f.complete = false),
        ] {
            assert!(r.incomplete() && !r.removable(), "{r:?}");
        }
        // What no pull takes keeps the env, without making the pull incomplete.
        let left = with(&|f| f.never_copied.push("node_modules".into()));
        assert!(!left.incomplete() && !left.removable());
        // What the env deleted, or the folder's repository ignores, is nothing held.
        let fine = with(&|f| {
            f.deleted.push("old.rs".into());
            f.ignored = 4;
        });
        assert!(fine.removable());
        let failed = Report {
            error: Some("no volume".into()),
            ..report(vec![])
        };
        assert!(failed.incomplete() && failed.retry());
        let held = Report {
            held: true,
            ..report(vec![])
        };
        assert!(held.incomplete() && !held.retry());
    }

    #[test]
    fn a_notification_carries_counts_and_folders_never_a_file_name() {
        assert_eq!(report(vec![folder(0)]).note(), None, "nothing to tell");
        let mut f = folder(14);
        f.held = vec![
            ("\u{1b}]0;evil\u{7}.envrc".into(), "direnv".into()),
            ("vite.config.ts".into(), "code".into()),
        ];
        let note = report(vec![f]).note().unwrap();
        assert_eq!(note.title, "luoto pulled 14 files from `web`");
        assert_eq!(
            note.body,
            "into /srv/work/web; 2 held back: `luoto pull -e web`"
        );
        assert!(!note.body.contains("envrc") && !note.body.contains("evil"));
        let mut deferred = folder(0);
        deferred.deferred = Some("a merge is under way in it".into());
        let note = report(vec![deferred]).note().unwrap();
        assert_eq!(note.title, "luoto pulled nothing from `web`");
        assert!(
            note.body
                .ends_with("not all of it could be pulled: `luoto pull -e web`")
        );
        assert_eq!(
            report(vec![folder(1)]).note().unwrap().title,
            "luoto pulled 1 file from `web`"
        );
    }

    #[test]
    fn a_report_lists_what_happened_capped_and_escaped() {
        let mut f = folder(3);
        f.held = vec![("a\u{1b}[2J.envrc".into(), "direnv loads it".into())];
        f.conflicts = vec!["src/both.rs".into()];
        f.deleted = vec!["old.rs".into()];
        f.never_copied = vec!["node_modules".into()];
        f.ignored = 2;
        let r = report(vec![f]);
        let mut out = Vec::new();
        r.print(&mut out, crate::style::Style::PLAIN, 2);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "pulled 3 file(s) from `web` into /srv/work/web\n\
             wrote:\n  f0\n  f1\n  … and 1 more\n\
             held back (`luoto pull -e web` reviews them):\n  a\\u{1b}[2J.envrc — direnv loads it\n\
             changed here and in the env (yours kept):\n  src/both.rs\n\
             deleted in the env, kept here:\n  old.rs\n\
             never copied, so only in the env:\n  node_modules\n\
             2 file(s) your .gitignore ignores stay in the env\n"
        );
        assert_eq!(
            r.line(),
            "pulled 3 file(s) from `web` into /srv/work/web; 2 left for you: `luoto pull -e web` \
             reviews"
        );
        for l in text.lines() {
            assert!(l.chars().count() <= 80, "{l}");
        }
    }

    #[test]
    fn only_folders_of_the_envs_own_file_are_pulled_into() {
        let root = tempfile::tempdir().unwrap();
        let api = tempfile::tempdir().unwrap();
        let repo = |dir: Option<&Path>| config::Repo {
            dir: dir.map(|d| d.display().to_string()),
            url: dir.is_none().then(|| "acme/web".to_string()),
            ..Default::default()
        };
        let repos = std::collections::BTreeMap::from([
            ("api".to_string(), repo(Some(api.path()))),
            ("web".to_string(), repo(None)),
        ]);
        let present: BTreeSet<String> = ["api", "web"].map(String::from).into();
        let with_folder = Workspace {
            dir: Some(root.path().display().to_string()),
            repos: repos.clone(),
            ..Default::default()
        };
        let all = folders(&with_folder, &present).unwrap();
        let names: Vec<Option<&str>> = all.iter().map(|t| t.repo.as_deref()).collect();
        assert_eq!(names, [None, Some("api")]);
        // A virtual workspace: its folder repos; a clone alone has no folder here.
        let launchpad = Workspace {
            repos,
            ..Default::default()
        };
        let all = folders(&launchpad, &present).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].repo.as_deref(), Some("api"));
        let cloned = Workspace {
            url: Some("acme/web".into()),
            ..Default::default()
        };
        assert!(folders(&cloned, &present).unwrap().is_empty());
    }
}
