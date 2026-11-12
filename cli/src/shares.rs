//! `luoto share`: folders of this machine an env reads at `/shares/<name>`, read-only. Each is
//! cloned into luoto's shares folder (`<root>/<instance>/<env>/<name>`; on APFS, btrfs and XFS a
//! clone of a file on the same disk takes no space until the file changes) and that env's
//! folder is mounted read-only in its dev container. On luoto's podman VM the shares folder is
//! the one folder of this machine the VM mounts, read-only, added after a yes
//! (`machine::ensure_shares`). A sync (every `up`, `luoto share sync`) clones again what changed
//! in the shared folder and removes what it no longer holds; nothing comes back. Only the env's
//! own file names a share (a repo's `luoto.toml` can't, `luoto import` leaves an archive's out),
//! and the folder is checked at every sync: inside the home folder (never home itself, a
//! dot-folder or `~/Library`) or on a disk (`/Volumes`, `/mnt`, `/media`, `/srv`), and never
//! a key folder (`.ssh`, `.aws`, …) anywhere. Only plain files are cloned, never what a symlink
//! points to, and a clone's folder is never written through a symlink.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};

use crate::config::{EnvConfig, EnvFile};
use crate::env::Ctx;
use crate::paths::Paths;
use crate::runtime::{Flavor, exec};
use crate::text::{display, sh_quote};
use crate::{machine, names, progress};

/// Where an env's shares are in its dev container.
pub const IN_ENV: &str = "/shares";

/// Folders that hold keys and tokens: never shared, nor what holds them, nor cloned from
/// inside a shared folder.
const KEYS: [&str; 7] = [
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".password-store",
];

/// Roots outside the home folder whose folders are disks of their own.
const DISKS: [&str; 4] = ["/Volumes", "/mnt", "/media", "/srv"];

/// luoto's shares folder: every instance's and env's clones, and the one folder luoto's
/// podman VM mounts.
pub fn root() -> Result<PathBuf> {
    let base = directories::BaseDirs::new().context("cannot determine the home directory")?;
    Ok(base.home_dir().join(".local/share/luoto-shares"))
}

/// `env`'s folder of clones.
fn env_dir(env: &str) -> Result<PathBuf> {
    Ok(root()?.join(names::instance()).join(env))
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn name_error(name: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`{}` is not a share name (lowercase letters, digits, `-` and `_`)",
        display(name)
    )
}

/// What an env file's `[shares]` may hold, checked as it loads: share names, and full paths
/// (`/…` or `~/…`), so that no share depends on the folder luoto runs in.
pub fn check_config(shares: &BTreeMap<String, String>) -> Result<()> {
    for (name, folder) in shares {
        if !valid_name(name) {
            return Err(name_error(name).context("[shares]"));
        }
        if !(folder.starts_with('/') || folder.starts_with("~/")) {
            bail!(
                "[shares] {name}: {} is not a full path (`/…` or `~/…`)",
                display(folder)
            );
        }
    }
    Ok(())
}

/// The real folder `folder` names, if it may be shared as `name`.
pub fn checked(paths: &Paths, name: &str, folder: &str) -> Result<PathBuf> {
    if !valid_name(name) {
        return Err(name_error(name));
    }
    if crate::workspace::network_path(folder) {
        bail!(
            "{} is on another machine: share a local folder",
            display(folder)
        );
    }
    let real = crate::workspace::canonical(folder)?;
    if !real.is_dir() {
        bail!("{} is not a folder", real.display());
    }
    let home = directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .and_then(|h| h.canonicalize().ok());
    let inside = |root: &Path| real.starts_with(root) && real != root;
    let under_home = home.as_deref().is_some_and(inside);
    let on_disk = DISKS.iter().any(|d| inside(Path::new(d)));
    if !under_home && !on_disk {
        bail!(
            "{}: a share is a folder inside your home folder, or on a disk under {}",
            real.display(),
            DISKS.join(", ")
        );
    }
    // At the top of home, dot-folders and ~/Library hold tools' and apps' data and tokens.
    let app_data = home
        .as_deref()
        .and_then(|h| real.strip_prefix(h).ok())
        .and_then(|rel| rel.components().next())
        .is_some_and(|c| {
            let c = c.as_os_str().to_string_lossy();
            c.starts_with('.') || c == "Library"
        });
    let keys = real
        .components()
        .any(|c| KEYS.contains(&&*c.as_os_str().to_string_lossy()));
    if app_data || keys {
        bail!(
            "{} holds keys or app data: share another folder",
            real.display()
        );
    }
    for own in [paths.config.clone(), paths.data.clone(), root()?] {
        if let Ok(own) = own.canonicalize()
            && (real.starts_with(&own) || own.starts_with(&real))
        {
            bail!(
                "{} holds luoto's own files: share another folder",
                real.display()
            );
        }
    }
    Ok(real)
}

/// Whether the runtime is luoto's podman VM, which sees the shares folder only once it has it.
fn in_vm(ctx: &Ctx) -> bool {
    ctx.rt.flavor == Flavor::Podman && machine::is_luoto(ctx.rt.connection.as_deref())
}

/// What the dev container of `env` binds at [`IN_ENV`], if it has shares: its folder of
/// clones, as the runtime sees it (on luoto's podman VM, through the VM's shares folder, once
/// the VM has it).
pub fn mount_source(ctx: &Ctx, env: &str, cfg: &EnvConfig) -> Result<Option<String>> {
    if cfg.shares.is_empty() || cfg!(windows) {
        return Ok(None);
    }
    real_dir(&root()?, &[names::instance(), env])?;
    if !in_vm(ctx) {
        return Ok(Some(env_dir(env)?.to_string_lossy().into_owned()));
    }
    if !machine::has_shares(&ctx.rt.bin) {
        return Ok(None);
    }
    Ok(Some(format!(
        "{}/{}/{env}",
        machine::SHARES_IN_VM,
        names::instance()
    )))
}

/// Whether the env's running dev container has its shares mount: one made before the env had
/// shares, or before luoto's VM had the shares folder, needs `up --recreate` once. Asked of the
/// container, so code in it could hide the hint, never reach a folder.
fn mounted(ctx: &Ctx, env: &str) -> bool {
    ctx.rt
        .run(exec(&names::dev(env)).sh(&format!("grep -q ' {IN_ENV} ' /proc/mounts")))
        .is_ok()
}

/// What `env` still needs to read its shares: the command that gives it.
pub fn needs(ctx: &Ctx, env: &str, cfg: &EnvConfig) -> Option<String> {
    if cfg.shares.is_empty() || cfg!(windows) {
        None
    } else if in_vm(ctx) && !machine::has_shares(&ctx.rt.bin) {
        Some(format!("luoto share sync -e {env} --yes"))
    } else if ctx.rt.is_running(&names::dev(env)) && !mounted(ctx, env) {
        Some(format!("luoto up --recreate -e {env}"))
    } else {
        None
    }
}

/// One file's size and modification time.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Stamp {
    size: u64,
    mtime: SystemTime,
}

/// What is under a folder, by path (`/`-separated); a symlink is never followed, and a key
/// folder ([`KEYS`]) never entered.
#[derive(Debug, Default)]
struct Walk {
    files: BTreeMap<String, Stamp>,
    /// Neither a plain file nor a folder: symlinks, sockets, devices.
    others: Vec<String>,
    /// Entries that couldn't be read (a root-only `.Trashes` on a disk).
    unreadable: usize,
}

fn walk(root: &Path) -> Result<Walk> {
    fn go(root: &Path, rel: &str, out: &mut Walk) -> Result<()> {
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if rel.is_empty() => {
                return Err(e).with_context(|| format!("read {}", dir.display()));
            }
            Err(_) => {
                out.unreadable += 1;
                return Ok(());
            }
        };
        for entry in entries {
            let Ok(entry) = entry else {
                out.unreadable += 1;
                continue;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                out.unreadable += 1;
                continue;
            };
            let r = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            match std::fs::symlink_metadata(entry.path()) {
                Ok(m) if m.is_dir() => {
                    if !KEYS.contains(&name.as_str()) {
                        go(root, &r, out)?;
                    }
                }
                Ok(m) if m.is_file() => match m.modified() {
                    Ok(mtime) => {
                        out.files.insert(
                            r,
                            Stamp {
                                size: m.len(),
                                mtime,
                            },
                        );
                    }
                    Err(_) => out.unreadable += 1,
                },
                Ok(_) => out.others.push(r),
                Err(_) => out.unreadable += 1,
            }
        }
        Ok(())
    }
    let mut out = Walk::default();
    if root.is_dir() {
        go(root, "", &mut out)?;
    }
    Ok(out)
}

/// What a sync clones again and removes, from the folder's files and the clones'.
fn diff(
    folder: &BTreeMap<String, Stamp>,
    clones: &BTreeMap<String, Stamp>,
) -> (Vec<String>, Vec<String>) {
    let send = folder
        .iter()
        .filter(|(p, s)| clones.get(*p) != Some(s))
        .map(|(p, _)| p.clone())
        .collect();
    let remove = clones
        .keys()
        .filter(|p| !folder.contains_key(*p))
        .cloned()
        .collect();
    (send, remove)
}

/// `base/parts…` as real folders: anything else in the way (a symlink, a file) is removed
/// first, so nothing is ever written through a link someone planted among the clones.
fn real_dir(base: &Path, parts: &[&str]) -> Result<PathBuf> {
    let mut at = base.to_path_buf();
    std::fs::create_dir_all(&at)?;
    for part in parts {
        at.push(part);
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => continue,
            Ok(_) => std::fs::remove_file(&at)?,
            Err(_) => {}
        }
        std::fs::create_dir(&at).with_context(|| format!("create {}", at.display()))?;
    }
    Ok(at)
}

/// Clone the folder's file `rel` (`/`-separated) to the clones at `dst`: readable by anyone,
/// as the env's user may be any ID, and with its time, so the next sync sees it as the same.
fn clone_file(src: &Path, dst: &Path, rel: &str, mtime: SystemTime) -> Result<()> {
    let parts: Vec<&str> = rel.split('/').collect();
    let (file, dirs) = parts.split_last().context("empty path")?;
    let to = real_dir(dst, dirs)?.join(file);
    match std::fs::symlink_metadata(&to) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(&to)?,
        Ok(_) => std::fs::remove_file(&to)?,
        Err(_) => {}
    }
    std::fs::copy(src.join(rel), &to).with_context(|| format!("clone {rel}"))?;
    // Writable to its owner (a copy keeps a read-only source's mode), as setting its time
    // needs on Windows.
    #[cfg(unix)]
    let perms = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(0o644)
    };
    #[cfg(not(unix))]
    #[allow(clippy::permissions_set_readonly_false)] // Windows: clears only the read-only flag
    let perms = {
        let mut p = std::fs::metadata(&to)?.permissions();
        p.set_readonly(false);
        p
    };
    std::fs::set_permissions(&to, perms)?;
    std::fs::File::options()
        .write(true)
        .open(&to)?
        .set_modified(mtime)?;
    Ok(())
}

/// What one sync of a share did, or why it couldn't.
#[derive(Debug, Default)]
pub struct Synced {
    name: String,
    files: usize,
    bytes: u64,
    cloned: usize,
    removed: usize,
    /// Files in the folder that couldn't be read or cloned.
    skipped: usize,
    error: Option<String>,
}

impl Synced {
    /// Whether it did anything worth a line where nothing was asked (`up`).
    pub fn worth_saying(&self) -> bool {
        self.cloned + self.removed + self.skipped > 0 || self.error.is_some()
    }

    pub fn failed(&self) -> bool {
        self.error.is_some()
    }

    pub fn said(&self) -> String {
        if let Some(e) = &self.error {
            return format!("share {} not synced: {e}", self.name);
        }
        let mut what = match (self.cloned, self.removed) {
            (0, 0) => "up to date".to_string(),
            (c, 0) => format!("{c} file(s) updated"),
            (0, r) => format!("{r} removed"),
            (c, r) => format!("{c} file(s) updated, {r} removed"),
        };
        if self.skipped > 0 {
            what += &format!(", {} unreadable left out", self.skipped);
        }
        format!(
            "share {}: {what}; {} file(s), {} in all",
            self.name,
            self.files,
            crate::disk::human(self.bytes)
        )
    }
}

/// Bring the clones at `dst` up to the folder `src`: changed files cloned anew, gone ones
/// removed, and anything there that isn't a plain file or folder removed.
fn mirror(src: &Path, dst: &Path) -> Result<Synced> {
    let have = walk(src)?;
    let clones = walk(dst)?;
    let (send, remove) = diff(&have.files, &clones.files);
    let mut skipped = have.unreadable;
    let mut cloned = 0;
    for f in &send {
        match clone_file(src, dst, f, have.files[f].mtime) {
            Ok(()) => cloned += 1,
            Err(_) => skipped += 1,
        }
    }
    for f in remove.iter().chain(&clones.others) {
        let _ = std::fs::remove_file(dst.join(f));
    }
    prune_empty(dst);
    Ok(Synced {
        files: have.files.len(),
        bytes: have.files.values().map(|s| s.size).sum(),
        cloned,
        removed: remove.len(),
        skipped,
        ..Synced::default()
    })
}

/// Remove the empty folders under `dir`, deepest first; `dir` itself stays.
fn prune_empty(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            let p = e.path();
            prune_empty(&p);
            let _ = std::fs::remove_dir(&p);
        }
    }
}

/// Sync `cfg`'s shares (only `only`, if given) for `env`, and drop the clones of shares it no
/// longer has.
pub fn sync(ctx: &Ctx, env: &str, cfg: &EnvConfig, only: Option<&str>) -> Vec<Synced> {
    if cfg!(windows) {
        return Vec::new();
    }
    if cfg.shares.is_empty() {
        forget(env);
        return Vec::new();
    }
    let dir = match env_dir(env).and_then(|d| {
        real_dir(&root()?, &[names::instance(), env])?;
        Ok(d)
    }) {
        Ok(d) => d,
        Err(e) => {
            return vec![Synced {
                name: "folder".into(),
                error: Some(format!("{e:#}")),
                ..Synced::default()
            }];
        }
    };
    if only.is_none()
        && let Ok(entries) = std::fs::read_dir(&dir)
    {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !cfg.shares.contains_key(&name) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    cfg.shares
        .iter()
        .filter(|(n, _)| only.is_none_or(|o| o == n.as_str()))
        .map(|(name, folder)| {
            let result = checked(&ctx.paths, name, folder).and_then(|real| {
                progress::wait(&format!("syncing share {name}"), || {
                    mirror(&real, &real_dir(&dir, &[name])?)
                })
            });
            match result {
                Ok(s) => Synced {
                    name: name.clone(),
                    ..s
                },
                Err(e) => Synced {
                    name: name.clone(),
                    error: Some(format!("{e:#}")),
                    ..Synced::default()
                },
            }
        })
        .collect()
}

/// Drop every clone of `env`'s shares: the env is gone.
pub fn forget(env: &str) {
    if let Ok(d) = env_dir(env) {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A share as it stands: its folder's files, and how many differ from the env's clones.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareStatus {
    pub name: String,
    pub folder: String,
    pub files: usize,
    pub bytes: u64,
    /// Files changed, added or removed in the folder since the last sync.
    pub changed: usize,
    /// Why it can't be synced (the folder gone, or refused); none when it can.
    pub error: Option<String>,
}

/// Each of `cfg`'s shares as it stands, without syncing.
pub fn status(paths: &Paths, env: &str, cfg: &EnvConfig) -> Vec<ShareStatus> {
    cfg.shares
        .iter()
        .map(|(name, folder)| {
            let now = (|| -> Result<(usize, u64, usize)> {
                let have = walk(&checked(paths, name, folder)?)?.files;
                let (send, remove) = diff(&have, &walk(&env_dir(env)?.join(name))?.files);
                Ok((
                    have.len(),
                    have.values().map(|s| s.size).sum(),
                    send.len() + remove.len(),
                ))
            })();
            let (files, bytes, changed) = now.as_ref().map_or((0, 0, 0), |n| *n);
            ShareStatus {
                name: name.clone(),
                folder: folder.clone(),
                files,
                bytes,
                changed,
                error: now.err().map(|e| format!("{e:#}")),
            }
        })
        .collect()
}

/// An env's shares as the UI shows them.
#[derive(Debug, serde::Serialize)]
pub struct SharesView {
    pub shares: Vec<ShareStatus>,
    /// What the env still needs to read them: the command that gives it.
    pub fix: Option<String>,
}

pub fn view(ctx: &Ctx, env: &str) -> Result<SharesView> {
    let cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    Ok(SharesView {
        shares: status(&ctx.paths, env, &cfg),
        fix: needs(ctx, env, &cfg),
    })
}

/// What a sync from the UI did: a line per share, for people.
#[derive(Debug, serde::Serialize)]
pub struct SyncedShares {
    pub said: Vec<String>,
    pub failed: bool,
}

pub fn sync_for_ui(ctx: &Ctx, env: &str) -> Result<SyncedShares> {
    let cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    let done = sync(ctx, env, &cfg, None);
    Ok(SyncedShares {
        failed: done.iter().any(Synced::failed),
        said: done.iter().map(Synced::said).collect(),
    })
}

/// The name a folder is shared under by default: its last part, made a share name.
fn default_name(folder: &Path) -> String {
    let base = folder
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let name: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    name.trim_matches('-').chars().take(64).collect()
}

fn refuse_windows() -> Result<()> {
    if cfg!(windows) {
        bail!("shares aren't supported on Windows yet");
    }
    Ok(())
}

/// `luoto share add`.
pub fn add(env: &str, folder: &str, name: Option<&str>, yes: bool) -> Result<ExitCode> {
    refuse_windows()?;
    let ctx = Ctx::load()?;
    let given = std::path::absolute(crate::workspace::expand(folder))?;
    let name = name.map_or_else(|| default_name(&given), str::to_string);
    let real = checked(&ctx.paths, &name, folder)?;
    let mut f = EnvFile::load(&ctx.paths, env)?;
    if let Some(had) = f.cfg.shares.get(&name)
        && Path::new(had) != real
    {
        bail!(
            "env `{env}` shares {} as `{name}` already; `--name` gives this one another",
            display(had)
        );
    }
    if in_vm(&ctx) {
        let again = format!(
            "luoto share add -e {env} {} --yes",
            sh_quote(&real.to_string_lossy())
        );
        machine::ensure_shares(&ctx.rt.bin, &root()?, yes, &again)?;
    }
    let folder = real.to_string_lossy().into_owned();
    f.set_in_table("shares", &name, &folder)?;
    f.cfg.shares.insert(name.clone(), folder);
    for s in sync(&ctx, env, &f.cfg, Some(&name)) {
        println!("{}", s.said());
    }
    println!(
        "{}",
        crate::prompt::summary(
            &format!("share {name}"),
            &[
                ("folder", real.display().to_string()),
                ("in the env", format!("{IN_ENV}/{name}, read-only")),
                ("change it", format!("luoto share rm -e {env} {name}")),
            ],
        )
    );
    if let Some(cmd) = needs(&ctx, env, &f.cfg) {
        println!("the running env sees its shares after `{cmd}` (its volumes are kept)");
    } else if !ctx.rt.is_running(&names::dev(env)) {
        println!("in the env from its next `luoto up`");
    }
    println!(
        "Any code in the env can read it. A change in the folder reaches the env\n\
         at its next `luoto up` or `luoto share sync`."
    );
    Ok(ExitCode::SUCCESS)
}

/// `luoto share sync`.
pub fn sync_cmd(env: &str, name: Option<&str>, yes: bool) -> Result<ExitCode> {
    refuse_windows()?;
    let ctx = Ctx::load()?;
    let cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    if let Some(n) = name
        && !cfg.shares.contains_key(n)
    {
        bail!(
            "env `{env}` has no share `{}` (`luoto share list`)",
            display(n)
        );
    }
    if in_vm(&ctx) && !cfg.shares.is_empty() {
        let again = format!("luoto share sync -e {env} --yes");
        machine::ensure_shares(&ctx.rt.bin, &root()?, yes, &again)?;
    }
    let done = sync(&ctx, env, &cfg, name);
    for s in &done {
        println!("{}", s.said());
    }
    if let Some(cmd) = needs(&ctx, env, &cfg) {
        println!("the running env sees its shares after `{cmd}` (its volumes are kept)");
    }
    Ok(if done.iter().any(Synced::failed) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// `luoto share rm`: the share and its clones.
pub fn rm(env: &str, name: &str) -> Result<ExitCode> {
    if !valid_name(name) {
        return Err(name_error(name));
    }
    let paths = Paths::get()?;
    if !EnvFile::load(&paths, env)?.remove_from_table("shares", name)? {
        bail!(
            "env `{env}` has no share `{}` (`luoto share list`)",
            display(name)
        );
    }
    let _ = std::fs::remove_dir_all(env_dir(env)?.join(name));
    println!("removed share `{name}` from env `{env}`; it is gone from {IN_ENV} at once");
    Ok(ExitCode::SUCCESS)
}

/// `luoto share list`.
pub fn list(env: &str) -> Result<ExitCode> {
    let paths = Paths::get()?;
    let cfg = EnvFile::load(&paths, env)?.cfg;
    if cfg.shares.is_empty() {
        println!(
            "env `{env}` shares no folder of this machine (`luoto share add -e {env} <folder>`)"
        );
        return Ok(ExitCode::SUCCESS);
    }
    for s in status(&paths, env, &cfg) {
        let size = format!("{} file(s), {}", s.files, crate::disk::human(s.bytes));
        let state = match (&s.error, s.changed) {
            (Some(e), _) => format!("not synced: {e}"),
            (None, 0) => format!("{size}, up to date"),
            (None, n) => format!("{size}, {n} changed since the last sync: `luoto share sync`"),
        };
        println!("{IN_ENV}/{}  {}\n  {state}", s.name, display(&s.folder));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sync_clones_what_changed_and_removes_what_went() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::create_dir(src.path().join(".ssh")).unwrap();
        std::fs::write(src.path().join(".ssh/id"), b"key").unwrap();
        std::fs::write(src.path().join("a.wav"), b"aaa").unwrap();
        std::fs::write(src.path().join("sub/b.wav"), b"bb").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc", src.path().join("link")).unwrap();
        let first = mirror(src.path(), dst.path()).unwrap();
        assert_eq!((first.cloned, first.removed, first.files), (2, 0, 2));
        assert!(!dst.path().join("link").exists());
        assert!(!dst.path().join(".ssh").exists());
        assert_eq!(mirror(src.path(), dst.path()).unwrap().cloned, 0);

        std::fs::write(src.path().join("a.wav"), b"changed").unwrap();
        std::fs::remove_file(src.path().join("sub/b.wav")).unwrap();
        let next = mirror(src.path(), dst.path()).unwrap();
        assert_eq!((next.cloned, next.removed), (1, 1));
        assert_eq!(std::fs::read(dst.path().join("a.wav")).unwrap(), b"changed");
        assert!(!dst.path().join("sub").exists());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_files_sync_and_a_planted_link_is_never_written_through() {
        use std::os::unix::fs::PermissionsExt;
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/obj"), b"git object").unwrap();
        std::fs::set_permissions(
            src.path().join("sub/obj"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dst.path().join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", dst.path().join("planted")).unwrap();

        let s = mirror(src.path(), dst.path()).unwrap();
        assert_eq!((s.cloned, s.skipped), (1, 0));
        assert!(
            std::fs::symlink_metadata(dst.path().join("sub"))
                .unwrap()
                .is_dir()
        );
        assert!(
            std::fs::read_dir(elsewhere.path())
                .unwrap()
                .next()
                .is_none()
        );
        assert!(std::fs::symlink_metadata(dst.path().join("planted")).is_err());
        assert_eq!(mirror(src.path(), dst.path()).unwrap().cloned, 0);
    }

    #[test]
    fn a_share_is_a_named_folder_inside_home_never_home_or_app_data() {
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();
        let luoto = tempfile::tempdir().unwrap();
        let p = Paths {
            config: luoto.path().join("config"),
            data: luoto.path().join("data"),
        };
        assert!(checked(&p, "home", "~").is_err());
        assert!(checked(&p, "root", "/").is_err());
        assert!(checked(&p, "etc", "/etc").is_err());
        for app in ["~/.ssh", "~/.cargo", "~/.config"] {
            if Path::new(&crate::workspace::expand(app)).is_dir() {
                assert!(checked(&p, "app", app).is_err(), "{app}");
            }
        }
        let ok = tempfile::Builder::new()
            .prefix("luoto-test-")
            .tempdir_in(&home)
            .unwrap();
        let folder = ok.path().to_string_lossy().into_owned();
        assert!(checked(&p, "audio", &folder).is_ok());
        let keys = ok.path().join("backup/.aws");
        std::fs::create_dir_all(&keys).unwrap();
        assert!(checked(&p, "aws", &keys.to_string_lossy()).is_err());
        for bad in ["", "Audio", "-a", "a b", "a/b", ".."] {
            assert!(checked(&p, bad, &folder).is_err(), "{bad:?}");
        }
        assert_eq!(default_name(Path::new("/x/My Recordings")), "my-recordings");
    }

    #[test]
    fn an_env_file_names_shares_by_name_and_full_path() {
        let ok: BTreeMap<String, String> = [
            ("audio".into(), "/data/audio".into()),
            ("notes".into(), "~/notes".into()),
        ]
        .into();
        assert!(check_config(&ok).is_ok());
        for (name, folder) in [("../..", "/x"), ("a", "rel/dir"), ("a", "~other/x")] {
            let bad: BTreeMap<String, String> = [(name.into(), folder.into())].into();
            assert!(check_config(&bad).is_err(), "{name} {folder}");
        }
    }
}
