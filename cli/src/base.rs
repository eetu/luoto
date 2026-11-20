//! What an env's copy of a folder started from: a fingerprint per path, kept on this machine
//! in the env's state. A copy into the env writes it from the bytes sent, and every pull
//! brings it up to date, so a pull can tell what the env changed from what changed in the
//! folder meanwhile (`judge`), and write only the former.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::paths::Paths;

/// What a path holds: a file's bytes and whether it is executable, or a link's target. No
/// time: a file saved again unchanged is the same file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Print {
    /// SHA-256 of the bytes, or of the link's target.
    pub hash: [u8; 32],
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Executable,
    Link,
}

impl Print {
    pub fn of_file(hash: [u8; 32], executable: bool) -> Self {
        // Windows keeps no such bit: a file there would never equal the env's.
        let kind = if executable && cfg!(unix) {
            Kind::Executable
        } else {
            Kind::File
        };
        Print { hash, kind }
    }

    pub fn of_bytes(bytes: &[u8], executable: bool) -> Self {
        Self::of_file(Sha256::digest(bytes).into(), executable)
    }

    pub fn of_link(target: &Path) -> Self {
        Print {
            hash: Sha256::digest(target.as_os_str().as_encoded_bytes()).into(),
            kind: Kind::Link,
        }
    }

    pub fn hex(&self) -> String {
        hex::encode(self.hash)
    }
}

impl From<Print> for String {
    fn from(p: Print) -> String {
        let k = match p.kind {
            Kind::File => 'f',
            Kind::Executable => 'x',
            Kind::Link => 'l',
        };
        format!("{k}:{}", hex::encode(p.hash))
    }
}

impl TryFrom<String> for Print {
    type Error = String;

    fn try_from(s: String) -> std::result::Result<Self, String> {
        let (k, h) = s.split_once(':').ok_or("not a fingerprint")?;
        let kind = match k {
            "f" => Kind::File,
            "x" => Kind::Executable,
            "l" => Kind::Link,
            _ => return Err("not a fingerprint".into()),
        };
        let hash: [u8; 32] = hex::decode(h)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or("not a fingerprint")?;
        Ok(Print { hash, kind })
    }
}

/// What the folder holds at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Absent,
    Is(Print),
    /// A folder or a special file: nothing a pull compares or replaces.
    Other,
    /// It couldn't be read.
    Unread,
}

impl Host {
    /// What is at `path`, the link itself when it is one.
    pub fn at(path: &Path) -> Host {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return Host::Absent;
        };
        if meta.file_type().is_symlink() {
            return match std::fs::read_link(path) {
                Ok(t) => Host::Is(Print::of_link(&t)),
                Err(_) => Host::Unread,
            };
        }
        if !meta.is_file() {
            return Host::Other;
        }
        match hash_file(path) {
            Ok(hash) => Host::Is(Print::of_file(hash, executable(&meta))),
            Err(_) => Host::Unread,
        }
    }
}

#[cfg(unix)]
pub fn executable(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
pub fn executable(_m: &std::fs::Metadata) -> bool {
    false
}

fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buf[..n]);
    }
}

/// A reader that fingerprints what passes through it: the bytes a copy sends.
pub struct Hashing<R> {
    inner: R,
    hasher: Sha256,
    pub read: u64,
}

impl<R: Read> Hashing<R> {
    pub fn new(inner: R) -> Self {
        Hashing {
            inner,
            hasher: Sha256::new(),
            read: 0,
        }
    }

    pub fn finish(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.read += n as u64;
        Ok(n)
    }
}

/// What a pull does with a path the env has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The folder holds the same: nothing to write, and the base says so from now on.
    Same,
    /// The env didn't change it: what the folder holds stays, whatever that is.
    Yours,
    /// The env changed it and the folder didn't.
    Write,
    /// Both changed it, or the folder has one the env's copy never started from.
    Conflict,
}

/// The three-way rule for one path: the env's `env`, what the copy started from (`base`, None
/// when it has no entry) and what the folder holds now.
pub fn judge(env: &Print, base: Option<&Print>, host: &Host) -> Verdict {
    if matches!(host, Host::Is(h) if h == env) {
        return Verdict::Same;
    }
    match base {
        Some(b) if b == env => Verdict::Yours,
        Some(b) if matches!(host, Host::Is(h) if h == b) => Verdict::Write,
        Some(_) => Verdict::Conflict,
        None if *host == Host::Absent => Verdict::Write,
        None => Verdict::Conflict,
    }
}

/// The rule for an env with no base at all (made before luoto kept one, or imported): what
/// differs is offered, for a person to review; nothing says who changed it.
pub fn judge_unbased(env: &Print, host: &Host) -> Verdict {
    if matches!(host, Host::Is(h) if h == env) {
        Verdict::Same
    } else {
        Verdict::Write
    }
}

/// The base of one folder of an env.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Base {
    pub files: BTreeMap<String, Print>,
    /// The folder's git HEAD when the copy was made or last pulled, if it is a repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
}

/// Where the base of the env's folder (`repo` None) or of a repo's folder is kept.
fn file(paths: &Paths, env: &str, repo: Option<&str>) -> PathBuf {
    let name = match repo {
        Some(r) => format!("repo-{r}.json"),
        None => "workspace.json".to_string(),
    };
    paths.env_state(env).join("base").join(name)
}

impl Base {
    /// The base kept for that folder; None when there is none, or it can't be read (a pull
    /// then asks a person).
    pub fn load(paths: &Paths, env: &str, repo: Option<&str>) -> Option<Base> {
        let bytes = std::fs::read(file(paths, env, repo)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Keep it, on disk before this returns: a pull's writes count as done only once it is.
    pub fn save(&self, paths: &Paths, env: &str, repo: Option<&str>) -> Result<()> {
        write_synced(&file(paths, env, repo), &serde_json::to_vec(self)?)
    }
}

/// Write `data` at `path`, only this user's, and have it on disk before returning: through a
/// temporary file, flushed, renamed, and its folder flushed.
pub fn write_synced(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().context("no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let written = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if cfg!(unix) {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(|| format!("write {}", path.display()))
}

/// The git HEAD of the repository whose root is `dir`, if it is one.
pub fn head_of(dir: &Path) -> Option<String> {
    if !dir.join(".git").exists() {
        return None;
    }
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "-q", "--verify", "HEAD"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let head = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && head.len() >= 40 && head.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Print {
        Print::of_bytes(text.as_bytes(), false)
    }

    #[test]
    fn the_three_way_rule() {
        let (a, b, c) = (p("a"), p("b"), p("c"));
        let is = |x: &Print| Host::Is(x.clone());
        // The env's equals the folder's: nothing to do, whatever the base says.
        for base in [None, Some(&a), Some(&b)] {
            assert_eq!(judge(&a, base, &is(&a)), Verdict::Same);
        }
        // The env didn't change it: the folder's stays, changed, deleted or not.
        for host in [is(&b), Host::Absent, Host::Other, Host::Unread] {
            assert_eq!(judge(&a, Some(&a), &host), Verdict::Yours);
        }
        // The env changed it and the folder didn't.
        assert_eq!(judge(&b, Some(&a), &is(&a)), Verdict::Write);
        // Both changed it, or the folder's is gone or can't be read.
        for host in [is(&c), Host::Absent, Host::Other, Host::Unread] {
            assert_eq!(judge(&b, Some(&a), &host), Verdict::Conflict);
        }
        // A file the copy never had: new in the env, unless the folder has one too.
        assert_eq!(judge(&a, None, &Host::Absent), Verdict::Write);
        for host in [is(&b), Host::Other, Host::Unread] {
            assert_eq!(judge(&a, None, &host), Verdict::Conflict);
        }
    }

    #[test]
    fn a_mode_or_kind_change_is_a_change() {
        let plain = Print::of_bytes(b"#!/bin/sh", false);
        let exec = Print::of_bytes(b"#!/bin/sh", true);
        let link = Print::of_link(Path::new("a"));
        if cfg!(unix) {
            assert_ne!(plain, exec);
            assert_eq!(
                judge(&exec, Some(&plain), &Host::Is(plain.clone())),
                Verdict::Write
            );
        }
        assert_ne!(link, Print::of_bytes(b"a", false));
    }

    #[test]
    fn without_a_base_every_difference_is_offered() {
        let (a, b) = (p("a"), p("b"));
        assert_eq!(judge_unbased(&a, &Host::Is(a.clone())), Verdict::Same);
        assert_eq!(judge_unbased(&a, &Host::Is(b)), Verdict::Write);
        assert_eq!(judge_unbased(&a, &Host::Absent), Verdict::Write);
    }

    #[test]
    fn a_base_is_kept_per_folder_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        assert_eq!(Base::load(&paths, "web", None), None);
        let base = Base {
            files: BTreeMap::from([
                ("src/main.rs".to_string(), p("fn main() {}")),
                ("run.sh".to_string(), Print::of_bytes(b"x", true)),
                ("l".to_string(), Print::of_link(Path::new("src/main.rs"))),
            ]),
            head: Some("a".repeat(40)),
        };
        base.save(&paths, "web", Some("api")).unwrap();
        assert_eq!(Base::load(&paths, "web", Some("api")), Some(base));
        assert_eq!(Base::load(&paths, "web", None), None);
        let text = std::fs::read_to_string(file(&paths, "web", Some("api"))).unwrap();
        assert!(text.contains("\"l\":\"l:"), "{text}");
        // One that doesn't parse is no base.
        std::fs::write(file(&paths, "web", Some("api")), b"{").unwrap();
        assert_eq!(Base::load(&paths, "web", Some("api")), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_folders_side_is_read_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join("a"), b"a").unwrap();
        std::os::unix::fs::symlink("a", d.join("l")).unwrap();
        std::fs::create_dir(d.join("sub")).unwrap();
        assert_eq!(Host::at(&d.join("a")), Host::Is(p("a")));
        assert_eq!(
            Host::at(&d.join("l")),
            Host::Is(Print::of_link(Path::new("a")))
        );
        assert_eq!(Host::at(&d.join("sub")), Host::Other);
        assert_eq!(Host::at(&d.join("none")), Host::Absent);
        let mut r = Hashing::new(&b"a"[..]);
        std::io::copy(&mut r, &mut std::io::sink()).unwrap();
        assert_eq!((r.read, Print::of_file(r.finish(), false)), (1, p("a")));
    }
}
