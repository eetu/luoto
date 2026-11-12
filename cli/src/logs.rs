//! `luoto logs`: the gate's container log, the background watcher's log (`watch.rs`) and what
//! an env's installs printed ([`InstallLog`], written by `deps` and `agents`). The sandbox
//! wrote much of each, so a terminal gets them escaped (`text::lines`); a pipe gets the bytes.

use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Result, bail};
use chrono::Utc;

use crate::env::Ctx;
use crate::paths::Paths;
use crate::runtime::Runtime;
use crate::{machine, names, progress};

/// The size at which an install log becomes `install.log.1`, replacing the older one: what is
/// kept is the newest output, up to twice this.
const CAP: u64 = 512 * 1024;
/// A longer line is shown in pieces: the sandbox decides how long its lines are.
const MAX_LINE: usize = 64 * 1024;
const POLL: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Source {
    /// The gate's container log: its diagnostics, and each connection as a JSON line.
    Gate,
    /// The background watcher's, one for every env: port forwards, idle stops, credentials
    /// read again, notifications shown.
    Watcher,
    /// What the env's installs printed (system packages, toolchains, agents): the newest MiB.
    Installs,
}

pub fn show(
    source: Source,
    env: impl FnOnce() -> Result<String>,
    follow: bool,
    lines: Option<usize>,
) -> Result<ExitCode> {
    let paths = Paths::get()?;
    let existing = |name: String| {
        if paths.env_config(&name).exists() {
            Ok(name)
        } else {
            Err(anyhow::anyhow!("no env `{name}` (`luoto ls` lists them)"))
        }
    };
    match source {
        Source::Watcher => files(
            &[paths.watch_log()],
            follow,
            lines,
            "the watcher has not run yet (`luoto up` starts it)",
        ),
        Source::Gate => gate(&existing(env()?)?, follow, lines),
        Source::Installs => {
            let name = existing(env()?)?;
            let log = paths.install_log(&name);
            files(
                &[older(&log), log],
                follow,
                lines,
                &format!("no install output kept for `{name}` yet"),
            )
        }
    }
}

fn gate(name: &str, follow: bool, lines: Option<usize>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let gate = names::gate(name);
    let Some(state) = ctx.rt.container_state(&gate) else {
        if machine::stopped(&ctx.rt) {
            bail!("luoto's VM is stopped, and the gate's log is in it (`luoto up -e {name}`)");
        }
        bail!("`{name}` has no gate yet (`luoto up -e {name}` starts it)");
    };
    let in_file = crate::events::in_file(&ctx.rt, &gate);
    if in_file && state != "running" {
        eprintln!("the gate isn't running: its events show once it is (`luoto up -e {name}`)");
    }
    let mut args = vec!["logs".to_string()];
    if follow {
        args.push("-f".into());
    }
    if let Some(n) = lines {
        let flag = if ctx.rt.flavor == crate::runtime::Flavor::Apple {
            "-n"
        } else {
            "--tail"
        };
        args.extend([flag.into(), n.to_string()]);
    }
    args.push(gate.clone());
    let out = Output::new();
    let log = || {
        ctx.rt
            .stream(&args, &|is_err, b| out.push(usize::from(is_err), b))
    };
    if !in_file || state != "running" {
        let status = log()?;
        let closed = !out.finish();
        return Ok(exit(status.success() || closed));
    }
    // The diagnostics are in the container's log, the events in their file.
    let events = crate::events::file_args(&gate, follow, lines);
    let file = || {
        ctx.rt
            .stream(&events, &|is_err, b| out.push(2 + usize::from(is_err), b))
    };
    let (log, file) = if follow {
        std::thread::scope(|s| {
            let log = s.spawn(log);
            let file = file();
            (
                log.join()
                    .unwrap_or_else(|_| bail!("reading the log failed")),
                file,
            )
        })
    } else {
        (log(), file())
    };
    let ok = log?.success() & file?.success();
    let closed = !out.finish();
    Ok(exit(ok || closed))
}

fn exit(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `paths` shown as one log, oldest first; with `follow`, then what is added to the last.
fn files(paths: &[PathBuf], follow: bool, lines: Option<usize>, missing: &str) -> Result<ExitCode> {
    let Some((current, earlier)) = paths.split_last() else {
        return Ok(ExitCode::SUCCESS);
    };
    let mut kept = Vec::new();
    for p in earlier {
        if let Ok(b) = std::fs::read(p) {
            kept.extend(b);
        }
    }
    let mut file = File::open(current).ok();
    if let Some(f) = &mut file {
        f.read_to_end(&mut kept)?;
    }
    if kept.is_empty() && !follow {
        eprintln!("{missing}");
        return Ok(ExitCode::SUCCESS);
    }
    let out = Output::new();
    let shown = lines.map_or(&kept[..], |n| tail(&kept, n));
    if !out.push(0, shown) {
        return Ok(ExitCode::SUCCESS);
    }
    if !follow {
        out.finish();
        return Ok(ExitCode::SUCCESS);
    }
    let mut f = Follow {
        path: current.clone(),
        file,
    };
    loop {
        let got = f.poll()?;
        if got.is_empty() {
            std::thread::sleep(POLL);
        } else if !out.push(0, &got) {
            return Ok(ExitCode::SUCCESS);
        }
    }
}

/// The last `n` lines of `text`.
fn tail(text: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &[];
    }
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    let mut seen = 0;
    for (i, &b) in body.iter().enumerate().rev() {
        if b == b'\n' {
            seen += 1;
            if seen == n {
                return &text[i + 1..];
            }
        }
    }
    text
}

/// Complete lines out of a stream of chunks; a line longer than [`MAX_LINE`] comes in pieces.
#[derive(Default)]
struct Lines(Vec<u8>);

impl Lines {
    fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for piece in chunk.split_inclusive(|&b| b == b'\n') {
            match piece.strip_suffix(b"\n") {
                Some(end) => {
                    self.0.extend_from_slice(end);
                    out.push(std::mem::take(&mut self.0));
                }
                None => self.0.extend_from_slice(piece),
            }
            while self.0.len() > MAX_LINE {
                out.push(self.0.drain(..MAX_LINE).collect());
            }
        }
        out
    }

    /// The last line, when it had no line break.
    fn rest(&mut self) -> Option<Vec<u8>> {
        (!self.0.is_empty()).then(|| std::mem::take(&mut self.0))
    }
}

/// `line` as stdout gets it: escaped on a terminal, else as it is.
fn render(line: &[u8], escape: bool) -> Vec<u8> {
    let mut out = if escape {
        crate::text::lines(&String::from_utf8_lossy(line)).into_bytes()
    } else {
        line.to_vec()
    };
    out.push(b'\n');
    out
}

/// Lines from up to four streams (two commands' stdout and stderr) to stdout, each as it ends.
struct Output {
    escape: bool,
    streams: Mutex<[Lines; 4]>,
}

impl Output {
    fn new() -> Self {
        Output {
            escape: std::io::stdout().is_terminal(),
            streams: Mutex::default(),
        }
    }

    /// False once stdout is gone (a closed pipe).
    fn push(&self, stream: usize, chunk: &[u8]) -> bool {
        let Ok(mut streams) = self.streams.lock() else {
            return false;
        };
        let lines = streams[stream].push(chunk);
        self.write(lines)
    }

    /// Print the lines left without a line break; false when stdout is gone.
    fn finish(&self) -> bool {
        let Ok(mut streams) = self.streams.lock() else {
            return false;
        };
        let rest: Vec<Vec<u8>> = streams.iter_mut().filter_map(Lines::rest).collect();
        self.write(rest)
    }

    fn write(&self, lines: Vec<Vec<u8>>) -> bool {
        let mut out = std::io::stdout().lock();
        lines
            .iter()
            .try_for_each(|l| out.write_all(&render(l, self.escape)))
            .and_then(|()| out.flush())
            .is_ok()
    }
}

/// Reads what is added to a file, also once the file is replaced by a new one of its name (an
/// install log turning over) or cut short.
struct Follow {
    path: PathBuf,
    file: Option<File>,
}

#[cfg(unix)]
fn file_id(m: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((m.dev(), m.ino()))
}

/// Elsewhere a replaced file shows only as one shorter than what was read.
#[cfg(not(unix))]
fn file_id(_: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

impl Follow {
    fn poll(&mut self) -> std::io::Result<Vec<u8>> {
        let mut got = Vec::new();
        if let Some(f) = &mut self.file {
            f.read_to_end(&mut got)?;
        }
        let Ok(now) = std::fs::metadata(&self.path) else {
            return Ok(got);
        };
        let stale = match &mut self.file {
            None => true,
            Some(f) => {
                file_id(&f.metadata()?) != file_id(&now) || now.len() < f.stream_position()?
            }
        };
        if stale {
            // What the old file got before it was replaced comes first.
            if let Some(f) = &mut self.file {
                f.read_to_end(&mut got)?;
            }
            let mut f = File::open(&self.path)?;
            f.read_to_end(&mut got)?;
            self.file = Some(f);
        }
        Ok(got)
    }
}

fn older(log: &Path) -> PathBuf {
    log.with_extension("log.1")
}

/// What an env's installs print, kept in its state dir for `luoto logs installs`; the terminal
/// gets it with `--verbose`, or its last lines when an install fails ([`progress::tool`]). Newest last; at [`CAP`] the file becomes `install.log.1`,
/// replacing the older one. Writing it never fails an install.
pub struct InstallLog {
    path: PathBuf,
    cap: u64,
    file: Mutex<Option<Open>>,
}

struct Open {
    file: File,
    len: u64,
    at_line_start: bool,
}

fn open_append(path: &Path) -> std::io::Result<Open> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let file = o.open(path)?;
    let len = file.metadata()?.len();
    Ok(Open {
        file,
        len,
        at_line_start: len == 0,
    })
}

impl InstallLog {
    pub fn new(paths: &Paths, env: &str) -> Self {
        InstallLog {
            path: paths.install_log(env),
            cap: CAP,
            file: Mutex::new(None),
        }
    }

    /// A line of luoto's own, with the time: what installs, or how it ended.
    pub fn note(&self, what: &str) {
        let ts = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        self.append(format!("== {ts} {what}\n").as_bytes(), true);
    }

    /// Run `args`, their output in the log ([`progress::tool`] for the terminal).
    pub fn run<I, S>(&self, rt: &Runtime, args: I) -> Result<ExitStatus>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        progress::tool(rt, args, &|b| self.append(b, false))
    }

    /// Append `bytes`, on a line of their own when `own_line`.
    fn append(&self, bytes: &[u8], own_line: bool) {
        let Ok(mut slot) = self.file.lock() else {
            return;
        };
        if slot.as_ref().is_none_or(|o| o.len >= self.cap) {
            let full = match slot.take() {
                Some(_) => true,
                None => std::fs::metadata(&self.path).is_ok_and(|m| m.len() >= self.cap),
            };
            if full {
                let _ = std::fs::rename(&self.path, older(&self.path));
            }
            *slot = open_append(&self.path).ok();
        }
        let Some(o) = slot.as_mut() else {
            return;
        };
        let lead: &[u8] = if own_line && !o.at_line_start {
            b"\n"
        } else {
            b""
        };
        if o.file
            .write_all(lead)
            .and_then(|()| o.file.write_all(bytes))
            .is_ok()
        {
            o.len += (lead.len() + bytes.len()) as u64;
            if let Some(&last) = bytes.last() {
                o.at_line_start = last == b'\n';
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_the_last_lines() {
        assert_eq!(tail(b"a\nb\nc\n", 2), b"b\nc\n");
        assert_eq!(tail(b"a\nb\nc", 2), b"b\nc");
        assert_eq!(tail(b"a\n", 5), b"a\n");
        assert_eq!(tail(b"a\nb\n", 0), b"");
    }

    #[test]
    fn lines_join_chunks_and_split_long_ones() {
        let mut l = Lines::default();
        assert!(l.push(b"one").is_empty());
        assert_eq!(
            l.push(b" two\nthree\nfo"),
            [b"one two".to_vec(), b"three".to_vec()]
        );
        assert_eq!(l.rest(), Some(b"fo".to_vec()));
        assert_eq!(l.rest(), None);
        let long = vec![b'x'; MAX_LINE * 2 + 3];
        let pieces = l.push(&long);
        assert_eq!(pieces.len(), 2);
        assert!(pieces.iter().all(|p| p.len() == MAX_LINE));
        assert_eq!(l.rest().map(|r| r.len()), Some(3));
    }

    #[test]
    fn a_terminal_gets_the_sandbox_lines_escaped() {
        let line = b"ok\x1b[2J\tdone\r";
        assert_eq!(render(line, true), b"ok\\u{1b}[2J\tdone\\u{d}\n");
        assert_eq!(render(line, false), b"ok\x1b[2J\tdone\r\n");
    }

    #[test]
    fn install_logs_turn_over_and_keep_the_newest() {
        let d = tempfile::tempdir().unwrap();
        let log = InstallLog {
            path: d.path().join("install.log"),
            cap: 64,
            file: Mutex::new(None),
        };
        log.note("installing node");
        log.append(b"partial", false);
        log.note("installed");
        let text = std::fs::read_to_string(&log.path).unwrap();
        let notes: Vec<&str> = text.lines().filter(|l| l.starts_with("== ")).collect();
        assert_eq!(notes.len(), 2);
        assert!(text.contains("partial\n== "));
        log.append(&[b'x'; 80], false);
        log.append(b"newest\n", false);
        assert!(older(&log.path).exists());
        assert_eq!(std::fs::read(&log.path).unwrap(), b"newest\n");
    }

    #[test]
    fn follow_reads_across_a_turnover_and_a_truncation() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("install.log");
        let append = |b: &[u8]| {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b).unwrap();
        };
        let mut f = Follow {
            path: path.clone(),
            file: None,
        };
        assert!(f.poll().unwrap().is_empty());
        append(b"one\n");
        assert_eq!(f.poll().unwrap(), b"one\n");
        append(b"two\nthree\n");
        assert_eq!(f.poll().unwrap(), b"two\nthree\n");
        append(b"four\n");
        std::fs::rename(&path, older(&path)).unwrap();
        append(b"five\n");
        assert_eq!(f.poll().unwrap(), b"four\nfive\n");
        assert!(f.poll().unwrap().is_empty());
        std::fs::write(&path, b"").unwrap();
        append(b"six\n");
        assert_eq!(f.poll().unwrap(), b"six\n");
    }
}
