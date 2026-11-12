//! The event file: where events go instead of stdout when `LUOTO_EVENTS_FILE` names one (a
//! runtime that keeps no bounded log of its own, Apple's). At half its cap the file becomes
//! `<file>.1`, replacing the older one, so the newest events are kept, up to the cap.
//! `luoto-gate events` prints and follows the pair for luoto, through the runtime's exec.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use chrono::{DateTime, Utc};

/// Where luoto points `LUOTO_EVENTS_FILE`: the state volume, so events outlive the gate.
const DEFAULT: &str = "/var/lib/luoto-gate/events.jsonl";
const POLL: Duration = Duration::from_millis(250);

pub fn older(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

/// The event file being written: whole lines only, turned over at a line's end.
pub struct EventFile {
    path: PathBuf,
    /// Size at which the file turns over.
    turn: u64,
    file: File,
    len: u64,
    at_line_start: bool,
}

impl EventFile {
    /// Open `path` for events, keeping at most `cap` bytes over it and its older file.
    pub fn open(path: &Path, cap: u64) -> std::io::Result<Self> {
        let file = open_append(path)?;
        let len = file.metadata()?.len();
        Ok(EventFile {
            path: path.to_path_buf(),
            turn: (cap / 2).max(1),
            file,
            len,
            at_line_start: true,
        })
    }

    fn turn_over(&mut self) -> std::io::Result<()> {
        if std::fs::rename(&self.path, older(&self.path)).is_err() {
            // The bound holds even when the older file can't be replaced.
            self.file.set_len(0)?;
        }
        self.file = open_append(&self.path)?;
        self.len = 0;
        Ok(())
    }
}

impl Write for EventFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.at_line_start && self.len > 0 && self.len + buf.len() as u64 > self.turn {
            self.turn_over()?;
        }
        let n = self.file.write(buf)?;
        self.len += n as u64;
        if n > 0 {
            self.at_line_start = buf[n - 1] == b'\n';
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Lines to stdout: those from `since` on (the file is in time order), only the last `tail`
/// when given. A line still being written waits for its end.
struct Sink<W: Write> {
    out: W,
    since: Option<DateTime<Utc>>,
    tail: Option<(usize, VecDeque<Vec<u8>>)>,
    pending: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct Stamped {
    ts: Option<DateTime<Utc>>,
}

impl<W: Write> Sink<W> {
    fn line(&mut self, line: &[u8]) -> std::io::Result<()> {
        if let Some(since) = self.since {
            match serde_json::from_slice::<Stamped>(line)
                .ok()
                .and_then(|s| s.ts)
            {
                Some(ts) if ts >= since => self.since = None,
                _ => return Ok(()),
            }
        }
        match &mut self.tail {
            Some((n, kept)) => {
                if *n > 0 {
                    if kept.len() == *n {
                        kept.pop_front();
                    }
                    kept.push_back(line.to_vec());
                }
                Ok(())
            }
            None => {
                self.out.write_all(line)?;
                self.out.write_all(b"\n")
            }
        }
    }

    fn chunk(&mut self, mut bytes: &[u8]) -> std::io::Result<()> {
        while let Some(i) = bytes.iter().position(|&b| b == b'\n') {
            if self.pending.is_empty() {
                self.line(&bytes[..i])?;
            } else {
                self.pending.extend_from_slice(&bytes[..i]);
                let line = std::mem::take(&mut self.pending);
                self.line(&line)?;
            }
            bytes = &bytes[i + 1..];
        }
        self.pending.extend_from_slice(bytes);
        Ok(())
    }

    /// Every whole line read so far is out, the tail too.
    fn flush(&mut self) -> std::io::Result<()> {
        if let Some((_, kept)) = self.tail.take() {
            for l in kept {
                self.out.write_all(&l)?;
                self.out.write_all(b"\n")?;
            }
        }
        self.out.flush()
    }
}

/// `path` opened for reading; None when there is none yet.
fn open(path: &Path) -> std::io::Result<Option<File>> {
    match File::open(path) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        )),
    }
}

/// Whether stdout's reader has closed its end.
fn reader_gone() -> bool {
    let mut fd = libc::pollfd {
        fd: libc::STDOUT_FILENO,
        events: 0,
        revents: 0,
    };
    // SAFETY: one valid pollfd, no wait.
    let n = unsafe { libc::poll(&mut fd, 1, 0) };
    n > 0 && fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
}

fn file_id(f: &File) -> Option<(u64, u64)> {
    f.metadata().ok().map(|m| (m.dev(), m.ino()))
}

/// Print the events of the file at `path` (its older file first) into `sink`; with `follow`,
/// then what is added, also once the file turns over. Ends when `sink` can't be written.
fn print<W: Write>(path: &Path, sink: &mut Sink<W>, follow: bool) -> std::io::Result<()> {
    if let Some(f) = open(&older(path))? {
        let mut r = BufReader::new(f);
        loop {
            let buf = r.fill_buf()?;
            if buf.is_empty() {
                break;
            }
            let n = buf.len();
            sink.chunk(buf)?;
            r.consume(n);
        }
        // The older file ends with a whole line.
        sink.pending.clear();
    }
    let mut file = open(path)?;
    let mut buf = vec![0; 64 * 1024];
    let mut read_all = |f: &mut File, sink: &mut Sink<W>| -> std::io::Result<()> {
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            sink.chunk(&buf[..n])?;
        }
    };
    if let Some(f) = &mut file {
        read_all(f, sink)?;
    }
    sink.flush()?;
    if !follow {
        return Ok(());
    }
    loop {
        std::thread::sleep(POLL);
        // A quiet file writes nothing that would fail once the reader is gone.
        if reader_gone() {
            return Ok(());
        }
        if let Some(f) = &mut file {
            read_all(f, sink)?;
        }
        let now = open(path)?;
        let turned = match (&mut file, &now) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(f), Some(n)) => {
                file_id(f) != file_id(n)
                    || n.metadata().map(|m| m.len()).unwrap_or(0) < f.stream_position()?
            }
        };
        if turned {
            // The old file ends with a whole line.
            sink.pending.clear();
            file = now;
            if let Some(f) = &mut file {
                read_all(f, sink)?;
            }
        }
        sink.flush()?;
    }
}

/// `luoto-gate events [-f] [-n <lines>] [--since <RFC 3339 time>]`.
pub fn command(args: &[String]) -> ExitCode {
    let mut follow = false;
    let mut tail = None;
    let mut since = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let parsed = match a.as_str() {
            "-f" | "--follow" => {
                follow = true;
                Some(())
            }
            "-n" => it
                .next()
                .and_then(|v| v.parse().ok())
                .map(|n| tail = Some(n)),
            "--since" => it
                .next()
                .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                .map(|t| since = Some(t.with_timezone(&Utc))),
            _ => None,
        };
        if parsed.is_none() {
            eprintln!("usage: luoto-gate events [-f] [-n <lines>] [--since <RFC 3339 time>]");
            return ExitCode::from(2);
        }
    }
    let path = std::env::var_os("LUOTO_EVENTS_FILE")
        .filter(|p| !p.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT), PathBuf::from);
    let mut sink = Sink {
        out: std::io::stdout().lock(),
        since,
        tail: tail.map(|n| (n, VecDeque::new())),
        pending: Vec::new(),
    };
    match print(&path, &mut sink, follow) {
        Ok(()) => ExitCode::SUCCESS,
        // The reader went away.
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("luoto-gate events: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh path for an event file, in a folder of its own.
    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("luoto-gate-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("events.jsonl")
    }

    fn line(ts: &str, n: u64) -> String {
        format!("{{\"seq\":{n},\"ts\":\"{ts}\"}}\n")
    }

    #[test]
    fn the_file_turns_over_at_a_line_end_and_stays_under_its_cap() {
        let path = scratch("turns");
        let mut f = EventFile::open(&path, 200).unwrap();
        for n in 0..100 {
            let l = line("2026-11-12T10:00:00Z", n);
            // Written in pieces, as `write_all` may.
            let (a, b) = l.as_bytes().split_at(10);
            f.write_all(a).unwrap();
            f.write_all(b).unwrap();
        }
        let cur = std::fs::read_to_string(&path).unwrap();
        let old = std::fs::read_to_string(older(&path)).unwrap();
        assert!(
            cur.len() + old.len() <= 200 + 50,
            "{} + {}",
            cur.len(),
            old.len()
        );
        for text in [&cur, &old] {
            assert!(text.ends_with('\n'));
            assert!(text.lines().all(|l| l.starts_with('{') && l.ends_with('}')));
        }
        assert!(cur.contains("\"seq\":99,"));
    }

    fn sink(since: Option<&str>, tail: Option<usize>) -> Sink<Vec<u8>> {
        Sink {
            out: Vec::new(),
            since: since.map(|s| s.parse().unwrap()),
            tail: tail.map(|n| (n, VecDeque::new())),
            pending: Vec::new(),
        }
    }

    #[test]
    fn prints_both_files_from_since_and_the_tail() {
        let path = scratch("prints");
        std::fs::write(
            older(&path),
            line("2026-11-12T10:00:00Z", 1) + &line("2026-11-12T11:00:00Z", 2),
        )
        .unwrap();
        std::fs::write(&path, line("2026-11-12T12:00:00Z", 3) + "{\"seq\":4,").unwrap();

        let mut s = sink(None, None);
        print(&path, &mut s, false).unwrap();
        let out = String::from_utf8(s.out).unwrap();
        assert_eq!(out.lines().count(), 3);

        let mut s = sink(Some("2026-11-12T10:30:00Z"), None);
        print(&path, &mut s, false).unwrap();
        let out = String::from_utf8(s.out).unwrap();
        assert!(out.starts_with("{\"seq\":2,"), "{out}");

        let mut s = sink(None, Some(2));
        print(&path, &mut s, false).unwrap();
        let out = String::from_utf8(s.out).unwrap();
        assert_eq!(out.lines().count(), 2);
        assert!(out.starts_with("{\"seq\":2,"), "{out}");
    }
}
