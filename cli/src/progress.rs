//! Progress for what takes a while. A step prints its line (`installing …`); on a terminal a
//! spinner with the time so far follows on the next line until the step ends. What the step's
//! tools print (installers, git) reaches the terminal only with `--verbose`, or its last lines
//! when one fails; the sandbox wrote much of it, so it comes escaped ([`text::Relay`]).
//!
//! The spinner line is short and the cursor stays at its start, so a line printed during a
//! step (a warning) overwrites it and the spinner carries on below.

use std::io::{IsTerminal, Write};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::runtime::Runtime;
use crate::text::{self, Relay};

static VERBOSE: AtomicBool = AtomicBool::new(false);
static OFF: AtomicBool = AtomicBool::new(false);
/// When each running step began, innermost last.
static STARTS: Mutex<Vec<Instant>> = Mutex::new(Vec::new());
static SPINNER: Mutex<Option<Spinner>> = Mutex::new(None);

const FRAMES: [char; 4] = ['-', '\\', '|', '/'];
const TICK: Duration = Duration::from_millis(125);
/// A step that ends sooner shows no spinner.
const DELAY: Duration = Duration::from_secs(1);
/// The spinner line's width: wider than any it draws, so each frame covers the last.
const WIDTH: usize = 12;
/// What a failed tool's output shows of itself.
const TAIL_LINES: usize = 20;
/// What a tool's output keeps for a failure: its newest bytes.
const KEEP: usize = 64 * 1024;

/// What tools print reaches the terminal as it comes (`--verbose`).
pub fn set_verbose() {
    VERBOSE.store(true, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// No spinner in this process: `luoto ui` runs steps for its pages, not for a terminal.
pub fn off() {
    OFF.store(true, Ordering::Relaxed);
}

/// A spinner only where it is alone on the terminal: `--verbose` and `LUOTO_TRACE` print as
/// the step runs.
fn spins() -> bool {
    !OFF.load(Ordering::Relaxed)
        && !verbose()
        && std::env::var_os("LUOTO_TRACE").is_none()
        && std::io::stderr().is_terminal()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Run `f` as a step: `label…` on a line of its own, then on a terminal a spinner with the
/// time the step has taken, until it ends. A step inside another shows its own time.
pub fn step<T>(label: &str, f: impl FnOnce() -> T) -> T {
    println!("{label}…");
    if !spins() {
        return f();
    }
    let _running = Running::start();
    f()
}

struct Spinner {
    stop: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

struct Running;

impl Running {
    fn start() -> Self {
        lock(&STARTS).push(Instant::now());
        let mut s = lock(&SPINNER);
        if s.is_none() {
            let (stop, stopped) = mpsc::channel();
            let thread = std::thread::spawn(move || spin(&stopped));
            *s = Some(Spinner { stop, thread });
        }
        Running
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let done = {
            let mut starts = lock(&STARTS);
            starts.pop();
            starts.is_empty()
        };
        if done && let Some(s) = lock(&SPINNER).take() {
            let _ = s.stop.send(());
            let _ = s.thread.join();
        }
    }
}

fn spin(stopped: &mpsc::Receiver<()>) {
    let mut drawn = false;
    let mut frame = 0;
    while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(TICK) {
        let Some(began) = lock(&STARTS).last().copied() else {
            break;
        };
        let took = began.elapsed();
        if took < DELAY {
            continue;
        }
        let line = format!("{} {}", FRAMES[frame % FRAMES.len()], elapsed(took));
        frame += 1;
        let mut e = std::io::stderr().lock();
        let _ = write!(e, "\r{line:<WIDTH$}\r");
        let _ = e.flush();
        drawn = true;
    }
    if drawn {
        let mut e = std::io::stderr().lock();
        let _ = write!(e, "\r{:WIDTH$}\r", "");
        let _ = e.flush();
    }
}

/// `12s`, `3m 05s`.
fn elapsed(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else {
        format!("{}m {:02}s", s / 60, s % 60)
    }
}

/// Run `args`, a command in the env that a step waits on: each chunk it prints goes to `also`
/// (an install log) and, with `--verbose`, to this terminal escaped. When it fails without
/// `--verbose`, its last lines follow on stderr, escaped.
pub fn tool<I, S>(rt: &Runtime, args: I, also: &(dyn Fn(&[u8]) + Sync)) -> Result<ExitStatus>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let verbose = verbose();
    let relays = [
        Mutex::new(Relay::new(std::io::stdout().is_terminal())),
        Mutex::new(Relay::new(std::io::stderr().is_terminal())),
    ];
    let kept = Mutex::new(Vec::new());
    let status = rt.stream(args, &|to_err, chunk| {
        also(chunk);
        if verbose {
            write(to_err, &lock(&relays[usize::from(to_err)]).feed(chunk));
        } else {
            let mut k = lock(&kept);
            k.extend_from_slice(chunk);
            if k.len() > 2 * KEEP {
                let cut = k.len() - KEEP;
                k.drain(..cut);
            }
        }
        true
    })?;
    if verbose {
        for (to_err, r) in [(false, &relays[0]), (true, &relays[1])] {
            let rest = lock(r).finish();
            if !rest.is_empty() {
                write(to_err, &format!("{rest}\n"));
            }
        }
    } else if !status.success() {
        let kept = kept.into_inner().unwrap_or_else(PoisonError::into_inner);
        for line in last_lines(&kept, TAIL_LINES) {
            eprintln!("  {line}");
        }
    }
    Ok(status)
}

fn write(to_err: bool, text: &str) {
    // The terminal may be gone (a closed `luoto ui`); the step goes on.
    let _ = if to_err {
        std::io::stderr().write_all(text.as_bytes())
    } else {
        let mut o = std::io::stdout();
        o.write_all(text.as_bytes()).and_then(|()| o.flush())
    };
}

/// The last `n` lines `out` shows, escaped: of a line redrawn with carriage returns (a
/// progress bar), what it ended as; blank lines left out.
fn last_lines(out: &[u8], n: usize) -> Vec<String> {
    let text = String::from_utf8_lossy(out);
    let shown: Vec<&str> = text
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .map(|l| l.rsplit('\r').next().unwrap_or(l))
        .filter(|l| !l.trim().is_empty())
        .collect();
    shown[shown.len().saturating_sub(n)..]
        .iter()
        .map(|l| text::display(l))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_shows_its_last_lines_as_they_ended_escaped() {
        let out = b"one\n\ntwo 10%\rtwo 100%\r\nthree \x1b]52;c;aGk=\x07\n";
        assert_eq!(
            last_lines(out, 2),
            [
                "two 100%".to_string(),
                text::display("three \x1b]52;c;aGk=\x07")
            ]
        );
        assert!(!last_lines(out, 2)[1].contains('\x1b'));
        assert_eq!(last_lines(out, 9).len(), 3);
        assert!(last_lines(b"", 3).is_empty());
    }

    #[test]
    fn times_read_in_seconds_then_minutes() {
        assert_eq!(elapsed(Duration::from_secs(12)), "12s");
        assert_eq!(elapsed(Duration::from_secs(185)), "3m 05s");
        assert!(format!("{} {}", '-', elapsed(Duration::from_secs(3599))).len() < WIDTH);
    }
}
