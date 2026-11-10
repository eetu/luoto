//! Progress for what takes a while. A step prints its line (`installing …`); on a terminal a
//! pulsing dot in the UI's accent follows on the next line, with the time so far and the
//! latest line its tool printed, until the step ends. `o` shows the tool's whole output from
//! there on. Otherwise what tools print (installers, git) reaches the terminal only with
//! `--verbose`, or its last lines when one fails. The sandbox wrote much of it, so it comes
//! escaped ([`text::Relay`]). A line luoto prints during a step goes through [`say`], which
//! clears the spinner's line first.

use std::io::{IsTerminal, Write};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::queue;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::terminal::{Clear, ClearType};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::runtime::Runtime;
use crate::text::{self, Relay};

static VERBOSE: AtomicBool = AtomicBool::new(false);
static OFF: AtomicBool = AtomicBool::new(false);
/// When each running step began, innermost last.
static STARTS: Mutex<Vec<Instant>> = Mutex::new(Vec::new());
static SPINNER: Mutex<Option<Spinner>> = Mutex::new(None);
/// Whether the spinner's line is on the terminal; held while it is drawn.
static DRAWN: Mutex<bool> = Mutex::new(false);
/// The output of the tool a spinning step runs now.
static TOOL: Mutex<Option<Arc<Mutex<Output>>>> = Mutex::new(None);
/// `o` was pressed: the rest of the step's tool output is shown as it comes.
static SHOWN: AtomicBool = AtomicBool::new(false);

/// The UI's accent (`--halo-accent` in frontend/src/lib/styles/halo.css).
const ACCENT: (u8, u8, u8) = (247, 143, 8);
/// The accent's nearest in xterm's 256 colors, last, after darker steps for the pulse.
const ACCENT_256: [u8; 4] = [94, 130, 172, 208];
/// How bright the dot is at the low of its pulse, of the accent.
const DIM: f64 = 0.35;
const PULSE: Duration = Duration::from_millis(1200);
const TICK: Duration = Duration::from_millis(83);
/// A step that ends sooner shows no spinner.
const DELAY: Duration = Duration::from_secs(1);
const HINT: &str = "o: output";
/// What a failed tool's output shows of itself.
const TAIL_LINES: usize = 20;
/// What a tool's output keeps for a failure: its newest bytes.
const KEEP: usize = 64 * 1024;
/// The longest line kept as the latest.
const MAX_LATEST: usize = 4096;

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
        && std::env::var("TERM").map_or(true, |t| t != "dumb")
        && std::io::stderr().is_terminal()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The accent as this terminal shows it, none where colors are off (`NO_COLOR`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Accent {
    Rgb(u8, u8, u8),
    Ansi(u8),
}

pub fn accent() -> Option<Accent> {
    match Look::detect().colors {
        Colors::True => Some(Accent::Rgb(ACCENT.0, ACCENT.1, ACCENT.2)),
        Colors::Ansi256 => Some(Accent::Ansi(ACCENT_256[3])),
        Colors::None => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Colors {
    True,
    Ansi256,
    None,
}

#[derive(Clone, Copy, Debug)]
struct Look {
    colors: Colors,
    /// The dot and `…` render: a UTF-8 locale.
    unicode: bool,
}

impl Look {
    fn detect() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let colors = if var("NO_COLOR").is_some() {
            Colors::None
        } else if var("COLORTERM").is_some_and(|v| v == "truecolor" || v == "24bit")
            || var("WT_SESSION").is_some()
        {
            Colors::True
        } else {
            Colors::Ansi256
        };
        let unicode = cfg!(windows)
            || ["LC_ALL", "LC_CTYPE", "LANG"]
                .iter()
                .find_map(|k| var(k))
                .is_some_and(|v| {
                    let v = v.to_ascii_lowercase();
                    v.contains("utf-8") || v.contains("utf8")
                });
        Look { colors, unicode }
    }

    /// The dot `t` into its pulse: brightness with colors, size without, a turning ASCII
    /// line where the dot may not render.
    fn dot(self, t: Duration) -> (char, Option<Color>) {
        let ms = t.as_millis();
        let phase = (ms % PULSE.as_millis()) as f64 / PULSE.as_millis() as f64;
        let level = (1.0 - (std::f64::consts::TAU * phase).cos()) / 2.0;
        let glyph = if !self.unicode {
            ['-', '\\', '|', '/'][(ms / 125 % 4) as usize]
        } else if self.colors == Colors::None && level < 0.5 {
            '•'
        } else {
            '●'
        };
        (glyph, self.color(level))
    }

    /// The accent at `level` (0 dim, 1 full).
    fn color(self, level: f64) -> Option<Color> {
        match self.colors {
            Colors::None => None,
            Colors::True => {
                let c = |v: u8| (f64::from(v) * (DIM + (1.0 - DIM) * level)).round() as u8;
                Some(Color::Rgb {
                    r: c(ACCENT.0),
                    g: c(ACCENT.1),
                    b: c(ACCENT.2),
                })
            }
            Colors::Ansi256 => Some(Color::AnsiValue(
                ACCENT_256[((level * 4.0) as usize).min(3)],
            )),
        }
    }

    fn grey(self) -> Option<Color> {
        (self.colors != Colors::None).then_some(Color::DarkGrey)
    }
}

/// Print with [`say`] during a step, so the line doesn't land on the spinner's.
pub fn say(f: impl FnOnce()) {
    let mut drawn = lock(&DRAWN);
    if *drawn {
        let mut e = std::io::stderr().lock();
        let _ = queue!(e, Print('\r'), Clear(ClearType::CurrentLine));
        let _ = e.flush();
        *drawn = false;
    }
    f();
}

/// Run `f` as a step: `label…` on a line of its own, then on a terminal the spinner, until it
/// ends. A step inside another shows its own time.
pub fn step<T>(label: &str, f: impl FnOnce() -> T) -> T {
    say(|| println!("{label}…"));
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
            let look = Look::detect();
            let keys = keys::listen();
            let (stop, stopped) = mpsc::channel();
            let thread = std::thread::spawn(move || spin(&stopped, look, keys.as_ref()));
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
            SHOWN.store(false, Ordering::Relaxed);
        }
    }
}

fn spin(stopped: &mpsc::Receiver<()>, look: Look, keys: Option<&keys::Keys>) {
    let pulse = Instant::now();
    while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(TICK) {
        if keys.is_some_and(keys::Keys::pressed_o) && !SHOWN.load(Ordering::Relaxed) {
            show_output();
        }
        if SHOWN.load(Ordering::Relaxed) {
            continue;
        }
        let Some(began) = lock(&STARTS).last().copied() else {
            break;
        };
        let took = began.elapsed();
        if took < DELAY {
            continue;
        }
        let tool = lock(&TOOL).clone();
        let latest = tool.as_ref().and_then(|o| lock(o).latest.clone());
        let width = crossterm::terminal::size()
            .ok()
            .filter(|(w, _)| *w > 0)
            .map_or(80, |(w, _)| usize::from(w));
        let mut drawn = lock(&DRAWN);
        let mut e = std::io::stderr().lock();
        let _ = draw(
            &mut e,
            look,
            pulse.elapsed(),
            took,
            latest.as_deref(),
            tool.is_some() && keys.is_some(),
            width,
        );
        *drawn = true;
    }
    say(|| {});
}

/// The spinner's line: the dot, the time so far, the tool's latest line cut to the
/// terminal's `width`, and the key that shows the rest.
fn draw(
    e: &mut impl Write,
    look: Look,
    pulse: Duration,
    took: Duration,
    latest: Option<&str>,
    key: bool,
    width: usize,
) -> std::io::Result<()> {
    let (glyph, color) = look.dot(pulse);
    queue!(e, Print('\r'), Clear(ClearType::CurrentLine))?;
    paint(e, color, &glyph.to_string())?;
    let time = elapsed(took);
    queue!(e, Print(format!(" {time}")))?;
    let hint = if key { HINT.len() + 2 } else { 0 };
    // One column to spare, so the line never wraps.
    let room = width.saturating_sub(2 + time.len() + 2 + hint + 1);
    if let Some(l) = latest.filter(|_| room >= 8) {
        paint(e, look.grey(), &format!("  {}", fit(l, room, look.unicode)))?;
    }
    if key {
        queue!(e, Print(format!("  {HINT}")))?;
    }
    e.flush()
}

fn paint(e: &mut impl Write, color: Option<Color>, s: &str) -> std::io::Result<()> {
    match color {
        Some(c) => queue!(e, SetForegroundColor(c), Print(s), ResetColor),
        None => queue!(e, Print(s)),
    }
}

/// `s` cut to `room` columns, ending in an ellipsis when cut.
fn fit(s: &str, room: usize, unicode: bool) -> String {
    if s.width() <= room {
        return s.to_string();
    }
    let more = if unicode { "…" } else { "..." };
    let mut out = String::new();
    let mut used = more.width();
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if used + w > room {
            break;
        }
        out.push(c);
        used += w;
    }
    out + more
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

/// `o`: the tool's output so far, then the rest of the step's as it comes.
fn show_output() {
    say(|| {
        SHOWN.store(true, Ordering::Relaxed);
        if let Some(o) = lock(&TOOL).clone() {
            lock(&o).show();
        }
    });
}

/// What the tool a step runs has printed.
struct Output {
    kept: Vec<u8>,
    relays: [Relay; 2],
    /// Each stream's line so far.
    partial: [Vec<u8>; 2],
    latest: Option<String>,
    shown: bool,
}

impl Output {
    fn new(shown: bool) -> Self {
        Output {
            kept: Vec::new(),
            relays: [
                Relay::new(std::io::stdout().is_terminal()),
                Relay::new(std::io::stderr().is_terminal()),
            ],
            partial: [Vec::new(), Vec::new()],
            latest: None,
            shown,
        }
    }

    fn feed(&mut self, to_err: bool, chunk: &[u8]) {
        let i = usize::from(to_err);
        if self.shown {
            write(to_err, &self.relays[i].feed(chunk));
            return;
        }
        self.kept.extend_from_slice(chunk);
        if self.kept.len() > 2 * KEEP {
            let cut = self.kept.len() - KEEP;
            self.kept.drain(..cut);
        }
        for &b in chunk {
            if b == b'\n' || b == b'\r' {
                let line = std::mem::take(&mut self.partial[i]);
                let line = String::from_utf8_lossy(&line);
                if !line.trim().is_empty() {
                    self.latest = Some(text::display(line.trim()));
                }
            } else if self.partial[i].len() < MAX_LATEST {
                self.partial[i].push(b);
            }
        }
    }

    fn show(&mut self) {
        let kept = std::mem::take(&mut self.kept);
        let mut r = Relay::new(std::io::stderr().is_terminal());
        write(true, &r.feed(&kept));
        let rest = r.finish();
        if !rest.is_empty() {
            write(true, &format!("{rest}\n"));
        }
        self.shown = true;
    }

    /// What the relays held back, once the tool is done.
    fn finish(&mut self) {
        for (to_err, r) in [(false, 0), (true, 1)] {
            let rest = self.relays[r].finish();
            if !rest.is_empty() {
                write(to_err, &format!("{rest}\n"));
            }
        }
    }
}

/// Run `args`, a command in the env that a step waits on: each chunk it prints goes to `also`
/// (an install log), and to the terminal escaped with `--verbose` or once `o` was pressed.
/// When it fails unseen, its last lines follow on stderr, escaped.
pub fn tool<I, S>(rt: &Runtime, args: I, also: &(dyn Fn(&[u8]) + Sync)) -> Result<ExitStatus>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let out = Arc::new(Mutex::new(Output::new(
        verbose() || SHOWN.load(Ordering::Relaxed),
    )));
    // Only a spinning step reads it: `luoto ui` runs installs for several envs at once.
    let watched = lock(&SPINNER).is_some();
    if watched {
        *lock(&TOOL) = Some(out.clone());
    }
    let status = rt.stream(args, &|to_err, chunk| {
        also(chunk);
        lock(&out).feed(to_err, chunk);
        true
    });
    if watched {
        lock(&TOOL).take();
    }
    let status = status?;
    let mut o = lock(&out);
    if o.shown {
        o.finish();
    } else if !status.success() {
        let tail = last_lines(&o.kept, TAIL_LINES);
        say(|| {
            for line in tail {
                eprintln!("  {line}");
            }
        });
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

/// Keys pressed while a step spins: read one at a time and unechoed, so `o` acts at once.
/// Signals and line breaks work as ever; what else is typed meanwhile is dropped.
#[cfg(unix)]
mod keys {
    use std::cell::UnsafeCell;
    use std::mem::MaybeUninit;

    /// What ends luoto from the terminal or a supervisor: the terminal's settings come back
    /// first.
    const SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];

    /// The terminal's settings and the signals' actions before [`listen`] changed them.
    struct Saved {
        termios: UnsafeCell<MaybeUninit<libc::termios>>,
        actions: UnsafeCell<[MaybeUninit<libc::sigaction>; 4]>,
    }

    // SAFETY: written only by `listen`, before it installs the handler that reads it, and only
    // the outermost step listens (one `Keys` at a time).
    unsafe impl Sync for Saved {}

    static SAVED: Saved = Saved {
        termios: UnsafeCell::new(MaybeUninit::uninit()),
        actions: UnsafeCell::new([const { MaybeUninit::uninit() }; 4]),
    };

    pub struct Keys(());

    /// Keys from this terminal, when luoto has it in the foreground (a background job that
    /// changed its settings would be stopped).
    pub fn listen() -> Option<Keys> {
        // SAFETY: libc calls on stdin; SAVED as above.
        unsafe {
            if libc::isatty(0) != 1 || libc::tcgetpgrp(0) != libc::getpgrp() {
                return None;
            }
            let mut t = MaybeUninit::<libc::termios>::uninit();
            if libc::tcgetattr(0, t.as_mut_ptr()) != 0 {
                return None;
            }
            let t = t.assume_init();
            (*SAVED.termios.get()).write(t);
            let actions = &mut *SAVED.actions.get();
            let mut on: libc::sigaction = std::mem::zeroed();
            on.sa_sigaction = restore_and_raise as *const () as libc::sighandler_t;
            libc::sigemptyset(&raw mut on.sa_mask);
            for (old, s) in actions.iter_mut().zip(SIGNALS) {
                libc::sigaction(s, &raw const on, old.as_mut_ptr());
            }
            let mut quiet = t;
            quiet.c_lflag &= !(libc::ICANON | libc::ECHO);
            quiet.c_cc[libc::VMIN] = 0;
            quiet.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(0, libc::TCSANOW, &raw const quiet) != 0 {
                put_back();
                return None;
            }
        }
        Some(Keys(()))
    }

    /// The terminal's settings and the signals' actions as they were.
    ///
    /// # Safety
    /// Only after [`listen`] saved them.
    unsafe fn put_back() {
        // SAFETY: tcsetattr and sigaction are async-signal-safe; SAVED was written.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, (*SAVED.termios.get()).as_ptr());
            let actions = &*SAVED.actions.get();
            for (old, s) in actions.iter().zip(SIGNALS) {
                libc::sigaction(s, old.as_ptr(), std::ptr::null_mut());
            }
        }
    }

    /// A signal while keys are read: the terminal as it was, then the signal as it would have
    /// acted (luoto ends, or `luoto run` counts a Ctrl-C).
    extern "C" fn restore_and_raise(sig: libc::c_int) {
        // SAFETY: installed only by `listen`, after SAVED was written; raise is
        // async-signal-safe.
        unsafe {
            put_back();
            // What prints next starts below the spinner rather than on its line.
            libc::write(2, c"\n".as_ptr().cast(), 1);
            libc::raise(sig);
        }
    }

    impl Keys {
        /// Whether `o` was pressed since the last call.
        pub fn pressed_o(&self) -> bool {
            let mut hit = false;
            let mut buf = [0u8; 64];
            loop {
                let mut fd = libc::pollfd {
                    fd: 0,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one pollfd, no wait; a read of at most `buf`'s length.
                let n = unsafe {
                    if libc::poll(&raw mut fd, 1, 0) <= 0 {
                        break;
                    }
                    libc::read(0, buf.as_mut_ptr().cast(), buf.len())
                };
                let Ok(n) = usize::try_from(n) else { break };
                if n == 0 {
                    break;
                }
                hit |= buf[..n].iter().any(|b| matches!(b, b'o' | b'O'));
            }
            hit
        }
    }

    impl Drop for Keys {
        fn drop(&mut self) {
            // SAFETY: a Keys exists only after `listen` saved them.
            unsafe { put_back() }
        }
    }
}

/// Keys pressed while a step spins, from the console's input events (they aren't echoed).
#[cfg(windows)]
mod keys {
    use std::io::IsTerminal;
    use std::time::Duration;

    use crossterm::event::{self, Event, KeyCode, KeyEventKind};

    pub struct Keys(());

    pub fn listen() -> Option<Keys> {
        std::io::stdin().is_terminal().then_some(Keys(()))
    }

    impl Keys {
        /// Whether `o` was pressed since the last call.
        pub fn pressed_o(&self) -> bool {
            let mut hit = false;
            while event::poll(Duration::ZERO).unwrap_or(false) {
                match event::read() {
                    Ok(Event::Key(k))
                        if k.kind == KeyEventKind::Press
                            && matches!(k.code, KeyCode::Char('o' | 'O')) =>
                    {
                        hit = true;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            hit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUE: Look = Look {
        colors: Colors::True,
        unicode: true,
    };

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
    }

    #[test]
    fn the_dot_pulses_between_dim_and_the_accent() {
        let at = |ms| TRUE.dot(Duration::from_millis(ms));
        assert_eq!(at(0).0, '●');
        assert_eq!(
            at(600).1,
            Some(Color::Rgb {
                r: ACCENT.0,
                g: ACCENT.1,
                b: ACCENT.2
            })
        );
        assert_eq!(at(0).1, at(1200).1);
        let Some(Color::Rgb { r, .. }) = at(0).1 else {
            panic!("not a color")
        };
        assert!(r < ACCENT.0 / 2);
        let ansi = Look {
            colors: Colors::Ansi256,
            ..TRUE
        };
        assert_eq!(
            ansi.dot(Duration::from_millis(600)).1,
            Some(Color::AnsiValue(208))
        );
        let plain = Look {
            colors: Colors::None,
            ..TRUE
        };
        assert_eq!(plain.dot(Duration::ZERO), ('•', None));
        assert_eq!(plain.dot(Duration::from_millis(600)), ('●', None));
        let ascii = Look {
            unicode: false,
            ..plain
        };
        assert_eq!(ascii.dot(Duration::ZERO).0, '-');
        assert_eq!(ascii.dot(Duration::from_millis(130)).0, '\\');
    }

    #[test]
    fn the_latest_line_is_cut_to_the_columns_left() {
        assert_eq!(fit("short", 10, true), "short");
        assert_eq!(fit("Downloading release", 10, true), "Downloadi…");
        assert_eq!(fit("Downloading release", 10, false), "Downloa...");
        assert_eq!(fit("日本語の行", 7, true), "日本語…");
    }

    #[test]
    fn the_line_fits_its_terminal() {
        let mut out = Vec::new();
        let latest = "x".repeat(200);
        draw(
            &mut out,
            Look {
                colors: Colors::None,
                ..TRUE
            },
            Duration::ZERO,
            Duration::from_secs(5),
            Some(&latest),
            true,
            60,
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        let line = s.rsplit('\r').next().unwrap();
        let line = line.trim_start_matches("\u{1b}[2K");
        assert!(line.width() < 60, "{line:?}");
        assert!(line.ends_with(HINT) && line.starts_with("• 5s  xxx"));
    }

    #[test]
    fn the_latest_line_is_the_last_one_finished_escaped() {
        let mut o = Output::new(false);
        o.feed(false, b"one\ntwo 10%\rtwo 100%\r");
        assert_eq!(o.latest.as_deref(), Some("two 100%"));
        o.feed(true, b"\x1b]0;title\x07 three\n  \n");
        let latest = o.latest.clone().unwrap();
        assert!(!latest.contains('\x1b') && latest.ends_with("three"));
        o.feed(false, b"unfinished");
        assert!(o.latest.unwrap().ends_with("three"));
    }
}
