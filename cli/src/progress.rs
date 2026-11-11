//! Progress for what takes a while. A step prints its line (`installing …`); on a terminal a
//! pulsing dot in the UI's accent follows on the next line, with the time so far and the
//! latest line its tool printed, until the step ends. `o` shows the tool's whole output from
//! there on. Otherwise what tools print (installers, git) reaches the terminal only with
//! `--verbose`, or its last lines when one fails. The sandbox wrote much of it, so it comes
//! escaped ([`text::Relay`]). A line luoto prints during a step goes through [`say`], which
//! clears the spinner's line first. A [`wait`] is a step without a line: the spinner names it
//! only once it takes a while. A question or `op` runs in a [`pause`].

use std::io::{IsTerminal, Write};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::queue;
use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};

use crate::runtime::Runtime;
use crate::text::{self, Relay};

static VERBOSE: AtomicBool = AtomicBool::new(false);
static OFF: AtomicBool = AtomicBool::new(false);
/// The running steps and waits, innermost last.
static STARTS: Mutex<Vec<Start>> = Mutex::new(Vec::new());
static SPINNER: Mutex<Option<Spinner>> = Mutex::new(None);
/// [`pause`]s under way: no spinner until they end.
static PAUSED: AtomicUsize = AtomicUsize::new(0);
/// What the spinner has on the terminal; held while it draws.
static SCREEN: Mutex<Screen> = Mutex::new(Screen {
    line: false,
    rest: Vec::new(),
    hidden: false,
});
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

#[derive(Default)]
struct Screen {
    /// The spinner's line is drawn.
    line: bool,
    /// Its text after the dot, as drawn: a frame with the same redraws only the dot.
    rest: Vec<u8>,
    /// The cursor is hidden, until the spinner ends.
    hidden: bool,
}

/// Erase the line, back to its start.
const ERASE: &[u8] = b"\r\x1b[2K";
/// Erase from the cursor to the end of the line.
const ERASE_REST: &[u8] = b"\x1b[K";
const HIDE_CURSOR: &[u8] = b"\x1b[?25l";
const SHOW_CURSOR: &[u8] = b"\x1b[?25h";
/// Synchronized output: terminals that know it paint the frame whole; others ignore it.
const BEGIN_FRAME: &[u8] = b"\x1b[?2026h";
const END_FRAME: &[u8] = b"\x1b[?2026l";

fn put(bytes: &[u8]) {
    let mut e = std::io::stderr().lock();
    let _ = e.write_all(bytes).and_then(|()| e.flush());
}

/// Print with [`say`] during a step, so the line doesn't land on the spinner's.
pub fn say(f: impl FnOnce()) {
    let mut s = lock(&SCREEN);
    if s.line {
        put(ERASE);
        s.line = false;
        s.rest.clear();
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
    let _running = Running::start(None);
    f()
}

/// Run `f` without a line of its own: on a terminal, once it takes a while, the spinner says
/// what it waits on (`label`), and its line goes when `f` ends. For what is quick when all is
/// well (a container starting, a status read), so it says nothing then.
pub fn wait<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let _waiting = waiting(label);
    f()
}

/// A [`wait`] that lasts until the guard drops, for a stretch of a function.
pub fn waiting(label: &str) -> Waiting {
    Waiting(spins().then(|| Running::start(Some(label.to_string()))))
}

pub struct Waiting(#[allow(dead_code)] Option<Running>);

/// Run `f` with the terminal as it was, for a question or a tool that may ask there (`op`):
/// the spinner stops, and with it the reading of keys, then goes on, its time without the
/// pause.
pub fn pause<T>(f: impl FnOnce() -> T) -> T {
    PAUSED.fetch_add(1, Ordering::SeqCst);
    let spinner = lock(&SPINNER).take();
    if let Some(s) = spinner {
        s.halt();
    }
    let began = Instant::now();
    let out = f();
    if PAUSED.fetch_sub(1, Ordering::SeqCst) == 1 {
        let paused = began.elapsed();
        let running = {
            let mut starts = lock(&STARTS);
            for s in starts.iter_mut() {
                s.at += paused;
            }
            !starts.is_empty()
        };
        if running {
            start_spinner();
        }
    }
    out
}

struct Start {
    at: Instant,
    /// What a [`wait`] waits on; none for a step, whose line says it.
    waits_on: Option<String>,
}

struct Spinner {
    stop: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

impl Spinner {
    /// Its line erased, the cursor and the terminal as they were.
    fn halt(self) {
        let _ = self.stop.send(());
        let _ = self.thread.join();
    }
}

fn start_spinner() {
    if PAUSED.load(Ordering::SeqCst) > 0 {
        return;
    }
    let mut s = lock(&SPINNER);
    if s.is_none() {
        let look = Look::detect();
        let term = term::Term::take();
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::spawn(move || spin(&stopped, look, &term));
        *s = Some(Spinner { stop, thread });
    }
}

struct Running;

impl Running {
    fn start(waits_on: Option<String>) -> Self {
        lock(&STARTS).push(Start {
            at: Instant::now(),
            waits_on,
        });
        start_spinner();
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
        if done {
            let spinner = lock(&SPINNER).take();
            if let Some(s) = spinner {
                s.halt();
            }
            SHOWN.store(false, Ordering::Relaxed);
        }
    }
}

/// When the spinner's time counts from: the innermost step's, which printed a line; under
/// waits alone, the outermost's. Then what the innermost waits on, if it is a wait.
fn timed(starts: &[Start]) -> Option<(Instant, Option<String>)> {
    let first = starts.first()?;
    let began = starts
        .iter()
        .rev()
        .find(|s| s.waits_on.is_none())
        .unwrap_or(first)
        .at;
    Some((began, starts.last()?.waits_on.clone()))
}

fn spin(stopped: &mpsc::Receiver<()>, look: Look, term: &term::Term) {
    let pulse = Instant::now();
    while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(TICK) {
        if term.pressed_o() && !SHOWN.load(Ordering::Relaxed) {
            show_output();
        }
        if SHOWN.load(Ordering::Relaxed) {
            continue;
        }
        let (first, timed) = {
            let starts = lock(&STARTS);
            (starts.first().map(|s| s.at), timed(&starts))
        };
        let (Some(first), Some((began, waits_on))) = (first, timed) else {
            break;
        };
        if first.elapsed() < DELAY {
            continue;
        }
        let took = began.elapsed();
        let tool = lock(&TOOL).clone();
        let latest = tool.as_ref().and_then(|o| lock(o).latest.clone());
        let width = crossterm::terminal::size()
            .ok()
            .filter(|(w, _)| *w > 0)
            .map_or(80, |(w, _)| usize::from(w));
        let rest = rest(
            look,
            took,
            latest.as_deref().map_or_else(
                || waits_on.as_deref().map(|w| (w, None)),
                |l| Some((l, look.grey())),
            ),
            tool.is_some() && term.keys(),
            width,
        );
        let mut s = lock(&SCREEN);
        let hide = term::HIDES_CURSOR && !s.hidden;
        let whole = !s.line || s.rest != rest;
        put(&frame(
            look.dot(pulse.elapsed()),
            whole.then_some(&rest[..]),
            hide,
        ));
        s.line = true;
        s.hidden |= hide;
        if whole {
            s.rest = rest;
        }
    }
    say(|| {});
    let mut s = lock(&SCREEN);
    if s.hidden {
        put(SHOW_CURSOR);
        s.hidden = false;
    }
}

/// One frame, written at once: the dot at the line's start and, when `rest` changed, the
/// line after it.
fn frame(dot: (char, Option<Color>), rest: Option<&[u8]>, hide: bool) -> Vec<u8> {
    let mut out = BEGIN_FRAME.to_vec();
    if hide {
        out.extend_from_slice(HIDE_CURSOR);
    }
    out.push(b'\r');
    let _ = paint(&mut out, dot.1, &dot.0.to_string());
    if let Some(rest) = rest {
        out.extend_from_slice(rest);
        out.extend_from_slice(ERASE_REST);
    }
    out.extend_from_slice(END_FRAME);
    out
}

/// The spinner's line after the dot: the time so far, its `line` (the tool's latest line, or
/// what a wait waits on) in its color, cut to the terminal's `width`, and the key that shows
/// the rest.
fn rest(
    look: Look,
    took: Duration,
    line: Option<(&str, Option<Color>)>,
    key: bool,
    width: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    let time = elapsed(took);
    out.extend_from_slice(format!(" {time}").as_bytes());
    let hint = if key { HINT.len() + 2 } else { 0 };
    // One column to spare, so the line never wraps.
    let room = width.saturating_sub(2 + time.len() + 2 + hint + 1);
    if let Some((l, color)) = line.filter(|_| room >= 8) {
        let _ = paint(
            &mut out,
            color,
            &format!("  {}", text::fit(l, room, look.unicode)),
        );
    }
    if key {
        out.extend_from_slice(format!("  {HINT}").as_bytes());
    }
    out
}

fn paint(e: &mut impl Write, color: Option<Color>, s: &str) -> std::io::Result<()> {
    match color {
        Some(c) => queue!(e, SetForegroundColor(c), Print(s), ResetColor),
        None => queue!(e, Print(s)),
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
    tool_with(|each| rt.stream(args, each), also, &|out| {
        last_lines(out, TAIL_LINES)
    })
}

/// [`tool`] for a command on this machine (`podman machine`).
pub fn host(cmd: std::process::Command) -> Result<ExitStatus> {
    tool_with(
        |each| crate::runtime::stream_command(cmd, each),
        &|_| {},
        &|out| last_lines(out, TAIL_LINES),
    )
}

/// [`tool`] for git in the env: a failure shows [`git_tail`].
pub fn git<I, S>(rt: &Runtime, args: I) -> Result<ExitStatus>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    tool_with(|each| rt.stream(args, each), &|_| {}, &git_tail)
}

/// What a failed git shows of its output: its `fatal:` and `error:` lines, and the reason the
/// gate gave for a request it refused; its last lines when it printed none of those.
fn git_tail(out: &[u8]) -> Vec<String> {
    let kept: Vec<String> = last_lines(out, usize::MAX)
        .into_iter()
        .filter_map(|l| {
            let t = l.trim_start();
            if t.starts_with("fatal:") || t.starts_with("error:") {
                Some(t.to_string())
            } else {
                t.strip_prefix("remote: reason:")
                    .map(|r| format!("the gate: {}", r.trim()))
            }
        })
        .collect();
    if kept.is_empty() {
        last_lines(out, TAIL_LINES)
    } else {
        kept
    }
}

/// Run what `run` starts, given each chunk it prints (`true` for stderr).
fn tool_with(
    run: impl FnOnce(&(dyn Fn(bool, &[u8]) -> bool + Sync)) -> Result<ExitStatus>,
    also: &(dyn Fn(&[u8]) + Sync),
    tail: &dyn Fn(&[u8]) -> Vec<String>,
) -> Result<ExitStatus> {
    let out = Arc::new(Mutex::new(Output::new(
        verbose() || SHOWN.load(Ordering::Relaxed),
    )));
    // Only a spinning step reads it: `luoto ui` runs installs for several envs at once.
    let watched = lock(&SPINNER).is_some();
    if watched {
        *lock(&TOOL) = Some(out.clone());
    }
    let status = run(&|to_err, chunk| {
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
        let tail = tail(&o.kept);
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

/// The terminal while a step spins. Its cursor is hidden, and keys are read one at a time and
/// unechoed, so `o` acts at once; signals and line breaks work as ever, and what else is typed
/// meanwhile is dropped. A signal that ends luoto meanwhile puts the terminal back first.
#[cfg(unix)]
mod term {
    use std::cell::UnsafeCell;
    use std::mem::MaybeUninit;
    use std::sync::atomic::{AtomicBool, Ordering};

    pub const HIDES_CURSOR: bool = true;

    /// What ends luoto from the terminal or a supervisor.
    /// What stops it as well (Ctrl-Z): after `fg` the spinner goes on without reading keys.
    const SIGNALS: [libc::c_int; 5] = [
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGTSTP,
    ];

    /// The terminal's settings and the signals' actions before [`Term::take`] changed them.
    struct Saved {
        termios: UnsafeCell<MaybeUninit<libc::termios>>,
        /// `termios` holds stdin's settings, changed for keys.
        keys: AtomicBool,
        actions: UnsafeCell<[MaybeUninit<libc::sigaction>; 5]>,
    }

    // SAFETY: written only by `take`, before it installs the handler that reads it, and only
    // the outermost step takes the terminal (one `Term` at a time).
    unsafe impl Sync for Saved {}

    static SAVED: Saved = Saved {
        termios: UnsafeCell::new(MaybeUninit::uninit()),
        keys: AtomicBool::new(false),
        actions: UnsafeCell::new([const { MaybeUninit::uninit() }; 5]),
    };

    pub struct Term(());

    impl Term {
        /// Keys come from stdin when it is this terminal and luoto has it in the foreground
        /// (a background job that changed its settings would be stopped).
        pub fn take() -> Term {
            // SAFETY: libc calls on stdin; SAVED as above.
            unsafe {
                let actions = &mut *SAVED.actions.get();
                let mut on: libc::sigaction = std::mem::zeroed();
                on.sa_sigaction = restore_and_raise as *const () as libc::sighandler_t;
                libc::sigemptyset(&raw mut on.sa_mask);
                for (old, s) in actions.iter_mut().zip(SIGNALS) {
                    libc::sigaction(s, &raw const on, old.as_mut_ptr());
                }
                let mut t = MaybeUninit::<libc::termios>::uninit();
                if libc::isatty(0) == 1
                    && libc::tcgetpgrp(0) == libc::getpgrp()
                    && libc::tcgetattr(0, t.as_mut_ptr()) == 0
                {
                    let t = t.assume_init();
                    (*SAVED.termios.get()).write(t);
                    let mut quiet = t;
                    quiet.c_lflag &= !(libc::ICANON | libc::ECHO);
                    quiet.c_cc[libc::VMIN] = 0;
                    quiet.c_cc[libc::VTIME] = 0;
                    // Set first: a signal between the change and the flag would leave the
                    // terminal without echo.
                    SAVED.keys.store(true, Ordering::SeqCst);
                    if libc::tcsetattr(0, libc::TCSANOW, &raw const quiet) != 0 {
                        SAVED.keys.store(false, Ordering::SeqCst);
                    }
                }
            }
            Term(())
        }

        pub fn keys(&self) -> bool {
            SAVED.keys.load(Ordering::SeqCst)
        }

        /// Whether `o` was pressed since the last call.
        pub fn pressed_o(&self) -> bool {
            let mut hit = false;
            let mut buf = [0u8; 64];
            while self.keys() {
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

    /// The terminal's settings and the signals' actions as they were.
    ///
    /// # Safety
    /// Only after [`Term::take`] saved them.
    unsafe fn put_back() {
        // SAFETY: tcsetattr and sigaction are async-signal-safe; SAVED was written.
        unsafe {
            if SAVED.keys.swap(false, Ordering::SeqCst) {
                libc::tcsetattr(0, libc::TCSANOW, (*SAVED.termios.get()).as_ptr());
            }
            let actions = &*SAVED.actions.get();
            for (old, s) in actions.iter().zip(SIGNALS) {
                libc::sigaction(s, old.as_ptr(), std::ptr::null_mut());
            }
        }
    }

    /// A signal while a step spins: the terminal as it was, the cursor shown and the spinner's
    /// line ended, then the signal as it would have acted (luoto ends, or `luoto run` counts a
    /// Ctrl-C).
    extern "C" fn restore_and_raise(sig: libc::c_int) {
        const BACK: &[u8] = b"\x1b[?25h\n";
        // SAFETY: installed only by `take`, after SAVED was written; write and raise are
        // async-signal-safe.
        unsafe {
            put_back();
            libc::write(2, BACK.as_ptr().cast(), BACK.len());
            libc::raise(sig);
        }
    }

    impl Drop for Term {
        fn drop(&mut self) {
            // SAFETY: a Term exists only after `take` saved them.
            unsafe { put_back() }
        }
    }
}

/// The console while a step spins: keys from its input events (they aren't echoed). Its
/// cursor stays: nothing would show it again after a Ctrl-C.
#[cfg(windows)]
mod term {
    use std::io::IsTerminal;
    use std::time::Duration;

    use crossterm::event::{self, Event, KeyCode, KeyEventKind};

    pub const HIDES_CURSOR: bool = false;

    pub struct Term(bool);

    impl Term {
        pub fn take() -> Term {
            Term(std::io::stdin().is_terminal())
        }

        pub fn keys(&self) -> bool {
            self.0
        }

        /// Whether `o` was pressed since the last call.
        pub fn pressed_o(&self) -> bool {
            let mut hit = false;
            while self.0 && event::poll(Duration::ZERO).unwrap_or(false) {
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
    use unicode_width::UnicodeWidthStr;

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
    fn a_failed_git_shows_its_errors_and_the_gates_reason() {
        let out = b"Cloning into '/workspace/.api.luoto-clone'...\n\
            remote: luoto: egress blocked by the sandbox policy of env \"web\"\n\
            remote: request: GET https://github.com/acme/api.git/info/refs\n\
            remote: reason:  no rule allows github.com\n\
            remote:\n\
            remote: To allow it, the user can run on the host:\n\
            remote:   luoto allow -e web github.com\n\
            fatal: unable to access 'https://github.com/acme/api.git/': The requested URL \
            returned error: 403\n";
        assert_eq!(
            git_tail(out),
            [
                "the gate: no rule allows github.com",
                "fatal: unable to access 'https://github.com/acme/api.git/': The requested URL \
                 returned error: 403",
            ]
        );
        // Nothing it recognizes: its last lines, as any tool's.
        assert_eq!(git_tail(b"one\ntwo\n"), ["one", "two"]);
    }

    /// What a terminal shows of `bytes`: control sequences left out.
    fn visible(bytes: &[u8]) -> String {
        let s = String::from_utf8_lossy(bytes);
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            match c {
                '\x1b' => {
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                '\r' => out.clear(),
                c => out.push(c),
            }
        }
        out
    }

    #[test]
    fn the_line_fits_its_terminal() {
        let plain = Look {
            colors: Colors::None,
            ..TRUE
        };
        let latest = "x".repeat(200);
        let rest = rest(
            plain,
            Duration::from_secs(5),
            Some((&latest, None)),
            true,
            60,
        );
        let line = visible(&frame(plain.dot(Duration::ZERO), Some(&rest), true));
        assert!(line.width() < 60, "{line:?}");
        assert!(
            line.ends_with(HINT) && line.starts_with("• 5s  xxx"),
            "{line:?}"
        );
    }

    #[test]
    fn a_wait_counts_from_the_outermost_and_names_the_innermost() {
        let at = Instant::now();
        let later = at + Duration::from_secs(3);
        let s = |at, w: Option<&str>| Start {
            at,
            waits_on: w.map(str::to_string),
        };
        let waits = [
            s(at, Some("starting `web`")),
            s(later, Some("starting the gate")),
        ];
        assert_eq!(
            timed(&waits),
            Some((at, Some("starting the gate".to_string())))
        );
        // A step has a line: its own time, and nothing to name.
        let step_in_wait = [s(at, Some("starting `web`")), s(later, None)];
        assert_eq!(timed(&step_in_wait), Some((later, None)));
        let wait_in_step = [s(at, None), s(later, Some("reading"))];
        assert_eq!(
            timed(&wait_in_step),
            Some((at, Some("reading".to_string())))
        );
        assert_eq!(timed(&[]), None);
    }

    #[test]
    fn a_frame_is_one_synchronized_write_that_overwrites_its_line() {
        let rest = rest(TRUE, Duration::from_secs(3), None, false, 80);
        let whole = frame(TRUE.dot(Duration::ZERO), Some(&rest), true);
        assert!(whole.starts_with(BEGIN_FRAME) && whole.ends_with(END_FRAME));
        let inner = &whole[BEGIN_FRAME.len()..whole.len() - END_FRAME.len()];
        assert!(inner.starts_with(HIDE_CURSOR));
        // Overwritten, then the leftover erased: never blank in between.
        assert!(!inner.windows(ERASE.len()).any(|w| w == ERASE));
        assert!(inner.ends_with(ERASE_REST));
        let dot = frame(TRUE.dot(Duration::ZERO), None, false);
        assert_eq!(visible(&dot), "●");
        assert!(!dot.windows(ERASE_REST.len()).any(|w| w == ERASE_REST));
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
