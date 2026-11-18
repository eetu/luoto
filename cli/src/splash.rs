//! The picture that starts `luoto setup`: the logo in half blocks (the island and
//! the sun in the accent, the palm and the sea in the terminal's own foreground) over the
//! tagline. On a terminal with colors it draws itself once: the palm grows, the sea spreads,
//! the sun rises and its reflection sinks. Without colors it is the still picture, without a
//! UTF-8 locale an ASCII one, and where stdout is no terminal there is none.
//!
//! The animation holds nothing up: what setup finds meanwhile is printed under the picture,
//! which keeps redrawing its own rows, and any key ends it at its last frame. It hides no
//! cursor, and every frame is one write that puts the cursor back and ends with all styles
//! reset. Keys are read in raw mode, where Ctrl-C is a key: it ends luoto as it would.

use std::io::{IsTerminal, Write};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::style::Style;

/// The animation's last frame is the still picture.
const FRAMES: usize = 34;
const TICK: Duration = Duration::from_millis(48);
/// Columns before the art; the tagline stands two further left.
const INDENT: usize = 4;
/// The widest line: a narrower terminal would wrap it.
const WIDTH: usize = 40;
/// What luoto's lines are written to fit. The animation needs as many columns: a line under
/// it that wrapped would be more rows than the redraw counts.
const LINE: usize = 80;
/// Lines the animation lets be printed under it.
const UNDER: usize = 4;
/// The rows the animation needs to stay on screen: a blank line, the picture, another, the
/// lines under it and two to spare.
const TALL: usize = 1 + H / 2 + 2 + 1 + UNDER + 2;

/// Pixels, two to a row of text.
const W: usize = 36;
const H: usize = 22;
/// The sea's crests; the sun and its reflection are mirrored about the line above them.
const SEA: usize = 15;

const ISLAND_TOP: usize = 10;
const ISLAND: [&str; 6] = [
    "............OOOOOOOOOO..",
    "..........OOOO......OOOO",
    ".........OOO..........OOO",
    "........OOO............OOO",
    "........OO..............OO",
    ".......OOO..............OOO",
];
/// The trunk from the island up, then each frond from the crown out: `(x, y)`.
const TRUNK: [(usize, usize); 8] = [
    (17, 9),
    (16, 8),
    (16, 7),
    (15, 6),
    (15, 5),
    (14, 4),
    (14, 3),
    (14, 2),
];
const FRONDS: [&[(usize, usize)]; 4] = [
    &[
        (13, 1),
        (12, 1),
        (11, 0),
        (10, 0),
        (9, 0),
        (8, 1),
        (7, 1),
        (6, 2),
        (6, 3),
    ],
    &[(13, 2), (12, 2), (11, 2), (10, 3), (9, 4), (9, 5)],
    &[
        (15, 1),
        (16, 0),
        (17, 0),
        (18, 0),
        (19, 0),
        (20, 1),
        (21, 2),
    ],
    &[
        (15, 2),
        (16, 2),
        (17, 2),
        (18, 3),
        (19, 3),
        (20, 4),
        (20, 5),
    ],
];
const SUN: [&str; 4] = [".OO.", "OOOO", "OOOO", ".OO."];
/// Two columns clear of the island, all the way up.
const SUN_X: usize = 29;
/// The sun's top row once it is up.
const SUN_TOP: usize = 4;

const TAGLINE: [(&str, Ink); 3] = [
    ("no tool is an island, except on ", Ink::Dim),
    ("luoto", Ink::Bold),
    (".", Ink::Accent),
];

/// What a cell is drawn in. Where a cell's two pixels differ, the later one wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ink {
    None,
    Dim,
    Fg,
    Bold,
    /// The accent, faint: the terminal blends it toward its own background.
    Faint,
    Accent,
}

type Line = Vec<(char, Ink)>;

fn put(line: &mut Line, at: usize, text: &str, ink: Ink) {
    line.resize(line.len().max(at), (' ', Ink::None));
    line.extend(
        text.chars()
            .map(|c| (c, if c == ' ' { Ink::None } else { ink })),
    );
}

/// The tagline's first `shown` characters.
fn tagline(shown: usize) -> Line {
    let mut line = Line::new();
    for (text, ink) in TAGLINE {
        put(&mut line, INDENT - 2, text, ink);
    }
    line.truncate(INDENT - 2 + shown);
    line
}

fn tagline_len() -> usize {
    TAGLINE.iter().map(|(t, _)| t.chars().count()).sum()
}

/// How far `t` (0..=1000 of the animation) is through `from..to`, 0..=1000.
fn part(t: usize, from: usize, to: usize) -> usize {
    (t.saturating_sub(from) * 1000 / (to - from)).min(1000)
}

/// [`part`], slowing toward its end.
fn eased(t: usize, from: usize, to: usize) -> usize {
    let left = 1000 - part(t, from, to);
    1000 - left * left * left / 1_000_000
}

/// `p` (0..=1000) of `len`, rounded.
fn of(p: usize, len: usize) -> usize {
    (p * len + 500) / 1000
}

/// The picture at `frame` of [`FRAMES`]; `reflect` adds the sun's reflection, which only
/// reads in color.
fn pixels(frame: usize, reflect: bool) -> [[Ink; W]; H] {
    let t = frame * 1000 / FRAMES;
    let mut px = [[Ink::None; W]; H];

    // The sun rises out of the sea once the sea has spread under it. A cell holds one color,
    // so it shows from the row of text above the crests.
    let top = SUN_TOP + of(1000 - eased(t, 300, 800), SEA - SUN_TOP);
    for (y, row) in SUN.iter().enumerate() {
        for (x, c) in row.chars().enumerate() {
            if c == 'O' && top + y < SEA - 1 {
                px[top + y][SUN_X + x] = Ink::Accent;
            }
        }
    }

    for &(x, y) in &TRUNK[..of(eased(t, 0, 350), TRUNK.len())] {
        px[y][x] = Ink::Fg;
    }
    for frond in FRONDS {
        for &(x, y) in &frond[..of(eased(t, 300, 600), frond.len())] {
            px[y][x] = Ink::Fg;
        }
    }

    // The sea spreads from the middle and rolls to rest.
    let roll = of(1000 - eased(t, 0, 800), 18);
    let reach = eased(t, 0, 300);
    let mut swell = |y: usize, from: usize, to: usize, phase: usize, ink: Ink| {
        for x in from..to {
            if (2 * x + 1).abs_diff(from + to) * 1000 <= (to - from) * reach {
                px[if (x + phase) % 6 < 3 { y } else { y + 1 }][x] = ink;
            }
        }
    };
    swell(SEA, 1, 35, roll, Ink::Fg);
    swell(SEA + 3, 8, 26, roll + 3, Ink::Dim);

    for (y, row) in ISLAND.iter().enumerate() {
        for (x, c) in row.chars().enumerate() {
            if c == 'O' {
                px[ISLAND_TOP + y][x] = Ink::Accent;
            }
        }
    }

    // The sun on the water, at two thirds of its height below the crests: two strokes that
    // sink as it rises, the nearer as wide as the sun. On the swell a stroke only tints the
    // swell. They shimmer until the sun is up.
    if reflect && top < SEA - 1 {
        let rising = t < 800;
        let bottom = (top + SUN.len() - 1).min(SEA - 2);
        let near = SEA + (SEA - 2 - bottom) * 2 / 3;
        let wide = SUN[0].len();
        let mut stroke = |y: usize, from: usize, to: usize, gap: Option<usize>| {
            for x in (from..to).filter(|x| Some(*x) != gap) {
                if y > SEA + 1 || px[y][x] == Ink::Fg {
                    px[y][x] = Ink::Faint;
                }
            }
        };
        stroke(
            near,
            SUN_X,
            SUN_X + wide,
            rising.then_some(SUN_X + frame % wide),
        );
        if bottom - top >= 2 {
            let from = SUN_X + if rising { [1, 2, 1, 0][frame % 4] } else { 1 };
            stroke(near + 2, from, from + wide - 2, None);
        }
    }
    px
}

/// The picture and the tagline at `frame`, as lines; as many at every frame.
fn blocks(frame: usize, reflect: bool) -> Vec<Line> {
    let px = pixels(frame, reflect);
    // The last row of text holds only the reflection.
    let rows = if reflect { H / 2 } else { H / 2 - 1 };
    let mut lines: Vec<Line> = (0..rows)
        .map(|r| {
            let mut line = vec![(' ', Ink::None); INDENT];
            line.extend((0..W).map(|x| match (px[2 * r][x], px[2 * r + 1][x]) {
                (Ink::None, Ink::None) => (' ', Ink::None),
                (upper, Ink::None) => ('▀', upper),
                (Ink::None, lower) => ('▄', lower),
                (upper, lower) => ('█', upper.max(lower)),
            }));
            line
        })
        .collect();
    lines.push(Line::new());
    let t = frame * 1000 / FRAMES;
    lines.push(tagline(of(part(t, 500, 950), tagline_len())));
    lines
}

/// The picture where half blocks may not render.
fn ascii() -> Vec<Line> {
    let mut lines = vec![Line::new(); 7];
    put(&mut lines[0], INDENT + 9, "__ _ __", Ink::Fg);
    put(&mut lines[1], INDENT + 7, ".'  \\|/  '.", Ink::Fg);
    put(&mut lines[1], INDENT + 24, "O", Ink::Accent);
    put(&mut lines[2], INDENT + 6, "'     |     '", Ink::Fg);
    put(&mut lines[3], INDENT + 9, ".--+--.", Ink::Accent);
    put(&mut lines[4], INDENT + 7, ".'       '.", Ink::Accent);
    put(&mut lines[5], INDENT + 1, "~~~~~", Ink::Fg);
    put(&mut lines[5], 0, "/", Ink::Accent);
    put(&mut lines[5], 0, "~~~~~~~~~~~", Ink::Fg);
    put(&mut lines[5], 0, "\\", Ink::Accent);
    put(&mut lines[5], 0, "~~~~~", Ink::Fg);
    put(&mut lines[6], INDENT + 6, "~~~~~~~~~~~~~", Ink::Dim);
    lines.push(Line::new());
    lines.push(tagline(tagline_len()));
    lines
}

/// `lines` as text, each without trailing spaces.
fn render(lines: &[Line], style: Style) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            let end = line.iter().rposition(|c| c.0 != ' ').map_or(0, |i| i + 1);
            let mut out = String::new();
            for run in line[..end].chunk_by(|a, b| a.1 == b.1) {
                let text: String = run.iter().map(|c| c.0).collect();
                out.push_str(&match run[0].1 {
                    Ink::None | Ink::Fg => text,
                    Ink::Dim => style.dim(&text),
                    Ink::Bold => style.head(&text),
                    Ink::Faint => style.dim(&style.marker(&text)),
                    Ink::Accent => style.marker(&text),
                });
            }
            out
        })
        .collect()
}

#[derive(Debug, PartialEq)]
enum Show {
    Nothing,
    Still,
    Moving,
}

/// What stdout gets: nothing unless it is a terminal wide enough for the picture; movement
/// only where colors and half blocks show and the terminal has the columns for the lines
/// printed under the picture and the rows to keep it on screen meanwhile.
fn plan(terminal: bool, styled: bool, unicode: bool, columns: usize, rows: usize) -> Show {
    if !terminal || columns <= WIDTH {
        Show::Nothing
    } else if styled && unicode && columns >= LINE && rows >= TALL {
        Show::Moving
    } else {
        Show::Still
    }
}

/// The still picture as `style` shows it.
fn still(style: Style) -> Vec<String> {
    if style.unicode() {
        render(&blocks(FRAMES, style.styled()), style)
    } else {
        render(&ascii(), style)
    }
}

/// Runs `work`, which prints and asks nothing, then prints `lines` of what it returned. Where
/// stdout is a terminal the picture comes first, between blank lines. An animation plays
/// while `work` runs and the lines are printed under it as soon as they are known; it has
/// ended, or a key has ended it, when this returns. Whatever is left of `work` after the
/// picture is a [`crate::progress::wait`] named `label`, as all of it is where nothing
/// moves.
pub fn during<T: Send>(
    label: &str,
    work: impl FnOnce() -> T + Send,
    lines: impl FnOnce(&T) -> Vec<String> + Send,
) -> T {
    let style = crate::style::out();
    let (columns, rows) =
        crossterm::terminal::size().map_or((80, 24), |(w, h)| (usize::from(w), usize::from(h)));
    let terminal = std::io::stdout().is_terminal();
    let show = plan(terminal, style.styled(), style.unicode(), columns, rows);
    if show != Show::Moving {
        if show == Show::Still {
            let mut stage = Stage::new(std::io::stdout(), columns, still(style));
            stage.open(&stage.last.clone());
        }
        let found = crate::progress::wait(label, work);
        for line in lines(&found) {
            println!("{line}");
        }
        return found;
    }
    let frames: Vec<_> = (0..=FRAMES)
        .map(|f| render(&blocks(f, true), style))
        .collect();
    let stage = Mutex::new(Stage::new(
        std::io::stdout(),
        columns,
        frames[FRAMES].clone(),
    ));
    let (found, unsaid) = beside(
        || {
            let keys = Keys::read();
            animate(&stage, &frames, |tick| keys.pressed(tick));
        },
        || {
            let found = work();
            let lines = lines(&found);
            let said = lock(&stage).say(&lines);
            (found, (!said).then_some(lines))
        },
        |done| crate::progress::wait(label, done),
    );
    // The work outlasted the picture.
    for line in unsaid.into_iter().flatten() {
        println!("{line}");
    }
    found
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The terminal while the picture is on it: the one way both its frames and the lines under
/// it are written, each in one write. Lines end in a carriage return too, for raw mode.
struct Stage<W> {
    out: W,
    columns: usize,
    /// The animation's last frame.
    last: Vec<String>,
    /// Lines printed under the picture.
    below: usize,
    /// The picture still moves.
    live: bool,
}

impl<W: Write> Stage<W> {
    fn new(out: W, columns: usize, last: Vec<String>) -> Self {
        Stage {
            out,
            columns,
            last,
            below: 0,
            live: true,
        }
    }

    /// A terminal that went away mid-picture is no error of setup's.
    fn write(&mut self, text: &str) {
        let _ = self
            .out
            .write_all(text.as_bytes())
            .and_then(|()| self.out.flush());
    }

    /// The first frame, between blank lines.
    fn open(&mut self, frame: &[String]) {
        let mut text = String::from("\r\n");
        for line in frame {
            text.push_str(line);
            text.push_str("\r\n");
        }
        text.push_str("\r\n");
        self.write(&text);
    }

    /// `frame` over the one before it: the cursor is saved, moved up to the picture's rows
    /// and put back, so what stands under the picture stays.
    fn redraw(&mut self, frame: &[String]) {
        let mut text = format!("\x1b7\x1b[{}A", frame.len() + 1 + self.below);
        for line in frame {
            text.push_str("\r\x1b[2K");
            text.push_str(line);
            text.push_str("\r\n");
        }
        text.push_str("\x1b8");
        self.write(&text);
    }

    /// The last frame; nothing redraws after it.
    fn end(&mut self) {
        if self.live {
            self.live = false;
            self.redraw(&self.last.clone());
        }
    }

    /// `lines` under the picture while it moves; false once it has ended, when printing is
    /// the caller's. Lines the redraw couldn't count on (one that would wrap, more than
    /// [`UNDER`]) end the animation first.
    fn say(&mut self, lines: &[String]) -> bool {
        if !self.live {
            return false;
        }
        let fits = lines.iter().all(|l| l.chars().count() < self.columns);
        if !fits || self.below + lines.len() > UNDER {
            self.end();
        }
        let mut text = String::new();
        for line in lines {
            text.push_str(line);
            text.push_str("\r\n");
        }
        self.write(&text);
        self.below += lines.len();
        true
    }
}

/// `frames` on `stage`, a tick apart, until the last or until `skip` (which waits the tick)
/// says a key was pressed. The stage is free between frames.
fn animate<W: Write>(
    stage: &Mutex<Stage<W>>,
    frames: &[Vec<String>],
    mut skip: impl FnMut(Duration) -> bool,
) {
    lock(stage).open(&frames[0]);
    for frame in &frames[1..frames.len() - 1] {
        if skip(TICK) || !lock(stage).live {
            break;
        }
        lock(stage).redraw(frame);
    }
    lock(stage).end();
}

/// Keys read without echo while the animation plays; the terminal's mode comes back when
/// this drops. `None` inside where raw mode can't be had: the animation then can't be
/// skipped.
struct Keys(bool);

impl Keys {
    fn read() -> Self {
        Keys(std::io::stdin().is_terminal() && crossterm::terminal::enable_raw_mode().is_ok())
    }

    /// Waits `tick`; true when a key was pressed in it. Ctrl-C, a key in raw mode, ends
    /// luoto as the signal would.
    fn pressed(&self, tick: Duration) -> bool {
        use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, poll, read};
        if !self.0 {
            std::thread::sleep(tick);
            return false;
        }
        if !poll(tick).unwrap_or(false) {
            return false;
        }
        match read() {
            Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => {
                if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                    let _ = crossterm::terminal::disable_raw_mode();
                    std::process::exit(130);
                }
                true
            }
            _ => false,
        }
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        if self.0 {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// `work` on a thread of its own while `draw` runs on this one. `rest` gets what waits for
/// `work` only once `draw` has ended, so no spinner draws during it.
fn beside<T: Send>(
    draw: impl FnOnce(),
    work: impl FnOnce() -> T + Send,
    rest: impl for<'a> FnOnce(Box<dyn FnOnce() -> T + 'a>) -> T,
) -> T {
    std::thread::scope(|s| {
        let worker = s.spawn(work);
        draw();
        rest(Box::new(move || {
            worker
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn widest(lines: &[String]) -> usize {
        lines.iter().map(|l| l.chars().count()).max().unwrap_or(0)
    }

    #[test]
    fn the_plain_picture_is_ten_rows_without_escapes() {
        let lines = still(Style::PLAIN);
        assert_eq!(lines.len(), 12, "ten of art, a blank one, the tagline");
        assert!(lines.iter().all(|l| !l.contains('\x1b')));
        assert!(widest(&lines) <= WIDTH);
        assert_eq!(
            lines.last().unwrap(),
            "  no tool is an island, except on luoto."
        );
        // No reflection: under the sun's columns the sea is the last thing drawn.
        assert!(lines[9].chars().count() <= INDENT + 26);
    }

    #[test]
    fn the_ascii_picture_is_ascii() {
        let lines = render(&ascii(), Style::PLAIN);
        assert!(lines.iter().all(|l| l.is_ascii()));
        assert!(widest(&lines) <= WIDTH);
        assert_eq!(lines[5], "     ~~~~~/~~~~~~~~~~~\\~~~~~");
        assert_eq!(lines.last(), still(Style::PLAIN).last());
    }

    #[test]
    fn every_frame_has_the_same_rows_within_the_width() {
        let rows = blocks(FRAMES, true).len();
        for f in 0..=FRAMES {
            let lines = render(&blocks(f, true), Style::PLAIN);
            assert_eq!(lines.len(), rows, "frame {f}");
            assert!(widest(&lines) <= WIDTH, "frame {f}");
        }
        // The reflection has its own row of text, under the sea.
        assert_eq!(rows, 13);
        assert!(blocks(FRAMES, true)[10].iter().any(|c| c.1 == Ink::Faint));
    }

    #[test]
    fn the_sun_never_touches_the_island_or_tints_the_sea() {
        for f in 0..=FRAMES {
            let px = pixels(f, false);
            for row in &px {
                assert!(row[SUN_X - 2..SUN_X].iter().all(|p| *p != Ink::Accent));
            }
            assert!(px[SEA - 1][SUN_X..].iter().all(|p| *p != Ink::Accent));
        }
    }

    #[test]
    fn work_runs_while_the_picture_draws_and_is_waited_for_after_it() {
        let (tx, rx) = std::sync::mpsc::channel();
        let log = std::sync::Mutex::new(Vec::new());
        let got = beside(
            || {
                let worked = rx.recv_timeout(Duration::from_secs(10));
                assert!(worked.is_ok(), "the work starts before the picture ends");
                log.lock().unwrap().push("drawn");
            },
            move || {
                tx.send(()).unwrap();
                7
            },
            |done| {
                log.lock().unwrap().push("waited");
                done()
            },
        );
        assert_eq!(got, 7);
        assert_eq!(*log.lock().unwrap(), ["drawn", "waited"]);
    }

    #[test]
    fn only_a_terminal_gets_a_picture_and_only_one_with_room_and_colors_moves() {
        assert_eq!(plan(false, false, true, 80, 24), Show::Nothing);
        assert_eq!(plan(true, true, true, 80, 24), Show::Moving);
        assert_eq!(plan(true, false, true, 80, 24), Show::Still);
        assert_eq!(plan(true, true, false, 80, 24), Show::Still);
        // Too narrow for the lines under it, or too short to stay on screen: still.
        assert_eq!(plan(true, true, true, LINE - 1, 24), Show::Still);
        assert_eq!(plan(true, true, true, WIDTH + 1, 50), Show::Still);
        assert_eq!(plan(true, true, true, 120, TALL - 1), Show::Still);
        assert_eq!(plan(true, true, true, 120, TALL), Show::Moving);
        // Too narrow for the picture: none.
        assert_eq!(plan(true, true, true, WIDTH, 50), Show::Nothing);
    }

    /// What a terminal of `columns` shows after `bytes`: the few sequences a frame uses.
    fn screen(bytes: &[u8]) -> Vec<String> {
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let mut rows: Vec<Vec<char>> = vec![Vec::new()];
        let (mut y, mut x, mut saved) = (0usize, 0usize, (0usize, 0usize));
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\r' => x = 0,
                '\n' => {
                    y += 1;
                    if y == rows.len() {
                        rows.push(Vec::new());
                    }
                }
                '\x1b' => match chars.next().unwrap() {
                    '7' => saved = (y, x),
                    '8' => (y, x) = saved,
                    '[' => {
                        let mut n = String::new();
                        while chars.peek().unwrap().is_ascii_digit() {
                            n.push(chars.next().unwrap());
                        }
                        match chars.next().unwrap() {
                            'A' => y -= n.parse::<usize>().unwrap(),
                            'K' => rows[y].clear(),
                            other => panic!("CSI {n}{other}"),
                        }
                    }
                    other => panic!("ESC {other}"),
                },
                c => {
                    let wide = rows[y].len().max(x + 1);
                    rows[y].resize(wide, ' ');
                    rows[y][x] = c;
                    x += 1;
                }
            }
        }
        rows.into_iter().map(|r| r.into_iter().collect()).collect()
    }

    fn plain_frames() -> Vec<Vec<String>> {
        (0..=FRAMES)
            .map(|f| render(&blocks(f, true), Style::PLAIN))
            .collect()
    }

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn lines_said_during_the_animation_stand_under_the_finished_picture() {
        let frames = plain_frames();
        let stage = Mutex::new(Stage::new(Vec::new(), 80, frames[FRAMES].clone()));
        let said = lines(&["host: macos aarch64", "  podman    6.2.0 podman"]);
        let mut tick = 0;
        animate(&stage, &frames, |_| {
            tick += 1;
            // Found a few frames in; one more line later.
            if tick == 5 {
                assert!(lock(&stage).say(&said[..1]));
            }
            if tick == 20 {
                assert!(lock(&stage).say(&said[1..]));
            }
            false
        });
        let stage = stage.into_inner().unwrap();
        assert!(!stage.live && stage.below == 2);
        let mut want = vec![String::new()];
        want.extend(frames[FRAMES].iter().cloned());
        want.push(String::new());
        want.extend(said);
        // The cursor rests on the line after them.
        want.push(String::new());
        assert_eq!(screen(&stage.out), want);
    }

    #[test]
    fn a_key_ends_the_animation_at_its_last_frame() {
        let frames = plain_frames();
        let stage = Mutex::new(Stage::new(Vec::new(), 80, frames[FRAMES].clone()));
        let mut ticks = 0;
        animate(&stage, &frames, |_| {
            ticks += 1;
            ticks == 3
        });
        assert_eq!(ticks, 3);
        let mut stage = stage.into_inner().unwrap();
        // Once ended, lines are the caller's to print.
        assert!(!stage.say(&lines(&["host"])));
        let shown = screen(&stage.out);
        assert_eq!(shown[1..=frames[FRAMES].len()], frames[FRAMES][..]);
    }

    #[test]
    fn a_line_that_would_wrap_or_one_too_many_ends_the_animation_before_it_prints() {
        let frames = plain_frames();
        for said in [lines(&[&"x".repeat(80)]), lines(&["1", "2", "3", "4", "5"])] {
            let mut stage = Stage::new(Vec::new(), 80, frames[FRAMES].clone());
            stage.open(&frames[0]);
            assert!(stage.say(&said));
            assert!(!stage.live);
            let shown = screen(&stage.out);
            assert_eq!(shown[1..=frames[FRAMES].len()], frames[FRAMES][..]);
            assert_eq!(shown[frames[FRAMES].len() + 2], said[0]);
        }
    }

    /// The animation on the terminal the test runs in, with lines found half a second in
    /// and a line after it where setup's question would come:
    /// `cargo test -p luoto splash::tests::on_this_terminal -- --ignored --nocapture`.
    #[test]
    #[ignore = "draws on the terminal, to be looked at"]
    fn on_this_terminal() {
        during(
            "looking at this machine's container runtimes",
            || std::thread::sleep(Duration::from_millis(500)),
            |()| {
                lines(&[
                    "host: macos aarch64",
                    "  container 1.7.1 Apple's container, service running",
                    "  podman    6.2.0 podman (luoto runs envs in its own VM)",
                    "  docker    29.10.0 docker CLI installed but the engine is not running",
                ])
            },
        );
        println!("? Run envs on: (setup's question comes here, after the picture)");
    }
}
