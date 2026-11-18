//! The picture that starts `luoto setup`: the logo in half blocks (the island and
//! the sun in the accent, the palm and the sea in the terminal's own foreground) over the
//! tagline. On a terminal with colors it draws itself once: the palm grows, the sea spreads,
//! the sun rises and its reflection sinks. Without colors it is the still picture, without a
//! UTF-8 locale an ASCII one, and where stdout is no terminal there is none.
//!
//! The animation hides no cursor and every frame is one write that ends with all styles
//! reset, so Ctrl-C at any moment leaves the terminal as it was.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use crate::style::Style;

/// The animation's last frame is the still picture.
const FRAMES: usize = 34;
const TICK: Duration = Duration::from_millis(48);
/// Columns before the art; the tagline stands two further left.
const INDENT: usize = 4;
/// The widest line: a narrower terminal would wrap it.
const WIDTH: usize = 40;

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

/// What stdout gets: nothing unless it is a terminal wide enough, and movement only where
/// both colors and half blocks show.
fn plan(terminal: bool, styled: bool, unicode: bool, columns: usize) -> Show {
    if !terminal || columns <= WIDTH {
        Show::Nothing
    } else if styled && unicode {
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

/// Runs `work`, which prints and asks nothing, and where stdout is a terminal prints the
/// picture first, between blank lines. An animation plays while `work` runs, so it costs no
/// time; whatever is left of `work` after the picture is a [`crate::progress::wait`] named
/// `label`, as all of it is where nothing moves.
pub fn during<T: Send>(label: &str, work: impl FnOnce() -> T + Send) -> T {
    let style = crate::style::out();
    let columns = crossterm::terminal::size().map_or(80, |(w, _)| usize::from(w));
    let terminal = std::io::stdout().is_terminal();
    match plan(terminal, style.styled(), style.unicode(), columns) {
        Show::Nothing => crate::progress::wait(label, work),
        Show::Still => {
            draw(&[still(style)]);
            crate::progress::wait(label, work)
        }
        Show::Moving => {
            let frames: Vec<_> = (0..=FRAMES)
                .map(|f| render(&blocks(f, true), style))
                .collect();
            beside(
                || draw(&frames),
                work,
                |done| crate::progress::wait(label, done),
            )
        }
    }
}

/// `work` on a thread of its own while `draw` runs on this one. `rest` gets what waits for
/// `work` only once `draw` has ended, so nothing else writes to the terminal during it.
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

/// `frames` one over the other, a tick apart, between blank lines.
fn draw(frames: &[Vec<String>]) {
    let mut out = std::io::stdout().lock();
    // A terminal that went away mid-picture is no error of setup's.
    let _ = writeln!(out);
    for (i, lines) in frames.iter().enumerate() {
        let mut text = String::new();
        if i > 0 {
            std::thread::sleep(TICK);
            text.push_str(&format!("\x1b[{}A", lines.len()));
        }
        for line in lines {
            if i > 0 {
                text.push_str("\r\x1b[2K");
            }
            text.push_str(line);
            text.push('\n');
        }
        let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
    }
    let _ = writeln!(out);
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
    fn only_a_terminal_gets_a_picture_and_only_colors_move() {
        assert_eq!(plan(false, false, true, 80), Show::Nothing);
        assert_eq!(plan(true, true, true, 80), Show::Moving);
        assert_eq!(plan(true, false, true, 80), Show::Still);
        assert_eq!(plan(true, true, false, 80), Show::Still);
        assert_eq!(plan(true, true, true, WIDTH), Show::Nothing);
    }
}
