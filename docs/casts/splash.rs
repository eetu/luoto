use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const UNICORN: [&str; 9] = [
    "",
    r"             /",
    r"          ij/",
    r"        ))).\",
    r#" .--,__)))"\,)"#,
    r"}\ )_ (  /",
    r#"||: " ||!"#,
    r"||:   ||!",
    r"▀▀▀   ▀▀▀",
];
const LOGO: [&str; 2] = ["█▀█ █ █ █   █▀▀ █▀▀", "█▀▀ █▄█ █▄▄ ▄▄█ ██▄"];
const TAG: &str = "response times at a glance";
const HORN: usize = 15;
const LEFT: usize = 20;
const DONE: usize = LEFT + TAG.len();

fn rainbow(x: usize, shift: f32) -> String {
    let hue = (x as f32 * 0.04 + shift).fract() * 6.0;
    let part = |n: f32| {
        let k = (n + hue) % 6.0;
        (255.0 * (1.0 - 0.55 * k.min(4.0 - k).clamp(0.0, 1.0))) as u8
    };
    format!("\x1b[1;38;2;{};{};{}m", part(5.0), part(3.0), part(1.0))
}

/// The unicorn, its laser as far as column `head`, and the wordmark it has drawn.
fn frame(head: usize, shift: f32) -> String {
    let beat = head / 2;
    let sparks: Vec<(usize, usize)> = (0..5)
        .map(|i| {
            (
                head.saturating_sub((beat * 7 + i * 5) % 9),
                (beat * 3 + i * 7) % 4,
            )
        })
        .collect();
    let mut out = String::new();
    for (y, beast) in UNICORN.iter().enumerate() {
        let text = match y {
            1 => LOGO[0],
            2 => LOGO[1],
            4 => TAG,
            _ => "",
        };
        for x in 0..DONE {
            let body = beast.chars().nth(x).filter(|c| *c != ' ');
            let mark = x
                .checked_sub(LEFT)
                .and_then(|i| text.chars().nth(i))
                .filter(|c| *c != ' ');
            match (body, mark) {
                (Some(c), _) if c == ')' && x < 12 => out += &rainbow(x * 4 + y * 3, shift),
                (Some('/'), _) if y < 3 => out += "\x1b[1;93m",
                (Some(_), _) => out += "\x1b[1;97m",
                (None, Some(_)) if y == 4 && head == DONE => out += "\x1b[0;2m",
                (None, Some(_)) if y != 4 && x < head => out += &rainbow(x, shift),
                _ if y == 1 && (HORN..=head).contains(&x) && head < DONE => {
                    out += &rainbow(x, shift);
                    out.push(if x == head { '✦' } else { '━' });
                    continue;
                }
                _ if head < DONE && sparks.contains(&(x, y)) => {
                    out += "\x1b[0;93m*";
                    continue;
                }
                _ => {
                    out.push(' ');
                    continue;
                }
            }
            out.push(body.or(mark).unwrap_or(' '));
        }
        out += "\x1b[0m\n";
    }
    out
}

/// The splash screen; `tty` says whether `out` is a terminal.
pub fn show(out: &mut impl Write, tty: bool) -> io::Result<()> {
    if !tty {
        return writeln!(out, "pulse\n{TAG}");
    }
    let heads: Vec<usize> = (HORN..LEFT + 21).chain([DONE; 12]).collect();
    write!(out, "\x1b[?25l")?;
    for (step, head) in heads.iter().enumerate() {
        write!(out, "{}", frame(*head, step as f32 * 0.03))?;
        out.flush()?;
        sleep(Duration::from_millis(50));
        write!(out, "\x1b[{}A", UNICORN.len())?;
    }
    write!(out, "{}\x1b[?25h", frame(DONE, heads.len() as f32 * 0.03))
}
