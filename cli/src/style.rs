//! How luoto's own text looks on a terminal: what a line is about in bold, keys and column
//! headings dim, the commands it names (in backticks) bold, markers in the UI's accent (the
//! only color of luoto's own), the `luoto:` of an error in the terminal's red and `warning:`
//! in its yellow, which follow the user's theme. Text is formatted plain, then styled as it
//! is printed: every style is a zero-width escape, so widths and wrapping hold. A stream
//! that is no terminal, and any with `NO_COLOR` set, gets the text as it is.

use std::io::IsTerminal;
use std::sync::OnceLock;

use crate::progress::Accent;

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
/// Ends bold and dim.
const NORMAL: &str = "\x1b[22m";
/// The terminal's own red and yellow, not their bright variants: themes with a light
/// background keep these two readable on it.
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
/// Ends a color.
const DEFAULT: &str = "\x1b[39m";

#[derive(Clone, Copy, Debug)]
pub struct Style {
    on: bool,
    accent: Option<Accent>,
    unicode: bool,
}

/// The style of what goes to stdout.
pub fn out() -> Style {
    static S: OnceLock<Style> = OnceLock::new();
    *S.get_or_init(|| Style::detect(std::io::stdout().is_terminal()))
}

/// The style of what goes to stderr.
pub fn err() -> Style {
    static S: OnceLock<Style> = OnceLock::new();
    *S.get_or_init(|| Style::detect(std::io::stderr().is_terminal()))
}

/// `println!` with the commands its own text names in bold: what stands between two
/// backticks of the format string. A backtick in what it interpolates (text from the sandbox)
/// opens and closes nothing ([`Style::literal`]).
macro_rules! out {
    ($fmt:literal $($arg:tt)*) => {
        println!(
            "{}",
            $crate::style::out().literal($fmt, format_args!($fmt $($arg)*))
        )
    };
}

/// `eprintln!` as [`out!`] prints.
macro_rules! err {
    ($fmt:literal $($arg:tt)*) => {
        eprintln!(
            "{}",
            $crate::style::err().literal($fmt, format_args!($fmt $($arg)*))
        )
    };
}

/// `println!` of text luoto composed before the print (a hint a function returns, wrapped
/// prose), the commands it names in bold ([`Style::commands`]).
macro_rules! out_text {
    ($($arg:tt)*) => {
        println!("{}", $crate::style::out().commands(&format!($($arg)*)))
    };
}

/// `eprintln!` as [`out_text!`] prints.
macro_rules! err_text {
    ($($arg:tt)*) => {
        eprintln!("{}", $crate::style::err().commands(&format!($($arg)*)))
    };
}

/// `println!` of what a step made or changed, in bold.
macro_rules! head {
    ($($arg:tt)*) => {
        println!("{}", $crate::style::out().head(&format!($($arg)*)))
    };
}

/// `println!` of a table's heading row, dim.
macro_rules! heading {
    ($($arg:tt)*) => {
        println!("{}", $crate::style::out().heading(&format!($($arg)*)))
    };
}

/// `println!` of a block as `prompt::summary` lays it out ([`Style::summary`]).
macro_rules! block {
    ($($arg:tt)*) => {
        println!("{}", $crate::style::out().summary(&format!($($arg)*)))
    };
}

impl Style {
    #[cfg(test)]
    pub(crate) const PLAIN: Style = Style {
        on: false,
        accent: None,
        unicode: true,
    };

    fn detect(terminal: bool) -> Self {
        let accent = crate::progress::accent();
        let on = terminal
            && accent.is_some()
            && std::env::var("TERM").map_or(true, |t| t != "dumb")
            && escapes();
        Style {
            on,
            accent,
            unicode: crate::progress::unicode(),
        }
    }

    /// Whether anything is styled: a terminal with colors.
    pub fn styled(self) -> bool {
        self.on
    }

    /// Whether characters beyond ASCII render: a UTF-8 locale.
    pub fn unicode(self) -> bool {
        self.unicode
    }

    fn wrap(self, start: &str, s: &str, end: &str) -> String {
        if self.on && !s.is_empty() {
            format!("{start}{s}{end}")
        } else {
            s.to_string()
        }
    }

    /// What a line is about: a summary's first line, an outcome.
    pub fn head(self, s: &str) -> String {
        self.wrap(BOLD, s, NORMAL)
    }

    /// A key before its value, a column heading, an aside.
    pub fn dim(self, s: &str) -> String {
        self.wrap(DIM, s, NORMAL)
    }

    /// A marker (`●`, `?`, `→`) in the accent.
    pub fn marker(self, s: &str) -> String {
        match self.accent.filter(|_| self.on) {
            Some(Accent::Rgb(r, g, b)) => format!("\x1b[38;2;{r};{g};{b}m{s}{DEFAULT}"),
            Some(Accent::Ansi(v)) => format!("\x1b[38;5;{v}m{s}{DEFAULT}"),
            None => s.to_string(),
        }
    }

    /// The dot before a closing line, with its space; nothing where nothing is styled.
    pub fn dot(self) -> String {
        if !self.on {
            return String::new();
        }
        self.marker(if self.unicode { "● " } else { "* " })
    }

    /// `luoto: `, before an error.
    pub fn error(self, label: &str) -> String {
        self.wrap(
            &format!("{BOLD}{RED}"),
            label,
            &format!("{DEFAULT}{NORMAL}"),
        )
    }

    /// `warning: `.
    pub fn warning(self, label: &str) -> String {
        self.wrap(
            &format!("{BOLD}{YELLOW}"),
            label,
            &format!("{DEFAULT}{NORMAL}"),
        )
    }

    /// What `args` formats, with bold between the backticks of `format`, their format string:
    /// those written in luoto's source. What an argument writes is passed on as it is, so a
    /// backtick in it neither starts nor ends the bold. The format string's pieces are told
    /// from its arguments by the writes they arrive in; where an argument writes just what a
    /// piece says, so that more than one reading fits, nothing is styled.
    pub fn literal(self, format: &str, args: std::fmt::Arguments) -> String {
        use std::fmt::Write;
        if !self.on || !format.contains('`') {
            return args.to_string();
        }
        let pieces = pieces(format);
        let mut writes = Writes(Vec::new());
        if pieces.iter().map(|p| p.matches('`').count()).sum::<usize>() % 2 == 1
            || writes.write_fmt(args).is_err()
            || !one_reading(&pieces, &writes.0)
        {
            return args.to_string();
        }
        let mut out = String::new();
        let (mut next, mut open) = (0, false);
        for w in &writes.0 {
            if pieces.get(next) != Some(w) {
                out.push_str(w);
                continue;
            }
            next += 1;
            for (i, part) in w.split('`').enumerate() {
                if i > 0 && open {
                    out.push_str(NORMAL);
                    out.push('`');
                } else if i > 0 {
                    out.push('`');
                    out.push_str(BOLD);
                }
                open ^= i > 0;
                out.push_str(part);
            }
        }
        out
    }

    /// `s` with each command it names in bold: what stands between two backticks of a line,
    /// which stay.
    pub fn commands(self, s: &str) -> String {
        if !self.on || !s.contains('`') {
            return s.to_string();
        }
        s.split('\n')
            .map(|l| self.line_commands(l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn line_commands(self, line: &str) -> String {
        let parts: Vec<&str> = line.split('`').collect();
        // An odd backtick opens nothing.
        let pairs = (parts.len() - 1) / 2;
        let mut out = String::with_capacity(line.len() + pairs * 9);
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                out.push('`');
            }
            if i % 2 == 1 && i / 2 < pairs {
                out.push_str(&self.head(part));
            } else {
                out.push_str(part);
            }
        }
        out
    }

    /// A question with its answers in brackets at its end (`Create it? [Y/n/c = customize]`):
    /// the marker before its last line, the answer Enter picks (the capital) bold, the other
    /// answers dim. A space ends it, where the answer is typed.
    pub fn question(self, q: &str) -> String {
        if !self.on {
            return format!("{} ", q.trim_end());
        }
        let (before, last) = match q.rfind('\n') {
            Some(i) => q.split_at(i + 1),
            None => ("", q),
        };
        let asked = last.trim_end();
        let (text, answers) = match asked.rfind(" [") {
            Some(i) if asked.ends_with(']') => (&asked[..i], &asked[i + 1..]),
            _ => (asked, ""),
        };
        let mut out = format!(
            "{}{}{} ",
            self.commands(before),
            self.marker("? "),
            self.commands(text)
        );
        if !answers.is_empty() {
            let default = answers.find(|c: char| c.is_ascii_uppercase());
            match default {
                Some(i) => {
                    out.push_str(&self.dim(&answers[..i]));
                    out.push_str(&self.head(&answers[i..=i]));
                    out.push_str(&self.dim(&answers[i + 1..]));
                }
                None => out.push_str(&self.dim(answers)),
            }
            out.push(' ');
        }
        out
    }

    /// A table's heading row.
    pub fn heading(self, s: &str) -> String {
        let row = s.trim_start_matches('\n');
        format!("{}{}", &s[..s.len() - row.len()], self.dim(row))
    }

    /// What a row says about the line above it: dim, and where it ends in ` → ` and the
    /// command that acts on it, the arrow in the accent and the command bold.
    pub fn aside(self, s: &str) -> String {
        match s.rsplit_once(" → ") {
            Some((why, command)) if self.on => format!(
                "{} {} {}",
                self.dim(why),
                self.marker("→"),
                self.head(command)
            ),
            _ => self.dim(s),
        }
    }

    /// A line of `luoto doctor`, or several: the label before its first `: ` dim, a check's
    /// `ok` dim and its `FAIL` as an error's label, the commands bold.
    pub fn check(self, text: &str) -> String {
        if !self.on {
            return text.to_string();
        }
        text.split('\n')
            .map(|l| {
                if let Some(rest) = l.strip_prefix("  ok  ") {
                    format!("  {}{rest}", self.dim("ok  "))
                } else if let Some(rest) = l.strip_prefix("  FAIL") {
                    format!("  {}{rest}", self.error("FAIL"))
                } else {
                    match l.split_once(": ") {
                        Some((label, rest)) if !l.starts_with(' ') => {
                            format!("{} {}", self.dim(&format!("{label}:")), self.commands(rest))
                        }
                        _ => self.commands(l),
                    }
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A block as `prompt::summary` and `prompt::rows` lay it out: its first line in bold,
    /// the key of each `  key   value` row dim, the commands bold (in backticks, or a value
    /// that is one: `luoto …`).
    pub fn summary(self, text: &str) -> String {
        if !self.on {
            return text.to_string();
        }
        let mut lines = text.split('\n');
        let mut out = String::new();
        // Blank lines lead a block that follows other output.
        for l in lines.by_ref() {
            if l.is_empty() {
                out.push('\n');
            } else {
                out.push_str(&self.head(l));
                break;
            }
        }
        for l in lines {
            out.push('\n');
            out.push_str(&self.row(l));
        }
        out
    }

    /// Lines whose first `width` columns hold a key or nothing (`  presets    debian, npm`):
    /// the key dim, the commands after it bold.
    pub fn keyed(self, text: &str, width: usize) -> String {
        if !self.on {
            return text.to_string();
        }
        text.split('\n')
            .map(|l| match l.char_indices().nth(width) {
                Some((at, _)) => {
                    format!("{}{}", self.dim(&l[..at]), self.commands(&l[at..]))
                }
                None => self.dim(l),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A line of rows under a heading: [`Style::summary`] without the first line.
    pub fn row(self, line: &str) -> String {
        if !self.on {
            return line.to_string();
        }
        let Some(rest) = line.strip_prefix("  ").filter(|r| !r.starts_with(' ')) else {
            return self.commands(line);
        };
        let Some(end) = rest.find("  ") else {
            return self.commands(line);
        };
        let (key, value) = rest.split_at(end);
        let shown = value.trim_start();
        let value = if shown.starts_with("luoto ") && !shown.contains('`') {
            format!(
                "{}{}",
                &value[..value.len() - shown.len()],
                self.head(shown)
            )
        } else {
            self.commands(value)
        };
        format!("  {}{value}", self.dim(key))
    }
}

/// The text of a format string between its arguments, in order, without the empty ones.
fn pieces(format: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut piece = String::new();
    let mut chars = format.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' | '}' if chars.peek() == Some(&c) => {
                chars.next();
                piece.push(c);
            }
            '{' => {
                for a in chars.by_ref() {
                    if a == '}' {
                        break;
                    }
                }
                if !piece.is_empty() {
                    out.push(std::mem::take(&mut piece));
                }
            }
            _ => piece.push(c),
        }
    }
    if !piece.is_empty() {
        out.push(piece);
    }
    out
}

/// What a format writes, write by write: each piece of its format string whole, and what
/// each argument writes.
struct Writes(Vec<String>);

impl std::fmt::Write for Writes {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        if !s.is_empty() {
            self.0.push(s.to_string());
        }
        Ok(())
    }
}

/// Whether `pieces` are among `writes`, in order, in exactly one way: then each piece is
/// the write it equals, and every other write an argument's.
fn one_reading(pieces: &[String], writes: &[String]) -> bool {
    // ways[n]: how many ways the first n pieces are among the writes so far, up to two.
    let mut ways = vec![0u8; pieces.len() + 1];
    ways[0] = 1;
    for w in writes {
        for n in (1..=pieces.len()).rev() {
            if &pieces[n - 1] == w {
                ways[n] = (ways[n] + ways[n - 1]).min(2);
            }
        }
    }
    ways[pieces.len()] == 1
}

/// Whether the terminal reads escape sequences: on Windows, a console that can be told to.
fn escapes() -> bool {
    #[cfg(windows)]
    {
        crossterm::ansi_support::supports_ansi()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON: Style = Style {
        on: true,
        accent: Some(Accent::Ansi(208)),
        unicode: true,
    };

    /// `s` without its escape sequences.
    fn plain(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for e in chars.by_ref() {
                    if e == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    const SUMMARY: &str = "\negress of `web` is open until 14:05\n  reaches      any host\n  \
                           close it     luoto egress close -e web\n               (a `luoto \
                           up` applies it)";

    #[test]
    fn off_leaves_every_text_as_it_is() {
        let p = Style::PLAIN;
        for s in [SUMMARY, "run `luoto up`", "", "a ` b"] {
            assert_eq!(p.head(s), s);
            assert_eq!(p.dim(s), s);
            assert_eq!(p.marker(s), s);
            assert_eq!(p.error(s), s);
            assert_eq!(p.warning(s), s);
            assert_eq!(p.commands(s), s);
            assert_eq!(p.summary(s), s);
            assert_eq!(p.row(s), s);
            assert_eq!(p.heading(s), s);
            assert_eq!(p.aside(s), s);
            assert_eq!(p.check(s), s);
            assert_eq!(p.keyed(s, 12), s);
        }
        assert_eq!(p.question("Add them? [Y/n]"), "Add them? [Y/n] ");
        assert_eq!(p.dot(), "");
    }

    #[test]
    fn styles_add_no_width_and_drop_no_character() {
        for s in [SUMMARY, "run `luoto up`, then `luoto status`", "a ` b"] {
            assert_eq!(plain(&ON.commands(s)), s);
            assert_eq!(plain(&ON.summary(s)), s);
            assert_eq!(plain(&ON.row(s)), s);
        }
        assert_eq!(plain(&ON.question("Add them? [Y/n]")), "? Add them? [Y/n] ");
    }

    #[test]
    fn commands_are_bold_between_their_backticks() {
        assert_eq!(
            ON.commands("run `luoto up`, then `a` or ` b"),
            "run `\x1b[1mluoto up\x1b[22m`, then `\x1b[1ma\x1b[22m` or ` b"
        );
        // A command ends with its line.
        assert_eq!(ON.commands("a ` b\nc ` d"), "a ` b\nc ` d");
    }

    #[test]
    fn only_the_backticks_of_the_format_string_are_bold() {
        let env = "web";
        // From the sandbox: its backticks open and close nothing.
        let theirs = "a`b` c";
        assert_eq!(
            ON.literal(
                "{theirs}: run `luoto up -e {env}` for {}, then `{theirs}`",
                format_args!(
                    "{theirs}: run `luoto up -e {env}` for {}, then `{theirs}`",
                    theirs
                )
            ),
            "a`b` c: run `\x1b[1mluoto up -e web\x1b[22m` for a`b` c, then \
             `\x1b[1ma`b` c\x1b[22m`"
        );
        // Braces written twice are text, and padding is the argument's.
        assert_eq!(
            ON.literal("{{}} `{:<4}`", format_args!("{{}} `{:<4}`", "a`")),
            "{} `\x1b[1ma`  \x1b[22m`"
        );
        // An argument that writes what the piece after it says: either could be the piece,
        // so nothing is bold rather than the wrong span.
        assert_eq!(
            ON.literal("`{}` and `up`", format_args!("`{}` and `up`", "` and `")),
            "`` and `` and `up`"
        );
        // A long piece is one piece.
        assert_eq!(
            ON.literal(
                "`up` xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
                 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
                 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx {env} `up`",
                format_args!(
                    "`up` xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
                 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
                 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx {env} `up`"
                )
            )
            .matches("\x1b[1m")
            .count(),
            2
        );
        // An odd backtick opens nothing, and off is the text.
        assert_eq!(
            ON.literal("a ` {env}", format_args!("a ` {env}")),
            "a ` web"
        );
        assert_eq!(
            Style::PLAIN.literal("`{env}`", format_args!("`{env}`")),
            "`web`"
        );
    }

    #[test]
    fn a_summary_has_a_bold_first_line_dim_keys_and_bold_commands() {
        assert_eq!(
            ON.summary(SUMMARY),
            "\n\x1b[1megress of `web` is open until 14:05\x1b[22m\n  \
             \x1b[2mreaches\x1b[22m      any host\n  \
             \x1b[2mclose it\x1b[22m     \x1b[1mluoto egress close -e web\x1b[22m\n               \
             (a `\x1b[1mluoto up\x1b[22m` applies it)"
        );
    }

    #[test]
    fn a_keyed_line_has_a_dim_key_and_bold_commands() {
        assert_eq!(
            ON.keyed(
                "  toolchains none; `mise use` adds one\n             more",
                12
            ),
            "\x1b[2m  toolchains\x1b[22m none; `\x1b[1mmise use\x1b[22m` adds one\n\
             \x1b[2m            \x1b[22m more"
        );
    }

    #[test]
    fn an_aside_is_dim_up_to_its_bold_command() {
        assert_eq!(
            ON.aside("  no rule allows a.example → luoto allow -e web a.example"),
            "\x1b[2m  no rule allows a.example\x1b[22m \x1b[38;5;208m→\x1b[39m \
             \x1b[1mluoto allow -e web a.example\x1b[22m"
        );
        assert_eq!(ON.aside("  rule npm-0"), "\x1b[2m  rule npm-0\x1b[22m");
        let off = "  no rule allows a.example → luoto allow -e web a.example";
        assert_eq!(Style::PLAIN.aside(off), off);
    }

    #[test]
    fn a_check_has_a_dim_label_and_a_failure_stands_out() {
        assert_eq!(
            ON.check("vault: not running (`luoto up` starts it)\n  ok   udp   no reply\n  FAIL dns   answered"),
            "\x1b[2mvault:\x1b[22m not running (`\x1b[1mluoto up\x1b[22m` starts it)\n  \
             \x1b[2mok  \x1b[22m udp   no reply\n  \
             \x1b[1m\x1b[31mFAIL\x1b[39m\x1b[22m dns   answered"
        );
    }

    #[test]
    fn labels_take_the_terminals_red_and_yellow() {
        assert_eq!(
            ON.error("luoto: "),
            "\x1b[1m\x1b[31mluoto: \x1b[39m\x1b[22m"
        );
        assert_eq!(
            ON.warning("warning: "),
            "\x1b[1m\x1b[33mwarning: \x1b[39m\x1b[22m"
        );
    }

    #[test]
    fn a_question_marks_the_answer_enter_picks() {
        assert_eq!(
            ON.question("\nCreate it? [Y/n/c = customize]"),
            "\n\x1b[38;5;208m? \x1b[39mCreate it? \x1b[2m[\x1b[22m\x1b[1mY\x1b[22m\
             \x1b[2m/n/c = customize]\x1b[22m "
        );
        assert_eq!(
            ON.question("Accept these risks? [y/N] "),
            "\x1b[38;5;208m? \x1b[39mAccept these risks? \x1b[2m[y/\x1b[22m\x1b[1mN\x1b[22m\
             \x1b[2m]\x1b[22m "
        );
    }
}
