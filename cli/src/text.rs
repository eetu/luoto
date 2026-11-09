//! Text made safe for a terminal or a shell. Text that came from the sandbox is shown with
//! control characters (escape sequences) and Unicode format characters (bidi overrides,
//! zero-width marks) as visible `\u{…}` escapes, so they can neither move the cursor nor
//! reorder what you read.

pub fn display(s: &str) -> String {
    escape(s, false)
}

/// [`display`] that keeps line breaks and tabs, for multi-line text such as an error with its
/// causes or an agent's answer.
pub fn lines(s: &str) -> String {
    escape(s, true)
}

fn escape(s: &str, keep_newlines: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if keep_newlines && (c == '\n' || c == '\t') {
            out.push(c);
        } else if c.is_control() || is_format(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// What a command in the env writes, passed on as it comes with each piece escaped
/// ([`lines`]). Its line ends stay, and so do carriage returns (progress redrawing its line)
/// where the output is a terminal; nothing else it writes reaches the terminal as a control.
pub struct Relay {
    pending: Vec<u8>,
    tty: bool,
}

impl Relay {
    /// The longest piece held back waiting for its end.
    const MAX: usize = 4096;

    pub fn new(tty: bool) -> Self {
        Relay {
            pending: Vec::new(),
            tty,
        }
    }

    /// What to write for `chunk`: each piece it completes, escaped.
    pub fn feed(&mut self, chunk: &[u8]) -> String {
        let mut out = String::new();
        for &b in chunk {
            if b == b'\n' || b == b'\r' {
                out.push_str(&self.finish());
                out.push(if self.tty { b as char } else { '\n' });
            } else {
                self.pending.push(b);
                if self.pending.len() >= Self::MAX {
                    out.push_str(&self.finish());
                }
            }
        }
        out
    }

    /// What is left, escaped.
    pub fn finish(&mut self) -> String {
        let s = lines(&String::from_utf8_lossy(&self.pending));
        self.pending.clear();
        s
    }
}

/// `s` as one POSIX shell word: as it is when it holds only characters no shell treats
/// specially, else single-quoted.
pub fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=:@,+".contains(&b))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Unicode general category Cf (format) code points that affect how text renders.
pub fn is_format(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

#[cfg(test)]
mod tests {
    use super::{Relay, display, sh_quote};

    #[test]
    fn relayed_output_keeps_its_lines_and_progress_but_no_controls() {
        let mut r = Relay::new(true);
        let mut out = r.feed(b"remote: \x1b[2J\x1b[Hok\nRecei");
        // A character split between two reads.
        let rest = "ving 50%\r100% \u{e9}".as_bytes();
        out += &r.feed(&rest[..15]);
        out += &r.feed(&rest[15..]);
        out += &r.finish();
        assert_eq!(
            out,
            "remote: \\u{1b}[2J\\u{1b}[Hok\nReceiving 50%\r100% \u{e9}"
        );
        let mut log = Relay::new(false);
        assert_eq!(log.feed(b"a\rb\n\x07"), "a\nb\n");
        assert_eq!(log.finish(), "\\u{7}");
        let mut long = Relay::new(true);
        assert_eq!(long.feed(&[b'x'; Relay::MAX + 1]).len(), Relay::MAX);
    }

    #[test]
    fn shell_words_survive_quotes() {
        assert_eq!(sh_quote("node@22"), "node@22");
        assert_eq!(sh_quote("a'b c"), r"'a'\''b c'");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("$HOME"), "'$HOME'");
    }

    #[test]
    fn escapes_terminal_and_bidi_tricks() {
        assert_eq!(display("a\u{1b}[2Kb"), "a\\u{1b}[2Kb");
        assert_eq!(display("/x\r/y"), "/x\\u{d}/y");
        assert_eq!(display("evil\u{202e}gpj.exe"), "evil\\u{202e}gpj.exe");
        assert_eq!(display(".g\u{200c}it"), ".g\\u{200c}it");
        assert_eq!(display("plain/päth"), "plain/päth");
    }
}
