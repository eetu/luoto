//! Text that came from the sandbox, made safe to show in a terminal: control characters
//! (escape sequences) and Unicode format characters (bidi overrides, zero-width marks) become
//! visible `\u{…}` escapes, so they can neither move the cursor nor reorder what you read.

pub fn display(s: &str) -> String {
    escape(s, false)
}

/// [`display`] that keeps line breaks, for multi-line text such as an error with its causes.
pub fn lines(s: &str) -> String {
    escape(s, true)
}

fn escape(s: &str, keep_newlines: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if keep_newlines && c == '\n' {
            out.push(c);
        } else if c.is_control() || is_format(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
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
    use super::display;

    #[test]
    fn escapes_terminal_and_bidi_tricks() {
        assert_eq!(display("a\u{1b}[2Kb"), "a\\u{1b}[2Kb");
        assert_eq!(display("/x\r/y"), "/x\\u{d}/y");
        assert_eq!(display("evil\u{202e}gpj.exe"), "evil\\u{202e}gpj.exe");
        assert_eq!(display(".g\u{200c}it"), ".g\\u{200c}it");
        assert_eq!(display("plain/päth"), "plain/päth");
    }
}
