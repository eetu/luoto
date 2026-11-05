//! Questions on the terminal.

use std::io::{IsTerminal, Write};

/// A yes/no question; no without a terminal to ask on.
pub fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    matches!(line.trim(), "y" | "Y" | "yes")
}

/// One-letter answer to `question`; Enter picks `default`.
pub fn ask(question: &str, default: char) -> char {
    print!("{question} ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim()
        .chars()
        .next()
        .map_or(default, |c| c.to_ascii_lowercase())
}
