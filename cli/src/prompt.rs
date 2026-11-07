//! Questions on the terminal.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static NEVER_ASK: AtomicBool = AtomicBool::new(false);

/// Ask nothing from now on: the process serves the UI, whose terminal nobody watches.
pub fn never_ask() {
    NEVER_ASK.store(true, Ordering::Relaxed);
}

/// Whether a question can be asked: a terminal, in a process that isn't the UI's server.
pub fn interactive() -> bool {
    !NEVER_ASK.load(Ordering::Relaxed) && std::io::stdin().is_terminal()
}

/// A yes/no question; no without a terminal to ask on.
pub fn confirm(question: &str) -> bool {
    if !interactive() {
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
