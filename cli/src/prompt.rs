//! Questions on the terminal.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static NEVER_ASK: AtomicBool = AtomicBool::new(false);

/// Ask nothing from now on: the process serves the UI, whose terminal nobody watches.
pub fn never_ask() {
    NEVER_ASK.store(true, Ordering::Relaxed);
}

/// Whether a question can be asked: a terminal, in a process that isn't the UI's server.
/// The prompts' markers in the UI's accent, as the spinner's dot. Their text keeps the
/// terminal's colors: the accent is too light to read on a light background.
pub fn theme() {
    use inquire::ui::{Attributes, Color, RenderConfig, StyleSheet, Styled};
    let Some(accent) = crate::progress::accent() else {
        inquire::set_global_render_config(RenderConfig::empty());
        return;
    };
    let c = match accent {
        crate::progress::Accent::Rgb(r, g, b) => Color::Rgb { r, g, b },
        crate::progress::Accent::Ansi(v) => Color::AnsiValue(v),
    };
    let mut r = RenderConfig::default_colored();
    r.prompt_prefix = Styled::new("?").with_fg(c);
    r.answered_prompt_prefix = Styled::new(">").with_fg(c);
    r.highlighted_option_prefix = Styled::new(">").with_fg(c);
    r.selected_checkbox = Styled::new("[x]").with_fg(c);
    r.selected_option = Some(StyleSheet::empty().with_attr(Attributes::BOLD));
    r.answer = StyleSheet::empty().with_attr(Attributes::BOLD);
    r.help_message = StyleSheet::empty().with_fg(Color::DarkGrey);
    inquire::set_global_render_config(r);
}

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

/// The help line under every menu: its keys, and what Esc does there (`back` past the first
/// question; at the first, `later` or `unchanged`).
pub fn menu_help(esc: &str) -> String {
    format!("↑↓ to move, Enter to pick, Esc: {esc}")
}

/// Menu entries as a label and a description, the descriptions lined up after the widest
/// label. A line fits `width` with the two columns inquire draws before it: the description
/// is cut, never the label.
pub fn menu_rows(rows: &[(String, String)], width: usize) -> Vec<String> {
    use unicode_width::UnicodeWidthStr;
    let wide = rows.iter().map(|(l, _)| l.width()).max().unwrap_or(0);
    rows.iter()
        .map(|(label, desc)| {
            if desc.is_empty() {
                return label.clone();
            }
            let room = width.saturating_sub(2 + wide + 2);
            let pad = " ".repeat(wide - label.width());
            format!("{label}{pad}  {}", crate::text::fit(desc, room, true))
        })
        .collect()
}

/// The closing summary of a step that wrote config: what it is about, then a row per setting
/// (`credential`, `access`) and the command that changes it. Every summary's values start in
/// the same column, unless a key is longer.
pub fn summary(title: &str, rows: &[(&str, String)]) -> String {
    let wide = rows
        .iter()
        .map(|(k, _)| k.len() + 3)
        .max()
        .unwrap_or(0)
        .max("credential".len() + 3);
    let mut out = title.to_string();
    for (k, v) in rows {
        out.push_str(&format!("\n  {k:<wide$}{v}"));
    }
    out
}

/// `what` and the command that acts on it: on one line where it fits `width`, else the
/// command on a line of its own.
pub fn with_command(what: &str, command: &str, width: usize) -> String {
    let one = format!("{what}; {command}");
    if one.chars().count() <= width {
        one
    } else {
        format!("{what}:\n  {command}")
    }
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
