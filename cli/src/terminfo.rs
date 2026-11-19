//! The terminal's name (`TERM`) in luoto's own terminal sessions: `luoto shell`, an agent's
//! run, a terminal workspace over SSH. A newer terminal names itself (`xterm-ghostty`,
//! `xterm-kitty`, `wezterm`) and an image has no terminfo entry for that name, so programs
//! there refuse the terminal. Where the env lacks the entry, this machine's is installed in
//! the env user's `~/.terminfo`; where that can't be done, the session is told
//! `xterm-256color`, which every image has.
//!
//! The entry goes host → sandbox only, as text `infocmp` wrote here and `tic` compiles there;
//! nothing the sandbox wrote is read or run on this machine.

use std::process::{Command, Stdio};

use crate::env::Ctx;
use crate::names;
use crate::runtime::exec;

/// What a session is told where its terminal's own name can't be used.
pub const FALLBACK: &str = "xterm-256color";
/// An entry is a few kilobytes; more is not one.
const MAX_ENTRY: usize = 64 * 1024;

/// A name that is safe as an argument and a file name: letters, digits and `._+-`, at most
/// 64, not starting like an option or a hidden file.
fn safe(term: &str) -> bool {
    (1..=64).contains(&term.len())
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        && !term.starts_with(['-', '.'])
}

/// `entry` is what `infocmp` prints for `term`: plain text of a sane size whose names include
/// it.
fn valid(term: &str, entry: &str) -> bool {
    let plain = entry
        .chars()
        .all(|c| c == '\n' || c == '\t' || c == ' ' || c.is_ascii_graphic());
    let named = entry
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .and_then(|l| l.split(',').next())
        .is_some_and(|names| names.split('|').any(|n| n.trim() == term));
    entry.len() <= MAX_ENTRY && plain && named
}

/// `entry` without its comment lines: `infocmp` starts with the file it read, a path of
/// this machine (the user's name, maybe not ASCII) that the env has no use for.
fn bare(entry: &str) -> String {
    entry
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// What `luoto open --with ssh` adds where `got`, the name a session of luoto's would get,
/// isn't this terminal's (`here`): the user's own ssh sends its `TERM` whatever luoto does.
pub fn ssh_note(here: Option<&str>, got: &str) -> Option<String> {
    let here = here.filter(|t| *t != got)?;
    Some(format!(
        "The env has no terminfo entry for this terminal ({}): start ssh with `TERM={got}`.",
        crate::text::display(here)
    ))
}

/// The name a session gets, and the entry to install in the env first when it lacks one:
/// this terminal's name where the env has its entry (`in_env`) or this machine can give it
/// (`on_host`), else the fallback. Neither is asked about a name every image knows.
fn plan(
    term: Option<&str>,
    in_env: impl FnOnce(&str) -> bool,
    on_host: impl FnOnce(&str) -> Option<String>,
) -> (String, Option<String>) {
    let fallback = || (FALLBACK.to_string(), None);
    match term {
        Some(t) if t == FALLBACK => fallback(),
        Some(t) if !safe(t) => fallback(),
        Some(t) if in_env(t) => (t.to_string(), None),
        Some(t) => match on_host(t).map(|e| bare(&e)).filter(|e| valid(t, e)) {
            Some(entry) => (t.to_string(), Some(entry)),
            None => fallback(),
        },
        None => fallback(),
    }
}

/// This machine's entry for `term`, with the terminal's own extensions (`-x`).
fn host_entry(term: &str) -> Option<String> {
    let out = Command::new("infocmp")
        .args(["-x", "--", term])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    // Lossy: only its comment, which is dropped, may hold other than ASCII.
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The `TERM` for a terminal session of `user` in `env`: one exec where the env knows this
/// terminal, one more to install its entry the first time, none for a name every image
/// knows. Says why it fell back only with `--verbose`.
pub fn term_for(ctx: &Ctx, env: &str, user: &str) -> String {
    let dev = names::dev(env);
    let here = std::env::var("TERM").ok();
    let (term, entry) = crate::progress::wait("checking the env knows this terminal", || {
        plan(
            here.as_deref(),
            |t| {
                // Its name is an argument, never part of the script; the home is the one the
                // entry is installed in, which `exec` may not set.
                let known = exec(&dev).user(user).argv([
                    "sh",
                    "-c",
                    r#"HOME=$(getent passwd "$(id -u)" | cut -d: -f6) infocmp -- "$0" >/dev/null 2>&1"#,
                    t,
                ]);
                ctx.rt.succeeds(known)
            },
            host_entry,
        )
    });
    let Some(entry) = entry else {
        if term == FALLBACK
            && here.as_deref().is_some_and(|t| t != FALLBACK)
            && crate::progress::verbose()
        {
            eprintln!(
                "no terminfo entry for {} here or in `{env}`: the session gets {FALLBACK}",
                crate::text::display(here.as_deref().unwrap_or_default())
            );
        }
        return term;
    };
    // The user's home as the env's passwd has it: `exec` may not set HOME.
    let install = r#"d=$(getent passwd "$(id -u)" | cut -d: -f6); mkdir -p "$d/.terminfo" && tic -x -o "$d/.terminfo" - >/dev/null 2>&1"#;
    match ctx.rt.pipe_sh(&dev, user, install, entry.as_bytes()) {
        Ok(_) => term,
        Err(e) => {
            if crate::progress::verbose() {
                eprintln!(
                    "{term}'s terminfo entry didn't install in `{env}` ({e:#}): the session gets {FALLBACK}"
                );
            }
            FALLBACK.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GHOSTTY: &str = "#\tReconstructed via infocmp from file: /x/terminfo/78/xterm-ghostty\n\
                           xterm-ghostty|ghostty|Ghostty,\n\tam, bce, ccc,\n\tcolors#0x100, cols#80,\n\
                           \tbel=^G, bold=\\E[1m, clear=\\E[H\\E[2J,\n";

    #[test]
    fn a_terminal_name_is_letters_digits_and_a_few_marks() {
        for ok in [
            "xterm-ghostty",
            "xterm-kitty",
            "wezterm",
            "tmux-256color",
            "st+x_1.0",
        ] {
            assert!(safe(ok), "{ok}");
        }
        let long = "x".repeat(65);
        for bad in [
            "", "-x", ".hidden", "a b", "x/../y", "x;rm", "x\n", "$(id)", "ä", &long,
        ] {
            assert!(!safe(bad), "{bad:?}");
        }
        assert!(safe(&"x".repeat(64)));
    }

    #[test]
    fn an_entry_is_plain_text_that_names_its_terminal() {
        assert!(valid("xterm-ghostty", GHOSTTY));
        assert!(valid("ghostty", GHOSTTY), "an alias of it");
        assert!(!valid("xterm-kitty", GHOSTTY), "another terminal's");
        assert!(!valid("xterm-ghostty", ""));
        assert!(
            !valid("xterm-ghostty", &GHOSTTY.replace("^G", "\x07")),
            "a control byte"
        );
        assert!(!valid(
            "xterm-ghostty",
            &GHOSTTY.replace("bel=", "bel=\x1b")
        ));
        let big = format!("{GHOSTTY}{}", "\tx=y,\n".repeat(MAX_ENTRY / 6));
        assert!(!valid("xterm-ghostty", &big));
    }

    #[test]
    fn ssh_of_the_users_own_is_told_when_the_env_lacks_the_terminals_entry() {
        assert_eq!(
            ssh_note(Some("xterm-ghostty"), FALLBACK).unwrap(),
            "The env has no terminfo entry for this terminal (xterm-ghostty): start ssh with \
             `TERM=xterm-256color`."
        );
        assert_eq!(ssh_note(Some("xterm-ghostty"), "xterm-ghostty"), None);
        assert_eq!(ssh_note(Some(FALLBACK), FALLBACK), None);
        assert_eq!(ssh_note(None, FALLBACK), None);
    }

    #[test]
    fn a_session_keeps_its_terminals_name_where_the_env_has_or_gets_its_entry() {
        let never = |_: &str| -> bool { panic!("not asked") };
        let none = |_: &str| -> Option<String> { panic!("not asked") };
        // Present: nothing to copy, this machine isn't asked.
        assert_eq!(
            plan(Some("xterm-ghostty"), |_| true, none),
            ("xterm-ghostty".to_string(), None)
        );
        // Missing in the env, here on this machine: copied.
        let (term, entry) = plan(Some("xterm-ghostty"), |_| false, |_| Some(GHOSTTY.into()));
        let entry = entry.unwrap();
        assert_eq!(term, "xterm-ghostty");
        // Without the comment that names a file of this machine.
        assert!(entry.starts_with("xterm-ghostty|ghostty|Ghostty,\n"));
        assert!(entry.lines().all(|l| !l.starts_with('#')) && !entry.contains("/x/terminfo"));
        // A home that isn't ASCII is only in that comment.
        let home = GHOSTTY.replace("/x/", "/Users/mäki/");
        assert_eq!(
            plan(Some("xterm-ghostty"), |_| false, |_| Some(home)).1,
            Some(entry)
        );
        // Nowhere, or not an entry for it: the fallback.
        let fallback = (FALLBACK.to_string(), None);
        assert_eq!(plan(Some("xterm-ghostty"), |_| false, |_| None), fallback);
        assert_eq!(
            plan(Some("xterm-kitty"), |_| false, |_| Some(GHOSTTY.into())),
            fallback
        );
        // No name, an unsafe one, or the one every image has: nothing is asked.
        assert_eq!(plan(None, never, none), fallback);
        assert_eq!(plan(Some("x;rm -rf"), never, none), fallback);
        assert_eq!(plan(Some(FALLBACK), never, none), fallback);
    }
}
