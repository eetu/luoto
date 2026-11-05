//! The config format: `version` in config.toml, env files and a repo's luoto.toml. A file
//! without one is format 1. A format change bumps the format by appending a step to
//! [`MIGRATIONS`]; every file is upgraded in memory before it is parsed, so older files keep
//! loading (CLAUDE.md lists what else a migration brings).

use std::path::Path;

use anyhow::{Context, Result, bail};
use toml_edit::DocumentMut;

/// One format to the next: edits the document and says what it changed, for the user.
type Step = fn(&mut DocumentMut) -> Vec<String>;

/// `MIGRATIONS[i]` upgrades format `i + 1` to `i + 2`.
const MIGRATIONS: &[Step] = &[];

/// The format this luoto reads and writes.
pub const CURRENT: u32 = MIGRATIONS.len() as u32 + 1;

/// A file's text in the current format.
#[derive(Debug)]
pub struct Upgraded {
    pub text: String,
    /// The format the file was in.
    pub from: u32,
}

/// `text` (the file at `path`) in the current format; prints what an upgrade changed. Refuses
/// a file written by a newer luoto, whose keys this one would misread.
pub fn upgrade(path: &Path, text: &str) -> Result<Upgraded> {
    upgrade_with(path, text, MIGRATIONS)
}

fn upgrade_with(path: &Path, text: &str, steps: &[Step]) -> Result<Upgraded> {
    let current = u32::try_from(steps.len())
        .unwrap_or(u32::MAX)
        .saturating_add(1);
    let mut doc: DocumentMut = text
        .parse()
        .with_context(|| format!("parse {}", path.display()))?;
    let from = match doc.get("version") {
        None => 1,
        Some(v) => match v.as_integer().and_then(|n| u32::try_from(n).ok()) {
            Some(n) if n >= 1 => n,
            _ => bail!("`version` in {} is not a format number", path.display()),
        },
    };
    if from > current {
        bail!(
            "{} is config format {from}, from a newer luoto; this one reads up to {current}",
            path.display()
        );
    }
    if from == current {
        return Ok(Upgraded {
            text: text.to_string(),
            from,
        });
    }
    for step in &steps[(from - 1) as usize..] {
        for note in step(&mut doc) {
            eprintln!("{}: {}", path.display(), crate::text::display(&note));
        }
    }
    doc["version"] = toml_edit::value(i64::from(current));
    Ok(Upgraded {
        text: doc.to_string(),
        from,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rename_shell(doc: &mut DocumentMut) -> Vec<String> {
        match doc.remove("sh") {
            Some(v) => {
                doc["shell"] = v;
                vec!["`sh` is now `shell`".into()]
            }
            None => vec![],
        }
    }

    #[test]
    fn older_files_are_upgraded_and_newer_ones_refused() {
        let p = Path::new("x.toml");
        let steps: &[Step] = &[rename_shell];
        let up = upgrade_with(p, "sh = \"zsh\"\n", steps).unwrap();
        assert_eq!(up.from, 1);
        assert!(up.text.contains("shell = \"zsh\""));
        assert!(up.text.contains("version = 2"));

        let same = "version = 2\nshell = \"zsh\"\n";
        assert_eq!(upgrade_with(p, same, steps).unwrap().text, same);

        let err = upgrade_with(p, "version = 3\n", steps).unwrap_err();
        assert!(err.to_string().contains("newer luoto"));
        assert!(upgrade_with(p, "version = 0\n", steps).is_err());
        assert!(upgrade_with(p, "version = \"1\"\n", steps).is_err());
    }

    #[test]
    fn a_current_file_is_read_as_written() {
        let text = format!("# kept\nversion = {CURRENT}\nshell = \"zsh\"\n");
        let up = upgrade(Path::new("x.toml"), &text).unwrap();
        assert_eq!((up.from, up.text), (CURRENT, text));
    }
}
