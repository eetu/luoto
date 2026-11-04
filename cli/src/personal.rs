//! The dev user's own shell experience, applied on every `up`: the login shell, files from
//! `<config>/home/` (dotfiles) and the host's git identity. Everything flows host → sandbox,
//! the trusted direction; nothing is read back.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};

use crate::config::EnvConfig;
use crate::env::{Ctx, UID};
use crate::names;

/// Returns how many files from the home folder were copied.
pub fn apply(ctx: &Ctx, env: &str, cfg: &EnvConfig) -> usize {
    if let Some(shell) = preferred_shell(ctx, cfg) {
        match set_shell(ctx, env, &shell) {
            Ok(Some(path)) => println!("login shell: {}", crate::text::display(&path)),
            Ok(None) => {}
            Err(e) => eprintln!("warning: login shell not changed ({e:#})"),
        }
    }
    if let Err(e) = git_identity(ctx, env) {
        eprintln!("warning: git identity not set in the env ({e:#})");
    }
    match copy_home(ctx, env) {
        Ok(0) => 0,
        Ok(n) => {
            println!(
                "copied {n} file(s) from {} into the env's home",
                ctx.paths.home_files().display()
            );
            n
        }
        Err(e) => {
            eprintln!("warning: home files not copied ({e:#})");
            0
        }
    }
}

/// Seeded into a new home folder: the start of the files people tweak.
const SEED: &[(&str, &str)] = &[(
    ".claude/settings.json",
    "{\n  \"$schema\": \"https://json.schemastore.org/claude-code-settings.json\"\n}\n",
)];

/// Create the home folder with starter files, unless it exists.
pub fn seed_home(dir: &Path) -> Result<bool> {
    if dir.exists() {
        return Ok(false);
    }
    for (rel, text) in SEED {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, text)?;
    }
    Ok(true)
}

/// The env's `shell`, then config.toml's, then the host's own login shell. `None` keeps the
/// image's default.
pub fn preferred_shell(ctx: &Ctx, cfg: &EnvConfig) -> Option<String> {
    cfg.shell
        .clone()
        .or_else(|| ctx.global.shell.clone())
        .or_else(host_shell)
}

fn host_shell() -> Option<String> {
    let s = std::env::var("SHELL").ok()?;
    let name = Path::new(&s).file_name()?.to_str()?;
    ["fish", "zsh", "bash"]
        .contains(&name)
        .then(|| name.to_string())
}

fn valid_shell(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
}

/// Prints the shell's path when it changed; exit 3 = not installed in the image.
const SET_SHELL: &str = r#"s=$(command -v "$1") || exit 3
cur=$(awk -F: -v u="$2" '$3==u{print $7; exit}' /etc/passwd)
[ "$cur" = "$s" ] && exit 0
grep -qx "$s" /etc/shells 2>/dev/null || echo "$s" >>/etc/shells
awk -F: -v OFS=: -v u="$2" -v s="$s" '$3==u{$7=s}1' /etc/passwd >/etc/passwd.luoto &&
  cat /etc/passwd.luoto >/etc/passwd && rm -f /etc/passwd.luoto && echo "$s""#;

fn set_shell(ctx: &Ctx, env: &str, shell: &str) -> Result<Option<String>> {
    if !valid_shell(shell) {
        bail!("`{shell}` is not a shell name or path");
    }
    let out = ctx
        .rt
        .command()
        .args([
            "exec",
            "-u",
            "0",
            &names::dev(env),
            "sh",
            "-c",
            SET_SHELL,
            "sh",
            shell,
            UID,
        ])
        .output()
        .context("run the runtime")?;
    match out.status.code() {
        Some(0) => {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Ok((!path.is_empty()).then_some(path))
        }
        Some(3) => bail!("`{shell}` is not installed in the env's image"),
        _ => bail!("{}", String::from_utf8_lossy(&out.stderr).trim()),
    }
}

fn host_git(key: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["config", "--global", "--includes", "--get", key])
        .output()
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// The host's git author identity as system config, so commits made in the env are yours and
/// a `~/.gitconfig` in the env's home still overrides it.
fn git_identity(ctx: &Ctx, env: &str) -> Result<()> {
    let (name, email) = (host_git("user.name"), host_git("user.email"));
    if name.is_none() && email.is_none() {
        return Ok(());
    }
    ctx.rt.run([
        "exec",
        "-u",
        "0",
        &names::dev(env),
        "sh",
        "-c",
        r#"command -v git >/dev/null || exit 0
[ -z "$1" ] || git config --system user.name "$1"
[ -z "$2" ] || git config --system user.email "$2""#,
        "sh",
        name.as_deref().unwrap_or(""),
        email.as_deref().unwrap_or(""),
    ])?;
    Ok(())
}

struct Entry {
    path: PathBuf,
    rel: PathBuf,
    dir: bool,
}

/// Everything under `src`, following symlinks (a link to your dotfiles repo copies what it
/// points at). `.git` and Finder litter are skipped.
fn collect(src: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut seen = HashSet::from([src.canonicalize()?]);
    let mut stack = vec![src.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let path = entry?.path();
            let name = path.file_name().unwrap_or_default();
            if name == ".git" || name == ".DS_Store" {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            let rel = path.strip_prefix(src)?.to_path_buf();
            if meta.is_dir() {
                if !seen.insert(path.canonicalize()?) {
                    continue;
                }
                stack.push(path.clone());
                out.push(Entry {
                    path,
                    rel,
                    dir: true,
                });
            } else if meta.is_file() {
                out.push(Entry {
                    path,
                    rel,
                    dir: false,
                });
            }
        }
    }
    Ok(out)
}

const EXTRACT: &str = r#"h=$(awk -F: -v u="$1" '$3==u{print $6; exit}' /etc/passwd)
cd "${h:-$HOME}" && exec tar -x -f -"#;

fn copy_home(ctx: &Ctx, env: &str) -> Result<usize> {
    let src = ctx.paths.home_files();
    if !src.is_dir() {
        return Ok(0);
    }
    let entries = collect(&src)?;
    let files = entries.iter().filter(|e| !e.dir).count();
    if files == 0 {
        return Ok(0);
    }
    let mut child = ctx
        .rt
        .command()
        .args([
            "exec",
            "-i",
            "-u",
            UID,
            &names::dev(env),
            "sh",
            "-c",
            EXTRACT,
            "sh",
            UID,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("start tar in the env")?;
    let mut builder = tar::Builder::new(child.stdin.take().context("stdin")?);
    for e in &entries {
        if e.dir {
            builder.append_dir(&e.rel, &e.path)?;
        } else {
            builder.append_path_with_name(&e.path, &e.rel)?;
        }
    }
    builder.into_inner()?.flush()?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_names() {
        assert!(valid_shell("zsh"));
        assert!(valid_shell("/usr/bin/fish"));
        assert!(!valid_shell(""));
        assert!(!valid_shell("zsh; rm -rf /"));
    }

    #[cfg(unix)]
    #[test]
    fn collect_follows_links_once_and_skips_git() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("home");
        let dots = d.path().join("dots");
        std::fs::create_dir_all(dots.join(".git")).unwrap();
        std::fs::write(dots.join(".git/HEAD"), "x").unwrap();
        std::fs::write(dots.join("config.fish"), "x").unwrap();
        std::fs::create_dir_all(src.join(".config")).unwrap();
        std::fs::write(src.join(".zshrc"), "x").unwrap();
        std::os::unix::fs::symlink(&dots, src.join(".config/fish")).unwrap();
        std::os::unix::fs::symlink(&src, src.join(".config/loop")).unwrap();
        std::os::unix::fs::symlink(d.path().join("gone"), src.join(".dangling")).unwrap();
        let mut rels: Vec<_> = collect(&src)
            .unwrap()
            .into_iter()
            .filter(|e| !e.dir)
            .map(|e| e.rel.to_string_lossy().into_owned())
            .collect();
        rels.sort();
        assert_eq!(rels, [".config/fish/config.fish", ".zshrc"]);
    }
}
