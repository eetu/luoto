//! SSH access for editors (Zed, JetBrains Gateway, Remote-SSH). luoto owns one generated
//! config file with a `Host luoto-<env>` entry per env; the user includes it from
//! `~/.ssh/config` once. Connections run `sshd -i` through the runtime's exec — no port.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::env::{Ctx, EnvState, UID};
use crate::{config, names};

pub fn dir(ctx: &Ctx) -> PathBuf {
    ctx.paths.data.join("ssh")
}

/// The generated config file users include from `~/.ssh/config`.
pub fn config_path(ctx: &Ctx) -> PathBuf {
    ctx.paths.config.join("ssh_config")
}

fn user_ssh_config() -> Option<PathBuf> {
    Some(
        directories::BaseDirs::new()?
            .home_dir()
            .join(".ssh")
            .join("config"),
    )
}

/// `~/…` form of a path under the home directory (what people write in ssh config).
pub fn tilde(p: &Path) -> String {
    match directories::BaseDirs::new()
        .and_then(|b| p.strip_prefix(b.home_dir()).ok().map(Path::to_path_buf))
    {
        Some(rel) => format!("~/{}", rel.display()),
        None => p.display().to_string(),
    }
}

pub fn include_line(ctx: &Ctx) -> String {
    let p = tilde(&config_path(ctx));
    if p.contains(' ') {
        format!("Include \"{p}\"")
    } else {
        format!("Include {p}")
    }
}

/// Does an ssh config include luoto's file (by `~/…` or absolute path)?
pub fn includes(user_config: &str, generated: &Path) -> bool {
    let forms = [generated.display().to_string(), tilde(generated)];
    user_config.lines().any(|l| {
        let l = l.trim();
        let Some(rest) = l
            .strip_prefix("Include")
            .or_else(|| l.strip_prefix("include"))
        else {
            return false;
        };
        rest.split_whitespace()
            .map(|t| t.trim_matches('"'))
            .any(|t| forms.iter().any(|f| f == t))
    })
}

pub fn include_present(ctx: &Ctx) -> bool {
    user_ssh_config()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|c| includes(&c, &config_path(ctx)))
}

fn ensure_key(ctx: &Ctx) -> Result<PathBuf> {
    let d = dir(ctx);
    std::fs::create_dir_all(&d)?;
    let key = d.join("id_ed25519");
    if !key.exists() {
        let status = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "luoto", "-f"])
            .arg(&key)
            .status()
            .context("run ssh-keygen")?;
        if !status.success() {
            bail!("ssh-keygen failed");
        }
    }
    Ok(key)
}

/// Install luoto's public key for the env's user. No-op (false) when the image has no sshd.
pub fn authorize(ctx: &Ctx, env: &str) -> Result<bool> {
    let dev = names::dev(env);
    if !ctx
        .rt
        .succeeds(["exec", &dev, "test", "-x", "/usr/sbin/sshd"])
    {
        return Ok(false);
    }
    let key = ensure_key(ctx)?;
    let pubkey = std::fs::read(key.with_extension("pub"))?;
    ctx.rt.run_stdin(
        [
            "exec",
            "-i",
            "-u",
            UID,
            &dev,
            "sh",
            "-c",
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
        ],
        &pubkey,
    )?;
    pin_host_key(ctx, env)?;
    Ok(true)
}

/// A host key line as the env reports it: only a well-formed `ssh-ed25519 <base64>` (it comes
/// from the sandbox and goes into a file ssh reads).
fn parse_host_key(text: &str) -> Option<String> {
    let mut parts = text.split_whitespace();
    let (kind, key) = (parts.next()?, parts.next()?);
    (kind == "ssh-ed25519"
        && !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)))
    .then(|| format!("{kind} {key}"))
}

/// Pin the env's host key in luoto's known_hosts, replacing any earlier one. SSH reaches the env
/// through `exec` into this very container, so the key read the same way is the right one; a
/// recreated container (new keys) then connects without a "host key changed" refusal.
fn pin_host_key(ctx: &Ctx, env: &str) -> Result<()> {
    let out = ctx.rt.run([
        "exec",
        &names::dev(env),
        "cat",
        "/etc/ssh/ssh_host_ed25519_key.pub",
    ])?;
    let key = parse_host_key(&out).context("the env's SSH host key is not an ed25519 key")?;
    let mut lines = known_hosts_without(ctx, env);
    lines.push(format!("luoto-{env} {key}"));
    write_known_hosts(ctx, &lines)
}

/// Drop the env's host key (on `luoto rm`).
pub fn forget_host_key(ctx: &Ctx, env: &str) -> Result<()> {
    write_known_hosts(ctx, &known_hosts_without(ctx, env))
}

fn known_hosts_without(ctx: &Ctx, env: &str) -> Vec<String> {
    let host = format!("luoto-{env}");
    std::fs::read_to_string(dir(ctx).join("known_hosts"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_whitespace().next() != Some(host.as_str()))
        .map(str::to_string)
        .collect()
}

fn write_known_hosts(ctx: &Ctx, lines: &[String]) -> Result<()> {
    let mut text = lines.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    crate::paths::write_private(&dir(ctx).join("known_hosts"), text.as_bytes())
}

/// A portable POSIX user name (`[a-z_][a-z0-9_-]{0,31}`): safe inside ssh_config and URLs.
pub fn valid_user(s: &str) -> bool {
    let mut b = s.bytes();
    matches!(b.next(), Some(c) if c.is_ascii_lowercase() || c == b'_')
        && s.len() <= 32
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

fn block(ctx: &Ctx, env: &str, user: &str) -> Result<String> {
    let exe = std::env::current_exe()?;
    // Editors started from the GUI don't inherit the shell's LUOTO_HOME; carry it explicitly.
    let proxy = match std::env::var("LUOTO_HOME") {
        Ok(h) if !cfg!(windows) => {
            format!(
                "env LUOTO_HOME=\"{h}\" \"{}\" ssh-proxy {env}",
                exe.display()
            )
        }
        _ => format!("\"{}\" ssh-proxy {env}", exe.display()),
    };
    Ok(format!(
        "Host luoto-{env}\n  User {user}\n  ProxyCommand {proxy}\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  \
         StrictHostKeyChecking accept-new\n  UserKnownHostsFile \"{}\"\n  ForwardAgent no\n  ForwardX11 no\n  \
         PermitLocalCommand no\n  Tunnel no\n",
        dir(ctx).join("id_ed25519").display(),
        dir(ctx).join("known_hosts").display()
    ))
}

/// Regenerate the file from every env that has been started at least once.
pub fn write_config(ctx: &Ctx) -> Result<PathBuf> {
    let mut out = String::from(
        "# Generated by luoto — do not edit; regenerated on `luoto up` and `luoto rm`.\n\
         # Include it from ~/.ssh/config (before any Host block).\n\n",
    );
    for env in config::list_envs(&ctx.paths)? {
        if let Some(st) = EnvState::load(ctx, &env)? {
            out.push_str(&block(ctx, &env, st.login())?);
            out.push('\n');
        }
    }
    let path = config_path(ctx);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Instructions when the include is missing.
pub fn include_hint(ctx: &Ctx) -> String {
    format!(
        "Add this line at the top of ~/.ssh/config (once; luoto never edits that file):\n  {}",
        include_line(ctx)
    )
}

#[cfg(test)]
mod tests {
    use super::{includes, valid_user};
    use std::path::Path;

    #[test]
    fn host_keys_from_the_sandbox_are_plain() {
        use super::parse_host_key;
        assert_eq!(
            parse_host_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA+/x= root@luoto-web\n").as_deref(),
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA+/x=")
        );
        assert!(parse_host_key("ssh-rsa AAAA").is_none());
        // Only the first two fields survive: an injected second line never reaches the file.
        assert_eq!(
            parse_host_key("ssh-ed25519 AA\nluoto-x ssh-ed25519 BB").as_deref(),
            Some("ssh-ed25519 AA")
        );
        assert!(parse_host_key("ssh-ed25519").is_none());
    }

    #[test]
    fn user_names_from_the_sandbox_are_plain() {
        assert!(valid_user("dev"));
        assert!(valid_user("_build-1"));
        assert!(!valid_user("dev\nMatch exec \"touch /tmp/x\""));
        assert!(!valid_user("Dev"));
        assert!(!valid_user("-x"));
        assert!(!valid_user(""));
        assert!(!valid_user(&"a".repeat(33)));
    }

    #[test]
    fn detects_include_lines() {
        let generated = Path::new("/home/u/.config/luoto/ssh_config");
        assert!(includes(
            "Include /home/u/.config/luoto/ssh_config\nHost x\n",
            generated
        ));
        assert!(includes(
            "  Include \"/home/u/.config/luoto/ssh_config\"\n",
            generated
        ));
        assert!(includes(
            "Include ~/.orbstack/ssh/config /home/u/.config/luoto/ssh_config\n",
            generated
        ));
        assert!(!includes(
            "# Include /home/u/.config/luoto/ssh_config\n",
            generated
        ));
        assert!(!includes("Host luoto-x\n", generated));
    }
}
