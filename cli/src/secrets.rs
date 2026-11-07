//! Resolving secret refs on the host. Values go straight to the vault over stdin and are
//! never written to disk by luoto.
//!
//! Ref schemes:
//! - `op://vault/item/field` — 1Password CLI (desktop biometric unlock, or a service account)
//! - `vault://mount/path#field` — OpenBao / HashiCorp Vault KV via the `bao` or `vault` CLI
//! - `keyring:service/account` — macOS Keychain, Windows Credential Manager, Secret Service
//! - `env:NAME` — an environment variable of the luoto process
//! - `file:/path` or `file:~/path` — a file readable by the user

use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::GlobalConfig;

pub fn resolve_all(
    global: &GlobalConfig,
    refs: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for r in refs {
        let v = resolve(global, r).with_context(|| format!("resolve secret {r}"))?;
        out.insert(r.clone(), v);
    }
    Ok(out)
}

pub fn scheme_ok(r: &str) -> bool {
    ["op://", "vault://", "keyring:", "env:", "file:"]
        .iter()
        .any(|p| r.starts_with(p))
}

/// Why `r` can't be resolved as written, if it can't.
pub fn check_ref(r: &str) -> Result<()> {
    if !scheme_ok(r) {
        bail!(
            "secret ref `{r}` has an unknown scheme (use op://, vault://, keyring:, env: or file:)"
        );
    }
    if let Some(path) = r.strip_prefix("file:") {
        file_path(path)?;
    }
    Ok(())
}

pub fn resolve(global: &GlobalConfig, r: &str) -> Result<String> {
    if r.starts_with("op://") {
        return op_read(global, r);
    }
    if let Some(rest) = r.strip_prefix("vault://") {
        return vault_read(global, rest);
    }
    if let Some(rest) = r.strip_prefix("keyring:") {
        let (service, account) = rest
            .split_once('/')
            .context("keyring refs are keyring:<service>/<account>")?;
        let entry = keyring::Entry::new(service, account).context("open OS keyring")?;
        return entry
            .get_password()
            .with_context(|| format!("no keyring entry {service}/{account}"));
    }
    if let Some(name) = r.strip_prefix("env:") {
        return std::env::var(name)
            .with_context(|| format!("environment variable {name} is not set"));
    }
    if let Some(path) = r.strip_prefix("file:") {
        let path = file_path(path)?;
        return Ok(std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?
            .trim_end_matches(['\r', '\n'])
            .to_string());
    }
    bail!("unknown secret ref scheme (use op://, vault://, keyring:, env: or file:)")
}

/// Whether reading `r` needs no one at the machine: not the 1Password app, which asks for
/// Touch ID, and not `env:`, which a background process holds as it started. Only these are
/// read again on their own when an upstream refuses them.
pub fn unattended(global: &GlobalConfig, r: &str) -> bool {
    if r.starts_with("op://") {
        return global.sources.op.mode.as_deref() == Some("service-account");
    }
    ["keyring:", "file:", "vault://"]
        .iter()
        .any(|p| r.starts_with(p))
}

/// A `file:` ref's path. Only absolute and `~/` paths: a relative one would resolve against
/// whichever folder luoto happens to run in.
fn file_path(p: &str) -> Result<PathBuf> {
    if let Some(rest) = p.strip_prefix("~/") {
        let dirs = directories::BaseDirs::new().context("no home directory to expand `~/` in")?;
        return Ok(dirs.home_dir().join(rest));
    }
    if !Path::new(p).is_absolute() {
        bail!(
            "`file:{p}` is a relative path; write it absolute (file:/…) or from your home (file:~/…)"
        );
    }
    Ok(PathBuf::from(p))
}

/// `op <args>` as `config.toml`'s 1Password source says: its account, and the service
/// account's token when that mode is on.
fn op(global: &GlobalConfig, args: &[&str]) -> Result<Command> {
    let mut cmd = Command::new("op");
    cmd.args(args);
    if let Some(acct) = &global.sources.op.account {
        cmd.args(["--account", acct]);
    }
    if global.sources.op.mode.as_deref() == Some("service-account") {
        let token_ref = global
            .sources
            .op
            .service_account_token
            .as_deref()
            .context("sources.op.service_account_token must be set for service-account mode")?;
        if token_ref.starts_with("op://") {
            bail!("the 1Password service account token cannot itself be an op:// ref");
        }
        cmd.env("OP_SERVICE_ACCOUNT_TOKEN", resolve(global, token_ref)?);
    }
    Ok(cmd)
}

/// Run `op`, feeding `input` (if any) on stdin, and return its stdout. On a terminal `op` may
/// ask there (sign in, pick an account): its messages must show, or luoto just seems to hang.
/// Elsewhere they become the error.
fn op_output(mut cmd: Command, what: &str, input: Option<&[u8]>) -> Result<Vec<u8>> {
    let interactive = std::io::stdin().is_terminal();
    let mut child = cmd
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .stdout(Stdio::piped())
        .stderr(if interactive {
            Stdio::inherit()
        } else {
            Stdio::piped()
        })
        .spawn()
        .context("run the 1Password CLI (`op`); install it or use keyring:/env: refs")?;
    if let Some(bytes) = input {
        child.stdin.take().context("op's stdin")?.write_all(bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "{what} failed{}",
            if interactive {
                " (see above)".to_string()
            } else {
                format!(": {}", String::from_utf8_lossy(&out.stderr).trim())
            }
        );
    }
    Ok(out.stdout)
}

fn op_read(global: &GlobalConfig, r: &str) -> Result<String> {
    let out = op_output(op(global, &["read", "--no-newline", r])?, "op read", None)?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// The 1Password CLI is installed.
pub fn op_available() -> bool {
    Command::new("op")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Names of the 1Password vaults the account can see.
pub fn op_vaults(global: &GlobalConfig) -> Result<Vec<String>> {
    let out = op_output(
        op(global, &["vault", "list", "--format", "json"])?,
        "op vault list",
        None,
    )?;
    let vaults: Vec<serde_json::Value> =
        serde_json::from_slice(&out).context("op vault list: unexpected output")?;
    Ok(vaults
        .iter()
        .filter_map(|v| v["name"].as_str().map(str::to_string))
        .collect())
}

/// Save `secret` as a new API Credential item in `vault` and return its `op://` reference
/// (by item id, so a second item with the same title can't make it ambiguous). The secret
/// reaches `op` on stdin, never in its arguments.
pub fn op_save(
    global: &GlobalConfig,
    vault: &str,
    title: &str,
    secret: &str,
    note: &str,
) -> Result<String> {
    let item = serde_json::json!({
        "title": title,
        "category": "API_CREDENTIAL",
        "fields": [
            {"id": "credential", "type": "CONCEALED", "label": "credential", "value": secret},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": note},
        ],
    });
    let out = op_output(
        op(
            global,
            &["item", "create", "--vault", vault, "--format", "json", "-"],
        )?,
        "op item create",
        Some(&serde_json::to_vec(&item)?),
    )?;
    let created: serde_json::Value =
        serde_json::from_slice(&out).context("op item create: unexpected output")?;
    let id = created["id"]
        .as_str()
        .context("op item create: no item id")?;
    // A vault name with `/` can't be a reference segment; its id can.
    let vault_ref = match created["vault"]["name"].as_str() {
        Some(n) if !n.contains('/') => n,
        _ => created["vault"]["id"]
            .as_str()
            .context("op item create: no vault")?,
    };
    Ok(format!("op://{vault_ref}/{id}/credential"))
}

fn vault_read(global: &GlobalConfig, rest: &str) -> Result<String> {
    let src = global
        .sources
        .vault
        .as_ref()
        .context("vault:// refs need [sources.vault] in config.toml")?;
    let (path, field) = rest
        .split_once('#')
        .context("vault refs are vault://<mount>/<path>#<field>")?;
    let (mount, key) = path
        .split_once('/')
        .context("vault refs are vault://<mount>/<path>#<field>")?;
    let bin = if Command::new("bao").arg("version").output().is_ok() {
        "bao"
    } else {
        "vault"
    };
    let token = resolve(global, &src.token)?;
    let mut cmd = Command::new(bin);
    cmd.args([
        "kv",
        "get",
        &format!("-mount={mount}"),
        &format!("-field={field}"),
        key,
    ])
    .env("VAULT_ADDR", &src.addr)
    .env("BAO_ADDR", &src.addr)
    .env("VAULT_TOKEN", &token)
    .env("BAO_TOKEN", &token);
    if let Some(ns) = &src.namespace {
        cmd.env("VAULT_NAMESPACE", ns).env("BAO_NAMESPACE", ns);
    }
    let out = cmd
        .output()
        .with_context(|| format!("run `{bin}` (install the OpenBao or Vault CLI)"))?;
    if !out.status.success() {
        bail!(
            "{bin} kv get failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim_end_matches('\n')
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_refs_are_absolute_or_from_home() {
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();
        assert_eq!(file_path("~/k").unwrap(), home.join("k"));
        let abs = std::env::temp_dir().join("k");
        assert_eq!(file_path(abs.to_str().unwrap()).unwrap(), abs);
        for rel in ["k", "./k", "../k", "~k", ""] {
            let e = file_path(rel).unwrap_err().to_string();
            assert!(e.contains("relative"), "{rel:?}: {e}");
            assert!(check_ref(&format!("file:{rel}")).is_err());
        }
        assert!(check_ref("file:~/k").is_ok());
        assert!(check_ref("op://v/i/f").is_ok());
        assert!(check_ref("http://x").is_err());
    }
}
