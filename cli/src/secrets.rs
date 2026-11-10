//! Resolving secret refs on the host. Values go straight to the vault over stdin and are
//! never written to disk by luoto.
//!
//! Ref schemes:
//! - `op://vault/item/field` — 1Password CLI (desktop biometric unlock, or a service account);
//!   `?account=<sign-in address>` reads it from that account, when the app has several
//!   (luoto's own parameter: 1Password's refs name no account)
//! - `vault://mount/path#field` — OpenBao / HashiCorp Vault KV via the `bao` or `vault` CLI
//! - `keyring:service/account` — macOS Keychain, Windows Credential Manager, Secret Service
//! - `env:NAME` — an environment variable of the luoto process
//! - `file:/path` or `file:~/path` — a file readable by the user
//! - `azcli:<resource>[?tenant=<tenant>]` — a token from the Azure CLI's login on this machine

use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};

use crate::azure_identity::{self, AZCLI};
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

fn scheme_ok(r: &str) -> bool {
    ["op://", "vault://", "keyring:", "env:", "file:"]
        .iter()
        .any(|p| r.starts_with(p))
}

/// Why `r`, a ref written in a config, can't be resolved as written, if it can't. `azcli:` is
/// not one: only the bindings `[credentials.azure]` compiles to use it ([`check_vault_ref`]).
pub fn check_ref(r: &str) -> Result<()> {
    if r.starts_with(AZCLI) {
        bail!(
            "`{r}` is luoto's own ref for [credentials.azure], which reads your az login \
             without one"
        );
    }
    if !scheme_ok(r) {
        bail!(
            "secret ref `{r}` has an unknown scheme (use op://, vault://, keyring:, env: or \
             file:)"
        );
    }
    if let Some(path) = r.strip_prefix("file:") {
        file_path(path)?;
    }
    if r.starts_with("op://")
        && let (_, Some(account)) = op_parts(r)
    {
        check_op_account(&account)?;
    }
    Ok(())
}

/// An `op://` ref as `op` reads it, and the account it names (`?account=`), which luoto takes
/// out: the rest of the query (`?ssh-format=openssh`) stays.
pub fn op_parts(r: &str) -> (String, Option<String>) {
    let Some((base, query)) = r.split_once('?') else {
        return (r.to_string(), None);
    };
    let mut account = None;
    let rest: Vec<&str> = query
        .split('&')
        .filter(|kv| match kv.strip_prefix("account=") {
            Some(a) => {
                account = Some(a.to_string());
                false
            }
            None => true,
        })
        .collect();
    let op_ref = if rest.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", rest.join("&"))
    };
    (op_ref, account)
}

/// `r` read from 1Password account `account` instead of the one it names, if any.
pub fn op_with_account(r: &str, account: &str) -> String {
    let (op_ref, _) = op_parts(r);
    let sep = if op_ref.contains('?') { '&' } else { '?' };
    format!("{op_ref}{sep}account={account}")
}

/// An account as `op --account` takes one: a sign-in address, shorthand or ID, never a flag.
fn check_op_account(account: &str) -> Result<()> {
    let plain = !account.is_empty()
        && !account.starts_with('-')
        && account
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:/".contains(c));
    if !plain {
        bail!(
            "`account={account}` in an op:// ref is a 1Password sign-in address \
             (my.1password.com), shorthand or ID"
        );
    }
    Ok(())
}

/// [`check_ref`] for a ref a compiled binding uses, which may be an `azcli:` one
/// (`compile` lets only `[credentials.azure]`'s bindings have it).
pub fn check_vault_ref(r: &str) -> Result<()> {
    if r.starts_with(AZCLI) {
        return azure_identity::parse_ref(r).map(|_| ());
    }
    check_ref(r)
}

/// `r`'s value, and when it expires where its source says (an `azcli:` token).
pub fn resolve_expiring(global: &GlobalConfig, r: &str) -> Result<(String, Option<DateTime<Utc>>)> {
    if r.starts_with(AZCLI) {
        return azure_identity::read(r);
    }
    Ok((resolve(global, r)?, None))
}

pub fn resolve(global: &GlobalConfig, r: &str) -> Result<String> {
    if r.starts_with(AZCLI) {
        return Ok(azure_identity::read(r)?.0);
    }
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
    ["keyring:", "file:", "vault://", AZCLI]
        .iter()
        .any(|p| r.starts_with(p))
}

/// A `file:` ref's path. Only absolute and `~/` paths: a relative one would resolve against
/// whichever folder luoto happens to run in. Only this machine's (`workspace::network_path`).
fn file_path(p: &str) -> Result<PathBuf> {
    if crate::workspace::network_path(p) {
        bail!("`file:{p}` is on another machine; keep the secret in a file on this one");
    }
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

/// `op <args>` as `config.toml`'s 1Password source says: `account` (a ref's own) or its
/// account, and the service account's token when that mode is on.
fn op(global: &GlobalConfig, args: &[&str], account: Option<&str>) -> Result<Command> {
    let mut cmd = Command::new("op");
    cmd.args(args);
    if let Some(acct) = account.or(global.sources.op.account.as_deref()) {
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

/// Trimmed as a `file:` is: text typed into 1Password (a Secure Note's) often ends in a line
/// break, which no header value can carry.
fn op_read(global: &GlobalConfig, r: &str) -> Result<String> {
    let (op_ref, account) = op_parts(r);
    if let Some(a) = &account {
        check_op_account(a)?;
    }
    let out = op_output(
        op(
            global,
            &["read", "--no-newline", &op_ref],
            account.as_deref(),
        )?,
        "op read",
        None,
    )?;
    Ok(String::from_utf8_lossy(&out)
        .trim_end_matches(['\r', '\n'])
        .to_string())
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

/// An account added to the 1Password app.
pub struct OpAccount {
    /// Its sign-in address (`my.1password.com`), as `--account` takes it.
    pub address: String,
    pub email: String,
}

/// The accounts added to the 1Password app; none when `op` can't say.
pub fn op_accounts() -> Vec<OpAccount> {
    let Ok(out) = Command::new("op")
        .args(["account", "list", "--format", "json"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    let list: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap_or_default();
    list.iter()
        .filter_map(|a| {
            let url = a["url"].as_str()?;
            let address = url.strip_prefix("https://").unwrap_or(url);
            check_op_account(address).ok()?;
            Some(OpAccount {
                address: address.to_string(),
                email: a["email"].as_str().unwrap_or_default().to_string(),
            })
        })
        .collect()
}

/// Names of the 1Password vaults `account` (or the default one) can see.
pub fn op_vaults(global: &GlobalConfig, account: Option<&str>) -> Result<Vec<String>> {
    let out = op_output(
        op(global, &["vault", "list", "--format", "json"], account)?,
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

/// Save `secret` as a new API Credential item in `vault` (of `account`, or the default one) and
/// return its `op://` reference (by item id, so a second item with the same title can't make it
/// ambiguous). The secret reaches `op` on stdin, never in its arguments.
pub fn op_save(
    global: &GlobalConfig,
    account: Option<&str>,
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
            account,
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
    let r = format!("op://{vault_ref}/{id}/credential");
    Ok(match account {
        Some(a) => op_with_account(&r, a),
        None => r,
    })
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
    fn an_op_ref_can_name_its_account() {
        assert_eq!(op_parts("op://v/i/f"), ("op://v/i/f".into(), None));
        assert_eq!(
            op_parts("op://v/i/f?account=my.1password.com"),
            ("op://v/i/f".into(), Some("my.1password.com".into()))
        );
        assert_eq!(
            op_parts("op://v/ssh/private key?ssh-format=openssh&account=acme.1password.com"),
            (
                "op://v/ssh/private key?ssh-format=openssh".into(),
                Some("acme.1password.com".into())
            )
        );
        assert_eq!(
            op_with_account("op://v/i/f", "my.1password.com"),
            "op://v/i/f?account=my.1password.com"
        );
        assert_eq!(
            op_with_account(
                "op://v/k?ssh-format=openssh&account=old",
                "new.1password.com"
            ),
            "op://v/k?ssh-format=openssh&account=new.1password.com"
        );
        assert!(check_ref("op://v/i/f?account=https://my.1password.com").is_ok());
        for bad in ["", "-x", "a b", "a;b", "a$(id)"] {
            let r = format!("op://v/i/f?account={bad}");
            assert!(check_ref(&r).is_err(), "{r}");
        }
    }

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
        for remote in [
            r"file:\\server\share\k",
            "file://server/share/k",
            "file:/net/h/k",
        ] {
            assert!(check_ref(remote).is_err(), "{remote}");
        }
        assert!(check_ref("op://v/i/f").is_ok());
        assert!(check_ref("http://x").is_err());
        let azcli = "azcli:https://management.azure.com/";
        assert!(check_ref(azcli).is_err());
        assert!(check_vault_ref(azcli).is_ok());
        assert!(check_vault_ref("azcli:https://x?tenant=a/b").is_err());
        assert!(check_vault_ref("http://x").is_err());
    }
}
