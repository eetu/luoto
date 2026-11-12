//! Resolving secret refs on the host. Values go straight to the vault over stdin and are
//! never written to disk by luoto.
//!
//! Ref schemes:
//! - `op://vault/item/field` — 1Password CLI (desktop biometric unlock, or a service account);
//!   `?account=<account ID>` reads it from that account, when the app has several (luoto's own
//!   parameter: 1Password's refs name no account)
//! - `vault://mount/path#field` — OpenBao / HashiCorp Vault KV via the `bao` or `vault` CLI
//! - `keyring:service/account` — macOS Keychain, Windows Credential Manager, Secret Service
//! - `env:NAME` — an environment variable of the luoto process
//! - `file:/path` or `file:~/path` — a file readable by the user
//! - `azcli:<resource>[?tenant=<tenant>]` — a token from the Azure CLI's login on this machine

use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};

use crate::azure_identity::{self, AZCLI};
use crate::config::GlobalConfig;
use crate::text::display;

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

/// An account as `op --account` takes one: an account ID, sign-in address or shorthand, never
/// a flag.
fn check_op_account(account: &str) -> Result<()> {
    let plain = !account.is_empty()
        && !account.starts_with('-')
        && account
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:/".contains(c));
    if !plain {
        bail!(
            "`account={}` in an op:// ref is a 1Password account ID (`op account list` shows \
             them), sign-in address (my.1password.com) or shorthand",
            display(account)
        );
    }
    Ok(())
}

/// An account ID (`account_uuid`): upper-case letters and digits.
fn is_op_account_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Refuses `account` when several of `accounts` sign in at that address, as every individual
/// and family account does (`my.1password.com`): it can't say which one holds the ref.
fn check_unique_address(account: &str, accounts: &[OpAccount]) -> Result<()> {
    let address = |s: &str| {
        s.strip_prefix("https://")
            .unwrap_or(s)
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    let wanted = address(account);
    let same: Vec<String> = accounts
        .iter()
        .filter(|a| address(&a.address) == wanted)
        .map(|a| format!("{} (ID {})", a.shown(), a.id))
        .collect();
    if same.len() > 1 {
        bail!(
            "`account={account}`: {} accounts in the 1Password app sign in at that address: {}; \
             name the one that holds it by its ID (`?account=<ID>`)",
            same.len(),
            same.join(", ")
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
        return entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => anyhow::anyhow!("not in the keychain"),
            e => anyhow::anyhow!("{e}"),
        });
    }
    // Each error names what went wrong, not the ref: callers put the ref before it.
    if let Some(name) = r.strip_prefix("env:") {
        return std::env::var(name).map_err(|e| match e {
            std::env::VarError::NotPresent => anyhow::anyhow!("environment variable not set"),
            e => anyhow::anyhow!("{e}"),
        });
    }
    if let Some(path) = r.strip_prefix("file:") {
        let path = file_path(path)?;
        return Ok(std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("{e}"))?
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
        return op_service_account(global);
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

/// The sessions `op signin` gave this process (`OP_SESSION_<id>`, as `eval $(op signin)` sets
/// them in a shell), passed to every later `op`. Memory only: one lasts 30 minutes idle.
static OP_SESSIONS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

/// What to do when `op` isn't signed in on this terminal.
const OP_SIGN_IN: &str = "1Password isn't signed in: run `eval $(op signin)` before luoto, or \
                          turn on Settings > Developer > Integrate with 1Password CLI in the \
                          1Password app, which unlocks `op` with the app in every terminal";

/// `op <args>` as `config.toml`'s 1Password source says: `account` (a ref's own) or its
/// account, and the service account's token when that mode is on.
fn op(global: &GlobalConfig, args: &[&str], account: Option<&str>) -> Result<Command> {
    let mut cmd = Command::new("op");
    cmd.args(args);
    if let Some(acct) = account.or(global.sources.op.account.as_deref()) {
        cmd.args(["--account", acct]);
    }
    for (name, token) in OP_SESSIONS.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        cmd.env(name, token);
    }
    if op_service_account(global) {
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
    let mut run = || -> Result<std::process::Output> {
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
        Ok(child.wait_with_output()?)
    };
    let out = if interactive {
        crate::progress::pause(run)?
    } else {
        run()?
    };
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

/// `op <args>` run as [`op_output`] runs it. When it fails because 1Password isn't signed in
/// here (no app integration, no `eval $(op signin)` in this shell), a terminal is offered the
/// sign-in in place, and the command runs again: signing in from another terminal can't reach
/// this process, and leaving would end the question that needed `op`.
fn op_run(
    global: &GlobalConfig,
    args: &[&str],
    account: Option<&str>,
    what: &str,
    input: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let first = op_output(op(global, args, account)?, what, input);
    if first.is_ok()
        || op_service_account(global)
        || !op_available()
        || op_signed_in(global, account)
    {
        return first;
    }
    if !crate::prompt::confirm("1Password isn't signed in here. Sign in now (`op signin`)?") {
        bail!("{OP_SIGN_IN}");
    }
    op_sign_in(global, account)?;
    op_output(op(global, args, account)?, what, input)
}

/// Whether `op` is signed in to `account` (or the default one) here.
fn op_signed_in(global: &GlobalConfig, account: Option<&str>) -> bool {
    op(global, &["whoami"], account).is_ok_and(|mut cmd| {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// `op signin` on this terminal (it asks for the password there), keeping the session it
/// prints for this process. With the app integration on, it authorizes the terminal instead
/// and prints none.
fn op_sign_in(global: &GlobalConfig, account: Option<&str>) -> Result<()> {
    let mut cmd = op(global, &["signin"], account)?;
    let out = crate::progress::pause(|| -> Result<std::process::Output> {
        Ok(cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("run `op signin`")?
            .wait_with_output()?)
    })?;
    if !out.status.success() {
        bail!("`op signin` failed (see above). {OP_SIGN_IN}");
    }
    let found = op_sessions(&String::from_utf8_lossy(&out.stdout));
    let mut sessions = OP_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions.retain(|(name, _)| !found.iter().any(|(n, _)| n == name));
    sessions.extend(found);
    Ok(())
}

/// The `OP_SESSION_<id>` variables `op signin` prints, in any shell's syntax (`export NAME="…"`,
/// `set -x NAME "…"`, `$env:NAME="…"`).
fn op_sessions(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let rest = &l[l.find("OP_SESSION_")?..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let (name, after) = rest.split_at(end);
            let quoted = &after[after.find('"')? + 1..];
            let token = &quoted[..quoted.find('"')?];
            let plain = !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
            (name.len() > "OP_SESSION_".len() && plain)
                .then(|| (name.to_string(), token.to_string()))
        })
        .collect()
}

/// Trimmed as a `file:` is: text typed into 1Password (a Secure Note's) often ends in a line
/// break, which no header value can carry.
fn op_read(global: &GlobalConfig, r: &str) -> Result<String> {
    let (op_ref, account) = op_parts(r);
    if let Some(a) = &account {
        check_op_account(a)?;
        if !is_op_account_id(a) {
            check_unique_address(a, &op_accounts())?;
        }
    }
    let out = op_run(
        global,
        &["read", "--no-newline", &op_ref],
        account.as_deref(),
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

/// Whether `op` runs as `config.toml`'s service account, which is in one account only.
pub fn op_service_account(global: &GlobalConfig) -> bool {
    global.sources.op.mode.as_deref() == Some("service-account")
}

/// An account added to the 1Password app.
#[derive(Clone, Debug, PartialEq)]
pub struct OpAccount {
    /// Its ID (`account_uuid`), as refs name it: unique, and the same for every member.
    pub id: String,
    /// Its sign-in address, which every individual and family account shares
    /// (`my.1password.com`).
    pub address: String,
    pub email: String,
}

impl OpAccount {
    /// Its address and email, escaped.
    pub fn shown(&self) -> String {
        if self.email.is_empty() {
            return self.address.clone();
        }
        format!("{}, {}", self.address, display(&self.email))
    }
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
    parse_op_accounts(&out.stdout)
}

/// `op account list --format json`, less the accounts whose address or ID `--account` couldn't
/// take.
fn parse_op_accounts(json: &[u8]) -> Vec<OpAccount> {
    let list: Vec<serde_json::Value> = serde_json::from_slice(json).unwrap_or_default();
    list.iter()
        .filter_map(|a| {
            let url = a["url"].as_str()?;
            let address = url.strip_prefix("https://").unwrap_or(url);
            let id = a["account_uuid"].as_str()?;
            check_op_account(address).ok()?;
            if !is_op_account_id(id) {
                return None;
            }
            Some(OpAccount {
                id: id.to_string(),
                address: address.to_string(),
                email: a["email"].as_str().unwrap_or_default().to_string(),
            })
        })
        .collect()
}

/// The account ID an `op://` ref names, if it names one by ID.
fn op_account_id(r: &str) -> Option<String> {
    if !r.starts_with("op://") {
        return None;
    }
    op_parts(r).1.filter(|a| is_op_account_id(a))
}

/// `r` as luoto shows it, escaped: the account its `account=<ID>` names follows it as its
/// address and email, when `accounts` has it.
fn describe_ref(r: &str, accounts: &[OpAccount]) -> String {
    let shown = display(r);
    match op_account_id(r).and_then(|id| accounts.iter().find(|a| a.id == id)) {
        Some(a) => format!("{shown} ({})", a.shown()),
        None => shown,
    }
}

/// [`describe_ref`] with the accounts in the 1Password app, asked once, and only for a ref
/// that names one.
pub fn shown_ref(r: &str) -> String {
    static ACCOUNTS: OnceLock<Vec<OpAccount>> = OnceLock::new();
    if op_account_id(r).is_none() {
        return display(r);
    }
    describe_ref(r, ACCOUNTS.get_or_init(op_accounts))
}

/// A 1Password vault: its ID, as refs name it, and its name, written by whoever made it.
#[derive(Clone, Debug, PartialEq)]
pub struct OpVault {
    pub id: String,
    pub name: String,
}

/// An item as `op item list` gives it: an overview, which holds no field values.
#[derive(Clone, Debug, PartialEq)]
pub struct OpItem {
    pub id: String,
    pub title: String,
    pub category: String,
}

impl OpItem {
    /// "title (kind)", escaped: in a shared vault, other people write the titles.
    pub fn shown(&self) -> String {
        display(&format!("{} ({})", self.title, op_kind(&self.category)))
    }
}

/// `s` when it is a 1Password ID: letters and digits, safe as a ref's segment or an argument.
fn op_id(s: &str) -> Option<String> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())).then(|| s.to_string())
}

/// The vaults `account` (or the default one) can see, by name.
pub fn op_vaults(global: &GlobalConfig, account: Option<&str>) -> Result<Vec<OpVault>> {
    let out = op_run(
        global,
        &["vault", "list", "--format", "json"],
        account,
        "op vault list",
        None,
    )?;
    parse_op_vaults(&out)
}

fn parse_op_vaults(json: &[u8]) -> Result<Vec<OpVault>> {
    let list: Vec<serde_json::Value> =
        serde_json::from_slice(json).context("op vault list: unexpected output")?;
    let mut vaults: Vec<OpVault> = list
        .iter()
        .filter_map(|v| {
            Some(OpVault {
                id: op_id(v["id"].as_str()?)?,
                name: v["name"].as_str()?.to_string(),
            })
        })
        .collect();
    vaults.sort_by_cached_key(|v| (v.name.to_lowercase(), v.id.clone()));
    Ok(vaults)
}

/// The items in vault `vault` (an ID) of `account` (or the default one), by title.
pub fn op_items(global: &GlobalConfig, account: Option<&str>, vault: &str) -> Result<Vec<OpItem>> {
    let vault = op_id(vault).context("a 1Password vault ID is letters and digits")?;
    let out = op_run(
        global,
        &["item", "list", "--vault", &vault, "--format", "json"],
        account,
        "op item list",
        None,
    )?;
    parse_op_items(&out)
}

fn parse_op_items(json: &[u8]) -> Result<Vec<OpItem>> {
    let list: Vec<serde_json::Value> =
        serde_json::from_slice(json).context("op item list: unexpected output")?;
    let mut items: Vec<OpItem> = list
        .iter()
        .filter_map(|i| {
            Some(OpItem {
                id: op_id(i["id"].as_str()?)?,
                title: i["title"].as_str().unwrap_or_default().to_string(),
                category: i["category"].as_str().unwrap_or_default().to_string(),
            })
        })
        .collect();
    items.sort_by_cached_key(|i| (i.title.to_lowercase(), i.id.clone()));
    Ok(items)
}

/// What 1Password calls items of `category`.
pub fn op_kind(category: &str) -> String {
    match category {
        "LOGIN" => "Login".into(),
        "PASSWORD" => "Password".into(),
        "DATABASE" => "Database".into(),
        "API_CREDENTIAL" => "API Credential".into(),
        "SECURE_NOTE" => "Secure Note".into(),
        "SSH_KEY" => "SSH Key".into(),
        "SERVER" => "Server".into(),
        "EMAIL_ACCOUNT" => "Email Account".into(),
        "WIRELESS_ROUTER" => "Wireless Router".into(),
        "CUSTOM" => "Custom".into(),
        c => c.to_lowercase().replace('_', " "),
    }
}

/// The fields of an item of `category` that can hold a secret, as `op item template get`
/// lists them for that kind (op 2.42), the concealed ones first; taken from the templates once
/// so that browsing asks 1Password for nothing but the vault and item lists. Fields an item
/// adds of its own are typed.
pub fn op_kind_fields(category: &str) -> &'static [&'static str] {
    match category {
        "LOGIN" => &["password", "username", "notesPlain"],
        "PASSWORD" => &["password", "notesPlain"],
        "API_CREDENTIAL" => &["credential", "username", "hostname", "notesPlain"],
        "SECURE_NOTE" => &["notesPlain"],
        "SSH_KEY" => &["private key", "notesPlain"],
        "DATABASE" => &["password", "username", "server", "database", "notesPlain"],
        "SERVER" => &["password", "username", "URL", "notesPlain"],
        "EMAIL_ACCOUNT" => &["password", "username", "server", "notesPlain"],
        "WIRELESS_ROUTER" => &[
            "wireless network password",
            "base station password",
            "attached storage password",
            "notesPlain",
        ],
        "CUSTOM" => &["password", "recovery phrase", "notesPlain"],
        _ => &["notesPlain"],
    }
}

/// The field an item of `category` keeps its secret in.
pub fn op_field(category: &str) -> Option<&'static str> {
    match category {
        "LOGIN" | "PASSWORD" | "DATABASE" => Some("password"),
        "API_CREDENTIAL" => Some("credential"),
        "SECURE_NOTE" => Some("notesPlain"),
        "SSH_KEY" => Some("private key"),
        "SERVER" | "EMAIL_ACCOUNT" | "CUSTOM" => Some("password"),
        "WIRELESS_ROUTER" => Some("wireless network password"),
        _ => None,
    }
}

/// A field name as a ref's last segment, where `/`, `?`, `&` or `=` would change what the ref
/// names.
pub fn check_op_field(field: &str) -> Result<()> {
    if field.is_empty() {
        bail!("name the field");
    }
    if let Some(c) = field
        .chars()
        .find(|c| "/?&=".contains(*c) || c.is_control() || crate::text::is_format(*c))
    {
        bail!("a field name here can't hold {c:?}");
    }
    Ok(())
}

/// The ref to `field` of `item` in vault `vault` (an ID), from `account` when given. It names
/// the vault and item by ID: a name may hold `/`, `?` or `=`, and a rename leaves the ref
/// working. An SSH key's private key is read in OpenSSH format, as `[credentials.ssh]` takes it.
pub fn op_item_ref(
    account: Option<&str>,
    vault: &str,
    item: &OpItem,
    field: &str,
) -> Result<String> {
    check_op_field(field)?;
    let (Some(vault), Some(id)) = (op_id(vault), op_id(&item.id)) else {
        bail!("a 1Password vault or item ID is letters and digits");
    };
    let mut r = format!("op://{vault}/{id}/{field}");
    if item.category == "SSH_KEY" && field == "private key" {
        r.push_str("?ssh-format=openssh");
    }
    Ok(match account {
        Some(a) => {
            check_op_account(a)?;
            op_with_account(&r, a)
        }
        None => r,
    })
}

/// Save `secret` as a new API Credential item in vault `vault` (an ID) of `account`, or the
/// default one, and return its `op://` reference. The secret reaches `op` on stdin, never in
/// its arguments.
pub fn op_save(
    global: &GlobalConfig,
    account: Option<&str>,
    vault: &str,
    title: &str,
    secret: &str,
    note: &str,
) -> Result<String> {
    let vault = op_id(vault).context("a 1Password vault ID is letters and digits")?;
    let item = serde_json::json!({
        "title": title,
        "category": "API_CREDENTIAL",
        "fields": [
            {"id": "credential", "type": "CONCEALED", "label": "credential", "value": secret},
            {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain", "value": note},
        ],
    });
    let out = op_run(
        global,
        &["item", "create", "--vault", &vault, "--format", "json", "-"],
        account,
        "op item create",
        Some(&serde_json::to_vec(&item)?),
    )?;
    let created: serde_json::Value =
        serde_json::from_slice(&out).context("op item create: unexpected output")?;
    let created = OpItem {
        id: created["id"]
            .as_str()
            .context("op item create: no item id")?
            .to_string(),
        title: title.to_string(),
        category: "API_CREDENTIAL".to_string(),
    };
    op_item_ref(account, &vault, &created, "credential")
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
    fn each_kind_offers_its_secret_field_first_and_every_field_fits_a_ref() {
        for kind in [
            "LOGIN",
            "PASSWORD",
            "API_CREDENTIAL",
            "SECURE_NOTE",
            "SSH_KEY",
            "DATABASE",
            "SERVER",
            "EMAIL_ACCOUNT",
            "WIRELESS_ROUTER",
            "CUSTOM",
            "IDENTITY",
        ] {
            let fields = op_kind_fields(kind);
            assert!(!fields.is_empty(), "{kind}");
            if let Some(d) = op_field(kind) {
                assert_eq!(fields[0], d, "{kind}");
            }
            for f in fields {
                check_op_field(f).unwrap();
            }
        }
    }

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
        for good in [ACME, "my.1password.com", "acme"] {
            let r = format!("op://v/i/f?account={good}");
            assert!(check_ref(&r).is_ok(), "{r}");
        }
        for bad in ["", "-x", "a b", "a;b", "a$(id)", "A\u{1b}[2J"] {
            let r = format!("op://v/i/f?account={bad}");
            assert!(check_ref(&r).is_err(), "{r}");
        }
        let e = check_ref("op://v/i/f?account=A\u{1b}[2J").unwrap_err();
        assert!(!e.to_string().contains('\u{1b}'), "{e}");
    }

    const ACME: &str = "ZK4ONHBXKRHVBDDVX4L7QTCSDM";
    const MINE: &str = "VZ7CWAKJKFHWVHZ3UFZQ5GPNSU";
    const FAMILY: &str = "Q3RTX2UJWVE2TMXFPN6HVOIB3Y";

    /// `op account list --format json` from op 2.42, with a family account beside a personal
    /// one at the same address, and entries `--account` couldn't take.
    const ACCOUNTS: &str = r#"[
      {"url": "acme.1password.com", "email": "you@acme.example",
       "user_uuid": "BBWGBN7ZFNDRVPRPBXWNXTNC4Q", "account_uuid": "ZK4ONHBXKRHVBDDVX4L7QTCSDM"},
      {"url": "my.1password.com", "email": "you@example.com",
       "user_uuid": "XUQJRY5W7NC7BHG2QKVZ6JPF2A", "account_uuid": "VZ7CWAKJKFHWVHZ3UFZQ5GPNSU"},
      {"url": "my.1password.com", "email": "you\u001b[31m@example.com",
       "user_uuid": "M3C6JSF2PBBN5KQ3AIQPPLC6HU", "account_uuid": "Q3RTX2UJWVE2TMXFPN6HVOIB3Y"},
      {"url": "-evil.1password.com", "email": "x@example.com",
       "user_uuid": "AAAA", "account_uuid": "AAAAAAAAAAAAAAAAAAAAAAAAAA"},
      {"url": "ok.1password.com", "email": "x@example.com",
       "user_uuid": "AAAA", "account_uuid": "not-an-id"}
    ]"#;

    #[test]
    fn accounts_parse_from_op_account_list() {
        let accounts = parse_op_accounts(ACCOUNTS.as_bytes());
        let ids: Vec<&str> = accounts.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, [ACME, MINE, FAMILY]);
        assert_eq!(accounts[0].address, "acme.1password.com");
        assert_eq!(accounts[0].shown(), "acme.1password.com, you@acme.example");
        assert_eq!(
            accounts[2].shown(),
            "my.1password.com, you\\u{1b}[31m@example.com"
        );
        let https = r#"[{"url": "https://acme.1password.com", "email": "",
                         "account_uuid": "ZK4ONHBXKRHVBDDVX4L7QTCSDM"}]"#;
        let a = &parse_op_accounts(https.as_bytes())[0];
        assert_eq!(
            (a.address.as_str(), a.shown()),
            ("acme.1password.com", a.address.clone())
        );
        assert!(parse_op_accounts(b"not json").is_empty());
    }

    #[test]
    fn a_sign_in_address_two_accounts_share_names_neither() {
        let accounts = parse_op_accounts(ACCOUNTS.as_bytes());
        for unique in [
            "acme.1password.com",
            "https://ACME.1password.com/",
            "acme",
            "nowhere.com",
        ] {
            assert!(check_unique_address(unique, &accounts).is_ok(), "{unique}");
        }
        for shared in ["my.1password.com", "https://my.1password.com"] {
            let e = check_unique_address(shared, &accounts)
                .unwrap_err()
                .to_string();
            assert!(e.contains(MINE) && e.contains(FAMILY), "{e}");
            assert!(
                e.contains("you@example.com") && !e.contains('\u{1b}'),
                "{e}"
            );
            assert!(!e.contains(ACME), "{e}");
        }
        assert!(is_op_account_id(MINE));
        for not_id in ["my.1password.com", "acme", "", "VZ7C-WAKJ"] {
            assert!(!is_op_account_id(not_id), "{not_id}");
        }
    }

    #[test]
    fn a_ref_shows_the_account_its_id_names() {
        let accounts = parse_op_accounts(ACCOUNTS.as_bytes());
        assert_eq!(
            describe_ref(&format!("op://v/i/f?account={ACME}"), &accounts),
            format!("op://v/i/f?account={ACME} (acme.1password.com, you@acme.example)")
        );
        assert_eq!(
            describe_ref(
                &format!("op://v/k/private key?ssh-format=openssh&account={FAMILY}"),
                &accounts
            ),
            format!(
                "op://v/k/private key?ssh-format=openssh&account={FAMILY} \
                 (my.1password.com, you\\u{{1b}}[31m@example.com)"
            )
        );
        for plain in [
            "op://v/i/f".to_string(),
            "op://v/i/f?account=acme.1password.com".to_string(),
            "op://v/i/f?account=AAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            format!("keyring:luoto/x?account={ACME}"),
        ] {
            assert_eq!(describe_ref(&plain, &accounts), plain);
            assert_eq!(op_account_id(&plain).is_some(), plain.contains("=AAAA"));
        }
        assert_eq!(describe_ref("env:A\u{1b}[2J", &accounts), "env:A\\u{1b}[2J");
        // No `op` call for a ref that names no account.
        assert_eq!(shown_ref("op://v/i/f"), "op://v/i/f");
    }

    #[test]
    fn vaults_and_items_parse_from_their_listings() {
        let vaults = parse_op_vaults(
            br#"[
              {"id": "pqk3bxlnmi2adlfmzdp4syqxuu", "name": "Shared/Team?account=x",
               "content_version": 41, "created_at": "2024-01-02T10:00:00Z",
               "updated_at": "2026-10-01T10:00:00Z", "items": 12},
              {"id": "c6zqyv4ylr5gcz6t3tfjg6mbea", "name": "private", "content_version": 7},
              {"id": "../x", "name": "Bad id"},
              {"name": "No id"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            vaults,
            [
                OpVault {
                    id: "c6zqyv4ylr5gcz6t3tfjg6mbea".into(),
                    name: "private".into()
                },
                OpVault {
                    id: "pqk3bxlnmi2adlfmzdp4syqxuu".into(),
                    name: "Shared/Team?account=x".into()
                },
            ]
        );
        assert!(parse_op_vaults(b"[Error] not signed in").is_err());

        let items = parse_op_items(
            br#"[
              {"id": "w4mbq7hcm5b3xdhdajxxlwmj2a", "title": "zeta", "version": 2,
               "vault": {"id": "pqk3bxlnmi2adlfmzdp4syqxuu", "name": "Shared"},
               "category": "LOGIN", "last_edited_by": "BBWGBN7ZFNDRVPRPBXWNXTNC4Q",
               "created_at": "2025-03-04T10:00:00Z", "updated_at": "2026-10-01T10:00:00Z",
               "additional_information": "you", "urls": [{"primary": true, "href": "https://x"}]},
              {"id": "kqv5r2c6e4gq7ttnb2xmv4gm3q", "title": "Alpha\u001b]0;pwned\u0007/../x?account=EVIL",
               "category": "API_CREDENTIAL"},
              {"id": "zx3oyh4ffljsbcmgbxv7gaxnoy", "title": "deploy key", "category": "SSH_KEY"},
              {"id": "a/b", "title": "bad id", "category": "LOGIN"}
            ]"#,
        )
        .unwrap();
        let titles: Vec<&str> = items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Alpha\u{1b}]0;pwned\u{7}/../x?account=EVIL",
                "deploy key",
                "zeta"
            ]
        );
        assert_eq!(
            items[0].shown(),
            "Alpha\\u{1b}]0;pwned\\u{7}/../x?account=EVIL (API Credential)"
        );
        assert_eq!(items[1].shown(), "deploy key (SSH Key)");
        assert_eq!(items[2].shown(), "zeta (Login)");
    }

    #[test]
    fn an_items_kind_names_its_secrets_field() {
        for (category, field) in [
            ("LOGIN", Some("password")),
            ("PASSWORD", Some("password")),
            ("DATABASE", Some("password")),
            ("API_CREDENTIAL", Some("credential")),
            ("SECURE_NOTE", Some("notesPlain")),
            ("SSH_KEY", Some("private key")),
            ("CREDIT_CARD", None),
            ("", None),
        ] {
            assert_eq!(op_field(category), field, "{category}");
        }
        assert_eq!(op_kind("CREDIT_CARD"), "credit card");
    }

    #[test]
    fn a_browsed_ref_names_vault_and_item_by_id() {
        let vault = "pqk3bxlnmi2adlfmzdp4syqxuu";
        let item = |category: &str| OpItem {
            id: "kqv5r2c6e4gq7ttnb2xmv4gm3q".into(),
            title: "a/b?account=EVIL&x=y".into(),
            category: category.into(),
        };
        assert_eq!(
            op_item_ref(None, vault, &item("API_CREDENTIAL"), "credential").unwrap(),
            "op://pqk3bxlnmi2adlfmzdp4syqxuu/kqv5r2c6e4gq7ttnb2xmv4gm3q/credential"
        );
        let ssh = op_item_ref(Some(MINE), vault, &item("SSH_KEY"), "private key").unwrap();
        assert_eq!(
            ssh,
            format!(
                "op://pqk3bxlnmi2adlfmzdp4syqxuu/kqv5r2c6e4gq7ttnb2xmv4gm3q/private key\
                 ?ssh-format=openssh&account={MINE}"
            )
        );
        assert_eq!(
            op_parts(&ssh),
            (
                "op://pqk3bxlnmi2adlfmzdp4syqxuu/kqv5r2c6e4gq7ttnb2xmv4gm3q/private key\
                 ?ssh-format=openssh"
                    .into(),
                Some(MINE.into())
            )
        );
        assert!(check_ref(&ssh).is_ok());
        // Another field of an SSH key is read as it is.
        assert!(
            op_item_ref(None, vault, &item("SSH_KEY"), "public key")
                .unwrap()
                .ends_with("/public key")
        );
        for field in [
            "",
            "a/b",
            "f?account=x",
            "a&b",
            "a=b",
            "a\u{1b}b",
            "a\u{202e}b",
        ] {
            assert!(check_op_field(field).is_err(), "{field:?}");
            assert!(op_item_ref(None, vault, &item("LOGIN"), field).is_err());
        }
        assert!(check_op_field("one-time password").is_ok());
        let hostile = OpItem {
            id: "x/y".into(),
            ..item("LOGIN")
        };
        assert!(op_item_ref(None, vault, &hostile, "password").is_err());
        assert!(op_item_ref(None, "../v", &item("LOGIN"), "password").is_err());
        assert!(op_item_ref(Some("-x"), vault, &item("LOGIN"), "password").is_err());
    }

    #[test]
    fn op_signin_sessions_are_read_in_any_shells_syntax() {
        let sh = "# This command is meant to be used with your shell's eval function.\n\
                  export OP_SESSION_ABC123DEF=\"tok-EN_1.x\"\n";
        let fish = "set -x OP_SESSION_ABC123DEF \"tok-EN_1.x\";\n";
        let ps = "$env:OP_SESSION_ABC123DEF=\"tok-EN_1.x\"\n";
        for out in [sh, fish, ps] {
            assert_eq!(
                op_sessions(out),
                [("OP_SESSION_ABC123DEF".to_string(), "tok-EN_1.x".to_string())],
                "{out}"
            );
        }
        // Nothing but a plain name and token: the value reaches a child's environment.
        for out in [
            "",
            "export OP_SESSION_=\"t\"",
            "export OP_SESSION_X=\"\"",
            "export OP_SESSION_X=\"a b\"",
            "export OP_SESSION_X=\"$(id)\"",
            "export OP_SESSION_X=unquoted",
        ] {
            assert!(op_sessions(out).is_empty(), "{out}");
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
