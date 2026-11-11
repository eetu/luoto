//! `[credentials.azure]` on the host: what it may name, the `azcli:` secret refs that read a
//! token from this machine's Azure CLI, and logging the env's own `az` in to the managed
//! identity the gate answers for.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Utc};
use luoto_shared::azure_identity::{
    Audience, is_guid, key_vault_name_ok, storage_account_ok, tenant_ok,
};
use serde::Deserialize;

use crate::config::AzureCred;
use crate::env::{Ctx, UID};
use crate::text::display;
use crate::{connect, names};

/// The secret ref scheme for a token from this machine's `az` login.
pub const AZCLI: &str = "azcli:";

/// How long `az account get-access-token` may run before it is killed. It answers from its
/// cache in a second or two (Python starting), or after one refresh at Entra ID; 30 s leaves
/// room for a slow network, and is the longest `up`, or the watcher's one loop (port forwards,
/// notifications, idle stops), waits on an `az` that hangs (a stuck proxy, a prompt).
const AZ_TIMEOUT: Duration = Duration::from_secs(30);

/// The tenant (`tid`) of the token last read for each ref in this process.
static TENANTS: Mutex<BTreeMap<String, String>> = Mutex::new(BTreeMap::new());

/// Why `c` is refused, if it is.
pub fn check(c: &AzureCred) -> Result<()> {
    if c.subscriptions.is_empty() {
        bail!(
            "credentials.azure: list the subscriptions the env may reach \
             (`subscriptions = [\"<subscription id>\"]`)"
        );
    }
    if let Some(s) = c.subscriptions.iter().find(|s| !is_guid(s)) {
        bail!(
            "credentials.azure: `{}` is not a subscription ID",
            display(s)
        );
    }
    if let Some(t) = c.tenant.as_deref().filter(|t| !tenant_ok(t)) {
        bail!(
            "credentials.azure: tenant `{}` is not a tenant ID or domain",
            display(t)
        );
    }
    if let Some(n) = c.key_vaults.iter().find(|n| !key_vault_name_ok(n)) {
        bail!(
            "credentials.azure: `{}` is not a key vault name (3-24 letters, digits and single \
             hyphens: the name, not its URL)",
            display(n)
        );
    }
    if let Some(n) = c.storage_accounts.iter().find(|n| !storage_account_ok(n)) {
        bail!(
            "credentials.azure: `{}` is not a storage account name (3-24 lower-case letters \
             and digits: the name, not its URL)",
            display(n)
        );
    }
    match (&c.client_id, &c.client_secret) {
        (Some(id), Some(_)) => {
            if !is_guid(id) {
                bail!(
                    "credentials.azure: client_id `{}` is not an application ID",
                    display(id)
                );
            }
            if c.tenant.is_none() {
                bail!("credentials.azure: a service principal (client_id) needs `tenant`");
            }
        }
        (Some(_), None) => {
            bail!("credentials.azure: client_id needs client_secret (a secret ref)")
        }
        (None, Some(_)) => bail!("credentials.azure: client_secret goes with client_id"),
        (None, None) => {}
    }
    Ok(())
}

/// The `azcli:` ref for a token for `aud`, in `tenant` or `az`'s current one.
pub fn azcli_ref(aud: Audience, tenant: Option<&str>) -> String {
    match tenant {
        Some(t) => format!("{AZCLI}{}?tenant={t}", aud.resource()),
        None => format!("{AZCLI}{}", aud.resource()),
    }
}

/// The resource and tenant an `azcli:` ref asks `az` for.
pub fn parse_ref(r: &str) -> Result<(&str, Option<&str>)> {
    let rest = r.strip_prefix(AZCLI).unwrap_or(r);
    let (resource, tenant) = match rest.split_once("?tenant=") {
        Some((resource, t)) => (resource, Some(t)),
        None => (rest, None),
    };
    let plain = |s: &str| !s.contains(|c: char| c.is_whitespace() || c.is_control() || c == '?');
    if !resource.starts_with("https://") || !plain(resource) {
        bail!("`azcli:` refs are azcli:<resource URL>, or azcli:<resource URL>?tenant=<tenant>");
    }
    if let Some(t) = tenant.filter(|t| !tenant_ok(t)) {
        bail!("`{}` is not a tenant ID or domain", display(t));
    }
    Ok((resource, tenant))
}

/// A token for ref `r` from this machine's Azure CLI, and when it expires if that is known.
pub fn read(r: &str) -> Result<(String, Option<DateTime<Utc>>)> {
    let (resource, tenant) = parse_ref(r)?;
    let mut cmd = Command::new(if cfg!(windows) { "az.cmd" } else { "az" });
    cmd.args([
        "account",
        "get-access-token",
        "--resource",
        resource,
        "--output",
        "json",
    ]);
    if let Some(t) = tenant {
        cmd.args(["--tenant", t]);
    }
    let out = match output_within(cmd, AZ_TIMEOUT) {
        Ok(Some(out)) => out,
        Ok(None) => bail!(
            "az account get-access-token gave no answer within {} s and was stopped",
            AZ_TIMEOUT.as_secs()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "the Azure CLI (`az`) is not installed on this machine: install it and run \
             `az login`, or give [credentials.azure] a service principal (client_id, \
             client_secret)"
        ),
        Err(e) => return Err(e).context("run the Azure CLI (`az`)"),
    };
    if !out.status.success() {
        let full = String::from_utf8_lossy(&out.stderr);
        if let Some(why) = login_needed(&full) {
            // `az login --identity` in the env asks the gate for this token.
            if resource.contains("management.azure.com") {
                LOGIN_NEEDED.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            bail!(
                "the Azure CLI's login on this machine {why}: run `az login{}` there{}",
                tenant.map(|t| format!(" --tenant {t}")).unwrap_or_default(),
                aad_reason(&full)
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default()
            );
        }
        let err: String = full.trim().chars().take(300).collect();
        bail!("az account get-access-token failed: {err}");
    }
    let (token, expires) = parse_output(&out.stdout)?;
    remember_tenant(r, &token);
    Ok((token, expires))
}

/// An `az` login on this machine failed for want of the user: in-env logins that would only
/// fail the same way are skipped.
static LOGIN_NEEDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Why `az`'s error asks for a new `az login`, if it does: an expired or revoked refresh
/// token, a sign-in that wants the user again (MFA, consent), or none at all.
fn login_needed(err: &str) -> Option<&'static str> {
    const EXPIRED: [&str; 4] = ["AADSTS700082", "AADSTS70043", "AADSTS50173", "AADSTS700084"];
    if EXPIRED.iter().any(|c| err.contains(c)) || err.contains("refresh token has expired") {
        Some("has expired")
    } else if err.contains("AADSTS50076")
        || err.contains("AADSTS50078")
        || err.contains("AADSTS65001")
        || err.contains("interaction_required")
    {
        Some("needs you to sign in again")
    } else if err.contains("AADSTS") {
        // az appends "run az login" to every AAD error: another code is no login of yours.
        None
    } else if err.contains("az login") {
        Some("is missing")
    } else {
        None
    }
}

/// Forget an earlier command's failed login: the user may have logged in since (`luoto ui`
/// lives on).
pub fn forget_login_needed() {
    LOGIN_NEEDED.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// The AADSTS code in `err` and its first sentence: `AADSTS700082: The refresh token has
/// expired due to inactivity.`
fn aad_reason(err: &str) -> Option<String> {
    let at = err.find("AADSTS")?;
    let rest = &err[at..];
    let end = rest.find(". ").map_or(rest.len(), |i| i + 1);
    let line = rest[..end].lines().next().unwrap_or_default().trim();
    Some(crate::text::display(line)).filter(|l| !l.is_empty())
}

/// Whether an `az` login on this machine failed for want of the user in this command.
pub fn login_was_needed() -> bool {
    LOGIN_NEEDED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Keep the tenant `token`, read for `r`, is for: its `tid`, when that is a tenant ID.
fn remember_tenant(r: &str, token: &str) {
    if let Some(tid) = claims(token)
        .and_then(|c| c.get("tid")?.as_str().map(str::to_string))
        .filter(|t| is_guid(t))
    {
        TENANTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(r.to_string(), tid);
    }
}

/// The tenant of `az`'s token for ref `r`: the token this process read last, else one read
/// now. Its `tid` claim, unverified: it only names the tenant to tools in the env, while the
/// gate decides where the token goes.
pub fn tenant(r: &str) -> Option<String> {
    let known = |r: &str| {
        TENANTS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(r)
            .cloned()
    };
    known(r).or_else(|| read(r).ok().and_then(|_| known(r)))
}

/// `cmd`'s output, or `None` once it has run for `limit`, when it is killed. Its stdin is
/// empty, so it can't wait on a prompt.
fn output_within(mut cmd: Command, limit: Duration) -> std::io::Result<Option<Output>> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Each pipe is read on its own thread, so one filling up can't stall the process.
    let drain = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut out);
            }
            out
        })
    };
    let stdout = drain(child.stdout.take().map(|p| Box::new(p) as _));
    let stderr = drain(child.stderr.take().map(|p| Box::new(p) as _));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // A process it started may still hold the pipes: their threads are left to end
            // with it.
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Ok(Some(Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    }))
}

/// The token in `az account get-access-token`'s JSON and when it expires: `expires_on`
/// (seconds since the epoch, from az 2.54), else the token's own `exp`.
pub fn parse_output(json: &[u8]) -> Result<(String, Option<DateTime<Utc>>)> {
    #[derive(Deserialize)]
    struct Out {
        #[serde(rename = "accessToken")]
        access_token: String,
        #[serde(default)]
        expires_on: Option<i64>,
    }
    // The output holds the token: an error never repeats it.
    let out: Out = serde_json::from_slice(json)
        .map_err(|_| anyhow!("az account get-access-token printed something unexpected"))?;
    if out.access_token.is_empty() {
        bail!("az account get-access-token gave no token");
    }
    let expires = out
        .expires_on
        .and_then(|s| DateTime::from_timestamp(s, 0))
        .or_else(|| token_expiry(&out.access_token));
    Ok((out.access_token, expires))
}

/// When JWT `token` expires, by its `exp` claim.
pub fn token_expiry(token: &str) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(claims(token)?.get("exp")?.as_i64()?, 0)
}

/// The claims of JWT `token`, unverified.
fn claims(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = B64URL.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Log the env's Azure CLI in to the gate's managed identity as the dev user, with the first
/// subscription as its default, when the image has `az`. Best effort: a failure is a note.
pub fn login_in_env(ctx: &Ctx, env: &str, c: &AzureCred) {
    // Its token comes from the login on this machine, whose failure was already said.
    if login_was_needed() {
        return;
    }
    // Checked to be an ID, so a plain shell word.
    let Some(sub) = c.subscriptions.first().filter(|s| is_guid(s)) else {
        return;
    };
    let script = format!(
        "command -v az >/dev/null 2>&1 || exit 0\n\
         az login --identity --output none --only-show-errors && \
         az account set --subscription {sub} --only-show-errors"
    );
    let dev = names::dev(env);
    let run = crate::progress::wait("signing in to Azure in the env", || {
        ctx.rt.run([
            "exec",
            "-u",
            UID,
            dev.as_str(),
            "sh",
            "-c",
            connect::LOGIN,
            &script,
        ])
    });
    if let Err(e) = run {
        eprintln!(
            "note: `az login --identity` failed in `{env}`, so az there is not logged in: {}\n      \
             see docs/guides/azure.md; `luoto up -e {env}` tries again",
            crate::text::lines(&format!("{e:#}"))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expired_az_login_says_so_in_a_line() {
        let err = "ERROR: AADSTS700082: The refresh token has expired due to inactivity. The \
                   token was issued on 2026-07-03T13:13:54Z and was inactive for 90.00:00:00. \
                   Trace ID: dfb4\nRun the command below to authenticate interactively; \
                   additional arguments may be added as needed:\naz login --scope x";
        assert_eq!(login_needed(err), Some("has expired"));
        assert_eq!(
            aad_reason(err).as_deref(),
            Some("AADSTS700082: The refresh token has expired due to inactivity.")
        );
        assert_eq!(
            login_needed("ERROR: Please run 'az login' to setup account."),
            Some("is missing")
        );
        assert_eq!(login_needed("ERROR: (ResourceNotFound) nope"), None);
        // Another AAD error carries the same "az login" advice, and isn't a login to redo.
        let typo = "ERROR: AADSTS500011: The resource principal named https://x was not found. \
                    Run the command below to authenticate interactively:\naz login --scope x";
        assert_eq!(login_needed(typo), None);
    }

    const SUB: &str = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0";
    const APP: &str = "11111111-2222-3333-4444-555555555555";

    fn cred() -> AzureCred {
        toml::from_str(&format!("subscriptions = [\"{SUB}\"]")).unwrap()
    }

    #[test]
    fn a_credential_names_ids_and_azure_names_only() {
        let c = cred();
        assert_eq!(c.access, luoto_shared::policy::AccessLevel::Read);
        check(&c).unwrap();
        let refused = |c: AzureCred, why: &str| {
            let e = check(&c).unwrap_err().to_string();
            assert!(e.contains(why), "{e}");
        };
        refused(
            AzureCred {
                subscriptions: vec![],
                ..cred()
            },
            "list the subscriptions",
        );
        refused(
            AzureCred {
                subscriptions: vec!["prod".into()],
                ..cred()
            },
            "not a subscription ID",
        );
        refused(
            AzureCred {
                key_vaults: vec!["kv.evil.example".into()],
                ..cred()
            },
            "not a key vault name",
        );
        refused(
            AzureCred {
                key_vaults: vec!["*".into()],
                ..cred()
            },
            "not a key vault name",
        );
        refused(
            AzureCred {
                storage_accounts: vec!["acct.blob.core.windows.net".into()],
                ..cred()
            },
            "not a storage account name",
        );
        refused(
            AzureCred {
                tenant: Some("evil.example/x".into()),
                ..cred()
            },
            "not a tenant",
        );
        refused(
            AzureCred {
                client_id: Some(APP.into()),
                ..cred()
            },
            "client_id needs client_secret",
        );
        refused(
            AzureCred {
                client_secret: Some("op://v/i/f".into()),
                ..cred()
            },
            "client_secret goes with client_id",
        );
        refused(
            AzureCred {
                client_id: Some(APP.into()),
                client_secret: Some("op://v/i/f".into()),
                ..cred()
            },
            "needs `tenant`",
        );
        check(&AzureCred {
            client_id: Some(APP.into()),
            client_secret: Some("op://v/i/f".into()),
            tenant: Some("contoso.onmicrosoft.com".into()),
            ..cred()
        })
        .unwrap();
        assert!(toml::from_str::<AzureCred>("subscriptions = []\naccess = \"admin\"").is_err());
        assert!(toml::from_str::<AzureCred>("subscriptions = []\nscope = \"x\"").is_err());
    }

    #[test]
    fn azcli_refs_name_a_resource_and_maybe_a_tenant() {
        let r = azcli_ref(Audience::Arm, None);
        assert_eq!(r, "azcli:https://management.azure.com/");
        assert_eq!(
            parse_ref(&r).unwrap(),
            ("https://management.azure.com/", None)
        );
        let r = azcli_ref(Audience::KeyVault, Some("contoso.onmicrosoft.com"));
        assert_eq!(
            parse_ref(&r).unwrap(),
            ("https://vault.azure.net", Some("contoso.onmicrosoft.com"))
        );
        for bad in [
            "azcli:management.azure.com",
            "azcli:https://x y",
            "azcli:https://x?resource=y",
            "azcli:https://x?tenant=a/b",
            "azcli:--help",
        ] {
            assert!(parse_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_token_comes_from_azs_json_and_never_into_an_error() {
        let claims = B64URL.encode(br#"{"exp":1900000000,"oid":"o"}"#);
        let jwt = format!("eyJhbGciOiJSUzI1NiJ9.{claims}.sig");
        let out = serde_json::json!({
            "accessToken": jwt,
            "expiresOn": "2030-03-17 18:46:40.000000",
            "expires_on": 1_900_000_100,
            "subscription": SUB,
            "tenant": "t",
            "tokenType": "Bearer",
        });
        let (token, exp) = parse_output(out.to_string().as_bytes()).unwrap();
        assert_eq!(token, jwt);
        assert_eq!(exp.unwrap().timestamp(), 1_900_000_100);

        // Before az 2.54 there is no `expires_on`: the token's own `exp` says.
        let old =
            serde_json::json!({"accessToken": jwt, "expiresOn": "2030-03-17 18:46:40.000000"});
        let (_, exp) = parse_output(old.to_string().as_bytes()).unwrap();
        assert_eq!(exp.unwrap().timestamp(), 1_900_000_000);
        assert_eq!(token_expiry(&jwt).unwrap().timestamp(), 1_900_000_000);
        assert_eq!(token_expiry("opaque"), None);

        let e = parse_output(format!("{{\"token\": \"{jwt}\"").as_bytes())
            .unwrap_err()
            .to_string();
        assert!(!e.contains(&jwt), "{e}");
        assert!(parse_output(br#"{"accessToken": ""}"#).is_err());
    }

    #[test]
    fn the_tenant_is_the_tid_of_the_token_read() {
        let jwt = |claims: &str| format!("h.{}.s", B64URL.encode(claims));
        let r = "azcli:https://management.azure.com/?tenant=test.example";
        remember_tenant(r, &jwt(r#"{"tid":"evil' $(x)"}"#));
        remember_tenant(r, "opaque");
        assert!(TENANTS.lock().unwrap().get(r).is_none());
        remember_tenant(r, &jwt(&format!(r#"{{"tid":"{SUB}"}}"#)));
        assert_eq!(tenant(r).as_deref(), Some(SUB));
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_hangs_is_stopped() {
        let started = Instant::now();
        let mut sleep = Command::new("sleep");
        sleep.arg("30");
        assert!(
            output_within(sleep, Duration::from_millis(200))
                .unwrap()
                .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let mut echo = Command::new("sh");
        echo.args(["-c", "echo out; echo err >&2"]);
        let out = output_within(echo, Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
    }
}
