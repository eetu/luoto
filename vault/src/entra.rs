//! Microsoft Entra ID tokens for a service principal (`[credentials.azure]` with a
//! `client_id`), by the client-credentials flow. The client secret never leaves the vault, and
//! the one host the vault reaches for these is login.microsoftonline.com.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeDelta, Utc};
use luoto_shared::azure_identity::{LOGIN_HOST, tenant_ok};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::upstream;

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Zeroizing<String>,
    /// Seconds; a number from the v2.0 endpoint, a string from some others.
    expires_in: serde_json::Value,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

/// Where tokens are minted: Entra ID, or the integration tests' server.
fn login_base() -> String {
    #[cfg(feature = "test-hooks")]
    if let Ok(base) = std::env::var("LUOTO_TEST_AZURE_LOGIN") {
        return base;
    }
    format!("https://{LOGIN_HOST}")
}

/// A token for `audience` as service principal `client_id` of `tenant`, and when it expires.
pub async fn client_credentials(
    tls: &Arc<rustls::ClientConfig>,
    tenant: &str,
    client_id: &str,
    secret: &str,
    audience: &str,
) -> Result<(Zeroizing<String>, DateTime<Utc>)> {
    // It becomes a path segment of the request.
    if !tenant_ok(tenant) {
        bail!("tenant `{tenant}` is not a tenant ID or domain");
    }
    let url = format!("{}/{tenant}/oauth2/v2.0/token", login_base());
    let scope = format!("{audience}/.default");
    let body = form(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", secret),
        ("scope", &scope),
    ]);
    let headers = [("accept", "application/json")];
    let (status, text) = upstream::post(
        tls,
        &url,
        &headers,
        "application/x-www-form-urlencoded",
        body,
    )
    .await?;
    if status != 200 {
        // Entra's error names what went wrong (an AADSTS code), never the secret.
        let why = match serde_json::from_str::<ErrorResponse>(&text) {
            Ok(e) => format!("{}: {}", e.error, e.error_description),
            Err(_) => text.as_str().to_string(),
        };
        bail!(
            "Microsoft Entra ID refused the token request ({status}): {}",
            why.chars().take(300).collect::<String>()
        );
    }
    let t: TokenResponse = serde_json::from_str(&text).context("Entra ID token response")?;
    let secs = match &t.expires_in {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .context("Entra ID token response: no expires_in")?;
    Ok((t.access_token, Utc::now() + TimeDelta::seconds(secs)))
}

/// `application/x-www-form-urlencoded` pairs.
fn form(pairs: &[(&str, &str)]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        let enc_k = encode(k);
        let enc_v = encode(v);
        out.push_str(&enc_k);
        out.push('=');
        out.push_str(&enc_v);
    }
    out
}

fn encode(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_form_escapes_everything_a_secret_may_hold() {
        assert_eq!(
            form(&[
                ("client_secret", "a+b/c=d&e f~"),
                ("scope", "https://x/.default")
            ])
            .as_str(),
            "client_secret=a%2Bb%2Fc%3Dd%26e%20f~&scope=https%3A%2F%2Fx%2F.default"
        );
    }
}
