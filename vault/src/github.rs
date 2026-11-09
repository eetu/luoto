//! GitHub App installation tokens, minted per env and restricted to its repositories and
//! permissions. The App private key never leaves the vault.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};

use crate::upstream;

#[derive(Serialize)]
struct Claims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: DateTime<Utc>,
}

pub fn app_jwt(app_id: &str, key_pem: &str) -> Result<String> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        iat: now - 60,
        exp: now + 9 * 60,
        iss: app_id.to_string(),
    };
    let key = EncodingKey::from_rsa_pem(key_pem.as_bytes()).context("GitHub App private key")?;
    encode(&Header::new(Algorithm::RS256), &claims, &key).context("sign GitHub App JWT")
}

pub async fn installation_token(
    tls: &Arc<rustls::ClientConfig>,
    api_base: &str,
    app_id: &str,
    installation_id: u64,
    key_pem: &str,
    repos: &[String],
    permissions: &BTreeMap<String, String>,
) -> Result<(String, DateTime<Utc>)> {
    let jwt = app_jwt(app_id, key_pem)?;
    let body = serde_json::json!({ "repositories": repos, "permissions": permissions });
    let url = format!(
        "{}/app/installations/{installation_id}/access_tokens",
        api_base.trim_end_matches('/')
    );
    let bearer = format!("Bearer {jwt}");
    let headers = [
        ("authorization", bearer.as_str()),
        ("accept", "application/vnd.github+json"),
        ("x-github-api-version", "2022-11-28"),
    ];
    let (status, text) =
        upstream::post(tls, &url, &headers, "application/json", body.to_string()).await?;
    if status != 201 {
        bail!(
            "GitHub refused the token request ({status}): {}",
            text.chars().take(300).collect::<String>()
        );
    }
    let t: TokenResponse = serde_json::from_str(&text).context("GitHub token response")?;
    Ok((t.token, t.expires_at))
}
