//! GitHub App installation tokens, minted per env and restricted to its repositories and
//! permissions. The App private key never leaves the vault.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

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
    let (status, text) = post(tls, &url, &jwt, body.to_string()).await?;
    if status != 201 {
        bail!(
            "GitHub refused the token request ({status}): {}",
            text.chars().take(300).collect::<String>()
        );
    }
    let t: TokenResponse = serde_json::from_str(&text).context("GitHub token response")?;
    Ok((t.token, t.expires_at))
}

async fn post(
    tls: &Arc<rustls::ClientConfig>,
    url: &str,
    bearer: &str,
    body: String,
) -> Result<(u16, String)> {
    let uri: http::Uri = url.parse().context("GitHub API url")?;
    let host = uri
        .host()
        .context("GitHub API url has no host")?
        .to_string();
    let https = uri.scheme_str() != Some("http");
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    #[cfg(not(feature = "test-hooks"))]
    if !https {
        bail!("the GitHub API must be reached over https");
    }
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .context("connect timed out")??;
    let req = http::Request::post(uri.path())
        .header(http::header::HOST, &host)
        .header(http::header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(http::header::ACCEPT, "application/vnd.github+json")
        .header(http::header::USER_AGENT, "luoto-vault")
        .header("x-github-api-version", "2022-11-28")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(bytes::Bytes::from(body)))?;
    let resp = if https {
        let name = ServerName::try_from(host.clone())?;
        let stream = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(name, tcp)
            .await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(conn);
        sender.send_request(req).await?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(conn);
        sender.send_request(req).await?
    };
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}
