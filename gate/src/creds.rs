//! Fetching credentials from luoto-vault and placing them on requests. The gate keeps only
//! short-lived values in memory; root secrets stay in the vault.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use chrono::Utc;
use http::{HeaderName, HeaderValue, Uri, request::Parts};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use luoto_shared::api::AgentMessage;
use luoto_shared::creds::{AgentRequest, CredentialValue, Injection, Placement};
use luoto_shared::ctl::CredentialRequest;
use tokio::net::TcpStream;

use crate::body::full;

/// How long a static value is reused before re-asking the vault (so revocation and
/// `luoto vault lock` take effect quickly).
const STATIC_TTL: Duration = Duration::from_secs(120);
/// Refresh expiring values this long before they expire.
const EXPIRY_MARGIN: chrono::TimeDelta = chrono::TimeDelta::seconds(120);

#[derive(Debug)]
pub enum CredError {
    Locked,
    Unknown(String),
    Unavailable(String),
}

struct Cached {
    value: CredentialValue,
    fetched: Instant,
}

pub struct VaultClient {
    url: String,
    token: String,
    cache: Mutex<HashMap<String, Cached>>,
    /// Bumped by every flush: a fetch that started before one isn't cached after it, so a
    /// changed credential can't come back from a request that was in flight.
    generation: AtomicU64,
}

impl VaultClient {
    pub fn new(url: String, token: String) -> Self {
        VaultClient {
            url,
            token,
            cache: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
        }
    }

    pub fn flush(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        self.generation.fetch_add(1, Ordering::SeqCst);
        cache.clear();
    }

    pub async fn get(&self, binding: &str) -> Result<String, CredError> {
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = cache.get(binding) {
                let fresh = match c.value.expires_at {
                    Some(exp) => exp - Utc::now() > EXPIRY_MARGIN,
                    None => c.fetched.elapsed() < STATIC_TTL,
                };
                if fresh {
                    return Ok(c.value.value.clone());
                }
            }
        }
        let started = self.generation.load(Ordering::SeqCst);
        let value = self.fetch(binding).await?;
        let secret = value.value.clone();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if self.generation.load(Ordering::SeqCst) == started {
            cache.insert(
                binding.to_string(),
                Cached {
                    value,
                    fetched: Instant::now(),
                },
            );
        }
        Ok(secret)
    }

    async fn fetch(&self, binding: &str) -> Result<CredentialValue, CredError> {
        let body = serde_json::to_vec(&CredentialRequest {
            binding: binding.to_string(),
        })
        .unwrap_or_default();
        let (status, bytes) = self.post("/v1/credential", body).await?;
        match status {
            200 => serde_json::from_slice(&bytes)
                .map_err(|e| CredError::Unavailable(format!("bad vault response: {e}"))),
            423 => Err(CredError::Locked),
            403 | 404 => Err(CredError::Unknown(binding.to_string())),
            _ => Err(unavailable(status, &bytes)),
        }
    }

    /// Pass one ssh-agent message to the vault, which holds the env's key under `binding`.
    pub async fn agent(&self, binding: &str, msg: AgentMessage) -> Result<AgentMessage, CredError> {
        let body = serde_json::to_vec(&AgentRequest {
            binding: binding.to_string(),
            message: msg,
        })
        .unwrap_or_default();
        let (status, bytes) = self.post("/v1/ssh-agent", body).await?;
        match status {
            200 => serde_json::from_slice(&bytes)
                .map_err(|e| CredError::Unavailable(format!("bad vault response: {e}"))),
            423 => Err(CredError::Locked),
            403 | 404 => Err(CredError::Unknown(binding.to_string())),
            _ => Err(unavailable(status, &bytes)),
        }
    }

    async fn post(&self, path: &str, body: Vec<u8>) -> Result<(u16, bytes::Bytes), CredError> {
        let uri: Uri = format!("{}{path}", self.url.trim_end_matches('/'))
            .parse()
            .map_err(|e| CredError::Unavailable(format!("bad vault url: {e}")))?;
        let authority = uri
            .authority()
            .ok_or_else(|| CredError::Unavailable("vault url has no host".into()))?
            .to_string();
        let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&authority))
            .await
            .map_err(|_| CredError::Unavailable("vault connect timed out".into()))?
            .map_err(|e| CredError::Unavailable(format!("vault unreachable: {e}")))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| CredError::Unavailable(e.to_string()))?;
        tokio::spawn(conn);
        let req = http::Request::post(uri.path())
            .header(http::header::HOST, authority)
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", self.token),
            )
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full(body))
            .map_err(|e| CredError::Unavailable(e.to_string()))?;
        let resp = tokio::time::timeout(Duration::from_secs(20), sender.send_request(req))
            .await
            .map_err(|_| CredError::Unavailable("vault request timed out".into()))?
            .map_err(|e| CredError::Unavailable(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| CredError::Unavailable(e.to_string()))?
            .to_bytes();
        Ok((status, bytes))
    }
}

fn unavailable(status: u16, body: &[u8]) -> CredError {
    CredError::Unavailable(format!(
        "vault returned {status}: {}",
        String::from_utf8_lossy(body)
            .chars()
            .take(200)
            .collect::<String>()
    ))
}

/// Place `secret` on the request as the injection says.
pub fn apply(parts: &mut Parts, inj: &Injection, secret: &str) -> Result<(), String> {
    match &inj.place {
        Placement::Header { name, format } => {
            let name = HeaderName::try_from(name.as_str()).map_err(|e| e.to_string())?;
            let mut value = HeaderValue::from_str(&format.replace("{secret}", secret))
                .map_err(|_| "credential is not a valid header value".to_string())?;
            value.set_sensitive(true);
            parts.headers.insert(name, value);
        }
        Placement::Basic { username } => {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
            let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
                .map_err(|_| "credential is not a valid header value".to_string())?;
            value.set_sensitive(true);
            parts.headers.insert(http::header::AUTHORIZATION, value);
        }
        Placement::Query { param } => {
            let path = parts.uri.path().to_string();
            let mut pairs: Vec<String> = parts
                .uri
                .query()
                .unwrap_or("")
                .split('&')
                .filter(|kv| !kv.is_empty())
                .filter(|kv| kv.split('=').next() != Some(param.as_str()))
                .map(str::to_string)
                .collect();
            pairs.push(format!("{param}={}", urlencode(secret)));
            parts.uri = format!("{path}?{}", pairs.join("&"))
                .parse()
                .map_err(|e: http::uri::InvalidUri| e.to_string())?;
        }
    }
    Ok(())
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(uri: &str) -> Parts {
        http::Request::get(uri).body(()).unwrap().into_parts().0
    }

    #[test]
    fn header_basic_and_query_placements() {
        let mut p = parts("/v1/messages");
        let inj = Injection {
            binding: "a".into(),
            host: "api.anthropic.com".into(),
            paths: vec![],
            ignore_case: false,
            place: Placement::Header {
                name: "x-api-key".into(),
                format: "{secret}".into(),
            },
        };
        apply(&mut p, &inj, "sk-real").unwrap();
        assert_eq!(p.headers["x-api-key"], "sk-real");

        let mut p = parts("/o/r.git/info/refs?service=git-receive-pack");
        let inj = Injection {
            binding: "g".into(),
            host: "github.com".into(),
            paths: vec![],
            ignore_case: false,
            place: Placement::Basic {
                username: "x-access-token".into(),
            },
        };
        apply(&mut p, &inj, "ghs_x").unwrap();
        assert!(
            p.headers["authorization"]
                .to_str()
                .unwrap()
                .starts_with("Basic ")
        );

        let mut p = parts("/v1beta/models?key=PLACEHOLDER&alt=sse");
        let inj = Injection {
            binding: "gem".into(),
            host: "generativelanguage.googleapis.com".into(),
            paths: vec![],
            ignore_case: false,
            place: Placement::Query {
                param: "key".into(),
            },
        };
        apply(&mut p, &inj, "AIza real").unwrap();
        assert_eq!(p.uri.query(), Some("alt=sse&key=AIza%20real"));
    }
}
