//! The vault's API for gates: one binding's value, or one ssh-agent message, for the env whose
//! channel the request comes on, and only with that env's token.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use luoto_shared::api::{AgentMessage, MAX_AGENT_MESSAGE};
use luoto_shared::creds::{
    AgentRequest, CredentialError, CredentialRequest, VAULT_AGENT_PATH, VAULT_CREDENTIAL_PATH,
};
use luoto_shared::events::{Event, EventKind, Verdict};
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::AbortHandle;

use crate::agent;
use crate::state::Vault;

/// How gates reach the vault.
pub enum Channels {
    /// A socket per bound env, `<dir>/<env>/vault.sock`: each gate mounts only its env's folder.
    PerEnv(EnvSockets),
    /// One socket (Apple's, published to the host), on which each connection names its env in
    /// its first line: luoto's watcher writes it, joining the env's gate to the vault.
    Shared,
}

/// An env name as luoto gives them, and so a safe path segment.
pub fn valid_env(env: &str) -> bool {
    (1..=64).contains(&env.len())
        && env
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A listener on a new socket at `path`, for the vault's own user only: a gate runs as the same
/// uid (65534), and Apple's socket forwarder as root.
pub fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub struct EnvSockets {
    dir: PathBuf,
    served: Mutex<HashMap<String, AbortHandle>>,
}

impl EnvSockets {
    pub fn new(dir: PathBuf) -> Self {
        EnvSockets {
            dir,
            served: Mutex::default(),
        }
    }

    /// Serve `env` on its socket, unless it is served already. Its folder stays once made: a
    /// running gate mounts that folder, and sees a socket made in it again (after a restart).
    pub fn open(&self, vault: &Arc<Vault>, env: &str) -> anyhow::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        let mut served = self.served.lock().unwrap_or_else(|e| e.into_inner());
        if served.get(env).is_some_and(|h| !h.is_finished()) {
            return Ok(());
        }
        let dir = self.dir.join(env);
        std::fs::DirBuilder::new()
            .mode(0o755)
            .recursive(true)
            .create(&dir)
            .with_context(|| format!("create {}", dir.display()))?;
        let listener = bind(&dir.join("vault.sock"))?;
        let task = tokio::spawn(serve_env(vault.clone(), listener, env.to_string()));
        served.insert(env.to_string(), task.abort_handle());
        Ok(())
    }

    /// Stop serving `env` and remove its folder (its gate is gone).
    pub fn close(&self, env: &str) {
        let task = self
            .served
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(env);
        if let Some(t) = task {
            t.abort();
        }
        let dir = self.dir.join(env);
        let _ = std::fs::remove_file(dir.join("vault.sock"));
        let _ = std::fs::remove_dir(dir);
    }
}

async fn serve_env(vault: Arc<Vault>, listener: UnixListener, env: String) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(serve_conn(vault.clone(), stream, env.clone()));
    }
}

/// How long a connection on the shared socket has to name its env.
const NAME_WAIT: Duration = Duration::from_secs(10);

pub async fn serve_shared(vault: Arc<Vault>, listener: UnixListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let v = vault.clone();
        tokio::spawn(async move {
            if let Ok(Some(env)) = tokio::time::timeout(NAME_WAIT, env_line(&mut stream)).await {
                serve_conn(v, stream, env).await;
            }
        });
    }
}

/// The env a connection on the shared socket names, read a byte at a time so that nothing
/// after its line is taken from the HTTP that follows.
async fn env_line(stream: &mut UnixStream) -> Option<String> {
    let mut line = Vec::new();
    loop {
        match stream.read_u8().await.ok()? {
            b'\n' => break,
            b if line.len() < 64 => line.push(b),
            _ => return None,
        }
    }
    String::from_utf8(line).ok().filter(|e| valid_env(e))
}

async fn serve_conn(vault: Arc<Vault>, stream: UnixStream, env: String) {
    let env: Arc<str> = env.into();
    let svc = service_fn(move |req| handle(vault.clone(), env.clone(), req));
    let _ = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), svc)
        .await;
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r
}

async fn handle(
    vault: Arc<Vault>,
    env: Arc<str>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let agent = path == VAULT_AGENT_PATH;
    if req.method() != Method::POST || !(agent || path == VAULT_CREDENTIAL_PATH) {
        return Ok(reply(StatusCode::NOT_FOUND, "not found"));
    }
    let token = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !vault.token_is(&env, token) {
        return Ok(reply(StatusCode::FORBIDDEN, "unknown token"));
    }
    // An agent message travels in base64 inside its JSON envelope.
    let limit = if agent { 2 * MAX_AGENT_MESSAGE } else { 4096 };
    let body = match Limited::new(req.into_body(), limit).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return Ok(reply(StatusCode::BAD_REQUEST, "body")),
    };
    Ok(if agent {
        agent_reply(&vault, &env, &body)
    } else {
        credential(&vault, &env, &body).await
    })
}

/// Record on `ev` why the vault refused, and answer with it. `failed` is the event's reason
/// when something failed.
fn refuse(ev: &mut Event, e: CredentialError, failed: &str) -> Response<Full<Bytes>> {
    let status = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_GATEWAY);
    let (reason, message) = match e {
        CredentialError::Locked => ("locked", "vault is locked; run `luoto vault unlock`".into()),
        CredentialError::NotBound => ("not_bound", "binding is not registered for this env".into()),
        CredentialError::Failed(m) => (failed, m),
    };
    ev.verdict = Some(Verdict::Deny);
    ev.reason = Some(reason.into());
    ev.message = Some(message.clone());
    reply(status, message)
}

/// Issue one binding's value, with an event either way.
async fn credential(vault: &Vault, env: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let Ok(cr) = serde_json::from_slice::<CredentialRequest>(body) else {
        return reply(StatusCode::BAD_REQUEST, "invalid request");
    };
    let mut ev = Event {
        kind: Some(EventKind::Creds),
        env: env.to_string(),
        binding: Some(cr.binding.clone()),
        ..Default::default()
    };
    let resp = match vault.issue(env, &cr.binding).await {
        Ok(v) => {
            ev.verdict = Some(Verdict::Allow);
            ev.message = Some(match v.expires_at {
                Some(e) => format!("issued, expires {}", e.format("%H:%M:%S UTC")),
                None => "issued".into(),
            });
            reply(StatusCode::OK, serde_json::to_vec(&v).unwrap_or_default())
        }
        Err(e) => refuse(&mut ev, e, "mint_failed"),
    };
    vault.emit(ev);
    resp
}

/// Answer one ssh-agent message, with an event for each bind, login and refusal.
fn agent_reply(vault: &Vault, env: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let Ok(req) = serde_json::from_slice::<AgentRequest>(body) else {
        return reply(StatusCode::BAD_REQUEST, "invalid request");
    };
    if !agent::conn_id_ok(&req.message.conn) {
        return reply(StatusCode::BAD_REQUEST, "invalid agent connection id");
    }
    let mut ev = Event {
        kind: Some(EventKind::Creds),
        env: env.to_string(),
        binding: Some(req.binding.clone()),
        ..Default::default()
    };
    let resp = match vault.agent(env, &req) {
        Ok((msg, note)) => {
            match note {
                agent::Note::Listed => {}
                agent::Note::Bound(host) => {
                    ev.verdict = Some(Verdict::Allow);
                    ev.message = Some(format!("ssh session to {host} bound"));
                    ev.host = Some(host);
                }
                agent::Note::Signed(host) => {
                    ev.verdict = Some(Verdict::Allow);
                    ev.message = Some(format!("ssh login to {host} signed"));
                    ev.host = Some(host);
                }
                agent::Note::Refused(why) => {
                    ev.verdict = Some(Verdict::Deny);
                    ev.reason = Some("ssh_agent".into());
                    ev.message = Some(why);
                }
            }
            let out = AgentMessage {
                conn: req.message.conn.clone(),
                message: B64.encode(msg),
            };
            reply(StatusCode::OK, serde_json::to_vec(&out).unwrap_or_default())
        }
        // An env without an SSH key: an agent asking is nothing to record.
        Err(CredentialError::NotBound) => {
            reply(StatusCode::NOT_FOUND, "no SSH key bound for this env")
        }
        Err(e) => refuse(&mut ev, e, "ssh_agent"),
    };
    if ev.verdict.is_some() {
        vault.emit(ev);
    }
    resp
}
