//! The vault's API for gates, on the vault network only: one binding's value, or one
//! ssh-agent message, for the env whose token the request bears.

use std::convert::Infallible;
use std::sync::Arc;

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
use tokio::net::TcpListener;

use crate::agent;
use crate::state::Vault;

pub async fn serve(vault: Arc<Vault>, listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let v = vault.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| handle(v.clone(), req));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r
}

async fn handle(
    vault: Arc<Vault>,
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
    let Some(env) = vault.env_for_token(token) else {
        return Ok(reply(StatusCode::FORBIDDEN, "unknown token"));
    };
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
