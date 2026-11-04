//! In-sandbox API at `http://gate:3128/_sandbox/…`: what the policy is, whether a URL would
//! pass, and filing access requests. Never changes policy itself.

use std::sync::Arc;

use chrono::Utc;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use luoto_shared::api::{
    API_PREFIX, AgentMessage, CheckQuery, CheckResult, NewAccessRequest, RuleSummary,
    SSH_AGENT_PATH, SandboxStatus,
};
use luoto_shared::events::{Event, EventKind};
use luoto_shared::host::split_authority;
use luoto_shared::policy::{Decision, RequestInfo};
use serde::de::DeserializeOwned;

use crate::body::{Body, collect_limited};
use crate::respond::{json, plain};
use crate::state::State;

const HELP: &str = "luoto sandbox gate. Endpoints:\n\
  GET  /_sandbox/status          policy, credentials, recent denials, requests\n\
  POST /_sandbox/check           {\"url\":\"https://…\",\"method\":\"GET\"}\n\
  POST /_sandbox/requests        {\"host\":\"docs.rs\",\"access\":\"read\",\"reason\":\"…\"}\n\
  GET  /_sandbox/requests/<id>   request status\n\
  GET  /_sandbox/ca.pem          the env CA certificate\n\
  POST /_sandbox/ssh-agent       one ssh-agent message for the vault (`sandbox ssh-agent`)\n\
Use the `sandbox` command instead of calling these by hand.\n";

pub async fn handle(state: Arc<State>, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let Some(rest) = path.strip_prefix(API_PREFIX) else {
        return plain(StatusCode::NOT_FOUND, HELP);
    };
    match (method, rest) {
        (Method::GET, "/status") => json(StatusCode::OK, &status(&state)),
        (Method::POST, "/check") => match read::<CheckQuery>(req).await {
            Ok(q) => json(StatusCode::OK, &check(&state, &q)),
            Err(e) => plain(StatusCode::BAD_REQUEST, e),
        },
        (Method::POST, "/requests") => match read::<NewAccessRequest>(req).await {
            Ok(new) => {
                let created = state
                    .requests
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .create(new);
                match created {
                    Ok(r) => {
                        state.events.emit(Event {
                            kind: Some(EventKind::Request),
                            host: Some(r.host.clone()),
                            request_id: Some(r.id),
                            message: Some(r.reason.clone()),
                            reason: Some(format!("{:?}", r.access).to_lowercase()),
                            ..Default::default()
                        });
                        json(StatusCode::CREATED, &r)
                    }
                    Err(e) => plain(StatusCode::UNPROCESSABLE_ENTITY, format!("{e}\n")),
                }
            }
            Err(e) => plain(StatusCode::BAD_REQUEST, e),
        },
        (Method::GET, p) if p.starts_with("/requests/") => {
            let id = p
                .trim_start_matches("/requests/")
                .parse::<u64>()
                .unwrap_or(0);
            let reqs = state.requests.lock().unwrap_or_else(|e| e.into_inner());
            match reqs.get(id) {
                Some(r) => json(StatusCode::OK, r),
                None => plain(StatusCode::NOT_FOUND, "no such request\n"),
            }
        }
        (Method::POST, p) if p == SSH_AGENT_PATH => match read::<AgentMessage>(req).await {
            // The vault answers: the env's SSH key never leaves it.
            Ok(msg) => match state.vault() {
                None => plain(StatusCode::SERVICE_UNAVAILABLE, "no vault configured\n"),
                Some(vault) => match vault.agent("ssh", msg).await {
                    Ok(reply) => json(StatusCode::OK, &reply),
                    Err(crate::creds::CredError::Unknown(_)) => {
                        plain(StatusCode::NOT_FOUND, "no SSH key: add [credentials.ssh]\n")
                    }
                    Err(crate::creds::CredError::Locked) => plain(
                        StatusCode::LOCKED,
                        "vault is locked: `luoto vault unlock`\n",
                    ),
                    Err(crate::creds::CredError::Unavailable(e)) => {
                        plain(StatusCode::BAD_GATEWAY, format!("{e}\n"))
                    }
                },
            },
            Err(e) => plain(StatusCode::BAD_REQUEST, e),
        },
        (Method::GET, "/ca.pem") => match state.ca() {
            Some(ca) => plain(StatusCode::OK, ca.cert_pem.clone()),
            None => plain(StatusCode::NOT_FOUND, "no CA installed\n"),
        },
        _ => plain(StatusCode::NOT_FOUND, HELP),
    }
}

async fn read<T: DeserializeOwned>(req: Request<Incoming>) -> Result<T, String> {
    let bytes = collect_limited(crate::body::boxed(req.into_body()), 16 * 1024)
        .await
        .map_err(|e| format!("body: {e}\n"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON: {e}\n"))
}

fn status(state: &State) -> SandboxStatus {
    let policy = state.policy();
    let now = Utc::now();
    let rules = policy
        .rules
        .iter()
        .filter(|r| !r.rule.expired(now))
        .map(|r| RuleSummary {
            id: r.id.clone(),
            origin: r.origin.clone(),
            host: r.rule.host.clone(),
            access: r.rule.access.describe(),
            paths: r.rule.paths.clone(),
            expires: r.rule.expires,
            mode: r.rule.mode,
        })
        .collect();
    let mut credentialed_hosts: Vec<String> =
        policy.injections.iter().map(|i| i.host.clone()).collect();
    credentialed_hosts.sort();
    credentialed_hosts.dedup();
    SandboxStatus {
        env: state.cfg.env.clone(),
        gate_version: luoto_shared::VERSION.into(),
        credentials_locked: state.vault().is_none() && !policy.injections.is_empty(),
        rules,
        credentialed_hosts,
        recent_denials: state.events.recent_denials(20),
        requests: state
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .list(),
    }
}

fn check(state: &State, q: &CheckQuery) -> CheckResult {
    let Ok(uri) = q.url.parse::<http::Uri>() else {
        return CheckResult {
            allowed: false,
            rule: None,
            reason: Some("invalid_url".into()),
            message: "not a valid URL".into(),
        };
    };
    let tls = uri.scheme_str() != Some("http");
    let Some(Ok((host, port))) = uri.authority().map(|a| split_authority(a.as_str())) else {
        return CheckResult {
            allowed: false,
            rule: None,
            reason: Some("invalid_url".into()),
            message: "URL has no valid host".into(),
        };
    };
    let port = port.unwrap_or(if tls { 443 } else { 80 });
    let method = q.method.to_ascii_uppercase();
    let decision = state.policy().decide(
        &RequestInfo {
            host: &host,
            port,
            method: &method,
            path: uri.path(),
            websocket: false,
            content_length: None,
        },
        Utc::now(),
    );
    match decision {
        Decision::Allow { rule, .. } => CheckResult {
            allowed: true,
            message: format!("{method} {host} is allowed by rule {rule}"),
            rule: Some(rule),
            reason: None,
        },
        Decision::Deny(r) => CheckResult {
            allowed: false,
            rule: None,
            message: r.message(&host),
            reason: Some(r.code().into()),
        },
    }
}
