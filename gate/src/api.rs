//! In-sandbox API at `http://gate:3128/_sandbox/…`: what the policy is, whether a URL would
//! pass, and filing access requests. Never changes policy itself.

use std::sync::Arc;

use chrono::Utc;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use luoto_shared::api::{
    API_PREFIX, AgentMessage, CheckQuery, CheckResult, MAX_AGENT_MESSAGE, NewAccessRequest,
    OpenEgress, RuleSummary, SSH_AGENT_PATH, SandboxStatus,
};
use luoto_shared::creds::{CredentialError, SSH_BINDING};
use luoto_shared::events::{Event, EventKind};
use luoto_shared::host::split_authority;
use luoto_shared::policy::{Decision, RequestInfo};
use serde::de::DeserializeOwned;

use crate::body::{Body, collect_limited};
use crate::handler::canonical_request;
use crate::respond::{json, plain};
use crate::state::State;

/// Every body the API reads is small; the largest is an ssh-agent message, in base64 inside
/// its JSON envelope.
const MAX_BODY: usize = 2 * MAX_AGENT_MESSAGE;

const HELP: &str = "luoto sandbox gate. Endpoints:\n\
  GET  /_sandbox/status          policy, credentials, recent denials, requests\n\
  POST /_sandbox/check           {\"url\":\"https://…\",\"method\":\"GET\"}\n\
  POST /_sandbox/requests        {\"host\":\"docs.rs\",\"access\":\"read\",\"reason\":\"…\"}\n\
                                 ({\"host\":\"db.example.com\",\"port\":5432,…}: a tunnel)\n\
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
                if new.install.is_none()
                    && let Some(d) = state.policy().wholly_denied(&new.host)
                {
                    let msg = format!(
                        "{} is refused by a [[deny]] rule ({}): no request can open it\n",
                        new.host.trim(),
                        d.reason
                    );
                    return plain(StatusCode::UNPROCESSABLE_ENTITY, msg);
                }
                let created = state.requests().create(new);
                match created {
                    Ok(r) => {
                        state.events.emit(Event {
                            kind: Some(EventKind::Request),
                            host: Some(r.host.clone()),
                            port: r.port,
                            request_id: Some(r.id),
                            message: Some(r.reason.clone()),
                            reason: Some(match r.port {
                                Some(_) => "tunnel".into(),
                                None => format!("{:?}", r.access).to_lowercase(),
                            }),
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
            let reqs = state.requests();
            match reqs.get(id) {
                Some(r) => json(StatusCode::OK, r),
                None => plain(StatusCode::NOT_FOUND, "no such request\n"),
            }
        }
        (Method::POST, p) if p == SSH_AGENT_PATH => match read::<AgentMessage>(req).await {
            // The vault answers: the env's SSH key never leaves it.
            Ok(msg) => match state.vault() {
                None => plain(StatusCode::SERVICE_UNAVAILABLE, "no vault configured\n"),
                Some(vault) => match vault.agent(SSH_BINDING, msg).await {
                    Ok(reply) => json(StatusCode::OK, &reply),
                    Err(CredentialError::NotBound) => {
                        plain(StatusCode::NOT_FOUND, "no SSH key: add [credentials.ssh]\n")
                    }
                    Err(CredentialError::Locked) => plain(
                        StatusCode::LOCKED,
                        "vault is locked: `luoto vault unlock`\n",
                    ),
                    Err(CredentialError::Failed(e)) => {
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
    let bytes = collect_limited(crate::body::boxed(req.into_body()), MAX_BODY)
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
            port: r.rule.port,
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
        recent_denials: state.events.recent_denials(),
        requests: state.requests().list(),
        open: policy.open_at(now).map(|o| OpenEgress { until: o.until }),
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
    let method = &q.method;
    let decision = match canonical_request(method, uri.path()) {
        Ok(path) => state.policy().decide(
            &RequestInfo {
                host: &host,
                port,
                method,
                path: &path,
                websocket: false,
                content_length: None,
            },
            Utc::now(),
        ),
        Err(reason) => Decision::Deny(reason),
    };
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
