//! One HTTP request through the gate, whichever way it arrived (explicit proxy, intercepted
//! TLS, transparent catch-all): agree on the destination, decide, apply guards and
//! credentials, forward, meter, record.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use chrono::Utc;
use http::header::{
    CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use luoto_shared::creds::AUTH_HEADERS;
use luoto_shared::events::{Event, EventKind, Intake, Verdict, clip_path};
use luoto_shared::host::{canonical_path, split_authority};
use luoto_shared::policy::{Decision, DenyReason, RequestInfo};

use crate::body::{Body, BodyError, Capped, Metered, boxed, collect_limited, full, is_too_large};
use crate::creds::{CredError, apply};
use crate::github::{
    Parse, PushRules, azure_repo_of, check_graphql, check_updates, parse_ref_updates, repo_of,
};
use crate::respond;
use crate::state::State;
use crate::upstream::{DialError, dial, http1_sender};

#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Target {
    fn default_port(&self) -> u16 {
        if self.tls { 443 } else { 80 }
    }

    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn url(&self, path: &str) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}{}", self.authority(), clip_path(path))
    }
}

/// A kept-alive upstream connection and the destination it is for.
type Upstream = (String, u16, bool, SendRequest<Body>);

/// Per client connection: how it arrived and a reusable upstream connection.
pub struct ConnCtx {
    pub intake: Intake,
    upstream: tokio::sync::Mutex<Option<Upstream>>,
}

impl ConnCtx {
    pub fn new(intake: Intake) -> Self {
        ConnCtx {
            intake,
            upstream: tokio::sync::Mutex::new(None),
        }
    }

    async fn sender(
        &self,
        state: &State,
        t: &Target,
        allow_private: bool,
    ) -> Result<SendRequest<Body>, DialError> {
        let cached = self.upstream.lock().await.take();
        if let Some((h, p, tls, mut s)) = cached
            && h == t.host
            && p == t.port
            && tls == t.tls
            && s.ready().await.is_ok()
        {
            return Ok(s);
        }
        let io = dial(state, &t.host, t.port, t.tls, allow_private).await?;
        http1_sender(io).await
    }

    async fn put_back(&self, t: &Target, s: SendRequest<Body>) {
        *self.upstream.lock().await = Some((t.host.clone(), t.port, t.tls, s));
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

fn strip_hop_by_hop(headers: &mut http::HeaderMap, keep_upgrade: bool) {
    let listed: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let upgrade = headers.get(UPGRADE).cloned();
    for name in HOP_BY_HOP.iter().copied().map(str::to_string).chain(listed) {
        headers.remove(name.as_str());
    }
    if keep_upgrade && let Some(u) = upgrade {
        headers.insert(UPGRADE, u);
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    }
}

pub async fn handle(
    state: Arc<State>,
    ctx: Arc<ConnCtx>,
    req: Request<Incoming>,
    target: Target,
) -> Result<Response<Body>, Infallible> {
    Ok(handle_inner(state, ctx, req, target).await)
}

fn denied(
    state: &State,
    mut ev: Event,
    method: &str,
    url: &str,
    host: &str,
    reason: DenyReason,
) -> Response<Body> {
    ev.verdict = Some(Verdict::Deny);
    ev.reason = Some(reason.code().to_string());
    ev.message = Some(reason.message(host));
    let resp = respond::deny(&state.cfg.env, method, url, host, &reason);
    ev.status = Some(resp.status().as_u16());
    state.events.emit(ev);
    resp
}

fn failed(state: &State, mut ev: Event, status: StatusCode, msg: String) -> Response<Body> {
    ev.verdict = Some(Verdict::Allow);
    ev.status = Some(status.as_u16());
    ev.message = Some(msg.clone());
    state.events.emit(ev);
    respond::plain(status, format!("luoto gate: {msg}\n"))
}

/// A local test server of the integration tests (`test-hooks` builds only), which speak plain
/// HTTP. Release builds have none, so every credential goes over TLS.
fn plaintext_test_server(state: &State, host: &str) -> bool {
    #[cfg(feature = "test-hooks")]
    return state.cfg.test_resolve.iter().any(|(h, _)| h == host);
    #[cfg(not(feature = "test-hooks"))]
    {
        let _ = (state, host);
        false
    }
}

async fn handle_inner(
    state: Arc<State>,
    ctx: Arc<ConnCtx>,
    mut req: Request<Incoming>,
    target: Target,
) -> Response<Body> {
    let started = Instant::now();
    let method = req.method().as_str().to_string();
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let (raw_path, query) = pq.split_at(pq.find('?').unwrap_or(pq.len()));
    // Rules, denies, guards and credentials all see this path, and upstream gets it too.
    let canonical = canonical_path(raw_path);
    let path = canonical.clone().unwrap_or_else(|_| raw_path.to_string());
    let query = query.to_string();
    let url = target.url(&path);
    let ev = Event {
        kind: Some(EventKind::Http),
        intake: Some(ctx.intake),
        method: Some(method.clone()),
        host: Some(target.host.clone()),
        port: Some(target.port),
        path: Some(clip_path(&path)),
        ..Default::default()
    };
    if let Err(why) = canonical {
        let reason = DenyReason::Guard {
            reason: format!("the path has {why}, which servers resolve differently"),
        };
        return denied(&state, ev, &method, &url, &target.host, reason);
    }
    // Methods are case-sensitive; the policy compares them without case, the guards with it.
    if method.bytes().any(|b| b.is_ascii_lowercase()) {
        let reason = DenyReason::Guard {
            reason: format!("method `{method}` is not upper-case"),
        };
        return denied(&state, ev, &method, &url, &target.host, reason);
    }

    // The destination is decided once, by the caller; the request may not disagree.
    let hosts: Vec<&HeaderValue> = req.headers().get_all(HOST).iter().collect();
    if hosts.len() > 1 {
        return denied(
            &state,
            ev,
            &method,
            &url,
            &target.host,
            DenyReason::InvalidHost,
        );
    }
    if let Some(h) = hosts.first() {
        let agrees = h
            .to_str()
            .ok()
            .and_then(|s| split_authority(s).ok())
            .is_some_and(|(hh, hp)| hh == target.host && hp.is_none_or(|p| p == target.port));
        if !agrees {
            return denied(
                &state,
                ev,
                &method,
                &url,
                &target.host,
                DenyReason::InvalidHost,
            );
        }
    }
    if req.headers().contains_key(TRANSFER_ENCODING) && req.headers().contains_key(CONTENT_LENGTH) {
        return denied(
            &state,
            ev,
            &method,
            &url,
            &target.host,
            DenyReason::Guard {
                reason: "ambiguous request framing (Content-Length with Transfer-Encoding)".into(),
            },
        );
    }
    let websocket = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("websocket"));
    let content_length = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    let policy = state.policy();
    let decision = policy.decide(
        &RequestInfo {
            host: &target.host,
            port: target.port,
            method: &method,
            path: &path,
            websocket,
            content_length,
        },
        Utc::now(),
    );
    let (rule, max_body, allow_private) = match decision {
        Decision::Allow {
            rule,
            max_body,
            allow_private,
        } => (rule, max_body, allow_private),
        Decision::Deny(reason) => return denied(&state, ev, &method, &url, &target.host, reason),
    };
    let mut ev = ev;
    ev.rule = Some(rule);

    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
    let (mut parts, incoming) = req.into_parts();
    let mut body: Body = boxed(incoming);

    // From here `parts` is what upstream gets: guards judge it, and credentials go in last, so
    // neither a header the client lists in `Connection` nor its own query can displace them.
    strip_hop_by_hop(&mut parts.headers, websocket);
    parts.uri = match format!("{path}{query}").parse() {
        Ok(u) => u,
        Err(_) => {
            return denied(
                &state,
                ev,
                &method,
                &url,
                &target.host,
                DenyReason::InvalidHost,
            );
        }
    };
    parts.version = Version::HTTP_11;
    if let Ok(v) = HeaderValue::from_str(&target.authority()) {
        parts.headers.insert(HOST, v);
    }

    // Git hosts route paths without regard to case, as their rules match them.
    let push = method == "POST" && path.to_ascii_lowercase().ends_with("/git-receive-pack");
    let guarded = if !push {
        None
    } else if target.host == "github.com"
        && let Some(g) = &policy.github
    {
        Some((
            repo_of(&path).is_some_and(|r| g.repos.contains(&r)),
            PushRules::from(g),
        ))
    } else if target.host == AZURE_HOST
        && let Some(g) = &policy.azure_devops
    {
        Some((
            azure_repo_of(&path).is_some_and(|r| g.repos.contains(&r)),
            PushRules::from(g),
        ))
    } else {
        None
    };
    if let Some((granted, rules)) = guarded {
        match guard_push(&parts.headers, body, granted, rules).await {
            Ok(b) => body = b,
            Err(reason) => {
                return denied(
                    &state,
                    ev,
                    &method,
                    &url,
                    &target.host,
                    DenyReason::Guard { reason },
                );
            }
        }
    }
    if let Some(guard) = &policy.github
        && target.host == "api.github.com"
        && method == "POST"
        && path.eq_ignore_ascii_case("/graphql")
    {
        let bytes = match collect_limited(body, 1 << 20).await {
            Ok(b) => b,
            Err(_) => {
                let reason = DenyReason::Guard {
                    reason: "GraphQL body too large".into(),
                };
                return denied(&state, ev, &method, &url, &target.host, reason);
            }
        };
        if let Err(reason) = check_graphql(guard, &bytes) {
            return denied(
                &state,
                ev,
                &method,
                &url,
                &target.host,
                DenyReason::Guard { reason },
            );
        }
        body = full(bytes);
    }

    if policy.is_credentialed_host(&target.host) {
        // Over plain HTTP the credential would cross the network readable.
        if !target.tls && !plaintext_test_server(&state, &target.host) {
            let reason = DenyReason::Guard {
                reason: format!("{} gets credentials only over HTTPS", target.host),
            };
            return denied(&state, ev, &method, &url, &target.host, reason);
        }
        for h in AUTH_HEADERS {
            parts.headers.remove(*h);
        }
        let injections = policy.injections_for(&target.host, &path);
        if !injections.is_empty() {
            let Some(vault) = state.vault() else {
                return denied(&state, ev, &method, &url, &target.host, DenyReason::Locked);
            };
            let mut used = Vec::new();
            for inj in injections {
                match vault.get(&inj.binding).await {
                    Ok(secret) => {
                        if let Err(e) = apply(&mut parts, inj, &secret) {
                            return failed(
                                &state,
                                ev,
                                StatusCode::BAD_GATEWAY,
                                format!("credential `{}`: {e}", inj.binding),
                            );
                        }
                        used.push(inj.binding.clone());
                    }
                    Err(CredError::Locked) => {
                        return denied(&state, ev, &method, &url, &target.host, DenyReason::Locked);
                    }
                    Err(CredError::Unknown(b)) => {
                        let reason = DenyReason::Guard {
                            reason: format!(
                                "credential `{b}` is not registered with the vault; run `luoto up -e {}` on the host",
                                state.cfg.env
                            ),
                        };
                        return denied(&state, ev, &method, &url, &target.host, reason);
                    }
                    Err(CredError::Unavailable(m)) => {
                        return failed(
                            &state,
                            ev,
                            StatusCode::BAD_GATEWAY,
                            format!("vault unavailable: {m}"),
                        );
                    }
                }
            }
            used.dedup();
            ev.binding = Some(used.join(","));
        }
    }

    if let Some(max) = max_body {
        body = Capped::new(body, max).boxed();
    }
    let up_bytes = Arc::new(AtomicU64::new(0));
    let counter = up_bytes.clone();
    body = Metered::new(body, move |n| counter.store(n, Ordering::Relaxed)).boxed();

    let mut sender = match ctx.sender(&state, &target, allow_private).await {
        Ok(s) => s,
        Err(DialError::Denied(reason)) => {
            return denied(&state, ev, &method, &url, &target.host, reason);
        }
        Err(DialError::Failed(msg)) => return failed(&state, ev, StatusCode::BAD_GATEWAY, msg),
    };
    let mut resp = match sender.send_request(Request::from_parts(parts, body)).await {
        Ok(r) => r,
        Err(e) => {
            let msg = if is_too_large(&e) {
                "request body exceeded the rule's size cap".to_string()
            } else {
                format!("upstream request failed: {e}")
            };
            return failed(&state, ev, StatusCode::BAD_GATEWAY, msg);
        }
    };
    let status = resp.status();
    if status == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let server_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(c), Ok(s)) = (client_upgrade.await, server_upgrade.await) {
                    let mut c = TokioIo::new(c);
                    let mut s = TokioIo::new(s);
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
                }
            });
        }
    } else {
        ctx.put_back(&target, sender).await;
    }

    let (mut rparts, rbody) = resp.into_parts();
    if status != StatusCode::SWITCHING_PROTOCOLS {
        strip_hop_by_hop(&mut rparts.headers, false);
    }
    ev.verdict = Some(Verdict::Allow);
    ev.status = Some(status.as_u16());
    let state2 = state.clone();
    let metered = Metered::new(boxed(rbody), move |down| {
        ev.bytes_down = Some(down);
        ev.bytes_up = Some(up_bytes.load(Ordering::Relaxed));
        ev.ms = Some(started.elapsed().as_millis() as u64);
        state2.events.emit(ev);
    });
    Response::from_parts(rparts, metered.boxed())
}

/// Azure DevOps Services, where its git repositories are served.
const AZURE_HOST: &str = "dev.azure.com";

/// A push to a guarded git host: only to the env's granted repositories, uncompressed, and
/// with every ref update allowed.
async fn guard_push(
    headers: &http::HeaderMap,
    body: Body,
    granted: bool,
    rules: PushRules<'_>,
) -> Result<Body, String> {
    if !granted {
        return Err("pushes are only allowed to the env's granted repositories".into());
    }
    if headers.contains_key(CONTENT_ENCODING) {
        return Err("compressed pushes cannot be inspected".into());
    }
    inspect_push(body, rules).await
}

/// Read the ref-update commands at the front of a push, check them, and hand back a body
/// that replays what was read followed by the rest of the stream.
async fn inspect_push(mut body: Body, guard: PushRules<'_>) -> Result<Body, String> {
    let mut buf = BytesMut::new();
    loop {
        match parse_ref_updates(&buf) {
            Ok(updates) => {
                check_updates(guard, &updates)?;
                break;
            }
            Err(Parse::Invalid(e)) => return Err(e),
            Err(Parse::NeedMore) => {}
        }
        if buf.len() > 1 << 20 {
            return Err("push command list too large".into());
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    buf.extend_from_slice(&data);
                }
            }
            Some(Err(e)) => return Err(format!("reading push: {e}")),
            None => return Err("truncated push".into()),
        }
    }
    Ok(Prefixed {
        prefix: Some(buf.freeze()),
        rest: body,
    }
    .boxed())
}

struct Prefixed {
    prefix: Option<Bytes>,
    rest: Body,
}

impl HttpBody for Prefixed {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if let Some(p) = self.prefix.take()
            && !p.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(p))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(|p| p.is_empty()) && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let inner = self.rest.size_hint();
        let extra = self.prefix.as_ref().map_or(0, |p| p.len() as u64);
        let mut h = SizeHint::new();
        if let Some(u) = inner.upper() {
            h.set_upper(u + extra);
        }
        h.set_lower(inner.lower() + extra);
        h
    }
}
