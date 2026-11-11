//! One HTTP request through the gate, whichever way it arrived (explicit proxy, intercepted
//! TLS, transparent catch-all): agree on the destination, decide, apply guards and
//! credentials, forward, meter, record.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use http::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use luoto_shared::creds::{AUTH_HEADERS, CredentialError};
use luoto_shared::events::{Event, EventKind, Intake, Verdict, clip_path};
use luoto_shared::host::{canonical_path, split_authority};
use luoto_shared::policy::{Decision, DenyReason, RequestInfo};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::body::{Body, Capped, Metered, boxed, is_too_large, watched};
use crate::creds::apply;
use crate::guards;
use crate::imds;
use crate::limits::{self, Activity, HEAD_GRACE, Limits, Slot, Watched};
use crate::respond;
use crate::state::State;
use crate::upstream::{DialError, Reach, dial, http1_sender, test_server};

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

/// A kept-alive upstream connection, the destination it is for and what its dial could
/// reach (a request reuses it only where its own decision allows as much).
type Upstream = (String, u16, bool, Reach, SendRequest<Body>);

/// Per client connection: how it arrived, its place under the connection cap, its progress
/// and a reusable upstream connection.
pub struct ConnCtx {
    pub intake: Intake,
    slot: Slot,
    pub activity: Arc<Activity>,
    upstream: tokio::sync::Mutex<Option<Upstream>>,
}

impl ConnCtx {
    pub fn new(intake: Intake, slot: Slot) -> Self {
        ConnCtx {
            intake,
            slot,
            activity: Activity::new(),
            upstream: tokio::sync::Mutex::new(None),
        }
    }

    /// For a task that carries the connection on after an upgrade.
    pub fn slot(&self) -> Slot {
        self.slot.clone()
    }

    async fn sender(
        &self,
        state: &State,
        t: &Target,
        reach: Reach,
    ) -> Result<SendRequest<Body>, DialError> {
        let cached = self.upstream.lock().await.take();
        if let Some((h, p, tls, had, mut s)) = cached
            && h == t.host
            && p == t.port
            && tls == t.tls
            && had.serves(reach)
            && s.ready().await.is_ok()
        {
            return Ok(s);
        }
        let io = dial(state, &t.host, t.port, t.tls, reach).await?;
        http1_sender(io).await
    }

    async fn put_back(&self, t: &Target, reach: Reach, s: SendRequest<Body>) {
        *self.upstream.lock().await = Some((t.host.clone(), t.port, t.tls, reach, s));
    }
}

/// Serve HTTP/1.1 from the sandbox on `io`: header names keep the case the client wrote them
/// in, the head must arrive within a minute, and upgrades pass through. The connection closes
/// once no byte has moved for `limits.idle`; while a request is handled the handler's own
/// limits apply first, with the response-head limit as the backstop.
pub async fn serve_http1<IO, F, Fut>(io: IO, activity: Arc<Activity>, limits: Limits, handle: F)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: Fn(Request<Incoming>) -> Fut,
    Fut: Future<Output = Result<Response<Body>, Infallible>>,
{
    let watched = Watched::new(io, activity.clone());
    let handling = activity.clone();
    let service = service_fn(move |req| {
        let busy = handling.busy();
        let resp = handle(req);
        async move {
            let resp = resp.await;
            drop(busy);
            resp
        }
    });
    let conn = http1::Builder::new()
        .preserve_header_case(true)
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(60))
        .serve_connection(TokioIo::new(watched), service)
        .with_upgrades();
    tokio::select! {
        _ = conn => {}
        () = activity.stalled(limits.idle, limits.response_head + HEAD_GRACE) => {}
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

fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|s| HeaderName::from_bytes(s.trim().as_bytes()).ok())
        .collect();
    let upgrade = headers.get(UPGRADE).cloned();
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    for name in listed {
        headers.remove(name);
    }
    if keep_upgrade && let Some(u) = upgrade {
        headers.insert(UPGRADE, u);
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    }
}

/// The path the gate matches and forwards for a request, or why the request is refused before
/// any rule. The path is canonical (`host::canonical_path`). Only upper-case methods pass:
/// methods are case-sensitive, and the policy compares them without case, the guards with it.
pub fn canonical_request(method: &str, raw_path: &str) -> Result<String, DenyReason> {
    let path = canonical_path(raw_path).map_err(|why| DenyReason::Guard {
        reason: format!("the path has {why}, which servers resolve differently"),
    })?;
    if method.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err(DenyReason::Guard {
            reason: format!("method `{method}` is not upper-case"),
        });
    }
    Ok(path)
}

pub async fn handle(
    state: Arc<State>,
    ctx: Arc<ConnCtx>,
    req: Request<Incoming>,
    target: Target,
) -> Result<Response<Body>, Infallible> {
    if imds::answers(&state.policy(), &target, req.uri().path()) {
        return Ok(imds::answer(&state, &ctx, req, &target).await);
    }
    Ok(handle_inner(state, ctx, req, target).await)
}

/// The destination is decided once, by the caller; the request may not disagree.
pub fn host_agrees(headers: &HeaderMap, target: &Target) -> bool {
    let mut hosts = headers.get_all(HOST).iter();
    match (hosts.next(), hosts.next()) {
        (None, _) => true,
        (Some(h), None) => h
            .to_str()
            .ok()
            .and_then(|s| split_authority(s).ok())
            .is_some_and(|(hh, hp)| hh == target.host && hp.is_none_or(|p| p == target.port)),
        (Some(_), Some(_)) => false,
    }
}

fn denied(
    state: &State,
    mut ev: Event,
    method: &str,
    url: &str,
    host: &str,
    path: &str,
    reason: DenyReason,
) -> Response<Body> {
    ev.verdict = Some(Verdict::Deny);
    ev.reason = Some(reason.code().to_string());
    ev.message = Some(reason.message(host));
    let resp = respond::deny(&state.cfg.env, method, url, host, path, &reason);
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
        .map_or("/", |p| p.as_str())
        .to_string();
    let (raw_path, query) = pq.split_at(pq.find('?').unwrap_or(pq.len()));
    // Rules, denies, guards and credentials all see this path, and upstream gets it too.
    let (path, refused) = match canonical_request(&method, raw_path) {
        Ok(path) => (path, None),
        Err(reason) => (raw_path.to_string(), Some(reason)),
    };
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
    let deny = |ev: Event, reason: DenyReason| {
        denied(&state, ev, &method, &url, &target.host, &path, reason)
    };
    if let Some(reason) = refused {
        return deny(ev, reason);
    }

    if !host_agrees(req.headers(), &target) {
        return deny(ev, DenyReason::InvalidHost);
    }
    if req.headers().contains_key(TRANSFER_ENCODING) && req.headers().contains_key(CONTENT_LENGTH) {
        let reason = DenyReason::Guard {
            reason: "ambiguous request framing (Content-Length with Transfer-Encoding)".into(),
        };
        return deny(ev, reason);
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
    let (rule, max_body, allow_private, rule_idle) = match decision {
        Decision::Allow {
            rule,
            max_body,
            allow_private,
            idle,
        } => (rule, max_body, allow_private, idle),
        Decision::Deny(reason) => {
            ctx.activity.set_rule_idle(None);
            return deny(ev, reason);
        }
    };
    // Every wait on this connection follows the rule until the next request is decided.
    ctx.activity.set_rule_idle(rule_idle);
    let mut ev = ev;
    ev.rule = Some(rule);

    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
    let (mut parts, incoming) = req.into_parts();

    // From here `parts` is what upstream gets: guards judge it, and credentials go in last, so
    // neither a header the client lists in `Connection` nor its own query can displace them.
    strip_hop_by_hop(&mut parts.headers, websocket);
    parts.uri = match format!("{path}{query}").parse() {
        Ok(u) => u,
        Err(_) => return deny(ev, DenyReason::InvalidHost),
    };
    parts.version = Version::HTTP_11;
    if let Ok(v) = HeaderValue::from_str(&target.authority()) {
        parts.headers.insert(HOST, v);
    }

    let guarded = guards::check(
        &policy,
        &target.host,
        &method,
        &path,
        &parts.headers,
        boxed(incoming),
    );
    let mut body = match guarded.await {
        Ok(body) => body,
        Err(reason) => return deny(ev, DenyReason::Guard { reason }),
    };

    // What the response must not carry back: every form of a credential put on the request.
    let mut placed: Vec<String> = Vec::new();
    let mut plain_to_this_machine = false;
    if policy.is_credentialed_host(&target.host) {
        // TRACE echoes the request, credential included.
        if method == "TRACE" {
            let reason = DenyReason::Guard {
                reason: format!("TRACE is not allowed to {}", target.host),
            };
            return deny(ev, reason);
        }
        // Java servers drop `;` parameters and resolve the `..` before them, and some decode
        // an escaped slash: a path the rules read one way would reach another.
        let lower = path.to_ascii_lowercase();
        if path.contains(';') || lower.contains("%2f") || lower.contains("%5c") {
            let reason = DenyReason::Guard {
                reason: format!(
                    "paths with `;` or an escaped slash are not allowed to {}",
                    target.host
                ),
            };
            return deny(ev, reason);
        }
        // Over plain HTTP the credential would cross the network readable; to this machine it
        // goes nowhere, and the dial makes sure it is this machine.
        let this_machine = policy
            .plain_http_credentials
            .iter()
            .any(|h| luoto_shared::host::host_matches(h, &target.host));
        plain_to_this_machine = !target.tls && this_machine;
        if !target.tls && !this_machine && test_server(&state, &target.host).is_none() {
            let reason = DenyReason::Guard {
                reason: format!("{} gets credentials only over HTTPS", target.host),
            };
            return deny(ev, reason);
        }
        // The client's own credentials go whether or not the gate adds one: a method outside
        // a credential's goes without any.
        for h in AUTH_HEADERS {
            parts.headers.remove(*h);
        }
        let injections = policy.injections_for(&method, &target.host, &path);
        if !injections.is_empty() {
            let Some(vault) = state.vault() else {
                return deny(ev, DenyReason::Locked);
            };
            let mut used = Vec::new();
            for inj in injections {
                let secret = match vault.get(&inj.binding).await {
                    Ok(secret) => secret,
                    Err(CredentialError::Locked) => return deny(ev, DenyReason::Locked),
                    Err(CredentialError::NotBound) => {
                        let reason = DenyReason::Guard {
                            reason: format!(
                                "credential `{}` is not registered with the vault; run `luoto up -e {}` on the host",
                                inj.binding, state.cfg.env
                            ),
                        };
                        return deny(ev, reason);
                    }
                    Err(CredentialError::Failed(m)) => {
                        let msg = format!("vault unavailable: {m}");
                        return failed(&state, ev, StatusCode::BAD_GATEWAY, msg);
                    }
                };
                match apply(&mut parts, inj, &secret) {
                    Ok(forms) => placed.extend(forms),
                    Err(e) => {
                        let msg = format!("credential `{}`: {e}", inj.binding);
                        return failed(&state, ev, StatusCode::BAD_GATEWAY, msg);
                    }
                }
                used.push(inj.binding.clone());
            }
            used.dedup();
            ev.binding = Some(used.join(","));
        }
    }
    // Screening reads the response: ask for it uncompressed.
    placed.retain(|p| p.len() >= 8);
    if !placed.is_empty() {
        parts.headers.insert(
            http::header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    }

    if let Some(max) = max_body {
        body = Capped::new(body, max).boxed();
    }
    let up_bytes = Arc::new(AtomicU64::new(0));
    let counter = up_bytes.clone();
    body = Metered::new(body, move |n| counter.store(n, Ordering::Relaxed)).boxed();
    // A long upload is progress, so the response-head limit counts from its last byte.
    body = watched(body, ctx.activity.clone());

    let reach = Reach {
        private: allow_private,
        private_only: plain_to_this_machine,
    };
    let mut sender = match ctx.sender(&state, &target, reach).await {
        Ok(s) => s,
        Err(DialError::Denied(reason)) => return deny(ev, reason),
        Err(DialError::Failed(msg)) => return failed(&state, ev, StatusCode::BAD_GATEWAY, msg),
    };
    let lim = state.cfg.limits;
    let head = lim.response_head;
    let sent = tokio::select! {
        r = sender.send_request(Request::from_parts(parts, body)) => r,
        () = ctx.activity.stalled(head, head) => {
            let waited = head.max(ctx.activity.idle_or(Duration::ZERO));
            let msg = format!("{} sent no response within {}", target.host, limits::spell(waited));
            return failed(&state, ev, StatusCode::GATEWAY_TIMEOUT, msg);
        }
    };
    ctx.activity.touch();
    let mut resp = match sent {
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
            let slot = ctx.slot();
            tokio::spawn(async move {
                let _slot = slot;
                if let (Ok(c), Ok(s)) = (client_upgrade.await, server_upgrade.await) {
                    let mut s = TokioIo::new(s);
                    let idle = rule_idle.unwrap_or(lim.tunnel_idle);
                    limits::pipe(TokioIo::new(c), &mut s, idle, std::future::pending()).await;
                }
            });
        }
    } else {
        ctx.put_back(&target, reach, sender).await;
    }

    let (mut rparts, rbody) = boxed_parts(resp);
    // A response that streams on is progress for the connection's idle limit.
    let mut rbody = watched(rbody, ctx.activity.clone());
    if status != StatusCode::SWITCHING_PROTOCOLS {
        strip_hop_by_hop(&mut rparts.headers, false);
        if !placed.is_empty() {
            let idle = ctx.activity.idle_or(lim.idle);
            let screened = tokio::select! {
                r = screen(&mut rparts.headers, rbody, &placed) => r,
                () = ctx.activity.stalled(idle, idle) => {
                    let msg = format!("{} stopped sending for {}", target.host, limits::spell(idle));
                    return failed(&state, ev, StatusCode::GATEWAY_TIMEOUT, msg);
                }
            };
            rbody = match screened {
                Ok(b) => b,
                Err(reason) => return failed(&state, ev, StatusCode::BAD_GATEWAY, reason),
            };
        }
    }
    ev.verdict = Some(Verdict::Allow);
    ev.status = Some(status.as_u16());
    let state2 = state.clone();
    let metered = Metered::new(rbody, move |down| {
        ev.bytes_down = Some(down);
        ev.bytes_up = Some(up_bytes.load(Ordering::Relaxed));
        ev.ms = Some(started.elapsed().as_millis() as u64);
        state2.events.emit(ev);
    });
    Response::from_parts(rparts, metered.boxed())
}

fn boxed_parts(resp: Response<Incoming>) -> (http::response::Parts, Body) {
    let (parts, body) = resp.into_parts();
    (parts, boxed(body))
}

/// The most of a response's start [`screen`] reads: a JSON one whole up to this, so an echo
/// in it can be taken out (LFS batch answers), any other this far.
const SCREEN_JSON: usize = 1 << 20;
const SCREEN_HEAD: usize = 64 << 10;

/// Keep a credential the gate put on a request from coming back in its response: refused in a
/// header; taken out of a JSON body that echoes it (Gitea and GitLab copy the request's
/// `Authorization` into their LFS batch answer, for the client to send on, and the gate adds
/// it to that request itself); anything else that carries it is refused.
async fn screen(
    headers: &mut HeaderMap,
    mut body: Body,
    placed: &[String],
) -> Result<Body, String> {
    let carries = |b: &[u8]| {
        placed
            .iter()
            .any(|p| b.windows(p.len()).any(|w| w == p.as_bytes()))
    };
    if headers.values().any(|v| carries(v.as_bytes())) {
        return Err("the response carried the request's credential back".into());
    }
    let json = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|t| t.contains("json"));
    let limit = if json { SCREEN_JSON } else { SCREEN_HEAD };
    let mut head = bytes::BytesMut::new();
    let mut ended = false;
    while head.len() < limit {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    head.extend_from_slice(&data);
                }
            }
            Some(Err(e)) => return Err(format!("reading the response: {e}")),
            None => {
                ended = true;
                break;
            }
        }
    }
    if !carries(&head) {
        return Ok(crate::body::prefixed(head.freeze(), body));
    }
    if json
        && ended
        && let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&head)
    {
        redact(&mut v, &carries);
        let out = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
        if !carries(&out) {
            headers.insert(CONTENT_LENGTH, HeaderValue::from(out.len()));
            return Ok(crate::body::full(out));
        }
    }
    Err("the response carried the request's credential back".into())
}

/// Drop every object member whose string value `carries` the credential, and blank such
/// strings in arrays.
fn redact(v: &mut serde_json::Value, carries: &dyn Fn(&[u8]) -> bool) {
    match v {
        serde_json::Value::Object(m) => {
            m.retain(|_, x| !x.as_str().is_some_and(|s| carries(s.as_bytes())));
            for x in m.values_mut() {
                redact(x, carries);
            }
        }
        serde_json::Value::Array(a) => {
            for x in a.iter_mut() {
                if x.as_str().is_some_and(|s| carries(s.as_bytes())) {
                    *x = serde_json::Value::String(String::new());
                } else {
                    redact(x, carries);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_echoed_credential_is_taken_out_of_json() {
        // Gitea's LFS batch answer, with the request's Authorization copied in.
        let mut v: serde_json::Value = serde_json::from_str(
            r#"{"objects":[{"oid":"ab","actions":{"upload":{"href":"https://f/x.git/info/lfs/objects/ab",
            "header":{"Authorization":"Basic ZGV2OnNlY3JldHRva2Vu","Accept":"x"}}}}],
            "list":["Basic ZGV2OnNlY3JldHRva2Vu","ok"]}"#,
        )
        .unwrap();
        let placed = [
            "secrettoken".to_string(),
            "ZGV2OnNlY3JldHRva2Vu".to_string(),
        ];
        let carries = |b: &[u8]| {
            placed
                .iter()
                .any(|p| b.windows(p.len()).any(|w| w == p.as_bytes()))
        };
        redact(&mut v, &carries);
        let out = serde_json::to_string(&v).unwrap();
        assert!(!carries(out.as_bytes()), "{out}");
        assert!(out.contains("\"Accept\":\"x\"") && out.contains("objects/ab"));
    }
}
