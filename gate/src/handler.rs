//! One HTTP request through the gate, whichever way it arrived (explicit proxy, intercepted
//! TLS, transparent catch-all): agree on the destination, decide, apply guards and
//! credentials, forward, meter, record.

use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use chrono::Utc;
use http::header::{
    CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, TE, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version};
use http_body_util::BodyExt;
use hyper::body::{Frame, Incoming};
use hyper::client::conn::{http1 as client1, http2 as client2};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use luoto_shared::creds::{AUTH_HEADERS, AUTH_QUERY_PARAMS, CredentialError, strip_query};
use luoto_shared::events::{Event, EventKind, Intake, Verdict, clip_path};
use luoto_shared::host::{canonical_path, split_authority};
use luoto_shared::policy::{Decision, DenyReason, RequestInfo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::body::{Body, Capped, Metered, boxed, finally, idle_limited, is_too_large, watched};
use crate::creds::apply;
use crate::guards;
use crate::imds;
use crate::limits::{
    self, Activity, H1_UPSTREAMS, HEAD_GRACE, Limits, MAX_STREAMS, STREAMS_OPEN, Slot, Watched,
};
use crate::redirects::Url;
use crate::respond;
use crate::screen::screen;
use crate::state::State;
use crate::upstream::{
    CONN_WINDOW, DialError, MAX_HEADER_LIST, Reach, SEND_BUF, STREAM_WINDOW, dial, http1_sender,
    http2_sender, test_server,
};

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

/// Per client connection: how it arrived, its place under the connection cap, its progress
/// and its upstream connections. Each HTTP/2 stream has one of its own ([`ConnCtx::stream`]).
pub struct ConnCtx {
    pub intake: Intake,
    slot: Slot,
    pub activity: Arc<Activity>,
    upstreams: Arc<Upstreams>,
    /// An HTTP/2 connection's open streams, each until its response ends.
    streams: Mutex<Vec<Weak<Activity>>>,
}

impl ConnCtx {
    pub fn new(intake: Intake, slot: Slot) -> Self {
        ConnCtx {
            intake,
            slot,
            activity: Activity::new(),
            upstreams: Arc::new(Upstreams::new()),
            streams: Mutex::new(Vec::new()),
        }
    }

    /// For one HTTP/2 stream: the connection's place, intake and upstream connections, and
    /// progress of its own.
    fn stream(&self) -> Self {
        let activity = Activity::new();
        lock(&self.streams).push(Arc::downgrade(&activity));
        ConnCtx {
            intake: self.intake,
            slot: self.slot.clone(),
            activity,
            upstreams: self.upstreams.clone(),
            streams: Mutex::new(Vec::new()),
        }
    }

    /// Resolves once an open stream has sat still past its idle limit without being ended:
    /// its response waits on room the client doesn't make, and hyper reads a body, where that
    /// limit is kept, only once there is room. The connection goes, as an HTTP/1.1 one that
    /// stops reading does.
    async fn stuck_stream(&self, idle: Duration) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let mut streams = lock(&self.streams);
            streams.retain(|s| s.strong_count() > 0);
            let stuck = streams
                .iter()
                .filter_map(Weak::upgrade)
                .any(|s| !s.is_busy() && s.still() >= s.idle_or(idle) + HEAD_GRACE);
            if stuck {
                return;
            }
        }
    }

    /// For a task that carries the connection on after an upgrade.
    pub fn slot(&self) -> Slot {
        self.slot.clone()
    }

    /// A connection to send a request for `t` on: HTTP/2 where the client speaks it and the
    /// server takes it, shared by the client's streams; otherwise HTTP/1.1, one request at a
    /// time, at most `H1_UPSTREAMS` of them in use, kept between requests.
    async fn sender(
        &self,
        state: &State,
        t: &Target,
        reach: Reach,
        h2: bool,
    ) -> Result<Sender, DialError> {
        let up = &self.upstreams;
        let dest = Dest::of(t);
        let h2 = h2 && t.tls;
        if h2 && !up.h1_only(&dest) {
            if let Some(s) = up.kept_h2(&dest, reach) {
                return Ok(Sender::H2(s));
            }
            // The first streams wait for one dial and share what it makes.
            let dialing = up.dialing.lock().await;
            if let Some(s) = up.kept_h2(&dest, reach) {
                return Ok(Sender::H2(s));
            }
            if !up.h1_only(&dest) {
                let dialed = dial(state, &t.host, t.port, t.tls, reach, true).await?;
                if dialed.h2 {
                    let sender = http2_sender(dialed.io).await?;
                    *lock(&up.h2) = Some(Kept {
                        dest,
                        reach,
                        sender: sender.clone(),
                    });
                    return Ok(Sender::H2(sender));
                }
                *lock(&up.h1_only) = Some(dest);
                drop(dialing);
                let permit = up.in_use().await;
                return Ok(Sender::H1 {
                    sender: http1_sender(dialed.io).await?,
                    permit,
                });
            }
        }
        let permit = up.in_use().await;
        while let Some(mut kept) = up.take_h1(&dest, reach) {
            if kept.sender.ready().await.is_ok() {
                return Ok(Sender::H1 {
                    sender: kept.sender,
                    permit,
                });
            }
        }
        up.make_room();
        let dialed = dial(state, &t.host, t.port, t.tls, reach, false).await?;
        Ok(Sender::H1 {
            sender: http1_sender(dialed.io).await?,
            permit,
        })
    }
}

/// Where an upstream connection goes.
#[derive(Clone, PartialEq)]
struct Dest {
    host: String,
    port: u16,
    tls: bool,
}

impl Dest {
    fn of(t: &Target) -> Self {
        Dest {
            host: t.host.clone(),
            port: t.port,
            tls: t.tls,
        }
    }
}

/// An upstream connection kept for later requests, and what its dial could reach: a request
/// reuses it only where its own decision allows as much.
struct Kept<S> {
    dest: Dest,
    reach: Reach,
    sender: S,
}

impl<S> Kept<S> {
    fn fits(&self, dest: &Dest, reach: Reach) -> bool {
        self.dest == *dest && self.reach.serves(reach)
    }
}

/// A client connection's upstream connections.
struct Upstreams {
    h2: Mutex<Option<Kept<client2::SendRequest<Body>>>>,
    /// The destination that last answered an offer of HTTP/2 with HTTP/1.1.
    h1_only: Mutex<Option<Dest>>,
    /// HTTP/1.1 connections between requests; with those in use, at most `H1_UPSTREAMS`.
    h1: Mutex<Vec<Kept<client1::SendRequest<Body>>>>,
    in_use: Arc<Semaphore>,
    dialing: tokio::sync::Mutex<()>,
}

/// A connection to send one request on; an HTTP/1.1 one holds its place among those in use.
enum Sender {
    H1 {
        sender: client1::SendRequest<Body>,
        permit: OwnedSemaphorePermit,
    },
    H2(client2::SendRequest<Body>),
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Upstreams {
    fn new() -> Self {
        Upstreams {
            h2: Mutex::new(None),
            h1_only: Mutex::new(None),
            h1: Mutex::new(Vec::new()),
            in_use: Arc::new(Semaphore::new(H1_UPSTREAMS)),
            dialing: tokio::sync::Mutex::new(()),
        }
    }

    fn h1_only(&self, dest: &Dest) -> bool {
        lock(&self.h1_only).as_ref() == Some(dest)
    }

    fn kept_h2(&self, dest: &Dest, reach: Reach) -> Option<client2::SendRequest<Body>> {
        lock(&self.h2)
            .as_ref()
            .filter(|k| k.fits(dest, reach) && !k.sender.is_closed())
            .map(|k| k.sender.clone())
    }

    async fn in_use(&self) -> OwnedSemaphorePermit {
        self.in_use
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore stays open")
    }

    fn take_h1(&self, dest: &Dest, reach: Reach) -> Option<Kept<client1::SendRequest<Body>>> {
        let mut kept = lock(&self.h1);
        let i = kept.iter().position(|k| k.fits(dest, reach))?;
        Some(kept.remove(i))
    }

    /// Close kept connections, oldest first, until one more fits under `H1_UPSTREAMS`.
    fn make_room(&self) {
        let in_use = H1_UPSTREAMS - self.in_use.available_permits();
        let mut kept = lock(&self.h1);
        while !kept.is_empty() && kept.len() + in_use > H1_UPSTREAMS {
            kept.remove(0);
        }
    }

    /// `sender` is free again; its place among those in use goes once it is kept.
    fn give_back(
        &self,
        dest: Dest,
        reach: Reach,
        sender: client1::SendRequest<Body>,
        permit: OwnedSemaphorePermit,
    ) {
        lock(&self.h1).push(Kept {
            dest,
            reach,
            sender,
        });
        drop(permit);
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

/// Serve HTTP/2 from the sandbox on `io`, every stream a request to `target` with limits of
/// its own, as an HTTP/1.1 connection has, so a quiet stream or a denial ends no other. The
/// connection closes once no byte has moved for `limits.idle` with no stream open.
pub async fn serve_http2<IO>(io: IO, state: Arc<State>, ctx: Arc<ConnCtx>, target: Target)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = state.cfg.limits;
    let activity = ctx.activity.clone();
    let watched = Watched::new(io, activity.clone());
    let streams = ctx.clone();
    let service = service_fn(move |req| {
        let (state, ctx, target) = (state.clone(), ctx.clone(), target.clone());
        async move { Ok::<_, Infallible>(stream(state, &ctx, req, target).await) }
    });
    let conn = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .max_concurrent_streams(MAX_STREAMS)
        .max_header_list_size(MAX_HEADER_LIST)
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_send_buf_size(SEND_BUF)
        .serve_connection(TokioIo::new(watched), service);
    tokio::select! {
        _ = conn => {}
        () = activity.stalled(limits.idle, STREAMS_OPEN) => {}
        () = streams.stuck_stream(limits.idle) => {}
    }
}

/// One HTTP/2 stream: the connection counts it open until its response ends, and while it is
/// handled the response-head limit is the backstop, as for an HTTP/1.1 connection.
async fn stream(
    state: Arc<State>,
    conn: &ConnCtx,
    req: Request<Incoming>,
    target: Target,
) -> Response<Body> {
    let limits = state.cfg.limits;
    let open = conn.activity.busy();
    // The connection's idle limit counts from the end of its last stream: its last frames are
    // still to be written then.
    let connection = conn.activity.clone();
    let ctx = Arc::new(conn.stream());
    let busy = ctx.activity.busy();
    let resp = tokio::select! {
        r = handle(state, ctx.clone(), req, target) => match r {
            Ok(r) => r,
            Err(never) => match never {},
        },
        () = ctx.activity.stalled(limits.idle, limits.response_head + HEAD_GRACE) => {
            respond::plain(StatusCode::GATEWAY_TIMEOUT, "luoto gate: no response in time\n")
        }
    };
    drop(busy);
    // Open, for the connection's `stuck_stream`, until the response ends.
    let progress = ctx.activity.clone();
    resp.map(|body| {
        finally(body, move |_| {
            connection.touch();
            drop((open, progress));
        })
    })
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

/// Remove from `headers` each named in `names`, in any case and with `_` for `-`: servers
/// behind Rack, WSGI and some proxies read `x_api_key` as `x-api-key`.
fn strip_headers<'a>(headers: &mut HeaderMap, names: impl IntoIterator<Item = &'a str>) {
    let names: Vec<&str> = names.into_iter().collect();
    let same = |name: &str, stripped: &str| {
        name.len() == stripped.len()
            && name
                .bytes()
                .zip(stripped.bytes())
                .all(|(a, b)| a.eq_ignore_ascii_case(&b) || (a == b'_' && b == b'-'))
    };
    let doomed: Vec<http::HeaderName> = headers
        .keys()
        .filter(|k| names.iter().any(|n| same(k.as_str(), n)))
        .cloned()
        .collect();
    for k in doomed {
        headers.remove(k);
    }
}

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
/// The longest method the gate forwards: every real one (WebDAV's included) is far shorter.
const MAX_METHOD: usize = 32;

pub fn canonical_request(method: &str, raw_path: &str) -> Result<String, DenyReason> {
    if method.len() > MAX_METHOD {
        return Err(DenyReason::Guard {
            reason: format!("a method of over {MAX_METHOD} bytes is not allowed"),
        });
    }
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

/// The destination is decided once, by the caller; the request may not disagree, in `Host`
/// or in its URI's authority (HTTP/2's `:authority`, an absolute-form target).
pub fn host_agrees(headers: &HeaderMap, uri: &Uri, target: &Target) -> bool {
    let agrees = |s: &str| {
        split_authority(s)
            .is_ok_and(|(h, p)| h == target.host && p.is_none_or(|p| p == target.port))
    };
    let mut hosts = headers.get_all(HOST).iter();
    let header = match (hosts.next(), hosts.next()) {
        (None, _) => true,
        (Some(h), None) => h.to_str().is_ok_and(agrees),
        (Some(_), Some(_)) => false,
    };
    header && uri.authority().is_none_or(|a| agrees(a.as_str()))
}

/// A gRPC request: its client reads the outcome from `grpc-status`, not the HTTP status.
fn is_grpc(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .is_some_and(|v| v.as_bytes().starts_with(b"application/grpc"))
}

#[allow(clippy::too_many_arguments)]
fn denied(
    state: &State,
    mut ev: Event,
    method: &str,
    url: &str,
    host: &str,
    path: &str,
    reason: DenyReason,
    grpc: bool,
) -> Response<Body> {
    ev.verdict = Some(Verdict::Deny);
    ev.reason = Some(reason.code().to_string());
    ev.message = Some(reason.message(host));
    let env = &state.cfg.env;
    let resp = if grpc {
        respond::deny_grpc(env, method, url, host, path, &reason)
    } else {
        respond::deny(env, method, url, host, path, &reason)
    };
    ev.status = Some(resp.status().as_u16());
    state.events.emit(ev);
    resp
}

fn failed(
    state: &State,
    mut ev: Event,
    status: StatusCode,
    msg: String,
    grpc: bool,
) -> Response<Body> {
    ev.verdict = Some(Verdict::Allow);
    ev.status = Some(status.as_u16());
    ev.message = Some(msg.clone());
    state.events.emit(ev);
    let msg = format!("luoto gate: {msg}");
    if grpc {
        let code = if status == StatusCode::GATEWAY_TIMEOUT {
            respond::GRPC_DEADLINE_EXCEEDED
        } else {
            respond::GRPC_UNAVAILABLE
        };
        return respond::grpc(code, &msg);
    }
    respond::plain(status, format!("{msg}\n"))
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
        // HTTP takes a method of any length; an event line keeps a bounded one.
        method: Some(method.get(..MAX_METHOD).unwrap_or(&method).to_string()),
        host: Some(target.host.clone()),
        port: Some(target.port),
        path: Some(clip_path(&path)),
        ..Default::default()
    };
    let client_h2 = req.version() == Version::HTTP_2;
    let grpc = is_grpc(req.headers());
    let deny = |ev: Event, reason: DenyReason| {
        denied(&state, ev, &method, &url, &target.host, &path, reason, grpc)
    };
    let fail = |ev: Event, status: StatusCode, msg: String| failed(&state, ev, status, msg, grpc);
    if let Some(reason) = refused {
        return deny(ev, reason);
    }
    if client_h2 && method == "CONNECT" {
        let reason = DenyReason::Guard {
            reason: "CONNECT inside an HTTP/2 connection is not allowed".into(),
        };
        return deny(ev, reason);
    }

    if !host_agrees(req.headers(), req.uri(), &target) {
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

    // Before the policy: a policy applied in between leaves this request's redirect ungranted.
    let generation = state.redirects.generation();
    let policy = state.policy();
    let info = RequestInfo {
        host: &target.host,
        port: target.port,
        method: &method,
        path: &path,
        websocket,
        content_length,
    };
    // A URL an allowed redirect named goes through on its permit, unless a deny refuses it.
    let here = Url::of(target.tls, &target.host, target.port, &path, query);
    let permit = state.redirects.allows(&method, &here, Instant::now());
    let decision = match &permit {
        Some(granted) => match policy.explicitly_denied(&info) {
            Some(reason) => Decision::Deny(reason),
            None => Decision::Allow {
                rule: format!("redirect from {}", granted.from),
                max_body: None,
                allow_private: granted.private,
                idle: None,
            },
        },
        None => policy.decide(&info, Utc::now()),
    };
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
    // A gRPC stream may sit quiet as long as a tunnel, unless the rule says otherwise.
    let lim = state.cfg.limits;
    let rule_idle = rule_idle.or(grpc.then_some(lim.tunnel_idle));
    // Every wait on this connection (an HTTP/2 stream: on this stream) follows the rule until
    // the next request is decided.
    ctx.activity.set_rule_idle(rule_idle);
    let mut ev = ev;
    ev.rule = Some(rule.clone());

    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));
    let (mut parts, incoming) = req.into_parts();

    // From here `parts` is what upstream gets: guards judge it, and credentials go in last, so
    // neither a header the client lists in `Connection` nor its own query can displace them.
    // `te: trailers` stays: gRPC servers refuse a request without it.
    let trailers = parts
        .headers
        .get(TE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"trailers"));
    strip_hop_by_hop(&mut parts.headers, websocket);
    if trailers {
        parts
            .headers
            .insert(TE, HeaderValue::from_static("trailers"));
    }
    parts.uri = match format!("{path}{query}").parse() {
        Ok(u) => u,
        Err(_) => return deny(ev, DenyReason::InvalidHost),
    };
    if let Ok(v) = HeaderValue::from_str(&target.authority()) {
        parts.headers.insert(HOST, v);
    }
    // The signed URL is the whole authorization: storage refuses a request that carries
    // another, and nothing of the client's own goes with it.
    if permit.is_some() {
        strip_headers(&mut parts.headers, AUTH_HEADERS.iter().copied());
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
        // A path the rules read one way would reach another (npm's `@scope%2fname` passes).
        if luoto_shared::host::hides_a_path(&path) {
            let reason = DenyReason::Guard {
                reason: format!(
                    "paths with `;` or an escaped slash (other than npm's `@scope%2fname`) are not allowed to {}",
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
        let (headers, params) = policy.credential_names(&target.host);
        let names: Vec<String> = AUTH_HEADERS
            .iter()
            .copied()
            .chain(headers)
            .map(str::to_string)
            .collect();
        strip_headers(&mut parts.headers, names.iter().map(String::as_str));
        // And from a request's trailers, which a server may read as headers.
        body = body
            .map_frame(move |frame| match frame.into_trailers() {
                Ok(mut trailers) => {
                    strip_headers(&mut trailers, names.iter().map(String::as_str));
                    Frame::trailers(trailers)
                }
                Err(frame) => frame,
            })
            .boxed();
        let params: Vec<&str> = AUTH_QUERY_PARAMS.iter().copied().chain(params).collect();
        if let Some(query) = parts.uri.query().and_then(|q| strip_query(q, &params)) {
            let path = parts.uri.path();
            let uri = if query.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{query}")
            };
            let Ok(uri) = uri.parse() else {
                let reason = DenyReason::Guard {
                    reason: "the request's query could not be rewritten".into(),
                };
                return deny(ev, reason);
            };
            parts.uri = uri;
        }
        let injections = policy.injections_for(&method, &target.host, target.port, &path);
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
                        return fail(ev, StatusCode::BAD_GATEWAY, msg);
                    }
                };
                match apply(&mut parts, inj, &secret) {
                    Ok(forms) => placed.extend(forms),
                    Err(e) => {
                        let msg = format!("credential `{}`: {e}", inj.binding);
                        return fail(ev, StatusCode::BAD_GATEWAY, msg);
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
    body = Metered::new(body, move |n, _| counter.store(n, Ordering::Relaxed)).boxed();
    // A long upload is progress, so the response-head limit counts from its last byte.
    body = watched(body, ctx.activity.clone());

    let reach = Reach {
        private: allow_private,
        private_only: plain_to_this_machine,
    };
    let mut sender = match ctx.sender(&state, &target, reach, client_h2).await {
        Ok(s) => s,
        Err(DialError::Denied(reason)) => return deny(ev, reason),
        Err(DialError::Failed(msg)) => return fail(ev, StatusCode::BAD_GATEWAY, msg),
    };
    if let Sender::H2(_) = sender {
        // HTTP/2 takes the destination from the URI (`:authority`), never from `Host`.
        parts.version = Version::HTTP_2;
        parts.headers.remove(HOST);
        let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        parts.uri = match absolute(&target, pq) {
            Some(u) => u,
            None => return deny(ev, DenyReason::InvalidHost),
        };
    } else {
        parts.version = Version::HTTP_11;
        join_cookies(&mut parts.headers);
    }
    let head = lim.response_head;
    let request = Request::from_parts(parts, body);
    let sending = async {
        match &mut sender {
            Sender::H1 { sender, .. } => sender.send_request(request).await,
            Sender::H2(sender) => sender.send_request(request).await,
        }
    };
    let sent = tokio::select! {
        r = sending => r,
        () = ctx.activity.stalled(head, head) => {
            let waited = head.max(ctx.activity.idle_or(Duration::ZERO));
            let msg = format!("{} sent no response within {}", target.host, limits::spell(waited));
            return fail(ev, StatusCode::GATEWAY_TIMEOUT, msg);
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
            return fail(ev, StatusCode::BAD_GATEWAY, msg);
        }
    };
    let status = resp.status();
    let h1 = match sender {
        Sender::H1 { sender, permit } => Some((sender, permit)),
        Sender::H2(_) => None,
    };
    let mut give_back = None;
    if status == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let server_upgrade = hyper::upgrade::on(&mut resp);
            let slot = ctx.slot();
            // The upgraded connection keeps its place among those in use.
            let permit = h1.map(|(_, permit)| permit);
            tokio::spawn(async move {
                let _held = (slot, permit);
                if let (Ok(c), Ok(s)) = (client_upgrade.await, server_upgrade.await) {
                    let mut s = TokioIo::new(s);
                    let idle = rule_idle.unwrap_or(lim.tunnel_idle);
                    limits::pipe(TokioIo::new(c), &mut s, idle, std::future::pending()).await;
                }
            });
        }
    } else {
        give_back = h1;
    }

    let (mut rparts, mut rbody) = boxed_parts(resp);
    if !client_h2 {
        rparts.version = Version::HTTP_11;
    }
    // An HTTP/1.1 connection carries the next request once this response has been read to
    // its end; one dropped part read is closed.
    if let Some((sender, permit)) = give_back {
        let (up, dest) = (ctx.upstreams.clone(), Dest::of(&target));
        rbody = finally(rbody, move |ended| {
            if ended {
                up.give_back(dest, reach, sender, permit);
            }
        });
    }
    if status.is_redirection() && permit.is_none() {
        let to = policy.redirect_targets(&method, &target.host, &path);
        let location = rparts.headers.get(http::header::LOCATION);
        if let (false, Some(loc)) = (to.is_empty(), location.and_then(|l| l.to_str().ok())) {
            let plain = |host: &str| test_server(&state, host).is_some();
            if let Some(url) = Url::redirect(loc, &to, plain) {
                let private = policy.redirect_private(&target.host, &path, &url.host);
                state
                    .redirects
                    .grant(url, &rule, private, generation, Instant::now());
            }
        }
    }
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
                    return fail(ev, StatusCode::GATEWAY_TIMEOUT, msg);
                }
            };
            rbody = match screened {
                Ok(b) => b,
                Err(reason) => return fail(ev, StatusCode::BAD_GATEWAY, reason),
            };
        }
    }
    if client_h2 {
        rbody = idle_limited(rbody, ctx.activity.clone(), ctx.activity.idle_or(lim.idle));
    }
    ev.verdict = Some(Verdict::Allow);
    ev.status = Some(status.as_u16());
    let state2 = state.clone();
    let metered = Metered::new(rbody, move |down, error| {
        if error.is_some() {
            ev.message = error;
        }
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

/// `pq` at `target` in absolute form, as HTTP/2 names a request's destination; built from its
/// parts, so the path can't run into the authority (`OPTIONS *`).
fn absolute(target: &Target, pq: &str) -> Option<Uri> {
    Uri::builder()
        .scheme("https")
        .authority(target.authority())
        .path_and_query(pq)
        .build()
        .ok()
}

/// HTTP/2 may send each cookie in a field of its own; HTTP/1.1 takes them in one.
fn join_cookies(headers: &mut HeaderMap) {
    let cookies: Vec<&[u8]> = headers
        .get_all(COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    if cookies.len() < 2 {
        return;
    }
    if let Ok(v) = HeaderValue::from_bytes(&cookies.join(&b"; "[..])) {
        headers.insert(COOKIE, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clients_credentials_go_however_a_server_would_read_their_names() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x_api_key", "attacker"),
            ("Private_Token", "attacker"),
            ("authorization", "Bearer attacker"),
            ("x-request-id", "kept"),
            ("x_request_id", "kept"),
        ] {
            h.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        strip_headers(
            &mut h,
            AUTH_HEADERS.iter().copied().chain(["x-custom-auth"]),
        );
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["x-request-id", "x_request_id"]);
    }

    #[test]
    fn methods_are_upper_case_and_short() {
        assert!(canonical_request("PROPFIND", "/").is_ok());
        assert!(canonical_request("get", "/").is_err());
        let long = "A".repeat(MAX_METHOD + 1);
        let Err(DenyReason::Guard { reason }) = canonical_request(&long, "/") else {
            panic!("a long method passed");
        };
        assert!(!reason.contains(&long));
    }

    #[test]
    fn the_request_names_the_destination_only_as_decided() {
        let target = Target {
            host: "api.example".into(),
            port: 443,
            tls: true,
        };
        let agrees = |host: Option<&'static str>, uri: &str| {
            let mut h = HeaderMap::new();
            if let Some(host) = host {
                h.insert(HOST, HeaderValue::from_static(host));
            }
            host_agrees(&h, &uri.parse().unwrap(), &target)
        };
        // HTTP/2: `:authority`, no `Host`.
        assert!(agrees(None, "https://api.example/v1"));
        assert!(agrees(None, "https://api.example:443/v1"));
        assert!(!agrees(None, "https://other.example/v1"));
        assert!(!agrees(Some("api.example"), "https://other.example/v1"));
        assert!(!agrees(Some("other.example"), "https://api.example/v1"));
        // HTTP/1.1 in origin form.
        assert!(agrees(Some("api.example"), "/v1"));
        assert!(agrees(None, "/v1"));
        assert!(!agrees(Some("api.example:8443"), "/v1"));
    }

    #[test]
    fn an_http2_request_names_the_decided_destination_whatever_its_path() {
        let target = Target {
            host: "api.example".into(),
            port: 8443,
            tls: true,
        };
        let uri = |pq| absolute(&target, pq).map(|u| u.to_string());
        assert_eq!(
            uri("/v1/a?b=c").as_deref(),
            Some("https://api.example:8443/v1/a?b=c")
        );
        let star = absolute(&target, "*").unwrap();
        assert_eq!(star.authority().unwrap(), "api.example:8443");
        assert_eq!(star.path(), "*");
    }

    #[test]
    fn cookies_an_http2_client_split_go_on_in_one_field() {
        let mut h = HeaderMap::new();
        h.append(COOKIE, HeaderValue::from_static("a=1"));
        h.append(COOKIE, HeaderValue::from_static("b=2"));
        join_cookies(&mut h);
        let all: Vec<&HeaderValue> = h.get_all(COOKIE).iter().collect();
        assert_eq!(all, [&HeaderValue::from_static("a=1; b=2")]);
    }

    #[test]
    fn grpc_is_told_by_its_content_type() {
        let ct = |v: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(CONTENT_TYPE, HeaderValue::from_static(v));
            is_grpc(&h)
        };
        assert!(ct("application/grpc") && ct("application/grpc+proto"));
        assert!(ct("application/grpc-web+proto"));
        assert!(!ct("application/json") && !is_grpc(&HeaderMap::new()));
    }
}
