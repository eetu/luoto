//! The explicit proxy listener: CONNECT (intercepted or tunneled), absolute-form plain HTTP,
//! and origin-form requests to the gate itself (the in-sandbox API).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use luoto_shared::events::{Event, EventKind, Intake, Verdict};
use luoto_shared::host::split_authority;
use luoto_shared::policy::DenyReason;
use tokio::net::TcpListener;

use crate::body::{Body, empty};
use crate::handler::{ConnCtx, Target, handle, serve_http1};
use crate::limits::{self, End, Slot};
use crate::mitm::{self, Expect};
use crate::state::State;
use crate::upstream::{DialError, dial_tcp};
use crate::{api, respond};

/// The answer to a connection over the cap, written without reading its request.
const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nconnection: close\r\n\r\n\
luoto gate: too many open connections\n";

pub async fn serve(state: Arc<State>, listener: TcpListener) {
    loop {
        let (stream, _peer) = limits::accept(&listener).await;
        let Some(slot) = limits::admit(&state, Intake::Proxy) else {
            let _ = stream.try_write(BUSY);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let state = state.clone();
        tokio::spawn(async move {
            let ctx = Arc::new(ConnCtx::new(Intake::Proxy, slot));
            let (activity, lim) = (ctx.activity.clone(), state.cfg.limits);
            serve_http1(stream, activity, lim, move |req| {
                route(state.clone(), ctx.clone(), req)
            })
            .await;
        });
    }
}

async fn route(
    state: Arc<State>,
    ctx: Arc<ConnCtx>,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    if req.method() == Method::CONNECT {
        return Ok(connect(state, ctx.slot(), req).await);
    }
    let absolute = req
        .uri()
        .scheme_str()
        .zip(req.uri().authority().map(|a| a.as_str().to_string()));
    if let Some((scheme, authority)) = absolute {
        let Ok((host, port)) = split_authority(&authority) else {
            return Ok(respond::plain(
                StatusCode::BAD_REQUEST,
                "invalid destination\n",
            ));
        };
        if state.is_self(&host) {
            return Ok(api::handle(state, req).await);
        }
        if scheme != "http" {
            return Ok(respond::plain(
                StatusCode::BAD_REQUEST,
                "use CONNECT for https through this proxy\n",
            ));
        }
        let target = Target {
            host,
            port: port.unwrap_or(80),
            tls: false,
        };
        return handle(state, ctx, req, target).await;
    }
    Ok(api::handle(state, req).await)
}

/// The client connection's `slot` goes with it into the tunnel or interception.
async fn connect(state: Arc<State>, slot: Slot, req: Request<Incoming>) -> Response<Body> {
    let authority = req.uri().authority().map(|a| a.as_str().to_string());
    let Some(Ok((host, port))) = authority.as_deref().map(split_authority) else {
        // No destination to record: the authority itself, clipped, says what was asked.
        state.events.emit(Event {
            kind: Some(EventKind::Http),
            intake: Some(Intake::Proxy),
            verdict: Some(Verdict::Deny),
            method: Some("CONNECT".into()),
            reason: Some(DenyReason::InvalidHost.code().into()),
            message: Some(format!(
                "invalid CONNECT authority {:?}",
                authority
                    .unwrap_or_default()
                    .chars()
                    .take(100)
                    .collect::<String>()
            )),
            ..Default::default()
        });
        return respond::plain(StatusCode::BAD_REQUEST, "invalid CONNECT authority\n");
    };
    let port = port.unwrap_or(443);
    if state.is_self(&host) {
        return respond::plain(StatusCode::BAD_REQUEST, "use plain http for the gate API\n");
    }

    let tunnel = state
        .policy()
        .tunnel_rule(&host, port, Utc::now())
        .map(|r| (r.id.clone(), r.rule.allow_private));
    if let Some((rule_id, allow_private)) = tunnel {
        let upstream = match dial_tcp(&state, &host, port, allow_private).await {
            Ok(s) => s,
            Err(DialError::Denied(reason)) => {
                state.events.deny_conn(
                    EventKind::Tunnel,
                    Intake::Proxy,
                    &host,
                    port,
                    reason.code(),
                    reason.message(&host),
                );
                let url = format!("{host}:{port}");
                return respond::deny(&state.cfg.env, "CONNECT", &url, &host, &reason);
            }
            Err(DialError::Failed(msg)) => {
                return respond::plain(StatusCode::BAD_GATEWAY, format!("{msg}\n"));
            }
        };
        tokio::spawn(async move {
            let _slot = slot;
            if let Ok(upgraded) = hyper::upgrade::on(req).await {
                let client = TokioIo::new(upgraded);
                splice(state, client, upstream, host, port, rule_id, Intake::Proxy).await;
            }
        });
        return Response::new(empty());
    }

    if state.ca().is_none() {
        return respond::plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "luoto gate has no CA yet; run `luoto up` on the host\n",
        );
    }
    tokio::spawn(async move {
        if let Ok(upgraded) = hyper::upgrade::on(req).await {
            mitm::serve(
                state,
                TokioIo::new(upgraded),
                Expect::Host(host),
                port,
                Intake::Proxy,
                slot,
            )
            .await;
        }
    });
    Response::new(empty())
}

/// Copy both ways between the client and the upstream a tunnel rule allowed, until either
/// side closes, nothing moves for the tunnel idle limit, or the rule is removed or expires;
/// one event at the end.
pub async fn splice<C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    state: Arc<State>,
    client: C,
    upstream: tokio::net::TcpStream,
    host: String,
    port: u16,
    rule_id: String,
    intake: Intake,
) {
    let started = std::time::Instant::now();
    let mut upstream = upstream;
    let watch_state = state.clone();
    let watch_host = host.clone();
    // Open only while a tunnel rule still admits it: expired, revoked or edited away all close it.
    let watchdog = async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let policy = watch_state.policy();
            if policy.tunnel_rule(&watch_host, port, Utc::now()).is_none() {
                return;
            }
        }
    };
    let idle = state.cfg.limits.tunnel_idle;
    let piped = limits::pipe(client, &mut upstream, idle, watchdog).await;
    let message = match piped.end {
        End::Closed => None,
        End::Idle => Some(format!(
            "closed after {} without traffic",
            limits::spell(idle)
        )),
        End::Stopped => Some("closed: no tunnel rule admits it any more".to_string()),
    };
    state.events.emit(Event {
        kind: Some(EventKind::Tunnel),
        intake: Some(intake),
        verdict: Some(Verdict::Allow),
        host: Some(host),
        port: Some(port),
        rule: Some(rule_id),
        message,
        bytes_up: Some(piped.up),
        bytes_down: Some(piped.down),
        ms: Some(started.elapsed().as_millis() as u64),
        ..Default::default()
    });
}
