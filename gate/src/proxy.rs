//! The explicit proxy listener: CONNECT (intercepted or tunneled), absolute-form plain HTTP,
//! and origin-form requests to the gate itself (the in-sandbox API).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use luoto_shared::events::{Event, EventKind, Intake, Verdict};
use luoto_shared::host::split_authority;
use luoto_shared::policy::{DenyReason, Mode};
use tokio::net::TcpListener;

use crate::body::{Body, empty};
use crate::handler::{ConnCtx, Target, handle};
use crate::mitm::{self, Expect};
use crate::state::State;
use crate::upstream::{DialError, dial_tcp};
use crate::{api, respond};

pub async fn serve(state: Arc<State>, listener: TcpListener) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let state = state.clone();
        tokio::spawn(async move {
            let ctx = Arc::new(ConnCtx::new(Intake::Proxy));
            let svc = service_fn(move |req| route(state.clone(), ctx.clone(), req));
            let _ = http1::Builder::new()
                .preserve_header_case(true)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(60))
                .serve_connection(TokioIo::new(stream), svc)
                .with_upgrades()
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
        return Ok(connect(state, req).await);
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

async fn connect(state: Arc<State>, req: Request<Incoming>) -> Response<Body> {
    let authority = req.uri().authority().map(|a| a.as_str().to_string());
    let Some(Ok((host, port))) = authority.as_deref().map(split_authority) else {
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
    let policy = state.policy();
    let now = Utc::now();

    if policy.connect_mode(&host, port, now) == Mode::Tunnel {
        let rule = policy
            .tunnel_rule(&host, port, now)
            .map(|r| (r.id.clone(), r.rule.allow_private));
        let Some((rule_id, allow_private)) = rule else {
            return respond::plain(StatusCode::FORBIDDEN, "no tunnel rule\n");
        };
        let upstream = match dial_tcp(&state, &host, port, allow_private).await {
            Ok(s) => s,
            Err(DialError::Denied(reason)) => {
                let url = format!("{host}:{port}");
                let mut resp = respond::deny(&state.cfg.env, "CONNECT", &url, &host, &reason);
                state.events.emit(Event {
                    kind: Some(EventKind::Tunnel),
                    intake: Some(Intake::Proxy),
                    verdict: Some(Verdict::Deny),
                    host: Some(host.clone()),
                    port: Some(port),
                    reason: Some(reason.code().into()),
                    message: Some(reason.message(&host)),
                    ..Default::default()
                });
                *resp.status_mut() = StatusCode::FORBIDDEN;
                return resp;
            }
            Err(DialError::Failed(msg)) => {
                return respond::plain(StatusCode::BAD_GATEWAY, format!("{msg}\n"));
            }
        };
        tokio::spawn(tunnel(state.clone(), req, upstream, host, port, rule_id));
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
            )
            .await;
        }
    });
    Response::new(empty())
}

/// Opaque tunnel for a tunnel-mode rule; closed when the rule is removed or expires.
async fn tunnel(
    state: Arc<State>,
    req: Request<Incoming>,
    upstream: tokio::net::TcpStream,
    host: String,
    port: u16,
    rule_id: String,
) {
    let Ok(upgraded) = hyper::upgrade::on(req).await else {
        return;
    };
    splice(
        state,
        TokioIo::new(upgraded),
        upstream,
        host,
        port,
        rule_id,
        Intake::Proxy,
    )
    .await;
}

/// Copy both ways between the client and the upstream a tunnel rule allowed, until either
/// side closes or the rule is removed or expires; one event at the end.
pub async fn splice<C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    state: Arc<State>,
    mut client: C,
    upstream: tokio::net::TcpStream,
    host: String,
    port: u16,
    rule_id: String,
    intake: Intake,
) {
    let started = std::time::Instant::now();
    let mut upstream = upstream;
    let watch_state = state.clone();
    let watch_rule = rule_id.clone();
    let watchdog = async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let policy = watch_state.policy();
            let live = policy
                .rules
                .iter()
                .any(|r| r.id == watch_rule && !r.rule.expired(Utc::now()));
            if !live {
                return;
            }
        }
    };
    let (up, down) = tokio::select! {
        r = tokio::io::copy_bidirectional(&mut client, &mut upstream) => r.unwrap_or((0, 0)),
        _ = watchdog => (0, 0),
    };
    state.events.emit(Event {
        kind: Some(EventKind::Tunnel),
        intake: Some(intake),
        verdict: Some(Verdict::Allow),
        host: Some(host),
        port: Some(port),
        rule: Some(rule_id),
        bytes_up: Some(up),
        bytes_down: Some(down),
        ms: Some(started.elapsed().as_millis() as u64),
        ..Default::default()
    });
}
