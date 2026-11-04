//! Transparent catch-all for connections that bypass the proxy (tools that ignore
//! HTTPS_PROXY, raw IPs). iptables redirects all TCP from the sandbox here; the original
//! destination tells us the fake-IP name or the IP literal, then TLS/HTTP go through the
//! same policy. The client's chosen IP is never dialed — only the policy host, resolved by
//! the gate itself.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use luoto_shared::events::{Event, EventKind, Intake, Verdict};
use luoto_shared::host::split_authority;
use tokio::net::{TcpListener, TcpStream};

use crate::dns::FakeIps;
use crate::handler::{ConnCtx, Target, handle};
use crate::mitm::{self, Expect};
use crate::respond;
use crate::state::State;

const SO_ORIGINAL_DST: libc::c_int = 80;

fn original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    // SAFETY: getsockopt writes at most `len` bytes into `addr`, a properly sized and
    // zero-initialised sockaddr_in owned by this frame.
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok(SocketAddr::new(IpAddr::V4(ip), u16::from_be(addr.sin_port)))
}

fn looks_like_http(b: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC", b"CONN", b"TRAC",
    ];
    METHODS.iter().any(|m| b.starts_with(m))
}

pub async fn serve(state: Arc<State>, listener: TcpListener) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move { conn(state, stream).await });
    }
}

fn direct(state: &State, host: String, port: u16, message: String) {
    state.events.emit(Event {
        kind: Some(EventKind::Direct),
        intake: Some(Intake::Transparent),
        verdict: Some(Verdict::Deny),
        host: Some(host),
        port: Some(port),
        reason: Some("not_http".into()),
        message: Some(message),
        ..Default::default()
    });
}

async fn conn(state: Arc<State>, stream: TcpStream) {
    let Ok(dst) = original_dst(&stream) else {
        return;
    };
    let IpAddr::V4(ip) = dst.ip() else {
        return;
    };
    let name = if FakeIps::is_fake(ip) {
        let name = state
            .fake_ips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .name_for(ip);
        if name.is_none() {
            direct(
                &state,
                ip.to_string(),
                dst.port(),
                "connection to an unknown or expired fake address".into(),
            );
            return;
        }
        name
    } else {
        None
    };
    let label = name.clone().unwrap_or_else(|| ip.to_string());

    let mut peek = [0u8; 8];
    let n = match tokio::time::timeout(Duration::from_secs(10), stream.peek(&mut peek)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            direct(
                &state,
                label,
                dst.port(),
                "connection sent nothing (server-speaks-first protocol?)".into(),
            );
            return;
        }
    };
    if peek[0] == 0x16 {
        let expect = match name {
            Some(h) => Expect::Host(h),
            None => Expect::FromSni {
                fallback: ip.to_string(),
            },
        };
        mitm::serve(state, stream, expect, dst.port(), Intake::Transparent).await;
        return;
    }
    // Git over SSH, to hosts `[credentials.ssh]` names (as tunnel rules on their port),
    // passed through as it is: the vault's agent signs the login, for pinned host keys only.
    if peek[..n].starts_with(b"SSH-") {
        let port = dst.port();
        let rule = name.as_deref().and_then(|h| {
            state
                .policy()
                .tunnel_rule(h, port, chrono::Utc::now())
                .map(|r| (h.to_string(), r.id.clone(), r.rule.allow_private))
        });
        let Some((host, rule_id, allow_private)) = rule else {
            direct(
                &state,
                label.clone(),
                port,
                format!(
                    "SSH to {label}:{port} was refused; `[credentials.ssh] hosts` lists where git over SSH may go"
                ),
            );
            return;
        };
        match crate::upstream::dial_tcp(&state, &host, port, allow_private).await {
            Ok(upstream) => {
                crate::proxy::splice(
                    state,
                    stream,
                    upstream,
                    host,
                    port,
                    rule_id,
                    Intake::Transparent,
                )
                .await;
            }
            Err(crate::upstream::DialError::Denied(reason)) => {
                direct(&state, label, port, reason.message(&host));
            }
            Err(crate::upstream::DialError::Failed(msg)) => direct(&state, label, port, msg),
        }
        return;
    }
    if !looks_like_http(&peek[..n]) {
        direct(
            &state,
            label.clone(),
            dst.port(),
            format!(
                "non-HTTP connection to {label}:{} bypassing the proxy was refused; only HTTP(S) leaves the sandbox",
                dst.port()
            ),
        );
        return;
    }

    let ctx = Arc::new(ConnCtx::new(Intake::Transparent));
    let port = dst.port();
    let svc = service_fn(move |req: http::Request<hyper::body::Incoming>| {
        let state = state.clone();
        let ctx = ctx.clone();
        let name = name.clone();
        async move {
            let host = match name {
                Some(n) => Some(n),
                None => req
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| split_authority(v).ok())
                    .map(|(h, _)| h),
            };
            let Some(host) = host else {
                return Ok(respond::plain(
                    http::StatusCode::BAD_REQUEST,
                    "luoto gate: request without a Host header\n",
                ));
            };
            handle(
                state,
                ctx,
                req,
                Target {
                    host,
                    port,
                    tls: false,
                },
            )
            .await
        }
    });
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(60))
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await;
}
