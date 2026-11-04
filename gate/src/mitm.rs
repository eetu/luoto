//! TLS interception: terminate the client's TLS with a leaf minted by the env CA, then run
//! every request inside through the handler. Nothing is sent upstream until a request is
//! allowed, so a denied host sees no TCP, DNS or SNI from us.

use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use luoto_shared::events::{Event, EventKind, Intake, Verdict};
use luoto_shared::host::normalize_host;
use luoto_shared::policy::DenyReason;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::LazyConfigAcceptor;

use crate::handler::{ConnCtx, Target, handle};
use crate::state::State;

/// Who decides the hostname for this TLS connection.
pub enum Expect {
    /// The proxy CONNECT authority (or a fake-IP mapping); SNI must agree.
    Host(String),
    /// Unknown (raw IP dialed directly): use SNI, else the IP itself.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    FromSni { fallback: String },
}

pub async fn serve<IO>(state: Arc<State>, io: IO, expect: Expect, port: u16, intake: Intake)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(ca) = state.ca() else {
        return;
    };
    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io);
    let start = match tokio::time::timeout(Duration::from_secs(15), acceptor).await {
        Ok(Ok(s)) => s,
        _ => return,
    };
    let sni = start
        .client_hello()
        .server_name()
        .and_then(|s| normalize_host(s).ok());
    let host = match (expect, sni) {
        (Expect::Host(h), Some(s)) if s != h => {
            state.events.emit(Event {
                kind: Some(EventKind::Http),
                intake: Some(intake),
                verdict: Some(Verdict::Deny),
                host: Some(h.clone()),
                port: Some(port),
                reason: Some(DenyReason::InvalidHost.code().into()),
                message: Some(format!(
                    "TLS SNI `{s}` does not match the destination `{h}` (domain fronting)"
                )),
                ..Default::default()
            });
            return;
        }
        (Expect::Host(h), _) => h,
        (Expect::FromSni { .. }, Some(s)) => s,
        (Expect::FromSni { fallback }, None) => fallback,
    };
    let cfg = match ca.server_config(&host) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%host, error = %e, "could not mint certificate");
            return;
        }
    };
    let tls = match start.into_stream(cfg).await {
        Ok(t) => t,
        Err(e) => {
            if is_certificate_rejection(&e) {
                state.events.emit(Event {
                    kind: Some(EventKind::TlsReject),
                    intake: Some(intake),
                    verdict: Some(Verdict::Deny),
                    host: Some(host.clone()),
                    port: Some(port),
                    reason: Some("tls_reject".into()),
                    message: Some(format!(
                        "the client rejected the luoto certificate for {host}: it may pin certificates \
                         or ignore the CA bundle. If you trust it, allow it as a tunnel: \
                         luoto allow -e {} {host} --tunnel",
                        state.cfg.env
                    )),
                    ..Default::default()
                });
            }
            return;
        }
    };
    let ctx = Arc::new(ConnCtx::new(intake));
    let target = Target {
        host,
        port,
        tls: true,
    };
    let svc = service_fn(move |req| handle(state.clone(), ctx.clone(), req, target.clone()));
    let _ = http1::Builder::new()
        .preserve_header_case(true)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(60))
        .serve_connection(TokioIo::new(tls), svc)
        .with_upgrades()
        .await;
}

fn is_certificate_rejection(e: &std::io::Error) -> bool {
    let msg = e.to_string().to_ascii_lowercase();
    msg.contains("bad certificate")
        || msg.contains("badcertificate")
        || msg.contains("unknown ca")
        || msg.contains("unknownca")
        || msg.contains("certificate unknown")
        || msg.contains("certificateunknown")
        || msg.contains("decrypt error")
}
