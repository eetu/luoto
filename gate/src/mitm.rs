//! TLS interception: terminate the client's TLS with a leaf minted by the env CA, then run
//! every request inside through the handler. Nothing is sent upstream until a request is
//! allowed, so a denied host sees no TCP, DNS or SNI from us.

use std::sync::Arc;
use std::time::Duration;

use luoto_shared::events::{EventKind, Intake};
use luoto_shared::host::normalize_host;
use luoto_shared::policy::DenyReason;
use rustls::AlertDescription;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::LazyConfigAcceptor;

use crate::handler::{ConnCtx, Target, handle, serve_http1};
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
            state.events.deny_conn(
                EventKind::Http,
                intake,
                &h,
                port,
                DenyReason::InvalidHost.code(),
                format!("TLS SNI `{s}` does not match the destination `{h}` (domain fronting)"),
            );
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
                state.events.deny_conn(
                    EventKind::TlsReject,
                    intake,
                    &host,
                    port,
                    "tls_reject",
                    format!(
                        "the client rejected the luoto certificate for {host}: it may pin certificates \
                         or ignore the CA bundle. If you trust it, allow it as a tunnel: \
                         luoto allow -e {} {host} --tunnel",
                        state.cfg.env
                    ),
                );
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
    serve_http1(tls, move |req| {
        handle(state.clone(), ctx.clone(), req, target.clone())
    })
    .await;
}

/// The client ended the handshake with an alert about our certificate. tokio-rustls hands the
/// handshake's `rustls::Error` back as the `io::Error`'s inner error.
fn is_certificate_rejection(e: &std::io::Error) -> bool {
    matches!(
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(
            AlertDescription::BadCertificate
                | AlertDescription::UnknownCA
                | AlertDescription::CertificateUnknown
                | AlertDescription::DecryptError
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_alerts_are_rejections() {
        let tls = |e: rustls::Error| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
        let alert = |a| tls(rustls::Error::AlertReceived(a));
        assert!(is_certificate_rejection(&alert(
            AlertDescription::UnknownCA
        )));
        assert!(is_certificate_rejection(&alert(
            AlertDescription::BadCertificate
        )));
        assert!(!is_certificate_rejection(&alert(
            AlertDescription::HandshakeFailure
        )));
        assert!(!is_certificate_rejection(&tls(rustls::Error::DecryptError)));
        assert!(!is_certificate_rejection(
            &std::io::ErrorKind::UnexpectedEof.into()
        ));
    }
}
