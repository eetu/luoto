//! Dialing upstreams: resolve only after policy allowed the request, vet every address,
//! connect to exactly the vetted address, verify TLS for the policy host.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use luoto_shared::host::{is_never_dialed, is_private};
use luoto_shared::policy::DenyReason;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::body::Body;
use crate::state::State;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Debug)]
pub enum DialError {
    Denied(DenyReason),
    Failed(String),
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A local test server of the integration tests (`test-hooks` builds only): dialed at its
/// mapped address without the private-address check, and given credentials over plain HTTP.
/// Release builds have none.
pub fn test_server(state: &State, host: &str) -> Option<SocketAddr> {
    #[cfg(feature = "test-hooks")]
    return state
        .cfg
        .test_resolve
        .iter()
        .find(|(h, _)| h == host)
        .map(|(_, addr)| *addr);
    #[cfg(not(feature = "test-hooks"))]
    {
        let _ = (state, host);
        None
    }
}

/// Which addresses a dial may reach: private ones (`private`, a rule that allows them), and
/// only private ones (`private_only`, a credential going over plain HTTP).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Reach {
    pub private: bool,
    pub private_only: bool,
}

impl Reach {
    /// Whether a connection dialed under `self` may carry a request that needs `want`: one
    /// that may reach private addresses carries only requests that may too, and one that may
    /// reach public ones carries none that must stay private.
    pub fn serves(self, want: Reach) -> bool {
        (want.private || !self.private) && (!want.private_only || self.private_only)
    }
}

pub async fn dial_tcp(
    state: &State,
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<TcpStream, DialError> {
    dial_tcp_to(state, host, port, allow_private, false).await
}

/// [`dial_tcp`]; with `private_only`, every address `host` resolves to must be private: a
/// credential that goes over plain HTTP goes to this machine (a model server's host), never
/// where a DNS answer points it.
pub async fn dial_tcp_to(
    state: &State,
    host: &str,
    port: u16,
    allow_private: bool,
    private_only: bool,
) -> Result<TcpStream, DialError> {
    let mut addrs: Vec<SocketAddr> = if let Some(addr) = test_server(state, host) {
        vec![addr]
    } else {
        let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| DialError::Failed(format!("DNS lookup for {host} timed out")))?
                .map_err(|e| DialError::Failed(format!("DNS lookup for {host} failed: {e}")))?
                .collect()
        };
        if addrs.is_empty() {
            return Err(DialError::Failed(format!("{host} has no addresses")));
        }
        // Any private record taints the name: mixed answers are a rebinding trick.
        if addrs
            .iter()
            .any(|a| is_never_dialed(a.ip()) || (!allow_private && is_private(a.ip())))
        {
            return Err(DialError::Denied(DenyReason::PrivateAddress));
        }
        if private_only && addrs.iter().any(|a| !is_private(a.ip())) {
            return Err(DialError::Denied(DenyReason::Guard {
                reason: format!(
                    "{host} gets credentials over plain HTTP only on this machine, and it \
                     resolves elsewhere"
                ),
            }));
        }
        addrs
    };
    // IPv4 first: many networks (CI runners among them) have no IPv6 route, and each address
    // that can't connect costs a timeout.
    addrs.sort_by_key(|a| a.is_ipv6());
    // Every address and how it failed: why one family can't connect shows beside the other.
    let mut failed = Vec::new();
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => failed.push(format!("{addr}: {e}")),
            Err(_) => failed.push(format!("{addr}: connect timed out")),
        }
    }
    Err(DialError::Failed(format!(
        "could not connect to {host}:{port} ({})",
        failed.join("; ")
    )))
}

pub async fn dial(
    state: &State,
    host: &str,
    port: u16,
    tls: bool,
    reach: Reach,
) -> Result<Box<dyn Io>, DialError> {
    let tcp = dial_tcp_to(state, host, port, reach.private, reach.private_only).await?;
    if !tls {
        return Ok(Box::new(tcp));
    }
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| DialError::Failed(format!("invalid TLS name {host}")))?;
    let tls = state
        .host_tls
        .get(&host.to_ascii_lowercase())
        .unwrap_or(&state.client_tls);
    let connector = TlsConnector::from(Arc::clone(tls));
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| DialError::Failed(format!("TLS handshake with {host} timed out")))?
        .map_err(|e| DialError::Failed(format!("TLS handshake with {host} failed: {e}")))?;
    Ok(Box::new(stream))
}

pub async fn http1_sender(io: Box<dyn Io>) -> Result<SendRequest<Body>, DialError> {
    let (sender, conn) = http1::Builder::new()
        .preserve_header_case(true)
        .handshake(TokioIo::new(io))
        .await
        .map_err(|e| DialError::Failed(format!("HTTP handshake failed: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(sender)
}

#[cfg(test)]
mod reach_tests {
    use super::Reach;

    #[test]
    fn a_kept_connection_carries_only_requests_its_dial_was_vetted_for() {
        let public = Reach::default();
        let private = Reach {
            private: true,
            private_only: false,
        };
        let here = Reach {
            private: true,
            private_only: true,
        };
        assert!(public.serves(public) && private.serves(private) && here.serves(here));
        // A model server rule dialed it; open egress or an approved request must not ride it.
        assert!(!private.serves(public) && !here.serves(public));
        // A token over plain HTTP needs a dial that found only private addresses.
        assert!(!public.serves(here) && !private.serves(here));
        assert!(here.serves(private));
    }
}
