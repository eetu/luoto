//! Dialing upstreams: resolve only after policy allowed the request, vet every address,
//! connect to exactly the vetted address, verify TLS for the policy host.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use luoto_shared::host::is_private;
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

pub async fn resolve_vetted(
    state: &State,
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, DialError> {
    #[cfg(feature = "test-hooks")]
    if let Some((_, addr)) = state.cfg.test_resolve.iter().find(|(h, _)| h == host) {
        return Ok(vec![*addr]);
    }
    #[cfg(not(feature = "test-hooks"))]
    let _ = state;

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
    if !allow_private && addrs.iter().any(|a| is_private(a.ip())) {
        return Err(DialError::Denied(DenyReason::PrivateAddress));
    }
    let mut addrs = addrs;
    addrs.sort_by_key(|a| a.is_ipv6());
    Ok(addrs)
}

pub async fn dial_tcp(
    state: &State,
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<TcpStream, DialError> {
    let mut addrs = resolve_vetted(state, host, port, allow_private).await?;
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
    allow_private: bool,
) -> Result<Box<dyn Io>, DialError> {
    let tcp = dial_tcp(state, host, port, allow_private).await?;
    if !tls {
        return Ok(Box::new(tcp));
    }
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| DialError::Failed(format!("invalid TLS name {host}")))?;
    let connector = TlsConnector::from(Arc::clone(&state.client_tls));
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
