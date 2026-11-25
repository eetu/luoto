//! Dialing upstreams: resolve only after policy allowed the request, vet every address,
//! connect to exactly the vetted address, verify TLS for the policy host.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use luoto_shared::host::{is_never_dialed, is_private, leaves_host};
use luoto_shared::policy::DenyReason;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::body::Body;
use crate::hostdial::HostDialError;
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
) -> Result<Box<dyn Io>, DialError> {
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
) -> Result<Box<dyn Io>, DialError> {
    let mut addrs: Vec<SocketAddr> = if let Some(addr) = test_server(state, host) {
        vec![addr]
    } else {
        let mut gateway = false;
        let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else if let Some(at) = state.cfg.host_gateway.as_deref()
            && host.eq_ignore_ascii_case(luoto_shared::THIS_MACHINE)
        {
            // Never DNS: on a LAN, a resolver may name another machine this.
            gateway = true;
            vec![SocketAddr::new(this_machine(at)?, port)]
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
            .any(|a| refused(a.ip(), gateway, allow_private))
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
    // Apple: an address a rule with private access allows leaves through the host, whose VPN
    // routes the VM's NAT doesn't follow. Not a credential over plain HTTP: that goes to this
    // machine.
    let host_dial = state
        .host_dial
        .get()
        .filter(|_| allow_private && !private_only);
    // Every address and how it failed: why one family can't connect shows beside the other.
    let mut failed = Vec::new();
    let mut timed_out = Timeout::Plain;
    for addr in addrs {
        if let Some(hd) = host_dial
            && leaves_host(addr.ip())
        {
            match hd
                .dial(addr, CONNECT_TIMEOUT + Duration::from_secs(2))
                .await
            {
                Ok(link) => return Ok(Box::new(link)),
                // The host's own address or a runtime network: dialed from here, as before.
                Err(HostDialError::Refused(_)) => {}
                Err(HostDialError::NoLink) => {
                    return Err(DialError::Failed(format!(
                        "no link to this Mac for {addr}: luoto's background watcher isn't \
                         running; `luoto up {}` starts it",
                        state.cfg.env
                    )));
                }
                Err(HostDialError::Failed(why)) => {
                    if why == "connect timed out" {
                        timed_out = timed_out.max(Timeout::OnNetwork);
                    }
                    failed.push(format!("{addr} from this Mac: {why}"));
                    continue;
                }
            }
        }
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(Box::new(s));
            }
            Ok(Err(e)) => failed.push(format!("{addr}: {e}")),
            Err(_) => {
                timed_out = timed_out.max(if is_private(addr.ip()) {
                    Timeout::OnNetwork
                } else if state.host_dial.get().is_some() && !allow_private {
                    Timeout::MaybeVpn
                } else {
                    Timeout::Plain
                });
                failed.push(format!("{addr}: connect timed out"));
            }
        }
    }
    Err(DialError::Failed(cannot_connect(
        host, port, &failed, timed_out,
    )))
}

/// Whether `ip` is refused before a dial. The gateway is this machine, even in 10.212.0.0/16,
/// luoto's own never-dialed range that Apple's NAT networks take.
fn refused(ip: IpAddr, gateway: bool, allow_private: bool) -> bool {
    let nat = matches!(ip, IpAddr::V4(v4) if v4.octets()[..2] == [10, 212]);
    (is_never_dialed(ip) && !(gateway && nat)) || (!allow_private && is_private(ip))
}

/// [`luoto_shared::THIS_MACHINE`]'s address from `LUOTO_HOST_GATEWAY`: an address, or `route`,
/// the gate's default gateway.
fn this_machine(at: &str) -> Result<IpAddr, DialError> {
    if let Ok(ip) = at.parse() {
        return Ok(ip);
    }
    let unknown = |why: &str| DialError::Failed(format!("this machine's address: {why}"));
    if at != "route" {
        return Err(unknown(
            "LUOTO_HOST_GATEWAY is neither an address nor `route`",
        ));
    }
    let table = std::fs::read_to_string("/proc/net/route").map_err(|e| unknown(&e.to_string()))?;
    default_gateway(&table).ok_or_else(|| unknown("the gate has no default route"))
}

/// The gateway of the default route in a `/proc/net/route` table (addresses in hex, in the
/// host's byte order: little-endian on the machines a gate runs on).
fn default_gateway(table: &str) -> Option<IpAddr> {
    table.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (dest, gw) = (f.get(1)?, f.get(2)?);
        if *dest != "00000000" {
            return None;
        }
        let n = u32::from_str_radix(gw, 16).ok().filter(|n| *n != 0)?;
        Some(IpAddr::V4(std::net::Ipv4Addr::from(n.swap_bytes())))
    })
}

/// What a connect that timed out may mean, by what the gate knows of the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Timeout {
    Plain,
    /// A public address dialed from Apple's VM, whose NAT never goes onto the Mac's VPN.
    MaybeVpn,
    /// On the user's network or VPN: a private address, or one this Mac dialed.
    OnNetwork,
}

/// Why `host:port` can't be reached: each address's failure, and for one that timed out on
/// the user's network or VPN, what usually causes that.
fn cannot_connect(host: &str, port: u16, failed: &[String], timed_out: Timeout) -> String {
    let mut msg = format!("could not connect to {host}:{port} ({})", failed.join("; "));
    msg.push_str(match timed_out {
        Timeout::Plain => "",
        Timeout::MaybeVpn => {
            "; if this machine reaches it over a VPN, the rule needs private access"
        }
        Timeout::OnNetwork => "; is the network or VPN that reaches it up on this machine?",
    });
    msg
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
        return Ok(tcp);
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
mod this_machine_tests {
    use super::{default_gateway, refused, this_machine};

    #[test]
    fn only_this_machine_is_dialed_in_luotos_own_range() {
        let gw: std::net::IpAddr = "10.212.3.1".parse().unwrap();
        assert!(!refused(gw, true, true));
        assert!(refused(gw, false, true));
        assert!(refused("10.212.0.2".parse().unwrap(), false, true));
        assert!(refused(gw, true, false));
        assert!(refused("127.0.0.1".parse().unwrap(), true, true));
        assert!(refused("169.254.169.254".parse().unwrap(), true, true));
    }

    #[test]
    fn this_machine_is_the_default_gateway_or_the_address_given() {
        // Apple's VM network: default via 192.168.71.1.
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t0047A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
                     eth0\t00000000\t0147A8C0\t0003\t0\t0\t0\t00000000\n";
        assert_eq!(
            default_gateway(table),
            Some("192.168.71.1".parse().unwrap())
        );
        assert_eq!(default_gateway("Iface\tDestination\tGateway\n"), None);
        assert_eq!(
            this_machine("10.0.0.1").unwrap(),
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert!(this_machine("dns").is_err());
    }
}

#[cfg(test)]
mod connect_tests {
    use super::{Timeout, cannot_connect};

    #[test]
    fn a_timeout_on_the_users_network_asks_about_it() {
        let failed = ["10.10.0.8:443: connect timed out".to_string()];
        assert_eq!(
            cannot_connect("kb.example", 443, &failed, Timeout::OnNetwork),
            "could not connect to kb.example:443 (10.10.0.8:443: connect timed out); is the \
             network or VPN that reaches it up on this machine?"
        );
        let failed = ["203.0.113.5:443: connect timed out".to_string()];
        assert_eq!(
            cannot_connect("api.example", 443, &failed, Timeout::Plain),
            "could not connect to api.example:443 (203.0.113.5:443: connect timed out)"
        );
        assert!(
            cannot_connect("api.example", 443, &failed, Timeout::MaybeVpn).ends_with(
                "; if this machine reaches it over a VPN, the rule needs private access"
            )
        );
    }
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
