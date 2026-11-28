//! Dialing upstreams: resolve only after policy allowed the request, vet every address,
//! connect to exactly the vetted address, verify TLS for the policy host.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hyper::client::conn::http1::{self, SendRequest};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
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
    // Only this name reaches this machine, however it resolves (luoto's gateway, the runtime's
    // hosts file); another the sandbox's DNS answers for may point at it too, which no rule for
    // that name lets through.
    let this_name = host.eq_ignore_ascii_case(luoto_shared::THIS_MACHINE);
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
        if !this_name && allow_private {
            let machine = this_machine_addrs(state);
            if addrs.iter().any(|a| machine.contains(&a.ip())) {
                return Err(on_this_machine(host));
            }
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
                // This Mac, which only its own name reaches.
                Err(HostDialError::Refused(why)) if why == OWN_ADDRESS && !this_name => {
                    return Err(on_this_machine(host));
                }
                // The host's own address or a runtime network: dialed from here, as before.
                Err(HostDialError::Refused(_)) => {}
                Err(HostDialError::NoLink) => {
                    return Err(DialError::Failed(format!(
                        "no link to this Mac for {addr}: luoto's background watcher isn't \
                         running; `luoto up -e {}` starts it",
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

/// What the host's dialer answers for one of the Mac's own addresses (`cli/src/hostdial.rs`).
const OWN_ADDRESS: &str = "this Mac's own address";

/// A name other than [`luoto_shared::THIS_MACHINE`] that resolved to this machine.
fn on_this_machine(host: &str) -> DialError {
    DialError::Denied(DenyReason::Guard {
        reason: format!(
            "{host} resolves to this machine, which a rule reaches only as `{}`",
            luoto_shared::THIS_MACHINE
        ),
    })
}

/// The addresses that are this machine, from the gate: the host gateway luoto names
/// (`LUOTO_HOST_GATEWAY`), the one the runtime writes in the hosts file, and the default
/// gateway, which is the runtime's host.
fn this_machine_addrs(state: &State) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    if let Some(at) = state.cfg.host_gateway.as_deref()
        && let Ok(ip) = this_machine(at)
    {
        out.push(ip);
    }
    if let Ok(table) = std::fs::read_to_string("/proc/net/route")
        && let Some(gw) = default_gateway(&table)
    {
        out.push(gw);
    }
    if let Ok(hosts) = std::fs::read_to_string("/etc/hosts") {
        out.extend(gateway_in_hosts(&hosts));
    }
    out
}

/// The addresses a hosts file gives the runtime's names for its host.
fn gateway_in_hosts(hosts: &str) -> Vec<IpAddr> {
    hosts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('#').next()?.split_whitespace();
            let ip = fields.next()?.parse::<IpAddr>().ok()?;
            fields
                .any(|n| {
                    n.eq_ignore_ascii_case(luoto_shared::THIS_MACHINE)
                        || n.eq_ignore_ascii_case("host.containers.internal")
                })
                .then_some(ip)
        })
        .collect()
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

/// A dialed upstream connection, and whether its server took HTTP/2.
pub struct Dialed {
    pub io: Box<dyn Io>,
    pub h2: bool,
}

/// Dial `host`, offering HTTP/2 over TLS where `h2` (the client speaks it); otherwise, and
/// over plain HTTP, the connection speaks HTTP/1.1.
pub async fn dial(
    state: &State,
    host: &str,
    port: u16,
    tls: bool,
    reach: Reach,
    h2: bool,
) -> Result<Dialed, DialError> {
    let tcp = dial_tcp_to(state, host, port, reach.private, reach.private_only).await?;
    if !tls {
        return Ok(Dialed { io: tcp, h2: false });
    }
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| DialError::Failed(format!("invalid TLS name {host}")))?;
    let connector = TlsConnector::from(state.tls_for(host));
    let connect = if h2 {
        connector
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
            .connect(name, tcp)
    } else {
        connector.connect(name, tcp)
    };
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| DialError::Failed(format!("TLS handshake with {host} timed out")))?
        .map_err(|e| DialError::Failed(tls_failed(&state.cfg.env, host, &e)))?;
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    Ok(Dialed {
        io: Box::new(stream),
        h2,
    })
}

/// Why the handshake with `host` failed; for a certificate no CA the gate trusts signed, how
/// the user trusts the host's own.
fn tls_failed(env: &str, host: &str, e: &std::io::Error) -> String {
    let unknown_ca = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|e| {
            matches!(
                e,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            )
        });
    let mut msg = format!("TLS handshake with {host} failed: {e}");
    if unknown_ca {
        msg.push_str(&format!(
            "; if {host} has a CA of its own (an internal service), the user can trust it for \
             this host: luoto allow -e {env} {host} --ca <file>"
        ));
    }
    msg
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

pub async fn http2_sender(io: Box<dyn Io>) -> Result<http2::SendRequest<Body>, DialError> {
    let (sender, conn) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_header_list_size(MAX_HEADER_LIST)
        // A connection the network dropped (a VPN switch, a NAT timeout) ends instead of
        // taking the client's next streams.
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20))
        .handshake(TokioIo::new(io))
        .await
        .map_err(|e| DialError::Failed(format!("HTTP/2 handshake failed: {e}")))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

/// HTTP/2 flow control, both ways: how far a peer may send to the gate ahead of its reading,
/// on one stream and on the whole connection.
pub const STREAM_WINDOW: u32 = 256 << 10;
pub const CONN_WINDOW: u32 = 1 << 20;
/// What the gate buffers of a response for a client not reading it yet, per stream: with
/// `MAX_STREAMS` of them, the most one client connection holds.
pub const SEND_BUF: usize = 64 << 10;
/// The largest header block the gate takes over HTTP/2, decoded.
pub const MAX_HEADER_LIST: u32 = 64 << 10;

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

    #[test]
    fn the_hosts_file_names_this_machine_by_the_runtimes_names() {
        let hosts = "127.0.0.1 localhost\n\
                     192.168.127.254 host.containers.internal host.docker.internal # podman\n\
                     10.0.0.9 db.corp.example\n\
                     # 10.0.0.10 host.docker.internal\n\
                     172.17.0.1\tHost.Docker.Internal\n";
        assert_eq!(
            super::gateway_in_hosts(hosts),
            [
                "192.168.127.254".parse::<std::net::IpAddr>().unwrap(),
                "172.17.0.1".parse().unwrap()
            ]
        );
    }
}

#[cfg(test)]
mod connect_tests {
    use super::{Timeout, cannot_connect, tls_failed};

    #[test]
    fn an_unknown_ca_names_how_the_user_trusts_the_hosts_own() {
        let failed = |e: rustls::Error| {
            let e = std::io::Error::new(std::io::ErrorKind::InvalidData, e);
            tls_failed("web", "api.internal", &e)
        };
        let unknown = failed(rustls::Error::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
        assert!(
            unknown.ends_with("luoto allow -e web api.internal --ca <file>"),
            "{unknown}"
        );
        let expired = failed(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        ));
        assert!(!expired.contains("--ca"), "{expired}");
    }

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
