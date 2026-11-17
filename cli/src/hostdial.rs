//! The host's part of a gate's dials to private addresses on Apple (`gate/src/hostdial.rs`),
//! whose VMs leave through macOS's NAT, which translates only out of the primary interface,
//! never onto a VPN: [`IDLE`] links open
//! to each gate's `dial.sock`; on a line naming an address, check it again, connect from this
//! Mac (its routes, a VPN's among them) and join the link to the connection. The gate decided
//! already; this side takes only an address, never a name, and refuses any that isn't a plain
//! private one (`host::leaves_host`), this Mac's own, or a container network's, so a stray
//! writer on the socket can't make it a relay to anything else.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use ipnet::IpNet;
use luoto_shared::host::leaves_host;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

/// Idle links per gate; the gate waits for one when all are in use.
pub const IDLE: usize = 8;
/// Connections from this Mac per gate at once.
pub const MAX_CONNS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A request line's longest: `dial [` + an IPv6 address + `]:65535`.
const MAX_LINE: usize = 64;
const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(2);

/// The networks of the runtime's containers (env, vault and others'): never dialed from here,
/// where they are the Mac's own bridges.
type Nets = Arc<RwLock<Vec<IpNet>>>;

/// Every gate's dialer, on one small runtime; dropping it ends them and what they carry.
pub struct Dialers {
    /// Always `Some` until dropped.
    rt: Option<tokio::runtime::Runtime>,
    nets: Nets,
    /// Whether `nets` was read: no dialer starts before.
    known: bool,
    envs: HashMap<String, (PathBuf, Vec<JoinHandle<()>>)>,
}

impl Dialers {
    pub fn new() -> io::Result<Self> {
        raise_open_files();
        Ok(Self {
            rt: Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("luoto-hostdial")
                    .enable_all()
                    .build()?,
            ),
            nets: Nets::default(),
            known: false,
            envs: HashMap::new(),
        })
    }

    /// The runtime's container networks, as `Runtime::subnets` lists them.
    pub fn set_nets(&mut self, subnets: &[(String, String)]) {
        let nets = subnets.iter().filter_map(|(_, s)| s.parse().ok()).collect();
        *self.nets.write().unwrap_or_else(|e| e.into_inner()) = nets;
        self.known = true;
    }

    /// Dial for each `(env, dial socket)` in `want` whose socket exists (a gate from before
    /// this has none); stop the others.
    pub fn keep(&mut self, want: &[(String, PathBuf)]) {
        let want: Vec<&(String, PathBuf)> = want.iter().filter(|(_, p)| p.exists()).collect();
        self.envs.retain(|env, (path, tasks)| {
            let kept = want.iter().any(|(e, p)| e == env && p == path);
            if !kept {
                tasks.iter().for_each(JoinHandle::abort);
            }
            kept
        });
        let Some(rt) = self.rt.as_ref().filter(|_| self.known) else {
            return;
        };
        for (env, path) in want {
            if self.envs.contains_key(env) {
                continue;
            }
            out!(
                "{} dialing private addresses for `{env}`",
                chrono::Utc::now()
            );
            let conns = Arc::new(Semaphore::new(MAX_CONNS));
            let tasks = (0..IDLE)
                .map(|_| {
                    let (path, nets, conns) = (path.clone(), self.nets.clone(), conns.clone());
                    rt.spawn(idle_link(path, nets, conns))
                })
                .collect();
            self.envs.insert(env.clone(), (path.clone(), tasks));
        }
    }
}

/// Ends every link and connection without waiting for them (blocking on a runtime's tasks is
/// refused from async code).
impl Drop for Dialers {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// Keep one link open to the gate: wait for its line, hand it on, open the next.
async fn idle_link(path: PathBuf, nets: Nets, conns: Arc<Semaphore>) {
    let mut backoff = BACKOFF_MIN;
    loop {
        let asked = match UnixStream::connect(&path).await {
            Ok(link) => request(link).await,
            Err(_) => None,
        };
        if let Some((link, line)) = asked {
            backoff = BACKOFF_MIN;
            tokio::spawn(serve(link, line, nets.clone(), conns.clone()));
            continue;
        }
        // Not up yet: a published socket accepts before the gate listens, then ends at once.
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// The gate's line, read a byte at a time. None when the link ends first or the line is too
/// long for any request.
async fn request(mut link: UnixStream) -> Option<(UnixStream, String)> {
    let mut line = Vec::new();
    loop {
        let b = link.read_u8().await.ok()?;
        if b == b'\n' {
            break;
        }
        if line.len() == MAX_LINE {
            return None;
        }
        line.push(b);
    }
    Some((link, String::from_utf8(line).ok()?))
}

/// Answer one request and carry its connection; a request that isn't one closes unanswered.
async fn serve(mut link: UnixStream, line: String, nets: Nets, conns: Arc<Semaphore>) {
    // The gate writes nothing more before the answer.
    if !matches!(link.try_read(&mut [0u8; 1]), Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
        return;
    }
    let vetted = {
        let nets = nets.read().unwrap_or_else(|e| e.into_inner());
        vet(&line, &nets)
    };
    match vetted {
        Err(Refusal::Unreadable) => {}
        Err(Refusal::Refused(why)) => {
            let _ = link.write_all(format!("refused {why}\n").as_bytes()).await;
        }
        Ok(v) => carry(link, v, &conns, Own::Refused).await,
    }
}

/// Whether a connection may end at this Mac's own address: only a test's loopback listener.
#[derive(Clone, Copy, PartialEq)]
enum Own {
    Refused,
    #[cfg(test)]
    Allowed,
}

/// Connect to `v` and carry the connection over `link` until either side closes.
async fn carry(mut link: UnixStream, v: Vetted, conns: &Arc<Semaphore>, own: Own) {
    let answer = match conns.clone().try_acquire_owned() {
        Err(_) => format!("failed {MAX_CONNS} connections from this Mac already open\n"),
        Ok(_permit) => match connect(v, own).await {
            Ok(mut tcp) => {
                if link.write_all(b"ok\n").await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(&mut link, &mut tcp).await;
                }
                return;
            }
            Err(answer) => answer,
        },
    };
    let _ = link.write_all(answer.as_bytes()).await;
}

/// An address checked to be dialed from this Mac; only [`vet`] makes one.
#[derive(Debug, PartialEq)]
pub struct Vetted(SocketAddr);

#[derive(Debug, PartialEq)]
enum Refusal {
    /// Not a request: closed unanswered.
    Unreadable,
    /// The gate dials it itself.
    Refused(&'static str),
}

fn vet(line: &str, nets: &[IpNet]) -> Result<Vetted, Refusal> {
    let addr: SocketAddr = line
        .strip_prefix("dial ")
        .and_then(|a| a.parse().ok())
        .ok_or(Refusal::Unreadable)?;
    if addr.port() == 0 {
        return Err(Refusal::Unreadable);
    }
    let ip = addr.ip();
    if !leaves_host(ip) {
        return Err(Refusal::Refused("not a private address"));
    }
    if nets.iter().any(|n| n.contains(&ip)) {
        return Err(Refusal::Refused("a container network"));
    }
    if is_own(ip) {
        return Err(Refusal::Refused("this Mac's own address"));
    }
    Ok(Vetted(addr))
}

/// Whether `ip` is this Mac's: the address it would send from to `ip` is `ip` itself. A
/// connected UDP socket sends nothing.
fn is_own(ip: IpAddr) -> bool {
    let any: SocketAddr = match ip {
        IpAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
        IpAddr::V6(_) => ([0u16; 8], 0).into(),
    };
    std::net::UdpSocket::bind(any)
        .and_then(|s| s.connect((ip, 9)).and_then(|()| s.local_addr()))
        .is_ok_and(|local| local.ip() == ip)
}

/// The only connect: to a vetted address, dropped before a byte if it turned out local.
async fn connect(v: Vetted, own: Own) -> Result<TcpStream, String> {
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(v.0)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => return Err(format!("failed {e}\n")),
        Err(_) => return Err("failed connect timed out\n".into()),
    };
    if own == Own::Refused && tcp.local_addr().is_ok_and(|l| l.ip() == v.0.ip()) {
        return Err("refused this Mac's own address\n".into());
    }
    let _ = tcp.set_nodelay(true);
    Ok(tcp)
}

/// Each carried connection holds two descriptors: the soft open-file limit to the hard one,
/// within what macOS lets a process open.
fn raise_open_files() {
    // SAFETY: getrlimit and setrlimit read and write the struct they are given.
    unsafe {
        let mut l: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut l) == 0 {
            l.rlim_cur = l.rlim_max.min(10_240);
            libc::setrlimit(libc::RLIMIT_NOFILE, &raw const l);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn nets() -> Vec<IpNet> {
        vec!["192.168.64.0/24".parse().unwrap()]
    }

    #[test]
    fn only_a_plain_private_address_is_dialed() {
        assert_eq!(
            vet("dial 10.10.0.8:443", &nets()),
            Ok(Vetted("10.10.0.8:443".parse().unwrap()))
        );
        assert!(vet("dial [fd12::8]:443", &nets()).is_ok());
        for line in [
            "dial kb.example:443",
            "dial 10.10.0.8",
            "dial 10.10.0.8:0",
            "connect 10.10.0.8:443",
            "dial  10.10.0.8:443",
            "",
        ] {
            assert_eq!(vet(line, &nets()), Err(Refusal::Unreadable), "{line}");
        }
        for line in [
            "dial 127.0.0.1:22",
            "dial 169.254.169.254:80",
            "dial 8.8.8.8:53",
            "dial [::1]:22",
            "dial [::ffff:10.0.0.1]:443",
            "dial 10.213.4.2:3128",
        ] {
            assert_eq!(
                vet(line, &nets()),
                Err(Refusal::Refused("not a private address"))
            );
        }
        assert_eq!(
            vet("dial 192.168.64.1:8000", &nets()),
            Err(Refusal::Refused("a container network"))
        );
    }

    /// One dialer on its own socket, with `nets`; the socket's path.
    async fn dialing(nets: &[(String, String)]) -> (Dialers, PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dial.sock");
        let mut d = Dialers::new().unwrap();
        d.set_nets(nets);
        (d, path, dir)
    }

    async fn ask(listener: &tokio::net::UnixListener, line: &str) -> (UnixStream, String) {
        let (mut link, _) = listener.accept().await.unwrap();
        link.write_all(line.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        loop {
            let b = link.read_u8().await.unwrap();
            if b == b'\n' {
                break;
            }
            answer.push(b);
        }
        (link, String::from_utf8(answer).unwrap())
    }

    #[tokio::test]
    async fn a_loopback_listener_is_never_reached() {
        let (mut d, path, _dir) = dialing(&[]).await;
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        d.keep(&[("web".into(), path.clone())]);
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = local.local_addr().unwrap().port();
        let (_, answer) = ask(&listener, &format!("dial 127.0.0.1:{port}\n")).await;
        assert_eq!(answer, "refused not a private address");
        let accepted = tokio::time::timeout(Duration::from_millis(300), local.accept()).await;
        assert!(accepted.is_err(), "a loopback dial connected");
        drop(d);
    }

    #[tokio::test]
    async fn this_macs_own_private_address_is_refused() {
        // The address this machine sends from on its default route, when that is private.
        let Some(own) = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("192.0.2.1:9").and_then(|()| s.local_addr()))
            .ok()
            .map(|a| a.ip())
            .filter(|ip| leaves_host(*ip))
        else {
            return;
        };
        assert!(is_own(own));
        assert_eq!(
            vet(&format!("dial {own}:22"), &[]),
            Err(Refusal::Refused("this Mac's own address"))
        );
    }

    #[tokio::test]
    async fn a_request_with_bytes_after_its_line_or_an_overlong_line_is_dropped() {
        let (mut d, path, _dir) = dialing(&[]).await;
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        d.keep(&[("web".into(), path.clone())]);
        for line in [
            "dial 10.10.0.8:443\nGET / HTTP/1.1\r\n".to_string(),
            "x".repeat(MAX_LINE + 1),
        ] {
            let (mut link, _) = listener.accept().await.unwrap();
            link.write_all(line.as_bytes()).await.unwrap();
            let mut rest = Vec::new();
            let read =
                tokio::time::timeout(Duration::from_secs(5), link.read_to_end(&mut rest)).await;
            // Closed unanswered: an end, or on Linux a reset (the host left bytes unread).
            assert!(
                read.is_ok() && rest.is_empty(),
                "{line:?} got {read:?} {rest:?}"
            );
        }
        drop(d);
    }

    /// A connected pair: the gate's end of a link and the host's.
    async fn link() -> (UnixStream, UnixStream, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dial.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (gate, host) = tokio::join!(UnixStream::connect(&path), listener.accept());
        (gate.unwrap(), host.unwrap().0, dir)
    }

    #[tokio::test]
    async fn a_vetted_dial_carries_bytes_both_ways_and_a_close() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let (mut gate, host, _dir) = link().await;
        // `vet` refuses loopback, and `connect` this Mac's own address: a test allows it.
        let conns = Arc::new(Semaphore::new(1));
        tokio::spawn(async move { carry(host, Vetted(addr), &conns, Own::Allowed).await });
        let mut ok = [0u8; 3];
        gate.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"ok\n");
        gate.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        gate.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
        let mut rest = Vec::new();
        assert_eq!(gate.read_to_end(&mut rest).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_loopback_connection_is_dropped_unless_a_test_allows_it() {
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = local.local_addr().unwrap();
        let e = connect(Vetted(addr), Own::Refused).await.unwrap_err();
        assert_eq!(e, "refused this Mac's own address\n");
    }

    #[tokio::test]
    async fn past_the_cap_a_dial_fails_without_connecting() {
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = local.local_addr().unwrap();
        let (mut gate, host, _dir) = link().await;
        carry(
            host,
            Vetted(addr),
            &Arc::new(Semaphore::new(0)),
            Own::Allowed,
        )
        .await;
        let mut answer = String::new();
        gate.read_to_string(&mut answer).await.unwrap();
        assert_eq!(
            answer,
            format!("failed {MAX_CONNS} connections from this Mac already open\n")
        );
        let accepted = tokio::time::timeout(Duration::from_millis(300), local.accept()).await;
        assert!(accepted.is_err());
    }

    #[tokio::test]
    async fn without_container_networks_read_no_dialer_starts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dial.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let mut d = Dialers::new().unwrap();
        d.keep(&[("web".into(), path.clone())]);
        let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(accepted.is_err());
        d.set_nets(&[]);
        d.keep(&[("web".into(), path)]);
        let links = (0..IDLE).map(|_| listener.accept());
        for l in links {
            tokio::time::timeout(Duration::from_secs(5), l)
                .await
                .unwrap()
                .unwrap();
        }
        drop(d);
    }
}
