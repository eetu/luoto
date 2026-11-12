//! The point-to-point link of an env without a network card (Linux, feature `tun`): a tun
//! device whose packets travel, framed (`frame`), over a unix socket the host joins to the
//! other end's. The dev end and the gate end are the same code with the addresses swapped.
//! Configured by ioctl, so it needs no `ip` in the image.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use crate::frame::{self, Decoder};

/// The gate's end of the link.
pub const GATE_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 1);
/// The dev's end of the link.
pub const DEV_ADDR: Ipv4Addr = Ipv4Addr::new(169, 254, 1, 2);
pub const NAME: &str = "tun0";
pub const MTU: usize = 1400;
/// Where the dev's end listens for the host (published to it).
pub const DEV_SOCKET: &str = "/run/luoto-net/net.sock";

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            data: [0; 24],
        };
        let bytes = name.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name",
            ));
        }
        req.name[..bytes.len()].copy_from_slice(bytes);
        Ok(req)
    }

    fn set_addr(&mut self, ip: Ipv4Addr) {
        self.data = [0; 24];
        self.data[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        self.data[4..8].copy_from_slice(&ip.octets());
    }
}

fn check(rc: libc::c_int, what: &str) -> io::Result<()> {
    if rc < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(())
}

/// Create tun device `name` with address `addr`, point-to-point to `peer`, and bring it up.
pub fn create(name: &str, addr: Ipv4Addr, peer: Ipv4Addr) -> io::Result<File> {
    let tun = open_tun()?;
    let mut req = IfReq::new(name)?;
    req.data[..2].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    // SAFETY: TUNSETIFF reads and writes one ifreq, which `req` is laid out as.
    check(
        unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF as _, &mut req) },
        "TUNSETIFF",
    )?;

    // SAFETY: plain socket call; the fd is owned by `sock` below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    check(fd, "socket")?;
    // SAFETY: `fd` is a fresh, valid descriptor nothing else owns.
    let sock = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let ioctl = |op: libc::c_ulong, req: &mut IfReq, what: &str| {
        // SAFETY: each SIOC*IF* request reads or writes one ifreq.
        check(unsafe { libc::ioctl(sock.as_raw_fd(), op as _, req) }, what)
    };
    let mut req = IfReq::new(name)?;
    req.set_addr(addr);
    ioctl(libc::SIOCSIFADDR as _, &mut req, "set address")?;
    req.set_addr(peer);
    ioctl(libc::SIOCSIFDSTADDR as _, &mut req, "set peer")?;
    req.set_addr(Ipv4Addr::BROADCAST);
    ioctl(libc::SIOCSIFNETMASK as _, &mut req, "set netmask")?;
    let mut req = IfReq::new(name)?;
    req.data[..4].copy_from_slice(&(MTU as libc::c_int).to_ne_bytes());
    ioctl(libc::SIOCSIFMTU as _, &mut req, "set mtu")?;
    let mut req = IfReq::new(name)?;
    ioctl(libc::SIOCGIFFLAGS as _, &mut req, "get flags")?;
    let flags = i16::from_ne_bytes([req.data[0], req.data[1]])
        | (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    req.data[..2].copy_from_slice(&flags.to_ne_bytes());
    ioctl(libc::SIOCSIFFLAGS as _, &mut req, "bring up")?;
    Ok(tun)
}

fn open_tun() -> io::Result<File> {
    let path = Path::new("/dev/net/tun");
    if !path.exists() {
        std::fs::create_dir_all("/dev/net")?;
        let c = c"/dev/net/tun";
        // SAFETY: valid NUL-terminated path; mode and device number are plain integers.
        let rc = unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(10, 200)) };
        check(rc, "mknod /dev/net/tun")?;
    }
    OpenOptions::new().read(true).write(true).open(path)
}

/// Route everything not on another link through `dev`.
pub fn default_route(dev: &str) -> io::Result<()> {
    let dev = std::ffi::CString::new(dev)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name"))?;
    // SAFETY: rtentry is plain data; zero is a valid value for every field.
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    let any = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    // SAFETY: sockaddr_in and sockaddr are the same size; both are plain data.
    let any: libc::sockaddr = unsafe { std::mem::transmute(any) };
    rt.rt_dst = any;
    rt.rt_genmask = any;
    rt.rt_flags = libc::RTF_UP;
    rt.rt_dev = dev.as_ptr().cast_mut();
    // SAFETY: plain socket call; the fd is owned by `sock` below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    check(fd, "socket")?;
    // SAFETY: `fd` is a fresh, valid descriptor nothing else owns.
    let sock = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    // SAFETY: SIOCADDRT reads one rtentry; `dev` outlives the call.
    check(
        unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCADDRT as _, &rt) },
        "add default route",
    )
}

/// Bind `path` for the host's connection, replacing a stale socket, readable by root only.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

/// Pump packets between `tun` and one connection on `listener` at a time, forever. While no
/// connection is up, packets from the tun are dropped; a connection that ends or sends a bad
/// frame is closed and the next one accepted. With `only_from`, a packet from the connection
/// reaches the tun only when it is IPv4 from that address (the gate's end: nothing the
/// sandbox writes may pass as coming from elsewhere).
pub fn serve(tun: File, listener: UnixListener, only_from: Option<Ipv4Addr>) -> io::Result<()> {
    let current: Arc<Mutex<Option<UnixStream>>> = Arc::default();
    let reader = tun.try_clone()?;
    let out = current.clone();
    std::thread::spawn(move || tun_to_socket(reader, &out));
    let mut tun = tun;
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let Ok(writer) = conn.try_clone() else {
            continue;
        };
        *current.lock().unwrap_or_else(PoisonError::into_inner) = Some(writer);
        socket_to_tun(&conn, &mut tun, only_from);
        // Wakes the writer if it is blocked on this connection, before it is replaced.
        let _ = conn.shutdown(Shutdown::Both);
        *current.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
    Ok(())
}

fn tun_to_socket(mut tun: File, current: &Mutex<Option<UnixStream>>) {
    let mut buf = vec![0u8; 2 + frame::MAX_FRAME];
    loop {
        let n = match tun.read(&mut buf[2..]) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let Ok(head) = frame::header(n) else { continue };
        buf[..2].copy_from_slice(&head);
        let mut guard = current.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(s) = guard.as_mut()
            && s.write_all(&buf[..2 + n]).is_err()
        {
            *guard = None;
        }
    }
}

fn socket_to_tun(mut conn: &UnixStream, tun: &mut File, only_from: Option<Ipv4Addr>) {
    let mut d = Decoder::new(MTU);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = match conn.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        d.push(&buf[..n]);
        loop {
            match d.next_frame() {
                // A packet the kernel refuses is dropped, as on a wire.
                Ok(Some(p)) => {
                    if only_from.is_none_or(|src| frame::ipv4_from(p, src)) {
                        let _ = tun.write(p);
                    }
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
}
