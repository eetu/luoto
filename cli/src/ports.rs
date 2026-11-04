//! Reaching servers in an env from this machine. A forward listens on localhost here and pipes
//! each connection into the env through `sandbox relay`, which connects from inside, so a
//! server bound to the env's own localhost (Vite, Next, …) works without flags. The watcher
//! forwards every port an env starts listening on; `luoto forward` does one by hand.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::env::UID;
use crate::runtime::Runtime;

/// Ports the watcher forwards on its own: above the privileged ones, below Linux's ephemeral
/// range (where servers asking for any free port land, editors' remote servers among them).
pub const AUTO: std::ops::RangeInclusive<u16> = 1024..=32767;

/// TCP ports something listens on in the env's dev container; None if that can't be asked.
pub fn listening(rt: &Runtime, dev: &str) -> Option<BTreeSet<u16>> {
    let out = rt
        .run(["exec", dev, "cat", "/proc/net/tcp", "/proc/net/tcp6"])
        .ok()?;
    Some(parse_listening(&out))
}

/// `/proc/net/tcp{,6}` rows in LISTEN state (`0A`), by local port.
fn parse_listening(table: &str) -> BTreeSet<u16> {
    table
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (_, port) = f.get(1)?.rsplit_once(':')?;
            (f.get(3) == Some(&"0A"))
                .then(|| u16::from_str_radix(port, 16).ok())
                .flatten()
        })
        .collect()
}

/// A running forward; dropping it closes its listeners (open connections finish).
pub struct Forward {
    stop: Arc<AtomicBool>,
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Forward {
    /// Listen on `local` at 127.0.0.1 (and ::1, when free) and relay to `env_port` in `dev`.
    pub fn start(rt: &Runtime, dev: &str, local: u16, env_port: u16) -> Result<Self> {
        if host_listens(local) {
            bail!("port {local} is taken on this machine");
        }
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, local))
            .with_context(|| format!("port {local} is taken on this machine"))?;
        // `localhost` resolves to ::1 first in most browsers.
        let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, local)).ok();
        let stop = Arc::new(AtomicBool::new(false));
        for l in std::iter::once(v4).chain(v6) {
            l.set_nonblocking(true)?;
            let (stop, rt, dev) = (stop.clone(), rt.clone(), dev.to_string());
            std::thread::spawn(move || accept(&l, &stop, &rt, &dev, env_port));
        }
        Ok(Forward { stop })
    }
}

/// Something on this machine answers on `port` at localhost. A host service on the port keeps
/// it: binding 127.0.0.1 succeeds beside one listening on 0.0.0.0 (or only on ::1) and would
/// take its local clients.
fn host_listens(port: u16) -> bool {
    [
        IpAddr::from(Ipv4Addr::LOCALHOST),
        IpAddr::from(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .any(|ip| {
        TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(300)).is_ok()
    })
}

fn accept(l: &TcpListener, stop: &AtomicBool, rt: &Runtime, dev: &str, port: u16) {
    while !stop.load(Ordering::Relaxed) {
        match l.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                let (rt, dev) = (rt.clone(), dev.to_string());
                std::thread::spawn(move || {
                    // A browser closing a connection ends a relay without a message.
                    if let Err(e) = relay(&rt, &dev, port, s)
                        && !e.to_string().is_empty()
                    {
                        eprintln!("port {port}: {}", crate::text::lines(&format!("{e:#}")));
                    }
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// Pipe one connection to `port` in the env through `sandbox relay`.
fn relay(rt: &Runtime, dev: &str, port: u16, stream: TcpStream) -> Result<()> {
    let mut child = rt
        .command()
        .args([
            "exec",
            "-i",
            "-u",
            UID,
            dev,
            "sandbox",
            "relay",
            &port.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start the relay in the env")?;
    let mut to_env = child.stdin.take().context("relay stdin")?;
    let mut from_env = child.stdout.take().context("relay stdout")?;
    let mut inbound = stream.try_clone()?;
    let mut outbound = stream;
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut inbound, &mut to_env);
    });
    let _ = std::io::copy(&mut from_env, &mut outbound);
    let _ = outbound.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{}", err.trim().trim_start_matches("sandbox: "));
    }
    Ok(())
}

/// `LOCAL:ENV`, or one port for both.
pub fn parse_spec(spec: &str) -> Result<(u16, u16)> {
    let parse = |p: &str| {
        p.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .with_context(|| format!("`{spec}`: ports are 1-65535, as PORT or LOCAL:ENV"))
    };
    match spec.split_once(':') {
        Some((l, e)) => Ok((parse(l)?, parse(e)?)),
        None => parse(spec).map(|p| (p, p)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_host_service_on_any_address_keeps_its_port() {
        let l = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(host_listens(port), "0.0.0.0:{port} answers at 127.0.0.1");
    }

    use super::*;

    #[test]
    fn listening_ports_come_from_both_tables() {
        let table = "  sl  local_address rem_address   st\n\
             0: 00000000:1F90 00000000:0000 0A 0\n\
             1: 0100007F:A3D2 0100007F:1F90 01 0\n\
             0: 00000000000000000000000001000000:1435 00000000000000000000000000000000:0000 0A 0\n";
        assert_eq!(parse_listening(table), BTreeSet::from([8080, 5173]));
    }

    #[test]
    fn specs_map_one_or_two_ports() {
        assert_eq!(parse_spec("5173").unwrap(), (5173, 5173));
        assert_eq!(parse_spec("8080:5173").unwrap(), (8080, 5173));
        assert!(parse_spec("0").is_err());
    }
}
