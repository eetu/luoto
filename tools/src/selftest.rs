//! `sandbox selftest`: verify the boundary from inside instead of trusting runtime
//! semantics. A failure means traffic can leave without the gate.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

use luoto_shared::events::SELFTEST_DOMAIN;
use serde::Serialize;

#[derive(Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

#[derive(Serialize)]
struct Report {
    ok: bool,
    checks: Vec<Check>,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok,
        detail: detail.into(),
    }
}

fn proxy_env() -> Check {
    match std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("https_proxy")) {
        Ok(v)
            if v.contains(luoto_shared::GATE_HOST)
                || v.contains(&luoto_shared::PROXY_PORT.to_string()) =>
        {
            check("proxy_env", true, format!("HTTPS_PROXY={v}"))
        }
        Ok(v) => check(
            "proxy_env",
            false,
            format!("HTTPS_PROXY={v} does not point at the gate"),
        ),
        Err(_) => check("proxy_env", false, "HTTPS_PROXY is not set"),
    }
}

fn gate_api() -> Check {
    match crate::gate::request("GET", "/_sandbox/status", None) {
        Ok(r) if r.status == 200 => check("gate_api", true, "gate answers"),
        Ok(r) => check("gate_api", false, format!("gate returned {}", r.status)),
        Err(e) => check("gate_api", false, format!("{e:#}")),
    }
}

fn dns() -> Check {
    let canary = format!(
        "{}.{SELFTEST_DOMAIN}",
        hex::encode(rand::random::<[u8; 6]>())
    );
    match (canary.as_str(), 80).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next().map(|a| a.ip()) {
            Some(IpAddr::V4(v4)) if v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18 => {
                check(
                    "dns_local",
                    true,
                    format!("{canary} answered locally ({v4}); never forwarded"),
                )
            }
            Some(ip) => check(
                "dns_local",
                false,
                format!(
                    "{canary} resolved to {ip}: DNS is answered by something other than the gate"
                ),
            ),
            None => check("dns_local", false, "no address returned"),
        },
        Err(e) => check(
            "dns_local",
            false,
            format!("lookup failed: {e} (resolver is not the gate)"),
        ),
    }
}

fn direct_tcp() -> Check {
    let addr = SocketAddr::from(([1, 1, 1, 1], 80));
    let mut s = match TcpStream::connect_timeout(&addr, Duration::from_secs(4)) {
        Ok(s) => s,
        Err(e) => {
            return check(
                "direct_tcp",
                true,
                format!("no route out ({e}); transparent catch-all not active"),
            );
        }
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.write_all(
        format!("GET / HTTP/1.1\r\nHost: {SELFTEST_DOMAIN}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    );
    let mut buf = Vec::new();
    let _ = s.take(8192).read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    if text.contains("x-luoto-denied") || text.contains("blocked-by-luoto") {
        check(
            "direct_tcp",
            true,
            "raw-IP connection was caught by the gate",
        )
    } else if text.is_empty() {
        check(
            "direct_tcp",
            true,
            "raw-IP connection was closed without a reply",
        )
    } else {
        check(
            "direct_tcp",
            false,
            "raw-IP connection reached a server directly — the sandbox can bypass the gate",
        )
    }
}

/// A DNS query sent straight to a public resolver, which answers anything it receives: UDP
/// that gets out comes back with the resolver's real answer, while the gate answers with a
/// stand-in address or not at all.
fn udp() -> Check {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return check("udp", true, "cannot open UDP sockets");
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    if sock.connect("1.1.1.1:53").is_err() {
        return check("udp", true, "no UDP route");
    }
    let name = format!(
        "{}.{SELFTEST_DOMAIN}",
        hex::encode(rand::random::<[u8; 6]>())
    );
    let _ = sock.send(&dns_query(&name));
    let mut buf = [0u8; 512];
    match sock.recv(&mut buf) {
        Err(e) => check("udp", true, format!("no reply ({e})")),
        Ok(n) if stand_in(&buf[..n]) => {
            check("udp", true, "answered by the gate with a stand-in address")
        }
        Ok(_) => check(
            "udp",
            false,
            "a public resolver answered over UDP: UDP leaves the sandbox",
        ),
    }
}

/// A recursive DNS query for `name`, type A.
fn dns_query(name: &str) -> Vec<u8> {
    let id: [u8; 2] = rand::random();
    let mut q = vec![id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// A reply that answers with one of the gate's stand-in addresses (198.18.0.0/15), which
/// ends the message.
fn stand_in(reply: &[u8]) -> bool {
    let n = reply.len();
    n >= 16 && reply[3] & 0x0f == 0 && reply[n - 4] == 198 && reply[n - 3] & 0xfe == 18
}

fn probe(target: &str) -> Check {
    let Some(addr) = target.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        return check(
            "host_exposure",
            false,
            format!("bad probe address {target}"),
        );
    };
    match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Err(e) => check(
            "host_exposure",
            true,
            format!("host-side listener unreachable ({e})"),
        ),
        Ok(mut s) => {
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap_or(0);
            if String::from_utf8_lossy(&buf[..n]).contains("luoto-probe") {
                check(
                    "host_exposure",
                    false,
                    format!("a host-network service at {target} is reachable from the sandbox"),
                )
            } else {
                check(
                    "host_exposure",
                    true,
                    "connection did not reach the host-side listener",
                )
            }
        }
    }
}

fn ca_bundle() -> Check {
    let path = std::env::var("SSL_CERT_FILE").unwrap_or_else(|_| "/etc/luoto/ca-bundle.pem".into());
    match std::fs::read_to_string(&path) {
        Ok(s) if s.contains("BEGIN CERTIFICATE") => check("ca_bundle", true, path),
        Ok(_) => check("ca_bundle", false, format!("{path} has no certificates")),
        Err(e) => check("ca_bundle", false, format!("{path}: {e}")),
    }
}

pub fn run(json: bool, probe_addr: Option<&str>) -> ExitCode {
    // Independent checks, run at once: the slowest one (a probe waiting out its timeout)
    // sets the time.
    let mut probes: Vec<Box<dyn FnOnce() -> Check + Send>> = vec![
        Box::new(proxy_env),
        Box::new(gate_api),
        Box::new(ca_bundle),
        Box::new(dns),
        Box::new(direct_tcp),
        Box::new(udp),
    ];
    if let Some(p) = probe_addr {
        let p = p.to_string();
        probes.push(Box::new(move || probe(&p)));
    }
    let checks: Vec<Check> = std::thread::scope(|s| {
        let handles: Vec<_> = probes.into_iter().map(|f| s.spawn(f)).collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| check("selftest", false, "a check panicked"))
            })
            .collect()
    });
    let ok = checks.iter().all(|c| c.ok);
    let report = Report { ok, checks };
    if json {
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
    } else {
        for c in &report.checks {
            println!(
                "{} {:<14} {}",
                if c.ok { "ok  " } else { "FAIL" },
                c.name,
                c.detail
            );
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_queries_and_stand_in_answers() {
        let q = dns_query("ab.luoto.invalid");
        assert_eq!(&q[2..6], &[0x01, 0x00, 0, 1]);
        assert_eq!(&q[12..16], &[2, b'a', b'b', 5]);
        assert_eq!(&q[q.len() - 5..], &[0, 0, 1, 0, 1]);
        let mut reply = q.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 19, 0, 7]);
        assert!(stand_in(&reply));
        let mut nx = q;
        nx[3] = 0x83;
        assert!(!stand_in(&nx));
    }
}
