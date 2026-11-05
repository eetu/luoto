//! Linux system setup: redirect the sandbox's traffic into the gate, and drop privileges
//! once every socket is bound.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use luoto_shared::TRANSPARENT_PORT;

use crate::config::Config;

/// Remove a default route that points at the gate itself. Podman gives every container on
/// the env's internal network the route that sends the sandbox's traffic to the gate, the
/// gate included; when the kernel picks that one over the egress network's, the gate's own
/// connections go to itself and fail with "host unreachable".
pub fn drop_self_route(cfg: &Config) -> Result<()> {
    let gate = cfg.gate_ip.to_string();
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .context("run ip (is it in the gate image?)")?;
    let routes = String::from_utf8_lossy(&out.stdout);
    let via_self = routes
        .lines()
        .any(|l| l.split_whitespace().skip_while(|w| *w != "via").nth(1) == Some(gate.as_str()));
    if via_self {
        let del = Command::new("ip")
            .args(["-4", "route", "del", "default", "via", &gate])
            .output()
            .context("run ip")?;
        if !del.status.success() {
            bail!(
                "remove the default route via the gate itself: {}",
                String::from_utf8_lossy(&del.stderr).trim()
            );
        }
    }
    Ok(())
}

/// nat PREROUTING for traffic arriving from the sandbox subnet:
/// - to the gate itself: untouched (proxy, DNS, API);
/// - DNS to anywhere: answered by the gate's resolver;
/// - any other TCP: the transparent catch-all;
/// - any other UDP: a closed port, so the kernel replies "unreachable" at once (QUIC
///   clients fall back to TCP immediately instead of timing out).
pub fn install_redirects(cfg: &Config) -> Result<()> {
    let subnet: IpNet = cfg
        .internal_subnet
        .as_deref()
        .context("LUOTO_INTERNAL_SUBNET is required for transparent mode")?
        .parse()
        .context("LUOTO_INTERNAL_SUBNET")?;
    let gate = cfg.gate_ip;
    // Addresses, a subnet and ports: no argument has a space in it.
    let rules = [
        "-t nat -F PREROUTING".to_string(),
        format!("-t nat -A PREROUTING -s {subnet} -d {gate} -j RETURN"),
        format!("-t nat -A PREROUTING -s {subnet} -p udp --dport 53 -j REDIRECT --to-ports 53"),
        format!("-t nat -A PREROUTING -s {subnet} -p tcp --dport 53 -j REDIRECT --to-ports 53"),
        format!(
            "-t nat -A PREROUTING -s {subnet} -p tcp -j REDIRECT --to-ports {TRANSPARENT_PORT}"
        ),
        format!("-t nat -A PREROUTING -s {subnet} -p udp -j REDIRECT --to-ports 9"),
    ];
    for rule in &rules {
        let out = Command::new("iptables")
            .args(rule.split_whitespace())
            .output()
            .context("run iptables (is it installed in the gate image?)")?;
        if !out.status.success() {
            bail!(
                "iptables {rule}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    // The gate must never route sandbox packets; everything goes through userspace policy.
    let forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
    if forwarding.trim() != "0" && std::fs::write("/proc/sys/net/ipv4/ip_forward", "0").is_err() {
        bail!("IP forwarding is enabled in the gate's network namespace and cannot be disabled");
    }
    Ok(())
}

pub fn chown_tree(dir: &Path, uid: u32) -> Result<()> {
    std::os::unix::fs::chown(dir, Some(uid), Some(uid))
        .with_context(|| format!("chown {}", dir.display()))?;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        std::os::unix::fs::chown(&path, Some(uid), Some(uid))
            .with_context(|| format!("chown {}", path.display()))?;
    }
    Ok(())
}

pub fn drop_privileges(uid: u32) -> Result<()> {
    // SAFETY: plain libc calls with valid arguments; failures are checked.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            bail!("setgroups: {}", std::io::Error::last_os_error());
        }
        if libc::setgid(uid) != 0 {
            bail!("setgid: {}", std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            bail!("setuid: {}", std::io::Error::last_os_error());
        }
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        if libc::setuid(0) == 0 {
            bail!("privilege drop did not stick");
        }
    }
    Ok(())
}
