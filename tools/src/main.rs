//! `sandbox` — the in-sandbox side of luoto. Shows the egress policy, checks URLs, files
//! access requests for the user to approve on the host, relays ports, serves MCP and the
//! ssh-agent socket (the key stays in the vault), and self-tests isolation. It can never
//! change policy.

mod agent_setup;
mod gate;
mod mcp;
mod selftest;
mod ssh_agent;

use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use luoto_shared::api::{
    AccessRequest, CheckQuery, CheckResult, NewAccessRequest, RequestStatus, SandboxStatus,
};
use luoto_shared::policy::AccessLevel;

#[derive(Parser)]
#[command(
    name = "sandbox",
    version,
    about = "Inspect and request egress from inside a luoto sandbox"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show this env's egress rules, credentialed hosts, recent denials and requests.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Would a request be allowed? (No network traffic is sent.)
    Check {
        url: String,
        #[arg(short = 'X', long, default_value = "GET")]
        method: String,
    },
    /// Ask the user (on the host) to allow a host. Only the user can approve.
    Request {
        /// Host (`docs.rs`) or URL (`https://docs.rs/serde`).
        target: String,
        /// Ask for write access (any method) instead of read-only.
        #[arg(long)]
        write: bool,
        /// Restrict to path globs (`/serde/**`).
        #[arg(long = "path")]
        paths: Vec<String>,
        /// Why this access is needed (shown to the user).
        #[arg(long)]
        reason: String,
        /// Wait until the user approves or rejects.
        #[arg(long)]
        wait: bool,
        /// Seconds to wait with --wait.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Relay stdin/stdout to a local TCP port (host-side port forwarding).
    Relay { port: u16 },
    /// Run an MCP server on stdio exposing status/check/request as tools.
    Mcp,
    /// Serve the env's ssh-agent socket; the key stays in the vault (started by init.sh).
    #[command(hide = true)]
    SshAgent {
        #[arg(long, default_value = ssh_agent::SOCKET)]
        socket: std::path::PathBuf,
    },
    /// Link the luoto briefing and register the MCP server for an agent (used by `luoto agent add`).
    #[command(hide = true)]
    AgentSetup {
        #[arg(long)]
        mcp: Option<String>,
        #[arg(long = "briefing")]
        briefing: Vec<String>,
    },
    /// Verify isolation from inside (run by `luoto up` and `luoto doctor`).
    Selftest {
        #[arg(long)]
        json: bool,
        /// host:port of a host-side probe listener that must be unreachable.
        #[arg(long)]
        probe: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Status { json } => status(json),
        Cmd::Check { url, method } => check(&url, &method),
        Cmd::Request {
            target,
            write,
            paths,
            reason,
            wait,
            timeout,
        } => request(&target, write, paths, &reason, wait, timeout),
        Cmd::Relay { port } => relay(port),
        Cmd::Mcp => mcp::serve(),
        Cmd::SshAgent { socket } => ssh_agent::serve(&socket).map(|()| ExitCode::SUCCESS),
        Cmd::AgentSetup { mcp, briefing } => agent_setup::run(mcp.as_deref(), &briefing),
        Cmd::Selftest { json, probe } => return selftest::run(json, probe.as_deref()),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sandbox: {e:#}");
            ExitCode::FAILURE
        }
    }
}

pub fn env_name() -> String {
    std::env::var("LUOTO_ENV").unwrap_or_else(|_| "<env>".into())
}

fn status(json: bool) -> Result<ExitCode> {
    let s: SandboxStatus = gate::get_json("/_sandbox/status")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&s)?);
        return Ok(ExitCode::SUCCESS);
    }
    print!("{}", render_status(&s));
    Ok(ExitCode::SUCCESS)
}

pub fn render_status(s: &SandboxStatus) -> String {
    let mut out = format!("luoto env: {}   (gate {})\n", s.env, s.gate_version);
    if s.credentials_locked {
        out.push_str("credentials: LOCKED — the user must run `luoto vault unlock` on the host\n");
    }
    out.push_str("\nallowed egress:\n");
    if s.rules.is_empty() {
        out.push_str("  (nothing — every destination is blocked)\n");
    }
    for r in &s.rules {
        let paths = if r.paths.is_empty() {
            String::new()
        } else {
            format!(" paths {}", r.paths.join(","))
        };
        let exp = r
            .expires
            .map(|e| format!(" (expires {})", e.format("%Y-%m-%d %H:%M UTC")))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {:<40} {}{}{}  [{}]\n",
            r.host, r.access, paths, exp, r.origin
        ));
    }
    if !s.credentialed_hosts.is_empty() {
        out.push_str(&format!(
            "\ncredentials injected by the gate (values never enter the sandbox): {}\n",
            s.credentialed_hosts.join(", ")
        ));
    }
    if !s.recent_denials.is_empty() {
        out.push_str("\nrecent denials:\n");
        for e in s.recent_denials.iter().take(10) {
            out.push_str(&format!(
                "  {} {}{}  — {}\n",
                e.method.as_deref().unwrap_or("-"),
                e.host.as_deref().unwrap_or("?"),
                e.path.as_deref().unwrap_or(""),
                e.message.as_deref().unwrap_or("")
            ));
        }
    }
    let pending: Vec<&AccessRequest> = s
        .requests
        .iter()
        .filter(|r| r.status == RequestStatus::Pending)
        .collect();
    if !pending.is_empty() {
        out.push_str("\npending access requests (the user approves on the host):\n");
        for r in pending {
            out.push_str(&format!(
                "  #{} {} {:?} — luoto approve -e {} {}\n",
                r.id, r.host, r.access, s.env, r.id
            ));
        }
    }
    out.push_str(&format!(
        "\nNeed more access? sandbox request <host> [--write] --reason \"…\" --wait\n\
         The user can also grant it on the host: luoto allow -e {} <host> [--write] [--ttl 1h]\n",
        s.env
    ));
    out
}

fn check(url: &str, method: &str) -> Result<ExitCode> {
    let q = CheckQuery {
        url: if url.contains("://") {
            url.to_string()
        } else {
            format!("https://{url}")
        },
        method: method.to_string(),
    };
    let (_, r) = gate::post_json::<_, CheckResult>("/_sandbox/check", &q)?;
    let r = r.map_err(anyhow::Error::msg)?;
    println!(
        "{} — {}",
        if r.allowed { "allowed" } else { "blocked" },
        r.message
    );
    Ok(if r.allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

pub fn host_of(target: &str) -> String {
    let t = target.trim();
    let no_scheme = t.split_once("://").map_or(t, |(_, r)| r);
    let authority = no_scheme.split(['/', '?', '#']).next().unwrap_or(no_scheme);
    authority
        .rsplit_once(':')
        .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
        .map_or(authority, |(h, _)| h)
        .to_string()
}

pub fn file_request(
    target: &str,
    write: bool,
    paths: Vec<String>,
    reason: &str,
) -> Result<AccessRequest> {
    let new = NewAccessRequest {
        host: host_of(target),
        access: if write {
            AccessLevel::Write
        } else {
            AccessLevel::Read
        },
        paths,
        reason: reason.to_string(),
    };
    let (_, r) = gate::post_json::<_, AccessRequest>("/_sandbox/requests", &new)?;
    r.map_err(anyhow::Error::msg)
}

pub fn wait_for(id: u64, timeout: Duration) -> Result<AccessRequest> {
    let start = Instant::now();
    loop {
        let r: AccessRequest = gate::get_json(&format!("/_sandbox/requests/{id}"))?;
        if r.status != RequestStatus::Pending || start.elapsed() >= timeout {
            return Ok(r);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn request(
    target: &str,
    write: bool,
    paths: Vec<String>,
    reason: &str,
    wait: bool,
    timeout: u64,
) -> Result<ExitCode> {
    let r = file_request(target, write, paths, reason)?;
    let env = env_name();
    println!(
        "Request #{} filed: {} access to {}.\nAsk the user to approve it on the host:  luoto approve -e {env} {}   (or in `luoto ui`)",
        r.id,
        if write { "write" } else { "read" },
        r.host,
        r.id
    );
    if !wait {
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!("waiting up to {timeout}s for the user…");
    let r = wait_for(r.id, Duration::from_secs(timeout))?;
    match r.status {
        RequestStatus::Approved => {
            println!("approved — {} is now reachable", r.host);
            Ok(ExitCode::SUCCESS)
        }
        RequestStatus::Rejected => {
            println!(
                "rejected by the user{}",
                r.note.map(|n| format!(": {n}")).unwrap_or_default()
            );
            Ok(ExitCode::from(1))
        }
        RequestStatus::Pending => {
            println!("still pending after {timeout}s");
            Ok(ExitCode::from(2))
        }
    }
}

fn relay(port: u16) -> Result<ExitCode> {
    // Both loopbacks: Node resolves `localhost` to ::1, so Vite and friends listen only there.
    let addrs = [
        std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
    ];
    let stream = std::net::TcpStream::connect(&addrs[..])
        .with_context(|| format!("nothing is listening on port {port} in the sandbox"))?;
    let mut to_stdout = stream.try_clone()?;
    let mut from_stdin = stream;
    // Flushed per chunk: stdout is line-buffered, and the tail of a binary response (no newline)
    // would wait there while the client keeps the connection open.
    let t = std::thread::spawn(move || {
        let mut out = std::io::stdout().lock();
        let mut buf = [0u8; 16384];
        loop {
            match to_stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.write_all(&buf[..n]).and_then(|()| out.flush()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut stdin = std::io::stdin().lock();
    let mut buf = [0u8; 16384];
    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        from_stdin.write_all(&buf[..n])?;
    }
    let _ = from_stdin.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn extracts_hosts() {
        assert_eq!(host_of("https://docs.rs/serde/latest"), "docs.rs");
        assert_eq!(host_of("docs.rs"), "docs.rs");
        assert_eq!(host_of("http://example.com:8080/x"), "example.com");
        assert_eq!(host_of("*.example.com"), "*.example.com");
    }
}
