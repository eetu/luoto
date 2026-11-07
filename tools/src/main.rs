//! `sandbox`: the in-sandbox side of luoto. Shows the egress policy, checks URLs, files
//! access requests for the user to approve on the host, relays ports, serves MCP and the
//! ssh-agent socket (the key stays in the vault), and self-tests isolation.

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
    AccessRequest, CheckQuery, CheckResult, Install, NewAccessRequest, RequestStatus, SandboxStatus,
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
    /// Ask the user (on the host) to allow a host, or to install a system package or a
    /// toolchain in the env for good. Only the user can approve.
    Request {
        /// Host (`docs.rs`) or URL (`https://docs.rs/serde`).
        #[arg(required_unless_present_any = ["package", "tool"])]
        target: Option<String>,
        /// A system package (apt, apk or dnf) the env should have; approved, it is installed
        /// now and again whenever the container is recreated.
        #[arg(long, conflicts_with_all = ["target", "tool", "write", "paths"])]
        package: Option<String>,
        /// A toolchain mise installs, as TOOL@VERSION (`node@24`, `cargo:ripgrep@latest`),
        /// kept in the env's config like a package.
        #[arg(long, value_name = "TOOL@VERSION", conflicts_with_all = ["target", "write", "paths"])]
        tool: Option<String>,
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
        /// A value to set in a JSON config, as JSON: `{"file": "~/…", "path": […], "value": …}`.
        #[arg(long = "set")]
        set: Vec<String>,
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
            package,
            tool,
            write,
            paths,
            reason,
            wait,
            timeout,
        } => request(
            target.as_deref(),
            package,
            tool.as_deref(),
            write,
            paths,
            &reason,
            wait.then(|| Duration::from_secs(timeout)),
        ),
        Cmd::Relay { port } => relay(port),
        Cmd::Mcp => mcp::serve(),
        Cmd::SshAgent { socket } => ssh_agent::serve(&socket).map(|()| ExitCode::SUCCESS),
        Cmd::AgentSetup { mcp, briefing, set } => agent_setup::run(mcp.as_deref(), &briefing, &set),
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
        out.push_str("\npending requests (the user approves on the host):\n");
        for r in pending {
            out.push_str(&format!(
                "  #{} {} — {}\n",
                r.id,
                what(r),
                approve_hint(&s.env, r.id)
            ));
        }
    }
    out.push_str(&format!(
        "\nNeed more access? sandbox request <host> [--write] --reason \"…\" --wait\n\
         The user can also grant it on the host: luoto allow -e {} <host> [--write] [--ttl 1h]\n\
         A system package or toolchain to keep: sandbox request --package <name> | --tool node@24 \
         --reason \"…\" --wait\n",
        s.env
    ));
    out
}

/// Ask the gate whether a request would pass. A bare host is read as `https://host`.
pub fn check_url(url: &str, method: &str) -> Result<CheckResult> {
    let q = CheckQuery {
        url: if url.contains("://") {
            url.to_string()
        } else {
            format!("https://{url}")
        },
        // The gate refuses lower-case methods; asked about `get`, the question is GET.
        method: method.to_ascii_uppercase(),
    };
    gate::post_json("/_sandbox/check", &q)
}

pub fn describe_check(r: &CheckResult) -> String {
    format!(
        "{} — {}",
        if r.allowed { "allowed" } else { "blocked" },
        r.message
    )
}

fn check(url: &str, method: &str) -> Result<ExitCode> {
    let r = check_url(url, method)?;
    println!("{}", describe_check(&r));
    Ok(if r.allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn approve_hint(env: &str, id: u64) -> String {
    format!("luoto approve -e {env} {id}")
}

/// What a request asks for, for people.
fn what(r: &AccessRequest) -> String {
    match &r.install {
        Some(i) => format!("install {}", i.describe()),
        None => format!(
            "{} access to {}",
            match r.access {
                AccessLevel::Write => "write",
                AccessLevel::Read => "read",
            },
            r.host
        ),
    }
}

/// A filed request and, when the caller waited, what the user decided.
pub struct Outcome {
    pub request: AccessRequest,
    pub waited: Option<Duration>,
}

/// File a request for access to a host for the user to decide on the host; with `wait`, poll
/// for the decision.
pub fn request_access(
    target: &str,
    write: bool,
    paths: Vec<String>,
    reason: &str,
    wait: Option<Duration>,
) -> Result<Outcome> {
    file(
        NewAccessRequest {
            host: luoto_shared::host::host_of(target).to_string(),
            access: if write {
                AccessLevel::Write
            } else {
                AccessLevel::Read
            },
            paths,
            reason: reason.to_string(),
            install: None,
        },
        wait,
    )
}

/// File a request to install software in the env (see [`request_access`]).
pub fn request_install(install: Install, reason: &str, wait: Option<Duration>) -> Result<Outcome> {
    file(
        NewAccessRequest {
            host: String::new(),
            access: AccessLevel::Read,
            paths: Vec::new(),
            reason: reason.to_string(),
            install: Some(install),
        },
        wait,
    )
}

/// `TOOL@VERSION` as a mise toolchain request; a bare tool means its latest version.
pub fn parse_tool(s: &str) -> Install {
    let (name, version) = match s.rsplit_once('@') {
        Some((n, v)) if !n.is_empty() => (n, v),
        _ => (s, "latest"),
    };
    Install::Tool {
        name: name.to_string(),
        version: version.to_string(),
    }
}

fn file(new: NewAccessRequest, wait: Option<Duration>) -> Result<Outcome> {
    let mut request: AccessRequest = gate::post_json("/_sandbox/requests", &new)?;
    if let Some(timeout) = wait {
        eprintln!(
            "{}\nwaiting up to {}s for the user…",
            describe_filed(&request),
            timeout.as_secs()
        );
        let start = Instant::now();
        loop {
            request = gate::get_json(&format!("/_sandbox/requests/{}", request.id))?;
            if request.status != RequestStatus::Pending || start.elapsed() >= timeout {
                break;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    Ok(Outcome {
        request,
        waited: wait,
    })
}

fn describe_filed(r: &AccessRequest) -> String {
    format!(
        "Request #{} filed: {}.\nAsk the user to approve it on the host:  {}   (or in `luoto ui`)",
        r.id,
        what(r),
        approve_hint(&env_name(), r.id)
    )
}

pub fn describe(o: &Outcome) -> String {
    let r = &o.request;
    match (r.status, o.waited) {
        (RequestStatus::Approved, _) => match &r.install {
            Some(i) => format!(
                "Request #{} approved: {}{}",
                r.id,
                i.describe(),
                r.note
                    .as_ref()
                    .map(|n| format!(" — {n}"))
                    .unwrap_or_else(|| " is installed.".into())
            ),
            None => format!("Request #{} approved: {} is reachable now.", r.id, r.host),
        },
        (RequestStatus::Rejected, _) => format!(
            "Request #{} was rejected by the user{}.",
            r.id,
            r.note
                .as_ref()
                .map(|n| format!(": {n}"))
                .unwrap_or_default()
        ),
        (RequestStatus::Pending, Some(t)) => {
            format!(
                "{}\nStill pending after {}s.",
                describe_filed(r),
                t.as_secs()
            )
        }
        (RequestStatus::Pending, None) => describe_filed(r),
    }
}

fn request(
    target: Option<&str>,
    package: Option<String>,
    tool: Option<&str>,
    write: bool,
    paths: Vec<String>,
    reason: &str,
    wait: Option<Duration>,
) -> Result<ExitCode> {
    let o = match (target, package, tool) {
        (_, Some(name), _) => request_install(Install::Package { name }, reason, wait)?,
        (_, _, Some(t)) => request_install(parse_tool(t), reason, wait)?,
        (Some(t), None, None) => request_access(t, write, paths, reason, wait)?,
        (None, None, None) => anyhow::bail!("name a host, --package or --tool"),
    };
    println!("{}", describe(&o));
    Ok(match (o.request.status, o.waited) {
        (RequestStatus::Rejected, _) => ExitCode::from(1),
        (RequestStatus::Pending, Some(_)) => ExitCode::from(2),
        _ => ExitCode::SUCCESS,
    })
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
