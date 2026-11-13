//! `sandbox`: the in-sandbox side of luoto. Shows the egress policy, checks URLs, files
//! access requests for the user to approve on the host, relays ports, serves MCP and the
//! ssh-agent socket (the key stays in the vault), and self-tests isolation.

mod agent_setup;
mod gate;
mod mcp;
mod net;
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
    /// Ask the user (on the host) to allow a host, to install a system package or a toolchain
    /// in the env for good, or to give it a variable. Only the user can approve.
    Request {
        /// Host (`docs.rs`) or URL (`https://docs.rs/serde`); `host:port` for a protocol other
        /// than HTTP(S) (`db.example.com:5432`, not 80 or 443), which the gate can only tunnel
        /// uninspected.
        #[arg(required_unless_present_any = ["package", "tool", "preset", "var"])]
        target: Option<String>,
        /// A system package (apt, apk or dnf) the env should have; approved, it is installed
        /// now and again whenever the container is recreated.
        #[arg(long, conflicts_with_all = ["target", "tool", "write", "paths"])]
        package: Option<String>,
        /// A toolchain mise installs, as TOOL@VERSION (`node@24`, `cargo:ripgrep@latest`),
        /// kept in the env's config like a package.
        #[arg(long, value_name = "TOOL@VERSION", conflicts_with_all = ["target", "write", "paths"])]
        tool: Option<String>,
        /// One of luoto's presets (`npm`, `pypi`, …) for a registry or service, instead of its
        /// hosts one by one.
        #[arg(long, conflicts_with_all = ["target", "package", "tool", "write", "paths"])]
        preset: Option<String>,
        /// An environment variable with a plain value the code needs (`RUST_LOG`): the user
        /// gives or accepts its value on the host, and new shells here get it. `NAME=value`
        /// suggests the value, which the user sees filled in. Not for a secret: the user adds
        /// one on the host (`luoto var set NAME`).
        #[arg(long, value_name = "NAME[=VALUE]", conflicts_with_all = ["target", "package", "tool", "preset", "write", "paths"])]
        var: Option<String>,
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
    /// Serve the env's tun link to the gate (started by init.sh when `LUOTO_NET=tun`).
    #[command(hide = true)]
    Net {
        #[arg(long, default_value = "/run/luoto-net/net.sock")]
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
    /// Report an agent's state to its terminal (OSC 7501, the Program Status Protocol), from
    /// the agent's hooks: idle, working, done, blocked or error.
    #[command(hide = true)]
    State {
        state: String,
        /// The agent, as the terminal names it (`claude-code`).
        #[arg(long)]
        app: Option<String>,
        /// What the agent appends to its hook's command (Codex: a JSON event), ignored.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        rest: Vec<String>,
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
            preset,
            var,
            write,
            paths,
            reason,
            wait,
            timeout,
        } => {
            let install = package
                .map(|name| Install::Package { name })
                .or_else(|| tool.as_deref().map(parse_tool))
                .or_else(|| preset.map(|name| Install::Preset { name }))
                .or_else(|| {
                    var.map(|v| match v.split_once('=') {
                        Some((name, value)) => Install::Var {
                            name: name.to_string(),
                            value: Some(value.to_string()),
                        },
                        None => Install::Var {
                            name: v,
                            value: None,
                        },
                    })
                });
            request(
                target.as_deref(),
                install,
                write,
                paths,
                &reason,
                wait.then(|| Duration::from_secs(timeout)),
            )
        }
        Cmd::Relay { port } => relay(port),
        Cmd::Mcp => mcp::serve(),
        Cmd::SshAgent { socket } => ssh_agent::serve(&socket).map(|()| ExitCode::SUCCESS),
        Cmd::Net { socket } => net::serve(&socket).map(|()| ExitCode::SUCCESS),
        Cmd::AgentSetup { mcp, briefing, set } => agent_setup::run(mcp.as_deref(), &briefing, &set),
        Cmd::State { state, app, .. } => {
            agent_setup::report_status(&state, app.as_deref());
            Ok(ExitCode::SUCCESS)
        }
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
    if let Some(open) = &s.open {
        let until = open
            .until
            .map(|u| format!("until {}", u.format("%Y-%m-%d %H:%M UTC")))
            .unwrap_or_else(|| "until the user closes it".into());
        out.push_str(&format!(
            "egress: OPEN {until}: any HTTP(S) host no rule allows goes out too (rule \
             `open`),\n  except hosts that get credentials; every request is still logged\n"
        ));
    }
    out.push_str("\nallowed egress:\n");
    if s.rules.is_empty() && s.open.is_none() {
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
        let to = match r.port {
            Some(port) => format!("{}:{port}", r.host),
            None => r.host.clone(),
        };
        let access = match r.mode {
            luoto_shared::policy::Mode::Tunnel => "uninspected tunnel",
            luoto_shared::policy::Mode::Inspect => r.access.as_str(),
        };
        out.push_str(&format!(
            "  {:<40} {}{}{}  [{}]\n",
            to, access, paths, exp, r.origin
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
         Not HTTP(S) (a database)? sandbox request <host>:<port> --reason \"…\" --wait\n\
         The user can also grant it on the host: luoto allow -e {} <host> [--write] [--ttl 1h]\n\
         A system package or toolchain to keep: sandbox request --package <name> | --tool node@24 \
         --reason \"…\" --wait\n\
         A plain variable the code needs: sandbox request --var <NAME>[=<value>] --reason \"…\" \
         --wait (a secret: ask the user to run luoto var set -e {} <NAME> on the host)\n",
        s.env, s.env
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
    match (&r.install, r.port) {
        (Some(i @ (Install::Preset { .. } | Install::Var { .. })), _) => i.describe(),
        (Some(i), _) => format!("install {}", i.describe()),
        (None, Some(port)) => format!("a tunnel to {}:{port}", r.host),
        (None, None) => format!(
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

/// The host a request names and, for `host:port` (not a URL), the port of a tunnel.
pub fn parse_target(target: &str) -> Result<(String, Option<u16>)> {
    let t = target.trim();
    if t.contains("://") {
        return Ok((luoto_shared::host::host_of(t).to_string(), None));
    }
    let authority = t.split(['/', '?', '#']).next().unwrap_or(t);
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => match rest.split_once("]:") {
            Some((v6, port)) => (v6, Some(port)),
            None => (authority, None),
        },
        // Several colons: an IPv6 address without brackets, so no port.
        None => match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            _ => (authority, None),
        },
    };
    let port = port
        .map(|p| {
            p.parse::<u16>()
                .ok()
                .filter(|n| *n != 0)
                .with_context(|| format!("`{p}` is not a port (1-65535)"))
        })
        .transpose()?;
    Ok((host.to_string(), port))
}

/// File a request for access to a host, or with `port` for a tunnel to it, for the user to
/// decide on the host; with `wait`, poll for the decision.
pub fn request_access(
    host: &str,
    port: Option<u16>,
    write: bool,
    paths: Vec<String>,
    reason: &str,
    wait: Option<Duration>,
) -> Result<Outcome> {
    file(
        NewAccessRequest {
            host: host.to_string(),
            port,
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
            port: None,
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
                "Request #{} approved: {}{}{}",
                r.id,
                i.describe(),
                r.note
                    .as_ref()
                    .map(|n| format!(" — {n}"))
                    .unwrap_or_else(|| " is in the env now.".into()),
                if i.variable().is_some() {
                    "\nA command that doesn't see it loads it with `. /run/luoto/env.sh`."
                } else {
                    ""
                }
            ),
            None => {
                let to = match r.port {
                    Some(port) => format!(
                        "a tunnel to {}:{port} is open now: connect to it as it is",
                        r.host
                    ),
                    None => format!("{} is reachable now", r.host),
                };
                match &r.note {
                    Some(n) => format!("Request #{} approved: {to}; {n}.", r.id),
                    None => format!("Request #{} approved: {to}.", r.id),
                }
            }
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
    install: Option<Install>,
    write: bool,
    paths: Vec<String>,
    reason: &str,
    wait: Option<Duration>,
) -> Result<ExitCode> {
    let o = match (install, target) {
        (Some(i), _) => request_install(i, reason, wait)?,
        (None, Some(t)) => {
            let (host, port) = parse_target(t)?;
            request_access(&host, port, write, paths, reason, wait)?
        }
        (None, None) => {
            anyhow::bail!("name a host, --preset, --package, --tool or --var")
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_takes_what_codex_appends() {
        let event = r#"{"type":"agent-turn-complete","last-assistant-message":"--done"}"#;
        let cli =
            Cli::try_parse_from(["sandbox", "state", "done", "--app", "codex", event]).unwrap();
        let Cmd::State { state, app, rest } = cli.cmd else {
            panic!("not state")
        };
        assert_eq!((state.as_str(), app.as_deref()), ("done", Some("codex")));
        assert_eq!(rest, [event]);
        assert!(Cli::try_parse_from(["sandbox", "state", "working", "--app", "x"]).is_ok());
    }

    #[test]
    fn a_target_with_a_port_asks_for_a_tunnel() {
        let t = |s: &str| parse_target(s).unwrap();
        assert_eq!(
            t("db.example.com:5432"),
            ("db.example.com".into(), Some(5432))
        );
        assert_eq!(t("[2001:db8::1]:5432"), ("2001:db8::1".into(), Some(5432)));
        assert_eq!(t("docs.rs"), ("docs.rs".into(), None));
        assert_eq!(t("https://docs.rs:8443/serde"), ("docs.rs".into(), None));
        assert_eq!(t("2001:db8::1"), ("2001:db8::1".into(), None));
        for bad in [
            "db.example.com:0",
            "db.example.com:70000",
            "db.example.com:x",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_approved_tunnel_says_how_to_reach_it() {
        let r = AccessRequest {
            id: 3,
            host: "db.example.com".into(),
            port: Some(5432),
            access: AccessLevel::Write,
            paths: vec![],
            reason: "migrations".into(),
            status: RequestStatus::Approved,
            created: Default::default(),
            resolved: None,
            note: None,
            install: None,
        };
        assert_eq!(what(&r), "a tunnel to db.example.com:5432");
        let said = describe(&Outcome {
            request: r,
            waited: None,
        });
        assert!(said.contains("db.example.com:5432 is open now"), "{said}");
    }

    #[test]
    fn status_says_when_egress_is_open() {
        let mut s = SandboxStatus {
            env: "web".into(),
            gate_version: "0".into(),
            credentials_locked: false,
            rules: vec![],
            credentialed_hosts: vec![],
            recent_denials: vec![],
            requests: vec![],
            open: None,
        };
        let closed = render_status(&s);
        assert!(closed.contains("every destination is blocked") && !closed.contains("OPEN"));
        s.open = Some(luoto_shared::api::OpenEgress {
            until: "2026-11-11T14:05:00Z".parse().ok(),
        });
        let open = render_status(&s);
        assert!(
            open.contains("egress: OPEN until 2026-11-11 14:05 UTC: any HTTP(S) host"),
            "{open}"
        );
        assert!(!open.contains("every destination is blocked"));
    }
}
