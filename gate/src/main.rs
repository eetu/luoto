//! luoto-gate: the only way out of a luoto sandbox.
//!
//! `luoto-gate run` (default) serves the explicit proxy, the in-sandbox API, DNS, the
//! transparent catch-all and dev-port relays. `luoto-gate ctl` forwards one control request
//! from stdin to the running gate (used by the host via `exec -i`).

mod api;
mod body;
mod ca;
mod config;
mod creds;
mod ctl;
mod dns;
mod events;
mod guards;
mod handler;
mod limits;
mod mitm;
mod proxy;
mod relay;
mod requests;
mod respond;
mod state;
#[cfg(target_os = "linux")]
mod system;
#[cfg(target_os = "linux")]
mod transparent;
mod upstream;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use luoto_shared::ctl::CTL_SOCKET;
use luoto_shared::events::{Event, EventKind};
use tokio::net::{TcpListener, UdpSocket, UnixListener};

use crate::config::Config;
use crate::state::State;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("ctl") => ctl::client(),
        Some("version" | "--version") => {
            println!("luoto-gate {}", luoto_shared::VERSION);
            ExitCode::SUCCESS
        }
        None | Some("run") => run(),
        Some(other) => {
            eprintln!("usage: luoto-gate [run|ctl|version] (got `{other}`)");
            ExitCode::from(2)
        }
    }
}

fn run() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("LUOTO_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("luoto-gate: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(serve()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("luoto-gate: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = Config::from_env()?;
    cfg.limits = cfg.limits.fit(limits::raise_nofile());
    std::fs::create_dir_all(&cfg.state_dir)
        .with_context(|| format!("create {}", cfg.state_dir.display()))?;

    #[cfg(target_os = "linux")]
    if cfg.transparent {
        system::drop_self_route(&cfg)?;
        system::install_redirects(&cfg)?;
    }

    let proxy = TcpListener::bind(cfg.proxy_addr)
        .await
        .with_context(|| format!("bind proxy {}", cfg.proxy_addr))?;
    let ctl_path =
        PathBuf::from(std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into()));
    if let Some(parent) = ctl_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&ctl_path);
    let ctl =
        UnixListener::bind(&ctl_path).with_context(|| format!("bind {}", ctl_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ctl_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let dns = if cfg.dns {
        let addr = cfg.dns_addr();
        Some((
            UdpSocket::bind(addr)
                .await
                .with_context(|| format!("bind dns {addr}"))?,
            TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind dns {addr}"))?,
        ))
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let transparent = if cfg.transparent {
        Some(
            TcpListener::bind(cfg.transparent_addr())
                .await
                .context("bind transparent")?,
        )
    } else {
        None
    };
    let mut relays = Vec::new();
    for port in &cfg.forwards {
        let addr = SocketAddr::from(([0, 0, 0, 0], *port));
        relays.push((
            *port,
            TcpListener::bind(addr)
                .await
                .with_context(|| format!("bind relay {addr}"))?,
        ));
    }

    #[cfg(target_os = "linux")]
    if let Some(uid) = cfg.run_as {
        system::chown_tree(&cfg.state_dir, uid)?;
        system::drop_privileges(uid)?;
    }

    let state = State::load(cfg)?;
    tokio::spawn(proxy::serve(state.clone(), proxy));
    tokio::spawn(ctl::serve(state.clone(), ctl));
    if let Some((udp, tcp)) = dns {
        tokio::spawn(dns::serve_udp(state.clone(), udp));
        tokio::spawn(dns::serve_tcp(state.clone(), tcp));
    }
    #[cfg(target_os = "linux")]
    if let Some(l) = transparent {
        tokio::spawn(transparent::serve(state.clone(), l));
    }
    for (port, l) in relays {
        tokio::spawn(relay::serve(state.clone(), l, port));
    }

    state.events.emit(Event {
        kind: Some(EventKind::Lifecycle),
        message: Some(format!(
            "gate {} started ({} rules, CA {}, vault {}, {} connections at most)",
            luoto_shared::VERSION,
            state.policy().rules.len(),
            if state.ca().is_some() {
                "installed"
            } else {
                "missing"
            },
            if state.vault().is_some() {
                "configured"
            } else {
                "not configured"
            },
            state.conns.max(),
        )),
        ..Default::default()
    });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    Ok(())
}
