//! luoto-gate: the only way out of a luoto sandbox.
//!
//! `luoto-gate run` (default) serves the explicit proxy, the in-sandbox API, DNS, the
//! transparent catch-all and dev-port relays. `luoto-gate ctl` forwards one control request
//! from stdin to the running gate (used by the host via `exec -i`). `luoto-gate events` prints
//! the event file the gate writes on a runtime without bounded logs (`eventlog.rs`).

mod api;
mod body;
mod ca;
mod config;
mod creds;
mod ctl;
mod dns;
mod eventlog;
mod events;
mod guards;
mod handler;
mod imds;
mod limits;
mod mitm;
mod proxy;
mod relay;
mod requests;
mod respond;
mod state;
#[cfg(target_os = "linux")]
mod system;
#[cfg(any(target_os = "linux", feature = "test-hooks"))]
mod transparent;
mod uplink;
mod upstream;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

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
        Some("events") => eventlog::command(&std::env::args().skip(2).collect::<Vec<_>>()),
        Some("version" | "--version") => {
            println!("luoto-gate {}", luoto_shared::VERSION);
            ExitCode::SUCCESS
        }
        None | Some("run") => run(),
        Some(other) => {
            eprintln!("usage: luoto-gate [run|ctl|events|version] (got `{other}`)");
            ExitCode::from(2)
        }
    }
}

/// With an event file, the gate's output goes to a log nothing caps (Apple's): its
/// diagnostics stop at this many bytes a start.
const DIAGNOSTICS: u64 = 1024 * 1024;
static DIAGNOSTICS_LEFT: AtomicU64 = AtomicU64::new(u64::MAX);

/// stderr for diagnostics, within [`DIAGNOSTICS_LEFT`].
struct Diagnostics;

impl std::io::Write for Diagnostics {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = buf.len() as u64;
        let left = DIAGNOSTICS_LEFT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |l| {
                Some(l.saturating_sub(len))
            })
            .unwrap_or(0);
        let mut err = std::io::stderr();
        if left >= len {
            err.write_all(buf)?;
        } else if left > 0 {
            err.write_all(b"luoto-gate: further diagnostics dropped until the gate restarts\n")?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

fn run() -> ExitCode {
    if std::env::var_os("LUOTO_EVENTS_FILE").is_some_and(|v| !v.is_empty()) {
        DIAGNOSTICS_LEFT.store(DIAGNOSTICS, Ordering::Relaxed);
    }
    tracing_subscriber::fmt()
        .with_writer(|| Diagnostics)
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

    // The link's address must exist before the listeners bind it.
    #[cfg(target_os = "linux")]
    let tun = cfg
        .tun_socket
        .as_deref()
        .map(system::tun_link)
        .transpose()?;
    #[cfg(target_os = "linux")]
    if cfg.transparent {
        if tun.is_none() {
            system::drop_self_route(&cfg)?;
        }
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

    let vault_links = match &cfg.vault_uplink {
        Some(up) => Some((
            uplink::listen(&cfg.vault_socket, cfg.run_as)?,
            uplink::listen(up, None)?,
        )),
        None => None,
    };

    #[cfg(target_os = "linux")]
    if let Some(uid) = cfg.run_as {
        system::chown_tree(&cfg.state_dir, uid)?;
        system::drop_privileges(uid)?;
    }
    // Opened as root, the device and the listener keep working after the drop.
    #[cfg(target_os = "linux")]
    if let Some((dev, listener)) = tun {
        std::thread::spawn(move || {
            if let Err(e) =
                luoto_shared::tun::serve(dev, listener, Some(luoto_shared::tun::DEV_ADDR))
            {
                tracing::error!("tun link: {e}");
            }
        });
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
    #[cfg(feature = "test-hooks")]
    if let Some((listen, dst)) = state.cfg.test_transparent {
        let l = TcpListener::bind(listen)
            .await
            .with_context(|| format!("bind test transparent {listen}"))?;
        tokio::spawn(transparent::serve_as(state.clone(), l, dst));
    }
    for (port, l) in relays {
        tokio::spawn(relay::serve(state.clone(), l, port));
    }
    if let Some((local, uplinks)) = vault_links {
        tokio::spawn(uplink::serve(local, uplinks));
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
