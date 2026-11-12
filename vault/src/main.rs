//! luoto-vault: one per runtime VM. Holds root secrets in memory only (pushed by `luoto
//! vault unlock`), knows which env may use which binding, and hands each gate only its own
//! credentials: static values as-is, GitHub and Azure tokens minted per env. `luoto-vault ctl`
//! forwards one control request from stdin (host → vault via `exec -i`).

mod agent;
mod ctl;
mod entra;
mod github;
mod http;
mod state;
mod upstream;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use luoto_shared::ctl::CTL_SOCKET;
use luoto_shared::events::{Event, EventKind};
use tokio::net::UnixListener;

use crate::http::Channels;
use crate::state::{Vault, client_tls};

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn serve() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Gates reach the vault on a socket per env, made in this folder for each bound env, or
    // (Apple) on one socket whose every connection names its env first.
    let (channels, shared) = match (var("LUOTO_VAULT_SOCKETS"), var("LUOTO_VAULT_SOCKET")) {
        (Some(dir), None) => (Channels::PerEnv(http::EnvSockets::new(dir.into())), None),
        (None, Some(path)) => (Channels::Shared, Some(http::bind(Path::new(&path))?)),
        _ => bail!("set one of LUOTO_VAULT_SOCKETS (a folder) and LUOTO_VAULT_SOCKET"),
    };
    let ctl_path = std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into());
    if let Some(parent) = std::path::Path::new(&ctl_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&ctl_path);
    let ctl = UnixListener::bind(&ctl_path).with_context(|| format!("bind {ctl_path}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ctl_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Keep secrets out of core dumps and ptrace.
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctl call with valid constant arguments.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    let vault = Arc::new(Vault::new(client_tls()));
    vault.emit(Event {
        kind: Some(EventKind::Lifecycle),
        message: Some(format!("vault {} started (locked)", luoto_shared::VERSION)),
        ..Default::default()
    });
    if let Some(listener) = shared {
        tokio::spawn(http::serve_shared(vault.clone(), listener));
    }
    ctl::serve(vault, Arc::new(channels), ctl).await;
    Ok(())
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("ctl") => ctl::client(),
        Some("version" | "--version") => {
            println!("luoto-vault {}", luoto_shared::VERSION);
            ExitCode::SUCCESS
        }
        None | Some("run") => {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("luoto-vault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(serve()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("luoto-vault: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("usage: luoto-vault [run|ctl|version] (got `{other}`)");
            ExitCode::from(2)
        }
    }
}
