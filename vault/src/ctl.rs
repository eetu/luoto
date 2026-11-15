//! Control socket (host → vault, via `exec -i luoto-vault ctl`). One JSON line each way.

use std::process::ExitCode;
use std::sync::Arc;

use luoto_shared::ctl::{CtlResponse, VaultCtl, read_request};
use luoto_shared::events::{Event, EventKind};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

use crate::http::{self, Channels};
use crate::state::Vault;

pub async fn serve(vault: Arc<Vault>, channels: Arc<Channels>, listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let vault = vault.clone();
        let channels = channels.clone();
        tokio::spawn(async move {
            let (mut r, mut w) = stream.into_split();
            let buf = match read_request(&mut r).await {
                Ok(b) => b,
                Err(_) => return,
            };
            let resp = match serde_json::from_slice::<VaultCtl>(&buf) {
                Ok(op) => dispatch(&vault, &channels, op),
                Err(e) => CtlResponse::err(format!("bad request: {e}")),
            };
            let mut out = serde_json::to_vec(&resp).unwrap_or_default();
            out.push(b'\n');
            let _ = w.write_all(&out).await;
        });
    }
}

fn lifecycle(vault: &Vault, env: &str, msg: String) {
    vault.emit(Event {
        kind: Some(EventKind::Lifecycle),
        env: env.to_string(),
        message: Some(msg),
        ..Default::default()
    });
}

fn dispatch(vault: &Arc<Vault>, channels: &Channels, mut op: VaultCtl) -> CtlResponse {
    match &mut op {
        VaultCtl::Status => CtlResponse::ok(vault.status()),
        VaultCtl::Load { secrets, held_only } => {
            let n = vault.load(std::mem::take(secrets), *held_only);
            lifecycle(vault, "", format!("{n} secret(s) loaded or changed"));
            CtlResponse::ok(n)
        }
        VaultCtl::Bind {
            env,
            token_sha256,
            bindings,
        } => {
            if !http::valid_env(env) {
                return CtlResponse::err("env names are 1-64 chars of a-z, 0-9 and '-'");
            }
            let Ok(raw) = hex::decode(&*token_sha256) else {
                return CtlResponse::err("token_sha256 is not hex");
            };
            let Ok(hash) = <[u8; 32]>::try_from(raw.as_slice()) else {
                return CtlResponse::err("token_sha256 must be 32 bytes");
            };
            let names: Vec<String> = bindings.keys().cloned().collect();
            vault.bind(env, hash, std::mem::take(bindings));
            if let Channels::PerEnv(sockets) = channels
                && let Err(e) = sockets.open(vault, env)
            {
                return CtlResponse::err(format!("{e:#}"));
            }
            lifecycle(
                vault,
                env,
                format!("bindings registered: {}", names.join(", ")),
            );
            CtlResponse::ok(true)
        }
        VaultCtl::Unbind { env } => {
            vault.unbind(env);
            if let Channels::PerEnv(sockets) = channels
                && http::valid_env(env)
            {
                sockets.close(env);
            }
            CtlResponse::ok(true)
        }
        VaultCtl::Lock => {
            vault.wipe();
            lifecycle(vault, "", "locked: all secrets wiped from memory".into());
            CtlResponse::ok(true)
        }
    }
}

/// `luoto-vault ctl`: forward one request from stdin to the socket, print the response.
pub fn client() -> ExitCode {
    luoto_shared::ctl::client("luoto-vault")
}
