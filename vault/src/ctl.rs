//! Control socket (host → vault, via `exec -i luoto-vault ctl`). One JSON line each way.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use luoto_shared::ctl::{CTL_SOCKET, CtlResponse, VaultCtl};
use luoto_shared::events::{Event, EventKind};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::state::Vault;

const MAX_REQUEST: u64 = 16 << 20;

pub async fn serve(vault: Arc<Vault>, listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let vault = vault.clone();
        tokio::spawn(async move {
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            let mut reader = BufReader::new(r.take(MAX_REQUEST));
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<VaultCtl>(&line) {
                Ok(op) => dispatch(&vault, op),
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

fn dispatch(vault: &Vault, op: VaultCtl) -> CtlResponse {
    match op {
        VaultCtl::Status => CtlResponse::ok(vault.status()),
        VaultCtl::Load { secrets, held_only } => {
            let n = vault.load(secrets, held_only);
            lifecycle(vault, "", format!("{n} secret(s) loaded or changed"));
            CtlResponse::ok(n)
        }
        VaultCtl::Bind {
            env,
            token_sha256,
            bindings,
        } => {
            let Ok(raw) = hex::decode(&token_sha256) else {
                return CtlResponse::err("token_sha256 is not hex");
            };
            let Ok(hash) = <[u8; 32]>::try_from(raw.as_slice()) else {
                return CtlResponse::err("token_sha256 must be 32 bytes");
            };
            let names: Vec<String> = bindings.keys().cloned().collect();
            vault.bind(&env, hash, bindings);
            lifecycle(
                vault,
                &env,
                format!("bindings registered: {}", names.join(", ")),
            );
            CtlResponse::ok(true)
        }
        VaultCtl::Unbind { env } => {
            vault.unbind(&env);
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
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return ExitCode::from(2);
    }
    let socket = std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into());
    let mut stream = match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("luoto-vault ctl: connect {socket}: {e}");
            return ExitCode::from(2);
        }
    };
    let line = input.trim().replace('\n', " ");
    if stream.write_all(format!("{line}\n").as_bytes()).is_err() {
        return ExitCode::from(2);
    }
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    print!("{out}");
    match serde_json::from_str::<CtlResponse>(&out) {
        Ok(r) if r.ok => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}
