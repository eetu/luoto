//! Control socket (host → gate, via `exec -i luoto-gate ctl`). One JSON line each way.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use luoto_shared::ctl::{CTL_SOCKET, CtlResponse, GateCtl, GateStatus};
use luoto_shared::events::{Event, EventKind};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::state::State;

const MAX_REQUEST: u64 = 16 << 20;

pub async fn serve(state: Arc<State>, listener: UnixListener) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            // Out of descriptors: wait for some to close rather than spin.
            Err(_) => {
                tokio::time::sleep(crate::limits::ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            let mut reader = BufReader::new(r.take(MAX_REQUEST));
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<GateCtl>(&line) {
                Ok(op) => dispatch(&state, op),
                Err(e) => CtlResponse::err(format!("bad request: {e}")),
            };
            let mut out = serde_json::to_vec(&resp).unwrap_or_default();
            out.push(b'\n');
            let _ = w.write_all(&out).await;
        });
    }
}

fn lifecycle(state: &State, msg: String) {
    state.events.emit(Event {
        kind: Some(EventKind::Lifecycle),
        message: Some(msg),
        ..Default::default()
    });
}

fn dispatch(state: &State, op: GateCtl) -> CtlResponse {
    match op {
        GateCtl::Status => CtlResponse::ok(GateStatus {
            rules: state.policy().rules.len(),
            ca_installed: state.ca().is_some(),
            ca_pem_sha256: state.ca().map(|ca| ca.pem_sha256.clone()),
            vault_configured: state.vault().is_some(),
            pending_requests: state.requests().pending(),
        }),
        GateCtl::ApplyPolicy { policy } => {
            if !policy.env.is_empty() && policy.env != state.cfg.env {
                return CtlResponse::err(format!(
                    "policy is for env `{}`, this gate serves `{}`",
                    policy.env, state.cfg.env
                ));
            }
            let n = policy.rules.len();
            match state.set_policy(*policy) {
                Ok(()) => {
                    lifecycle(state, format!("policy applied ({n} rules)"));
                    CtlResponse::ok(n)
                }
                Err(e) => CtlResponse::err(format!("{e:#}")),
            }
        }
        GateCtl::InstallCa { cert_pem, key_pem } => match state.set_ca(&cert_pem, &key_pem) {
            Ok(()) => {
                lifecycle(state, "CA installed".into());
                CtlResponse::ok(true)
            }
            Err(e) => CtlResponse::err(format!("{e:#}")),
        },
        GateCtl::SetVault { token } => match state.set_vault(token) {
            Ok(()) => {
                lifecycle(state, "vault configured".into());
                CtlResponse::ok(true)
            }
            Err(e) => CtlResponse::err(format!("{e:#}")),
        },
        GateCtl::Requests => CtlResponse::ok(state.requests().list()),
        GateCtl::Resolve { id, approved, note } => {
            let res = state.requests().resolve(id, approved, note);
            match res {
                Ok(r) => {
                    state.events.emit(Event {
                        kind: Some(EventKind::Resolve),
                        host: Some(r.host.clone()),
                        port: r.port,
                        request_id: Some(id),
                        message: Some(if approved { "approved" } else { "rejected" }.into()),
                        ..Default::default()
                    });
                    CtlResponse::ok(r)
                }
                Err(e) => CtlResponse::err(e),
            }
        }
        GateCtl::FlushCredentials => {
            if let Some(v) = state.vault() {
                v.flush();
            }
            CtlResponse::ok(true)
        }
    }
}

/// `luoto-gate ctl`: forward one request from stdin to the socket, print the response.
pub fn client() -> ExitCode {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("luoto-gate ctl: could not read stdin");
        return ExitCode::from(2);
    }
    let line = input.trim().replace('\n', " ");
    let socket = std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into());
    let mut stream = match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("luoto-gate ctl: connect {socket}: {e}");
            return ExitCode::from(2);
        }
    };
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
