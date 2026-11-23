//! Control socket (host → gate, via `exec -i luoto-gate ctl`). One JSON line each way.

use std::process::ExitCode;
use std::sync::Arc;

use luoto_shared::ctl::{CtlResponse, GateCtl, GateStatus, LookupReply, read_request};
use luoto_shared::events::{Event, EventKind};
use luoto_shared::policy::Policy;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

use crate::state::State;

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
            let (mut r, mut w) = stream.into_split();
            let buf = match read_request(&mut r).await {
                Ok(b) => b,
                Err(_) => return,
            };
            let resp = match serde_json::from_slice::<GateCtl>(&buf) {
                Ok(GateCtl::Lookup) => lookup(&state).await,
                Ok(op) => dispatch(&state, op),
                Err(e) => CtlResponse::err(format!("bad request: {e}")),
            };
            let mut out = serde_json::to_vec(&resp).unwrap_or_default();
            out.push(b'\n');
            let _ = w.write_all(&out).await;
        });
    }
}

/// A host of the policy the env reaches anyway: exact, named, public and not expiring.
fn lookup_host(policy: &Policy) -> Option<String> {
    policy
        .rules
        .iter()
        .map(|r| &r.rule)
        .find(|r| {
            !r.host.contains('*')
                && r.host.contains('.')
                && r.host.parse::<std::net::IpAddr>().is_err()
                && !r.host.eq_ignore_ascii_case(luoto_shared::THIS_MACHINE)
                && !r.allow_private
                && r.expires.is_none()
        })
        .map(|r| r.host.to_ascii_lowercase())
}

async fn lookup(state: &State) -> CtlResponse {
    let Some(host) = lookup_host(&state.policy()) else {
        return CtlResponse::ok(LookupReply {
            host: None,
            addresses: 0,
        });
    };
    let found = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host.clone(), 443)),
    )
    .await;
    match found {
        Err(_) => CtlResponse::err(format!("DNS lookup for {host} timed out")),
        // musl's words for NXDOMAIN: the resolver answered.
        Ok(Err(e)) if e.to_string().contains("Name does not resolve") => {
            CtlResponse::ok(LookupReply {
                host: Some(host),
                addresses: 0,
            })
        }
        Ok(Err(e)) => CtlResponse::err(format!("DNS lookup for {host} failed: {e}")),
        Ok(Ok(addrs)) => CtlResponse::ok(LookupReply {
            host: Some(host),
            addresses: addrs.count(),
        }),
    }
}

fn lifecycle(state: &State, msg: String) {
    state.events.emit(Event {
        kind: Some(EventKind::Lifecycle),
        message: Some(msg),
        ..Default::default()
    });
}

fn dispatch(state: &State, mut op: GateCtl) -> CtlResponse {
    match &mut op {
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
            match state.set_policy(std::mem::take(&mut **policy)) {
                Ok(()) => {
                    lifecycle(state, format!("policy applied ({n} rules)"));
                    CtlResponse::ok(n)
                }
                Err(e) => CtlResponse::err(format!("{e:#}")),
            }
        }
        GateCtl::InstallCa { cert_pem, key_pem } => match state.set_ca(cert_pem, key_pem) {
            Ok(()) => {
                lifecycle(state, "CA installed".into());
                CtlResponse::ok(true)
            }
            Err(e) => CtlResponse::err(format!("{e:#}")),
        },
        GateCtl::SetVault { token } => match state.set_vault(std::mem::take(token)) {
            Ok(()) => {
                lifecycle(state, "vault configured".into());
                CtlResponse::ok(true)
            }
            Err(e) => CtlResponse::err(format!("{e:#}")),
        },
        GateCtl::Requests => CtlResponse::ok(state.requests().list()),
        GateCtl::Resolve { id, approved, note } => {
            let res = state.requests().resolve(*id, *approved, note.take());
            match res {
                Ok(r) => {
                    state.events.emit(Event {
                        kind: Some(EventKind::Resolve),
                        host: Some(r.host.clone()),
                        port: r.port,
                        request_id: Some(*id),
                        message: Some(if *approved { "approved" } else { "rejected" }.into()),
                        ..Default::default()
                    });
                    CtlResponse::ok(r)
                }
                Err(e) => CtlResponse::err(e),
            }
        }
        GateCtl::Lookup => CtlResponse::err("lookup is answered before dispatch"),
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
    luoto_shared::ctl::client("luoto-gate")
}

#[cfg(test)]
mod tests {
    use luoto_shared::policy::{CompiledRule, Rule};

    use super::*;

    fn policy(rules: Vec<Rule>) -> Policy {
        Policy {
            rules: rules
                .into_iter()
                .map(|rule| CompiledRule {
                    id: String::new(),
                    origin: "user".into(),
                    rule,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn host(h: &str) -> Rule {
        Rule {
            host: h.into(),
            ..Default::default()
        }
    }

    #[test]
    fn looks_up_only_a_host_the_env_reaches_for_good() {
        let expiring = Rule {
            expires: Some(chrono::Utc::now()),
            ..host("downloads.example.org")
        };
        let private = Rule {
            allow_private: true,
            ..host("git.internal.example")
        };
        let p = policy(vec![
            host("*.npmjs.org"),
            host("10.0.0.1"),
            host(luoto_shared::THIS_MACHINE),
            host("localhost"),
            expiring,
            private,
            host("Registry.Example.com"),
        ]);
        assert_eq!(lookup_host(&p).as_deref(), Some("registry.example.com"));
        assert_eq!(lookup_host(&policy(vec![host("*.example.com")])), None);
    }
}
