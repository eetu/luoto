//! `sandbox ssh-agent`: the env's ssh-agent socket. Every message goes to the vault through
//! the gate (`/_sandbox/ssh-agent`), which holds the key and decides.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use luoto_shared::api::{API_PREFIX, AgentMessage, MAX_AGENT_MESSAGE, SSH_AGENT_PATH};

/// Where init.sh starts the agent, and ssh's `IdentityAgent` points.
pub const SOCKET: &str = "/run/luoto/ssh/agent.sock";

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;

pub fn serve(socket: &Path) -> Result<()> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let _ = std::fs::remove_file(socket);
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    }
    for stream in listener.incoming().flatten() {
        std::thread::spawn(move || {
            let _ = connection(stream);
        });
    }
    Ok(())
}

fn connection(mut stream: UnixStream) -> Result<()> {
    let conn = hex::encode(rand::random::<[u8; 16]>());
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_AGENT_MESSAGE {
            return Ok(());
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg)?;
        let reply = ask(&conn, &msg).unwrap_or_else(|| fallback(msg[0]));
        stream.write_all(&(reply.len() as u32).to_be_bytes())?;
        stream.write_all(&reply)?;
    }
}

/// The vault's answer, through the gate.
fn ask(conn: &str, msg: &[u8]) -> Option<Vec<u8>> {
    let body = serde_json::to_string(&AgentMessage {
        conn: conn.to_string(),
        message: B64.encode(msg),
    })
    .ok()?;
    let r = crate::gate::request(
        "POST",
        &format!("{API_PREFIX}{SSH_AGENT_PATH}"),
        Some(&body),
    )
    .ok()?;
    if r.status != 200 {
        return None;
    }
    let reply: AgentMessage = serde_json::from_str(&r.body).ok()?;
    B64.decode(reply.message).ok().filter(|m| !m.is_empty())
}

/// With no key bound (or the vault unreachable), the agent has nothing: no identities, and
/// every other request fails, so ssh moves on with an honest error.
fn fallback(kind: u8) -> Vec<u8> {
    if kind == REQUEST_IDENTITIES {
        vec![IDENTITIES_ANSWER, 0, 0, 0, 0]
    } else {
        vec![FAILURE]
    }
}
