//! Control protocol for the gate and the vault: one JSON request line in, one JSON response
//! line out, over a unix socket inside the container. Reached only through the runtime's
//! `exec -i` (the host user) — there is no network control port.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::creds::BindingSpec;
use crate::policy::Policy;

pub const CTL_SOCKET: &str = "/run/luoto/ctl.sock";
pub const MAX_REQUEST: usize = 16 << 20;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GateCtl {
    Status,
    ApplyPolicy {
        policy: Box<Policy>,
    },
    InstallCa {
        cert_pem: String,
        key_pem: String,
    },
    /// The token the gate shows the vault on its env's socket ([`crate::VAULT_SOCKET`]).
    SetVault {
        token: String,
    },
    Requests,
    Resolve {
        id: u64,
        approved: bool,
        #[serde(default)]
        note: Option<String>,
    },
    /// Drop cached credentials so a vault lock or binding change applies at once.
    FlushCredentials,
}

impl Drop for GateCtl {
    fn drop(&mut self) {
        match self {
            GateCtl::InstallCa { key_pem, .. } => {
                key_pem.zeroize();
            }
            GateCtl::SetVault { token } => {
                token.zeroize();
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum VaultCtl {
    Status,
    /// Resolved secret values keyed by their source ref. Merged into memory.
    Load {
        secrets: BTreeMap<String, String>,
        /// Only replace refs the vault holds: a renewal, which leaves a locked vault empty.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        held_only: bool,
    },
    /// Register (or replace) an env: its gate's token hash and its bindings.
    Bind {
        env: String,
        token_sha256: String,
        bindings: BTreeMap<String, BindingSpec>,
    },
    Unbind {
        env: String,
    },
    /// Wipe all secret material from memory.
    Lock,
}

impl Drop for VaultCtl {
    fn drop(&mut self) {
        match self {
            VaultCtl::Load { secrets, .. } => {
                for (mut k, mut v) in std::mem::take(secrets) {
                    k.zeroize();
                    v.zeroize();
                }
            }
            VaultCtl::Bind { token_sha256, .. } => {
                token_sha256.zeroize();
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CtlResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl CtlResponse {
    pub fn ok(data: impl Serialize) -> Self {
        CtlResponse {
            ok: true,
            error: None,
            data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null),
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        CtlResponse {
            ok: false,
            error: Some(msg.into()),
            data: serde_json::Value::Null,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GateStatus {
    pub rules: usize,
    pub ca_installed: bool,
    /// SHA-256 (hex) of the installed CA certificate's PEM text: the host installs the env's
    /// CA again when it differs, as after a renewal.
    #[serde(default)]
    pub ca_pem_sha256: Option<String>,
    pub vault_configured: bool,
    pub pending_requests: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VaultEnvSummary {
    pub env: String,
    pub bindings: Vec<String>,
    /// Refs the env's bindings need that are not loaded.
    pub missing: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VaultStatus {
    pub version: String,
    pub started: DateTime<Utc>,
    pub locked: bool,
    pub loaded_refs: Vec<String>,
    pub envs: Vec<VaultEnvSummary>,
}

/// Chunks and reads secret-bearing control payloads into `Zeroizing<Vec<u8>>` using an internal
/// `Zeroizing<[u8; 4096]>` buffer, ensuring that buffers are volatile-zeroized on drop in all
/// error, signal, and success paths.
pub struct LineAccumulator {
    buf: Zeroizing<Vec<u8>>,
    chunk: Zeroizing<[u8; 4096]>,
    max: usize,
    until_eof: bool,
}

impl LineAccumulator {
    pub fn new(max: usize) -> Self {
        LineAccumulator {
            buf: Zeroizing::new(Vec::new()),
            chunk: Zeroizing::new([0u8; 4096]),
            max,
            until_eof: false,
        }
    }

    pub fn until_eof(max: usize) -> Self {
        LineAccumulator {
            until_eof: true,
            ..Self::new(max)
        }
    }

    /// Slice of the chunk buffer available for reading next.
    pub fn chunk_mut(&mut self) -> &mut [u8] {
        let remaining = self.max.saturating_sub(self.buf.len());
        let cap = remaining.min(self.chunk.len());
        &mut self.chunk[..cap]
    }

    /// Feeds `n` bytes read into `chunk_mut()`.
    /// - Returns `Ok(Some(line))` when newline `b'\n'` is encountered (unless `until_eof`) or EOF.
    /// - Returns `Ok(None)` when more data is needed.
    /// - Returns `Err` on EOF with empty buffer (when `!until_eof`) or when `max` is exceeded.
    pub fn feed(&mut self, n: usize) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
        if n == 0 {
            if self.until_eof {
                let start = self
                    .buf
                    .iter()
                    .position(|b| !b.is_ascii_whitespace())
                    .unwrap_or(self.buf.len());
                let end = self
                    .buf
                    .iter()
                    .rposition(|b| !b.is_ascii_whitespace())
                    .map(|p| p + 1)
                    .unwrap_or(0);
                if start >= end {
                    self.buf.clear();
                    return Ok(Some(std::mem::take(&mut self.buf)));
                }
                let len = end - start;
                self.buf.copy_within(start..end, 0);
                self.buf[len..].zeroize();
                self.buf.truncate(len);
                for b in self.buf.iter_mut() {
                    if *b == b'\n' || *b == b'\r' {
                        *b = b' ';
                    }
                }
                return Ok(Some(std::mem::take(&mut self.buf)));
            }
            if self.buf.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "empty request",
                ));
            }
            return Ok(Some(std::mem::take(&mut self.buf)));
        }
        if !self.until_eof
            && let Some(pos) = self.chunk[..n].iter().position(|&b| b == b'\n')
        {
            self.buf.extend_from_slice(&self.chunk[..pos]);
            return Ok(Some(std::mem::take(&mut self.buf)));
        }
        self.buf.extend_from_slice(&self.chunk[..n]);
        if self.buf.len() >= self.max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("request exceeds max limit of {} bytes", self.max),
            ));
        }
        Ok(None)
    }
}

fn read_accumulated(
    mut r: impl std::io::Read,
    mut acc: LineAccumulator,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    loop {
        if is_interrupted() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "interrupted by signal",
            ));
        }
        let chunk = acc.chunk_mut();
        if chunk.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("request exceeds max limit of {} bytes", acc.max),
            ));
        }
        let n = match r.read(chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted && !is_interrupted() => continue,
            Err(e) => return Err(e),
        };
        if let Some(line) = acc.feed(n)? {
            return Ok(line);
        }
    }
}

/// Reads a single line (up to `b'\n'` or EOF, capped at `max` bytes) from synchronous reader `r`.
/// All intermediate stack buffers and the returned buffer are volatile-zeroized on drop.
pub fn read_line(r: impl std::io::Read, max: usize) -> std::io::Result<Zeroizing<Vec<u8>>> {
    read_accumulated(r, LineAccumulator::new(max))
}

/// Reads stdin payload up to `max` bytes until EOF (for `ctl::client`) via [`LineAccumulator`].
/// Trims leading and trailing whitespace and replaces interior newline/carriage return characters
/// with spaces in-place without allocating a second buffer.
pub fn read_stdin_payload(
    r: impl std::io::Read,
    max: usize,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    read_accumulated(r, LineAccumulator::until_eof(max))
}

static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_signal(_: libc::c_int) {
    INTERRUPTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub fn install_sigterm_handler() {
    #[cfg(unix)]
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as *const () as usize;
        // Do NOT set SA_RESTART so blocking syscalls return EINTR.
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

pub fn is_interrupted() -> bool {
    INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Unified control client (`luoto-vault ctl` / `luoto-gate ctl`):
/// Reads request payload from stdin into `Zeroizing<Vec<u8>>`, sends over unix socket, prints response.
/// Zeroizes secret buffers on drop in error, exit, or SIGTERM/SIGINT signal paths.
pub fn client(bin: &str) -> std::process::ExitCode {
    use std::io::{Read, Write};
    use std::process::ExitCode;

    install_sigterm_handler();

    let payload = match read_stdin_payload(std::io::stdin(), MAX_REQUEST) {
        Ok(p) => p,
        Err(e) => {
            if is_interrupted() {
                eprintln!("{bin} ctl: interrupted");
                return ExitCode::from(130);
            }
            eprintln!("{bin} ctl: could not read stdin: {e}");
            return ExitCode::from(2);
        }
    };

    if is_interrupted() {
        return ExitCode::from(130);
    }

    let socket = std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into());
    let mut stream = match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{bin} ctl: connect {socket}: {e}");
            return ExitCode::from(2);
        }
    };

    let write_res = stream
        .write_all(&payload)
        .and_then(|_| stream.write_all(b"\n"));
    drop(payload);
    if write_res.is_err() {
        if is_interrupted() {
            return ExitCode::from(130);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_accumulator_reads_lines_and_normalizes_stdin_payloads() {
        let line = read_line(&b"{\"op\":\"status\"}\nextra"[..], 1024).unwrap();
        assert_eq!(&*line, b"{\"op\":\"status\"}");

        let payload = read_stdin_payload(&b"  {\n\"op\": \"lock\"\r\n}\n  "[..], 1024).unwrap();
        assert_eq!(&*payload, b"{ \"op\": \"lock\"  }");

        let err = read_line(&b"123456"[..], 5).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
