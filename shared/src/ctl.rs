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
    /// Resolve a host the env's own rules name, as the gate does before it dials: whether
    /// the gate's DNS answers, without asking it about anything the env doesn't reach.
    Lookup,
}

/// What [`GateCtl::Lookup`] found.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LookupReply {
    /// The host looked up; none when no rule names one that can be.
    pub host: Option<String>,
    /// Its addresses; 0 when the resolver answered that there is no such name.
    pub addresses: usize,
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
    /// Swap on the kernel the vault runs on, in KiB.
    #[serde(default)]
    pub swap_kib: u64,
    /// The vault's cgroup's `memory.swap.max` (`0`: its memory is never swapped); `None` where
    /// no cgroup v2 memory controller limits it.
    #[serde(default)]
    pub swap_max: Option<String>,
}

/// `v` as JSON in a buffer of exactly its size, wiped on drop. Serializing into a growing `Vec`
/// would leave each smaller copy of any secret in it unwiped in freed memory.
pub fn to_json(v: &impl Serialize) -> serde_json::Result<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, v)?;
    let mut out = Zeroizing::new(Vec::with_capacity(count.0));
    serde_json::to_writer(&mut *out, v)?;
    Ok(out)
}

/// A control request read into one buffer that is wiped on drop. The buffer grows by moving
/// into a larger one and wiping the old, so no copy of a secret is left in freed memory.
// The CLI (Windows too) builds this crate without the gate's and vault's readers.
#[cfg_attr(not(unix), allow(dead_code))]
struct LineAccumulator {
    buf: Zeroizing<Vec<u8>>,
    chunk: Zeroizing<[u8; 4096]>,
    max: usize,
    until_eof: bool,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl LineAccumulator {
    fn new(max: usize, until_eof: bool) -> Self {
        LineAccumulator {
            buf: Zeroizing::new(Vec::new()),
            chunk: Zeroizing::new([0u8; 4096]),
            max,
            until_eof,
        }
    }

    /// Where the next read goes: never more than `max` in all.
    fn chunk_mut(&mut self) -> std::io::Result<&mut [u8]> {
        let cap = self
            .max
            .saturating_sub(self.buf.len())
            .min(self.chunk.len());
        if cap == 0 {
            return Err(too_long(self.max));
        }
        Ok(&mut self.chunk[..cap])
    }

    fn push(&mut self, n: usize) {
        let need = self.buf.len() + n;
        if need > self.buf.capacity() {
            let mut grown = Zeroizing::new(Vec::with_capacity(
                need.max(2 * self.buf.capacity()).min(self.max),
            ));
            grown.extend_from_slice(&self.buf);
            self.buf = grown;
        }
        self.buf.extend_from_slice(&self.chunk[..n]);
    }

    /// Takes the `n` bytes read into `chunk_mut()`: the request once a line ends (but
    /// `until_eof`) or at EOF, `None` while more is to come. Until EOF, the request is trimmed
    /// and its line breaks become spaces.
    fn feed(&mut self, n: usize) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
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
                    .map_or(0, |p| p + 1);
                let len = end.saturating_sub(start);
                self.buf.copy_within(start..start + len, 0);
                self.buf[len..].zeroize();
                self.buf.truncate(len);
                for b in self.buf.iter_mut() {
                    if *b == b'\n' || *b == b'\r' {
                        *b = b' ';
                    }
                }
            } else if self.buf.is_empty() {
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
            self.push(pos);
            return Ok(Some(std::mem::take(&mut self.buf)));
        }
        self.push(n);
        Ok(None)
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn too_long(max: usize) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("request exceeds max limit of {max} bytes"),
    )
}

#[cfg_attr(not(unix), allow(dead_code))]
fn read_accumulated(
    mut r: impl std::io::Read,
    mut acc: LineAccumulator,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    loop {
        let n = match r.read(acc.chunk_mut()?) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if let Some(line) = acc.feed(n)? {
            return Ok(line);
        }
    }
}

/// One request line (to `\n` or EOF, at most [`MAX_REQUEST`] bytes) from a ctl socket.
#[cfg(feature = "ctl-server")]
pub async fn read_request<R: tokio::io::AsyncRead + Unpin>(
    mut r: R,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    use tokio::io::AsyncReadExt;
    let mut acc = LineAccumulator::new(MAX_REQUEST, false);
    loop {
        let n = r.read(acc.chunk_mut()?).await?;
        if let Some(line) = acc.feed(n)? {
            return Ok(line);
        }
    }
}

/// `luoto-vault ctl` / `luoto-gate ctl`: forward the request on stdin to the socket and print
/// the response.
#[cfg(unix)]
pub fn client(bin: &str) -> std::process::ExitCode {
    use std::io::{Read, Write};
    use std::process::ExitCode;

    let payload = match read_accumulated(std::io::stdin(), LineAccumulator::new(MAX_REQUEST, true))
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{bin} ctl: could not read stdin: {e}");
            return ExitCode::from(2);
        }
    };
    let socket = std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into());
    let mut stream = match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{bin} ctl: connect {socket}: {e}");
            return ExitCode::from(2);
        }
    };
    let sent = stream
        .write_all(&payload)
        .and_then(|_| stream.write_all(b"\n"));
    drop(payload);
    if sent.is_err() {
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

    fn read(input: &[u8], max: usize, until_eof: bool) -> std::io::Result<Zeroizing<Vec<u8>>> {
        read_accumulated(input, LineAccumulator::new(max, until_eof))
    }

    #[test]
    fn line_accumulator_reads_lines_and_normalizes_stdin_payloads() {
        let line = read(b"{\"op\":\"status\"}\nextra", 1024, false).unwrap();
        assert_eq!(&*line, b"{\"op\":\"status\"}");

        let payload = read(b"  {\n\"op\": \"lock\"\r\n}\n  ", 1024, true).unwrap();
        assert_eq!(&*payload, b"{ \"op\": \"lock\"  }");
        assert!(read(b" \n ", 1024, true).unwrap().is_empty());

        assert_eq!(read(b"1234", 5, false).unwrap().as_slice(), b"1234");
        let err = read(b"12345", 5, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let err = read(b"", 5, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn line_accumulator_grows_past_a_chunk() {
        let mut input = vec![b'a'; 10_000];
        input.push(b'\n');
        input.extend_from_slice(b"next");
        let line = read(&input, MAX_REQUEST, false).unwrap();
        assert_eq!(line.len(), 10_000);
        assert!(line.iter().all(|&b| b == b'a'));
    }

    #[test]
    fn to_json_is_exactly_the_json() {
        let op = VaultCtl::Load {
            secrets: BTreeMap::from([("op://a/b/c".into(), "line\none\"".into())]),
            held_only: true,
        };
        let out = to_json(&op).unwrap();
        assert_eq!(out.as_slice(), serde_json::to_vec(&op).unwrap().as_slice());
        assert_eq!(out.capacity(), out.len());
    }
}
