//! The event stream the gate and vault write to stdout and the host ingests. Every line is
//! one serde-serialized object, so attacker-chosen strings (hosts, paths) are escaped and
//! cannot forge a line; `run` + `seq` identify a line, so the host stores each once.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Gate,
    Vault,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A DNS lookup from the sandbox (answered locally, never forwarded).
    Dns,
    /// An HTTP request (proxied or intercepted).
    Http,
    /// An opaque tunnel (tunnel-mode rule).
    Tunnel,
    /// A connection that bypassed the proxy and was caught transparently, non-HTTP.
    Direct,
    /// The client rejected our certificate (likely pinning) — suggests a tunnel rule.
    TlsReject,
    /// The sandbox filed an access request.
    Request,
    /// An access request was resolved on the host.
    Resolve,
    /// The vault issued (or refused) a credential.
    Creds,
    /// Start, policy reload, lock/unlock.
    Lifecycle,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Intake {
    Proxy,
    Transparent,
    Dns,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Event {
    pub seq: u64,
    pub run: String,
    pub ts: Option<DateTime<Utc>>,
    pub source: Option<Source>,
    pub env: String,
    pub kind: Option<EventKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intake: Option<Intake>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Machine code (`no_rule`, `method_not_allowed`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_up: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_down: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
}

/// Reserved name used by `sandbox selftest`; its events are hidden from egress views.
pub const SELFTEST_DOMAIN: &str = "selftest.luoto.invalid";

pub fn is_selftest(host: &str) -> bool {
    host == SELFTEST_DOMAIN || host.ends_with(&format!(".{SELFTEST_DOMAIN}"))
}

/// Longest path kept in an event; the rest is elided (paths are attacker-controlled).
pub const MAX_PATH: usize = 300;

pub fn clip_path(path: &str) -> String {
    let no_query = path.split('?').next().unwrap_or(path);
    if no_query.len() <= MAX_PATH {
        return no_query.to_string();
    }
    let mut end = MAX_PATH;
    while !no_query.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &no_query[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clips_queries_and_long_paths() {
        assert_eq!(clip_path("/a?token=x"), "/a");
        assert!(clip_path(&"/x".repeat(400)).ends_with('…'));
    }
}
