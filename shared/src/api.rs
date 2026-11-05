//! The in-sandbox API the gate serves at `http://gate:3128/_sandbox/…` for the `sandbox`
//! helper (and through it, MCP-capable agents). Read-mostly; the writes are filing an access
//! request, which only the host can resolve, and passing ssh-agent messages to the vault.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events::Event;
use crate::policy::{AccessLevel, Mode};

pub const API_PREFIX: &str = "/_sandbox";

/// Where `sandbox ssh-agent` sends each agent message (under [`API_PREFIX`]).
pub const SSH_AGENT_PATH: &str = "/ssh-agent";

/// The longest ssh-agent message passed on to the vault, unencoded. OpenSSH's (identities, a
/// session bind, a login to sign) take a few KiB at most; the gate and the vault size the JSON
/// body that carries one in base64 from this.
pub const MAX_AGENT_MESSAGE: usize = 8 * 1024;

/// One ssh-agent protocol message, or the reply to it: without its length prefix, base64.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentMessage {
    /// The agent connection it came on: a session bound on one connection holds only there.
    pub conn: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RuleSummary {
    pub id: String,
    pub origin: String,
    pub host: String,
    pub access: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    pub mode: Mode,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SandboxStatus {
    pub env: String,
    pub gate_version: String,
    pub credentials_locked: bool,
    pub rules: Vec<RuleSummary>,
    /// Hosts where the gate injects credentials (values never leave the gate).
    pub credentialed_hosts: Vec<String>,
    pub recent_denials: Vec<Event>,
    pub requests: Vec<AccessRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CheckQuery {
    pub url: String,
    #[serde(default = "get")]
    pub method: String,
}

fn get() -> String {
    "GET".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NewAccessRequest {
    pub host: String,
    pub access: AccessLevel,
    #[serde(default)]
    pub paths: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AccessRequest {
    pub id: u64,
    pub host: String,
    pub access: AccessLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Written by code in the sandbox — untrusted text, display escaped.
    pub reason: String,
    pub status: RequestStatus,
    pub created: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Limits on what the sandbox can file, so requests can't be used for approval fatigue.
pub const MAX_PENDING_REQUESTS: usize = 5;
pub const MAX_REASON_LEN: usize = 500;
