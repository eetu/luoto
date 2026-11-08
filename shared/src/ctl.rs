//! Control protocol for the gate and the vault: one JSON request line in, one JSON response
//! line out, over a unix socket inside the container. Reached only through the runtime's
//! `exec -i` (the host user) — there is no network control port.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::creds::BindingSpec;
use crate::policy::Policy;

pub const CTL_SOCKET: &str = "/run/luoto/ctl.sock";

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
    SetVault {
        url: String,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum VaultCtl {
    Status,
    /// Resolved secret values keyed by their source ref. Merged into memory.
    Load {
        secrets: BTreeMap<String, String>,
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
