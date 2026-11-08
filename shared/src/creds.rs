//! Credential injection: where the gate places a secret on an outgoing request, and the
//! binding specs the vault uses to produce that secret. Secret values never appear here.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::glob;

/// The binding that holds the env's SSH key (`[credentials.ssh]`); the gate's ssh-agent route
/// asks the vault to sign with it.
pub const SSH_BINDING: &str = "ssh";

/// The vault's route for one binding's value (gate → vault, bearer = the env's token).
pub const VAULT_CREDENTIAL_PATH: &str = "/v1/credential";
/// The vault's route for one ssh-agent message for the env's SSH key.
pub const VAULT_AGENT_PATH: &str = "/v1/ssh-agent";

/// Request body for [`VAULT_CREDENTIAL_PATH`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CredentialRequest {
    pub binding: String,
}

/// Why the vault gave no value, and the HTTP status that carries it from the vault to the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialError {
    /// The binding's secret is not loaded: `luoto vault unlock`.
    Locked,
    /// The env has no such binding, or the vault doesn't know the env's token.
    NotBound,
    Failed(String),
}

impl CredentialError {
    pub fn status(&self) -> u16 {
        match self {
            CredentialError::Locked => 423,
            CredentialError::NotBound => 404,
            CredentialError::Failed(_) => 502,
        }
    }

    /// What a vault answer other than 200 means; 403 is the vault refusing the env's token.
    pub fn from_status(status: u16, body: &[u8]) -> Self {
        match status {
            423 => CredentialError::Locked,
            403 | 404 => CredentialError::NotBound,
            _ => CredentialError::Failed(format!(
                "vault returned {status}: {}",
                String::from_utf8_lossy(body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )),
        }
    }
}

/// Headers removed from every client request on a credentialed host, so code in the
/// sandbox can never smuggle its own (e.g. an attacker's) token through.
pub const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "private-token",
    "job-token",
    "cookie",
    // Azure Resource Manager's token for another tenant, read beside the one the gate adds.
    "x-ms-authorization-auxiliary",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Placement {
    /// Set header `name` to `format` with `{secret}` replaced.
    Header { name: String, format: String },
    /// `Authorization: Basic base64(username:secret)` (git smart-HTTP).
    Basic { username: String },
    /// Replace the value of query parameter `param` (Gemini `?key=`).
    Query { param: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Injection {
    /// Vault binding that supplies the secret (e.g. `github`, `anthropic`).
    pub binding: String,
    pub host: String,
    /// Empty = every path on the host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// The methods it goes on, upper-case; empty = every method. A request another rule
    /// allows with a method outside these goes without it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    pub place: Placement,
    /// Match `paths` without regard to ASCII case (see `Rule::ignore_case`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_case: bool,
}

impl Injection {
    pub fn path_matches(&self, path: &str) -> bool {
        glob::matches_any(&self.paths, self.ignore_case, path)
    }

    pub fn method_matches(&self, method: &str) -> bool {
        self.methods.is_empty() || self.methods.iter().any(|m| m == method)
    }
}

/// What the vault hands the gate for one binding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CredentialValue {
    pub value: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// How the vault produces a binding's value. Secret material is referenced, never inlined:
/// `*_ref` fields name a resolved source ref loaded into the vault by `luoto vault unlock`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindingSpec {
    /// A long-lived value (API key, PAT, OAuth token) handed out as-is.
    Static { secret_ref: String },
    /// A GitHub App installation token minted per request window, restricted to `repos`
    /// and `permissions`; the App private key never leaves the vault.
    GithubApp {
        app_id: String,
        installation_id: u64,
        key_ref: String,
        /// Repository names (without owner) the token is restricted to.
        repos: Vec<String>,
        permissions: BTreeMap<String, String>,
        #[serde(default = "default_github_api")]
        api_base: String,
    },
    /// An SSH private key (OpenSSH format) the vault signs logins with, as an ssh-agent; it
    /// never leaves the vault, not even to the gate. A login is signed only for a session
    /// one of `host_keys` (`host algorithm base64`, as in known_hosts) bound.
    SshAgent {
        key_ref: String,
        host_keys: Vec<String>,
    },
    /// A Microsoft Entra ID token for `audience`, minted by the client-credentials flow with a
    /// service principal's secret; the secret never leaves the vault.
    AzureServicePrincipal {
        /// Tenant ID or domain.
        tenant: String,
        client_id: String,
        secret_ref: String,
        /// The resource the token is for (`https://management.azure.com/`).
        audience: String,
    },
}

pub fn default_github_api() -> String {
    "https://api.github.com".into()
}

impl BindingSpec {
    /// The source ref of the secret the binding is made from.
    pub fn secret_ref(&self) -> &str {
        match self {
            BindingSpec::Static { secret_ref }
            | BindingSpec::AzureServicePrincipal { secret_ref, .. } => secret_ref,
            BindingSpec::GithubApp { key_ref, .. } | BindingSpec::SshAgent { key_ref, .. } => {
                key_ref
            }
        }
    }
}

/// Request body for [`VAULT_AGENT_PATH`]: one ssh-agent message for the env's `binding`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentRequest {
    pub binding: String,
    #[serde(flatten)]
    pub message: crate::api::AgentMessage,
}

/// GitHub App permissions luoto refuses to request: each one turns a repo-scoped token into
/// a path to CI secrets or account control.
pub const FORBIDDEN_GITHUB_PERMISSIONS: &[&str] = &[
    "workflows",
    "actions",
    "secrets",
    "environments",
    "administration",
    "pages",
    "organization_secrets",
    "organization_administration",
    "members",
    "deployments",
    "repository_hooks",
    "organization_hooks",
    "self_hosted_runners",
    "organization_self_hosted_runners",
];
