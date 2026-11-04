//! Credential injection: where the gate places a secret on an outgoing request, and the
//! binding specs the vault uses to produce that secret. Secret values never appear here.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::glob::{glob_match, glob_match_any_case};

/// Headers removed from every client request on a credentialed host, so code in the
/// sandbox can never smuggle its own (e.g. an attacker's) token through.
pub const AUTH_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
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
    pub place: Placement,
    /// Match `paths` without regard to ASCII case (see `Rule::ignore_case`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_case: bool,
}

impl Injection {
    pub fn path_matches(&self, path: &str) -> bool {
        self.paths.is_empty()
            || self.paths.iter().any(|p| {
                if self.ignore_case {
                    glob_match_any_case(p, path)
                } else {
                    glob_match(p, path)
                }
            })
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
}

pub fn default_github_api() -> String {
    "https://api.github.com".into()
}

impl BindingSpec {
    pub fn refs(&self) -> Vec<&str> {
        match self {
            BindingSpec::Static { secret_ref } => vec![secret_ref.as_str()],
            BindingSpec::GithubApp { key_ref, .. } => vec![key_ref.as_str()],
            BindingSpec::SshAgent { key_ref, .. } => vec![key_ref.as_str()],
        }
    }
}

/// One ssh-agent message, as the gate passes it on to the vault for the env's `binding`.
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
