//! The egress policy: rules, explicit denies, and the decision function the gate runs for
//! every request. Default deny. The CLI compiles presets, agent/provider profiles and user
//! rules into one [`Policy`]; the gate only evaluates it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::creds::Injection;
use crate::forges;
use crate::glob;
use crate::host::{WildcardRisk, host_matches, normalize_host, normalize_pattern, wildcard_risk};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    /// GET, HEAD, OPTIONS.
    Read,
    /// Any method.
    Write,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Access {
    Level(AccessLevel),
    Methods(Vec<String>),
}

impl Default for Access {
    fn default() -> Self {
        Access::Level(AccessLevel::Read)
    }
}

pub const READ_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

impl Access {
    pub fn allows(&self, method: &str) -> bool {
        match self {
            Access::Level(AccessLevel::Read) => READ_METHODS.contains(&method),
            Access::Level(AccessLevel::Write) => true,
            Access::Methods(ms) => ms.iter().any(|m| m.eq_ignore_ascii_case(method)),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Access::Level(AccessLevel::Read) => "read-only (GET, HEAD, OPTIONS)".into(),
            Access::Level(AccessLevel::Write) => "any method".into(),
            Access::Methods(ms) => ms.join(", "),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// TLS is intercepted; method, path, body and credentials are enforced per request.
    #[default]
    Inspect,
    /// Opaque TCP tunnel to host:port — for certificate-pinning clients and gRPC. Only the
    /// host is enforced.
    Tunnel,
}

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// One allow rule. `port: None` means the standard ports 80 and 443.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable id for user rules in env configs (presets leave it empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default)]
    pub access: Access,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub mode: Mode,
    /// Permit `Upgrade: websocket` (a full-duplex channel even under read access).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ws: bool,
    /// Cap on request body bytes (used for read-POST endpoints like git-upload-pack).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body: Option<u64>,
    /// Allow dialing private/loopback/host-gateway addresses for this host.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_private: bool,
    /// Free-text note shown in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Match `paths` without regard to ASCII case, for hosts whose paths are case-insensitive
    /// (Azure DevOps organizations, projects and repositories).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_case: bool,
    /// How long the host may stay silent (`30m`, `2h`) before the gate closes the connection,
    /// in place of its default: for long polls such as `kubectl logs -f`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<String>,
}

/// The longest `idle` a rule may set.
pub const MAX_IDLE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// A rule's `idle`: a whole number of seconds, minutes or hours (`90s`, `30m`, `2h`), above
/// zero and at most [`MAX_IDLE`].
pub fn parse_idle(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("idle `{s}`: give a duration such as 30m or 2h"))?;
    let secs = match unit {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        _ => return Err(format!("idle `{s}`: use s, m or h")),
    };
    match secs.map(std::time::Duration::from_secs) {
        Some(d) if !d.is_zero() && d <= MAX_IDLE => Ok(d),
        _ => Err(format!("idle `{s}`: above zero and at most 24h")),
    }
}

impl Rule {
    /// The rule's valid `idle`, if it sets one.
    pub fn idle_limit(&self) -> Option<std::time::Duration> {
        self.idle.as_deref().and_then(|s| parse_idle(s).ok())
    }

    pub fn read(host: &str) -> Self {
        Rule {
            host: host.into(),
            ..Default::default()
        }
    }

    pub fn port_matches(&self, port: u16) -> bool {
        match self.port {
            Some(p) => p == port,
            None => port == 80 || port == 443,
        }
    }

    pub fn expired(&self, now: DateTime<Utc>) -> bool {
        self.expires.is_some_and(|e| e <= now)
    }

    pub fn path_matches(&self, path: &str) -> bool {
        glob::matches_any(&self.paths, self.ignore_case, path)
    }
}

/// A rule with provenance, as the gate sees it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CompiledRule {
    pub id: String,
    /// `preset:npm`, `user`, `request:3`, `agent:claude`, `provider:anthropic`, `github`.
    pub origin: String,
    #[serde(flatten)]
    pub rule: Rule,
}

/// Explicit deny, evaluated before any allow (e.g. GitHub Actions endpoints).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DenyRule {
    pub host: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Empty = all methods.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    pub reason: String,
}

/// A `[[deny]]` of the user's config, `config.toml` or a `luoto.toml`: refused whatever allows
/// it, a preset included. It only tightens, so a repository may write one.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Deny {
    pub host: String,
    /// Empty: the whole host. Matched in any case, as every explicit deny is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Empty: every method.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Shown with every request it refuses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Deny {
    /// What the gate enforces, or why the entry is refused.
    pub fn rule(&self) -> Result<DenyRule, String> {
        let host = pattern(&self.host)?;
        paths_ok(&self.paths)?;
        if let Some(m) = self
            .methods
            .iter()
            .find(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphabetic()))
        {
            return Err(format!("`{m}` is not an HTTP method"));
        }
        Ok(DenyRule {
            host,
            paths: self.paths.clone(),
            methods: self
                .methods
                .iter()
                .map(|m| m.to_ascii_uppercase())
                .collect(),
            reason: match &self.note {
                Some(n) => format!("denied by a [[deny]] rule: {n}"),
                None => "denied by a [[deny]] rule".into(),
            },
        })
    }
}

/// A `[[mute]]`: denials left out of egress views, for telemetry the user keeps denied. They
/// are still denied and recorded. Only the user's own config mutes: a repository's could hide
/// what its code tries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Mute {
    pub host: String,
    /// Empty: every denial at the host, and its lookups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Mute {
    /// The entry with its host in the form events carry hosts, or why it is refused.
    pub fn checked(&self) -> Result<Mute, String> {
        let host = pattern(&self.host)?;
        paths_ok(&self.paths)?;
        if host == "*" && self.paths.is_empty() {
            return Err("`*` without paths would hide every denial".into());
        }
        Ok(Mute {
            host,
            ..self.clone()
        })
    }

    /// Does it hide a denial at canonical `host`, of `path` if the denial was a request's?
    pub fn covers(&self, host: &str, path: Option<&str>) -> bool {
        host_matches(&self.host, host)
            && match path {
                Some(p) => glob::matches_any(&self.paths, true, p),
                None => self.paths.is_empty(),
            }
    }
}

fn pattern(host: &str) -> Result<String, String> {
    normalize_pattern(host).ok_or_else(|| format!("invalid host pattern `{host}`"))
}

fn paths_ok(paths: &[String]) -> Result<(), String> {
    match paths.iter().find(|p| !path_pattern_ok(p)) {
        Some(p) => Err(format!("path pattern `{p}` must start with `/`")),
        None => Ok(()),
    }
}

fn path_pattern_ok(p: &str) -> bool {
    p.starts_with('/') || p == "**"
}

/// JSON request bodies a host refuses: ones that ask a model API to reach the network for the
/// request (fetch a URL, call an MCP server). The gate reads such a body before forwarding it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct BodyDeny {
    pub host: String,
    /// Paths whose bodies are read.
    pub paths: Vec<String>,
    /// The methods whose bodies are read; empty: POST.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// `paths` match in any case, for a host that routes them so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_case: bool,
    /// The only top-level keys a body may have; empty: any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only_keys: Vec<String>,
    /// Top-level keys that ask for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// `tools[].type` values that ask for it, each also with a version suffix (`web_fetch`
    /// matches `web_fetch_20260209`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_types: Vec<String>,
    /// Keys of a `tools[]` entry that ask for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_keys: Vec<String>,
    pub reason: String,
}

impl BodyDeny {
    pub fn applies(&self, host: &str, method: &str, path: &str) -> bool {
        let method_ok = if self.methods.is_empty() {
            method == "POST"
        } else {
            self.methods.iter().any(|m| m == method)
        };
        self.host == host
            && method_ok
            && !self.paths.is_empty()
            && glob::matches_any(&self.paths, self.ignore_case, path)
    }

    pub fn asks(&self, body: &JsonBody) -> bool {
        let tool_type = |t: &str| {
            self.tool_types.iter().any(|x| {
                t.strip_prefix(x.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('_'))
            })
        };
        self.keys.iter().any(|k| body.keys.contains(k))
            || (!self.only_keys.is_empty() && body.keys.iter().any(|k| !self.only_keys.contains(k)))
            || body.tools.iter().any(|t| {
                t.get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(tool_type)
                    || self.tool_keys.iter().any(|k| t.contains_key(k))
            })
    }
}

/// What [`BodyDeny`] looks at in a JSON request body: its top-level keys and `tools` entries.
pub struct JsonBody {
    keys: std::collections::HashSet<String>,
    tools: Vec<serde_json::Map<String, serde_json::Value>>,
}

impl JsonBody {
    /// `None` unless the body is one JSON object whose `tools`, if any, is an array of
    /// objects. The rest of the body is skipped unread, however large. A key given twice is
    /// refused: the API might read the copy a check skipped.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        #[derive(Deserialize)]
        struct Tools {
            #[serde(default)]
            tools: Option<Vec<serde_json::Map<String, serde_json::Value>>>,
        }
        let keys: std::collections::HashMap<String, serde::de::IgnoredAny> =
            serde_json::from_slice(bytes).ok()?;
        let Tools { tools } = serde_json::from_slice(bytes).ok()?;
        Some(JsonBody {
            keys: keys.into_keys().collect(),
            tools: tools.unwrap_or_default(),
        })
    }
}

/// GitHub write guard-rails enforced by the gate on top of rules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct GithubGuard {
    /// `owner/repo`, lowercase.
    pub repos: Vec<String>,
    pub protected_branches: Vec<String>,
    /// GraphQL mutation root fields allowed; everything else that mutates is refused.
    pub graphql_mutations: Vec<String>,
    pub allow_tags: bool,
}

/// Azure DevOps write guard-rails enforced by the gate on top of rules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct AzureGuard {
    /// `org/project/repo` as their URLs write them, lowercase.
    pub repos: Vec<String>,
    pub protected_branches: Vec<String>,
    pub allow_tags: bool,
}

/// Push guard-rails on any other git host (`[[credentials.git]]`): the gate reads git's own
/// push protocol, so they hold whatever the forge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct GitGuard {
    pub host: String,
    /// Repository paths as their URLs write them (`group/sub/repo`), lowercase, no `.git`.
    pub repos: Vec<String>,
    pub protected_branches: Vec<String>,
    pub allow_tags: bool,
}

/// Name the gate answers itself in DNS (the gate, env services).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InternalName {
    pub name: String,
    pub ip: std::net::Ipv4Addr,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Policy {
    pub env: String,
    #[serde(default)]
    pub rules: Vec<CompiledRule>,
    #[serde(default)]
    pub denies: Vec<DenyRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_denies: Vec<BodyDeny>,
    #[serde(default)]
    pub injections: Vec<Injection>,
    #[serde(default)]
    pub github: Option<GithubGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_devops: Option<AzureGuard>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git: Vec<GitGuard>,
    #[serde(default)]
    pub internal_names: Vec<InternalName>,
}

#[derive(Debug, Clone)]
pub struct RequestInfo<'a> {
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    pub path: &'a str,
    pub websocket: bool,
    pub content_length: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum DenyReason {
    NoRule,
    Expired { rule: String },
    MethodNotAllowed { allowed: String },
    PathNotAllowed,
    WebSocketNotAllowed,
    BodyTooLarge { max: u64 },
    Explicit { reason: String },
    InvalidHost,
    PrivateAddress,
    Locked,
    Guard { reason: String },
}

impl DenyReason {
    pub fn message(&self, host: &str) -> String {
        match self {
            DenyReason::NoRule => format!("no rule allows {host}"),
            DenyReason::Expired { rule } => format!("the rule for {host} expired ({rule})"),
            DenyReason::MethodNotAllowed { allowed } => {
                format!("{host} is allowed {allowed} only")
            }
            DenyReason::PathNotAllowed => format!("this path on {host} is not allowed"),
            DenyReason::WebSocketNotAllowed => {
                format!("websocket upgrades to {host} are not allowed")
            }
            DenyReason::BodyTooLarge { max } => {
                format!("request body to {host} exceeds the {max}-byte cap")
            }
            DenyReason::Explicit { reason } => reason.clone(),
            DenyReason::InvalidHost => "invalid or ambiguous destination".into(),
            DenyReason::PrivateAddress => {
                format!("{host} resolves to a private/host address, which is never dialed")
            }
            DenyReason::Locked => format!(
                "credentials for {host} are locked; the user must run `luoto vault unlock` on the host"
            ),
            DenyReason::Guard { reason } => reason.clone(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::NoRule => "no_rule",
            DenyReason::Expired { .. } => "expired",
            DenyReason::MethodNotAllowed { .. } => "method_not_allowed",
            DenyReason::PathNotAllowed => "path_not_allowed",
            DenyReason::WebSocketNotAllowed => "websocket_not_allowed",
            DenyReason::BodyTooLarge { .. } => "body_too_large",
            DenyReason::Explicit { .. } => "explicit",
            DenyReason::InvalidHost => "invalid_host",
            DenyReason::PrivateAddress => "private_address",
            DenyReason::Locked => "locked",
            DenyReason::Guard { .. } => "guard",
        }
    }

    /// Would the user plausibly fix this with a write grant?
    pub fn wants_write(&self) -> bool {
        matches!(self, DenyReason::MethodNotAllowed { .. })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    Allow {
        rule: String,
        max_body: Option<u64>,
        allow_private: bool,
        /// The rule's `idle`, in place of the gate's.
        idle: Option<std::time::Duration>,
    },
    Deny(DenyReason),
}

impl Policy {
    fn live_rules<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        now: DateTime<Utc>,
    ) -> impl Iterator<Item = &'a CompiledRule> + 'a {
        self.rules.iter().filter(move |r| {
            host_matches(&r.rule.host, host) && r.rule.port_matches(port) && !r.rule.expired(now)
        })
    }

    /// The live tunnel rule covering `host:port`. A CONNECT without one is intercepted, denied
    /// hosts included, so the client gets a readable 403 instead of a TLS failure.
    pub fn tunnel_rule<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        now: DateTime<Utc>,
    ) -> Option<&'a CompiledRule> {
        self.live_rules(host, port, now)
            .find(|r| r.rule.mode == Mode::Tunnel)
    }

    pub fn decide(&self, req: &RequestInfo<'_>, now: DateTime<Utc>) -> Decision {
        for d in &self.denies {
            let method_hit = d.methods.is_empty()
                || d.methods.iter().any(|m| m.eq_ignore_ascii_case(req.method));
            // In any case: an explicit deny on a host that routes paths without case must not
            // be stepped around with capitals.
            let path_hit = glob::matches_any(&d.paths, true, req.path);
            if host_matches(&d.host, req.host) && method_hit && path_hit {
                return Decision::Deny(DenyReason::Explicit {
                    reason: d.reason.clone(),
                });
            }
        }

        let mut live = false;
        let mut path_ok_method_bad: Vec<&CompiledRule> = Vec::new();
        let mut ws_bad = false;
        let mut body_bad: Option<u64> = None;
        for r in self.live_rules(req.host, req.port, now) {
            live = true;
            if !r.rule.path_matches(req.path) {
                continue;
            }
            if !r.rule.access.allows(req.method) {
                path_ok_method_bad.push(r);
                continue;
            }
            if req.websocket && !r.rule.ws {
                ws_bad = true;
                continue;
            }
            if let (Some(max), Some(len)) = (r.rule.max_body, req.content_length)
                && len > max
            {
                body_bad = Some(max);
                continue;
            }
            return Decision::Allow {
                rule: r.id.clone(),
                max_body: r.rule.max_body,
                allow_private: r.rule.allow_private,
                idle: r.rule.idle_limit(),
            };
        }

        if !live {
            let expired = self
                .rules
                .iter()
                .find(|r| host_matches(&r.rule.host, req.host) && r.rule.port_matches(req.port));
            return Decision::Deny(match expired {
                Some(r) => DenyReason::Expired { rule: r.id.clone() },
                None => DenyReason::NoRule,
            });
        }
        if ws_bad {
            return Decision::Deny(DenyReason::WebSocketNotAllowed);
        }
        if let Some(max) = body_bad {
            return Decision::Deny(DenyReason::BodyTooLarge { max });
        }
        if !path_ok_method_bad.is_empty() {
            let mut allowed: Vec<String> = path_ok_method_bad
                .iter()
                .map(|r| r.rule.access.describe())
                .collect();
            allowed.dedup();
            return Decision::Deny(DenyReason::MethodNotAllowed {
                allowed: allowed.join("; "),
            });
        }
        Decision::Deny(DenyReason::PathNotAllowed)
    }

    /// Injections that apply to this request (host + path).
    pub fn injections_for<'a>(&'a self, host: &'a str, path: &'a str) -> Vec<&'a Injection> {
        self.injections
            .iter()
            .filter(|i| host_matches(&i.host, host) && i.path_matches(path))
            .collect()
    }

    /// Hosts carrying credentials: client-supplied auth headers are always stripped there.
    pub fn is_credentialed_host(&self, host: &str) -> bool {
        self.injections.iter().any(|i| host_matches(&i.host, host))
    }

    /// Why a tunnel rule for `pattern` is refused, if it is: the gate only passes a tunnel's
    /// bytes, so it can't strip the client's credentials, run the forge guards or apply the
    /// explicit denies on a host the tunnel covers.
    pub fn tunnel_bypass(&self, pattern: &str) -> Option<String> {
        let mut guards = Vec::new();
        if self.github.is_some() {
            guards.push((forges::GITHUB, "GitHub push guard"));
            guards.push((forges::GITHUB_API, "GitHub GraphQL guard"));
        }
        if self.azure_devops.is_some() {
            guards.push((forges::AZURE_DEVOPS, "Azure DevOps push guard"));
        }
        for g in &self.git {
            guards.push((g.host.as_str(), "git push guard"));
        }
        let skipped = if let Some(i) = self
            .injections
            .iter()
            .find(|i| patterns_overlap(pattern, &i.host))
        {
            format!(
                "credential stripping on {} (it gets the `{}` credential)",
                i.host, i.binding
            )
        } else if let Some((host, guard)) = guards
            .iter()
            .find(|(host, _)| patterns_overlap(pattern, host))
        {
            format!("the {guard} on {host}")
        } else {
            let d = self
                .denies
                .iter()
                .find(|d| patterns_overlap(pattern, &d.host))?;
            format!("the deny on {} ({})", d.host, d.reason)
        };
        Some(format!(
            "a tunnel to {pattern} is refused: it would skip {skipped}"
        ))
    }
}

/// Some host matches both patterns.
fn patterns_overlap(a: &str, b: &str) -> bool {
    host_matches(a, b)
        || host_matches(b, a)
        || match (a.strip_prefix("*."), b.strip_prefix("*.")) {
            (Some(x), Some(y)) => x == y || host_matches(a, y) || host_matches(b, x),
            _ => false,
        }
}

/// Who is asking for a rule — the sandbox may never ask for risky wildcards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleOrigin {
    Host,
    Sandbox,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Refused outright.
    Error,
    /// Allowed from the host only with explicit confirmation (`--force` / UI confirm).
    Risk,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub message: String,
}

/// The first issue that refuses `rule` outright, if any.
pub fn rule_error(rule: &Rule, origin: RuleOrigin) -> Option<Issue> {
    validate_rule(rule, origin)
        .into_iter()
        .find(|i| i.severity == Severity::Error)
}

pub fn validate_rule(rule: &Rule, origin: RuleOrigin) -> Vec<Issue> {
    let mut issues = Vec::new();
    let err = |m: String| Issue {
        severity: Severity::Error,
        message: m,
    };
    let risk = |m: String| Issue {
        severity: Severity::Risk,
        message: m,
    };
    // What the host user may confirm, the sandbox may not ask for.
    let host_risk = |m: String| {
        if origin == RuleOrigin::Sandbox {
            err(m)
        } else {
            risk(m)
        }
    };

    let host_ok = rule.host == "*"
        || rule.host.contains('/')
        || rule
            .host
            .strip_prefix("*.")
            .map_or_else(|| normalize_host(&rule.host), normalize_host)
            .is_ok();
    if !host_ok {
        issues.push(err(format!("invalid host pattern `{}`", rule.host)));
    }
    match wildcard_risk(&rule.host) {
        WildcardRisk::None => {}
        WildcardRisk::Everything => {
            issues.push(host_risk(
                "`*` covers every host: even read access lets code leak data in URLs".into(),
            ));
        }
        WildcardRisk::PublicSuffix => issues.push(err(format!(
            "`{}` spans a public suffix (unrelated owners); name exact hosts instead",
            rule.host
        ))),
        WildcardRisk::MultiTenant => issues.push(host_risk(format!(
            "`{}` covers a multi-tenant domain where anyone can host a subdomain",
            rule.host
        ))),
    }
    if rule.host.contains('/') && origin == RuleOrigin::Sandbox {
        issues.push(err("the sandbox may not request address ranges".into()));
    }
    for p in &rule.paths {
        if !path_pattern_ok(p) {
            issues.push(err(format!("path pattern `{p}` must start with `/`")));
        }
    }
    if rule.mode == Mode::Tunnel {
        let to = match rule.port {
            Some(port) => format!("{}:{port}", rule.host),
            None => rule.host.clone(),
        };
        issues.push(risk(format!(
            "a tunnel to {to} is not inspected: code in the sandbox gets full access to it, \
             any protocol and any data"
        )));
    }
    if let Some(Err(e)) = rule.idle.as_deref().map(parse_idle) {
        issues.push(err(e));
    }
    if rule.allow_private {
        issues.push(host_risk(
            "allows dialing private/host addresses (e.g. services on your machine)".into(),
        ));
    }
    if rule.mode != Mode::Tunnel
        && rule.access == Access::Level(AccessLevel::Write)
        && origin == RuleOrigin::Host
    {
        issues.push(risk(format!(
            "write access lets code in the sandbox upload data to {}",
            rule.host
        )));
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rules_idle_is_a_duration_up_to_a_day() {
        assert_eq!(parse_idle("90s"), Ok(std::time::Duration::from_secs(90)));
        assert_eq!(parse_idle("30m"), Ok(std::time::Duration::from_secs(1800)));
        assert_eq!(parse_idle("24h"), Ok(MAX_IDLE));
        for bad in [
            "0m",
            "25h",
            "1d",
            "soon",
            "",
            "-5m",
            "99999999999999999999h",
        ] {
            assert!(parse_idle(bad).is_err(), "{bad}");
        }
        let mut r = Rule::read("k8s.example");
        r.idle = Some("2d".into());
        assert!(
            validate_rule(&r, RuleOrigin::Host)
                .iter()
                .any(|i| i.severity == Severity::Error)
        );
        r.idle = Some("2h".into());
        assert!(validate_rule(&r, RuleOrigin::Host).is_empty());
        let p = Policy {
            rules: vec![CompiledRule {
                id: "k".into(),
                origin: "test".into(),
                rule: r,
            }],
            ..Default::default()
        };
        assert!(matches!(
            p.decide(&req("k8s.example", "GET", "/logs"), Utc::now()),
            Decision::Allow { idle: Some(d), .. } if d == std::time::Duration::from_secs(7200)
        ));
    }
    use chrono::Duration;

    fn rule(id: &str, r: Rule) -> CompiledRule {
        CompiledRule {
            id: id.into(),
            origin: "test".into(),
            rule: r,
        }
    }

    fn req<'a>(host: &'a str, method: &'a str, path: &'a str) -> RequestInfo<'a> {
        RequestInfo {
            host,
            port: 443,
            method,
            path,
            websocket: false,
            content_length: None,
        }
    }

    #[test]
    fn ignore_case_rules_match_paths_in_any_case() {
        let mut r = Rule {
            host: "dev.azure.com".into(),
            paths: vec!["/o/P/_git/r/**".into()],
            ..Default::default()
        };
        assert!(!r.path_matches("/O/p/_git/R/info/refs"));
        r.ignore_case = true;
        assert!(r.path_matches("/O/p/_git/R/info/refs"));
        assert!(!r.path_matches("/o/p/_git/other/info/refs"));
    }

    fn policy() -> Policy {
        Policy {
            env: "t".into(),
            rules: vec![
                rule("npm", Rule::read("registry.npmjs.org")),
                rule(
                    "npm-audit",
                    Rule {
                        host: "registry.npmjs.org".into(),
                        access: Access::Methods(vec!["POST".into()]),
                        paths: vec!["/-/npm/v1/security/**".into()],
                        max_body: Some(1024),
                        ..Default::default()
                    },
                ),
                rule(
                    "gh",
                    Rule {
                        host: "api.github.com".into(),
                        access: Access::Level(AccessLevel::Write),
                        ..Default::default()
                    },
                ),
                rule(
                    "old",
                    Rule {
                        host: "docs.rs".into(),
                        expires: Some(Utc::now() - Duration::minutes(1)),
                        ..Default::default()
                    },
                ),
            ],
            denies: vec![DenyRule {
                host: "api.github.com".into(),
                paths: vec!["/repos/*/*/actions/**".into()],
                methods: vec![],
                reason: "GitHub Actions endpoints are never reachable".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn read_rule_allows_get_denies_put() {
        let p = policy();
        let now = Utc::now();
        assert!(matches!(
            p.decide(&req("registry.npmjs.org", "GET", "/react"), now),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            p.decide(&req("registry.npmjs.org", "PUT", "/react"), now),
            Decision::Deny(DenyReason::MethodNotAllowed { .. })
        ));
    }

    #[test]
    fn read_post_needs_path_and_body_cap() {
        let p = policy();
        let now = Utc::now();
        let mut r = req(
            "registry.npmjs.org",
            "POST",
            "/-/npm/v1/security/advisories/bulk",
        );
        r.content_length = Some(100);
        assert!(matches!(
            p.decide(&r, now),
            Decision::Allow {
                max_body: Some(1024),
                ..
            }
        ));
        r.content_length = Some(5000);
        assert_eq!(
            p.decide(&r, now),
            Decision::Deny(DenyReason::BodyTooLarge { max: 1024 })
        );
        assert!(matches!(
            p.decide(
                &req("registry.npmjs.org", "POST", "/-/user/org.couchdb.user:x"),
                now
            ),
            Decision::Deny(DenyReason::MethodNotAllowed { .. })
        ));
    }

    #[test]
    fn explicit_deny_wins_and_unknown_hosts_fail() {
        let p = policy();
        let now = Utc::now();
        assert!(matches!(
            p.decide(
                &req(
                    "api.github.com",
                    "POST",
                    "/repos/a/b/actions/workflows/x/dispatches"
                ),
                now
            ),
            Decision::Deny(DenyReason::Explicit { .. })
        ));
        assert!(matches!(
            p.decide(&req("api.github.com", "POST", "/repos/a/b/pulls"), now),
            Decision::Allow { .. }
        ));
        assert_eq!(
            p.decide(&req("evil.example", "GET", "/"), now),
            Decision::Deny(DenyReason::NoRule)
        );
        assert!(matches!(
            p.decide(&req("docs.rs", "GET", "/serde"), now),
            Decision::Deny(DenyReason::Expired { .. })
        ));
    }

    #[test]
    fn a_deny_of_your_own_beats_an_allow_in_any_case() {
        let mut p = policy();
        let now = Utc::now();
        let d = Deny {
            host: "Registry.NPMjs.org.".into(),
            paths: vec!["/-/npm/v1/security/**".into()],
            methods: vec!["post".into()],
            note: Some("no audits".into()),
        };
        p.denies.push(d.rule().unwrap());
        let mut audit = req("registry.npmjs.org", "POST", "/-/NPM/v1/security/audits");
        audit.content_length = Some(10);
        assert_eq!(
            p.decide(&audit, now),
            Decision::Deny(DenyReason::Explicit {
                reason: "denied by a [[deny]] rule: no audits".into()
            })
        );
        assert!(matches!(
            p.decide(
                &req("registry.npmjs.org", "GET", "/-/npm/v1/security/x"),
                now
            ),
            Decision::Allow { .. }
        ));
        assert!(p.tunnel_bypass("*.npmjs.org").unwrap().contains("[[deny]]"));
    }

    #[test]
    fn denies_and_mutes_name_hosts_and_paths() {
        let deny = |host: &str, paths: &[&str], methods: &[&str]| {
            Deny {
                host: host.into(),
                paths: paths.iter().map(|p| p.to_string()).collect(),
                methods: methods.iter().map(|m| m.to_string()).collect(),
                note: None,
            }
            .rule()
        };
        assert!(deny("*", &[], &[]).is_ok());
        assert!(deny("*.github.io", &["/x/**"], &["DELETE"]).is_ok());
        for (host, paths, methods) in [
            ("a b", &[][..], &[][..]),
            ("x.example", &["v1/**"][..], &[][..]),
            ("x.example", &[][..], &["GET POST"][..]),
            ("x.example", &[][..], &[""][..]),
        ] {
            assert!(
                deny(host, paths, methods).is_err(),
                "{host} {paths:?} {methods:?}"
            );
        }
        let mute = |host: &str, paths: &[&str]| {
            Mute {
                host: host.into(),
                paths: paths.iter().map(|p| p.to_string()).collect(),
                note: None,
            }
            .checked()
        };
        assert!(mute("*", &[]).is_err());
        assert!(mute("x.example", &["v1"]).is_err());
        let all = mute("Telemetry.Example.", &[]).unwrap();
        assert!(all.covers("telemetry.example", None));
        assert!(all.covers("telemetry.example", Some("/v1/x")));
        assert!(!all.covers("other.example", None));
        let some = mute("*", &["/telemetry/**"]).unwrap();
        assert!(some.covers("a.example", Some("/Telemetry/1")));
        assert!(!some.covers("a.example", Some("/api")));
        assert!(!some.covers("a.example", None));
    }

    #[test]
    fn ports_and_websockets() {
        let p = policy();
        let now = Utc::now();
        let mut r = req("registry.npmjs.org", "GET", "/");
        r.port = 8443;
        assert_eq!(p.decide(&r, now), Decision::Deny(DenyReason::NoRule));
        let mut r = req("registry.npmjs.org", "GET", "/");
        r.websocket = true;
        assert_eq!(
            p.decide(&r, now),
            Decision::Deny(DenyReason::WebSocketNotAllowed)
        );
    }

    #[test]
    fn tunnel_mode_only_from_tunnel_rules() {
        let mut p = policy();
        let now = Utc::now();
        assert!(p.tunnel_rule("registry.npmjs.org", 443, now).is_none());
        p.rules.push(rule(
            "grpc",
            Rule {
                host: "grpc.example.com".into(),
                access: Access::Level(AccessLevel::Write),
                mode: Mode::Tunnel,
                ..Default::default()
            },
        ));
        assert_eq!(
            p.tunnel_rule("grpc.example.com", 443, now)
                .map(|r| r.id.as_str()),
            Some("grpc")
        );
        assert!(p.tunnel_rule("evil.example", 443, now).is_none());
    }

    #[test]
    fn sandbox_cannot_request_risky_rules() {
        let star = Rule::read("*");
        assert!(
            validate_rule(&star, RuleOrigin::Sandbox)
                .iter()
                .any(|i| i.severity == Severity::Error)
        );
        assert!(
            validate_rule(&star, RuleOrigin::Host)
                .iter()
                .all(|i| i.severity == Severity::Risk)
        );
        let suffix = Rule::read("*.github.io");
        assert!(
            validate_rule(&suffix, RuleOrigin::Host)
                .iter()
                .any(|i| i.severity == Severity::Error)
        );
        assert!(validate_rule(&Rule::read("docs.rs"), RuleOrigin::Sandbox).is_empty());
    }

    #[test]
    fn a_tunnel_is_one_risk_naming_its_port() {
        let tunnel = Rule {
            host: "db.example.com".into(),
            port: Some(5432),
            access: Access::Level(AccessLevel::Write),
            mode: Mode::Tunnel,
            ..Default::default()
        };
        for origin in [RuleOrigin::Host, RuleOrigin::Sandbox] {
            let issues = validate_rule(&tunnel, origin);
            assert_eq!(issues.len(), 1, "{issues:?}");
            assert_eq!(issues[0].severity, Severity::Risk);
            assert!(
                issues[0]
                    .message
                    .contains("db.example.com:5432 is not inspected")
            );
        }
    }

    #[test]
    fn tunnels_never_cover_what_the_gate_enforces() {
        let mut p = policy();
        assert!(p.tunnel_bypass("api.github.com").unwrap().contains("deny"));
        assert!(p.tunnel_bypass("github.com").is_none());
        p.github = Some(GithubGuard::default());
        p.injections.push(Injection {
            binding: "anthropic".into(),
            host: "api.anthropic.com".into(),
            paths: vec![],
            place: crate::creds::Placement::Header {
                name: "x-api-key".into(),
                format: "{secret}".into(),
            },
            ignore_case: false,
        });
        for host in [
            "api.anthropic.com",
            "*.anthropic.com",
            "*",
            "github.com",
            "api.github.com",
        ] {
            assert!(p.tunnel_bypass(host).is_some(), "{host}");
        }
        assert!(p.tunnel_bypass("grpc.example.com").is_none());
        assert!(p.tunnel_bypass("*.githubusercontent.com").is_none());
    }

    #[test]
    fn body_denies_match_server_tools_and_their_versions() {
        let d = BodyDeny {
            host: "api.example.com".into(),
            paths: vec!["/v1/messages".into()],
            keys: vec!["mcp_servers".into()],
            tool_types: vec!["web_fetch".into()],
            tool_keys: vec!["url_context".into()],
            reason: "no".into(),
            ..Default::default()
        };
        assert!(d.applies("api.example.com", "POST", "/v1/messages"));
        assert!(!d.applies("api.example.com", "PATCH", "/v1/messages"));
        assert!(!d.applies("api.example.com", "POST", "/v1/messages/count_tokens"));
        let asks = |body: &str| d.asks(&JsonBody::parse(body.as_bytes()).unwrap());
        assert!(asks(
            r#"{"tools":[{"type":"web_fetch_20260209","name":"web_fetch"}]}"#
        ));
        assert!(asks(r#"{"tools":[{"type":"web_fetch"}]}"#));
        assert!(asks(r#"{"mcp_servers":[],"model":"m"}"#));
        assert!(asks(
            r#"{"tools":[{"function_declarations":[]},{"url_context":{}}]}"#
        ));
        assert!(asks(r#"{"\u0074ools":[{"type":"web_fetch_1"}]}"#));
        assert!(!asks(
            r#"{"tools":[{"type":"web_fetcher"},{"type":"web_search_20250305"}]}"#
        ));
        assert!(!asks(
            r#"{"model":"m","messages":[{"role":"user","content":"web_fetch"}]}"#
        ));
        assert!(!asks(r#"{"tools":null}"#));
    }

    #[test]
    fn a_body_the_check_could_misread_does_not_parse() {
        for body in [
            r#"{"tools":[],"tools":[{"type":"web_fetch"}]}"#,
            r#"[{"tools":[]}]"#,
            r#"{"tools":{"type":"web_fetch"}}"#,
            r#"{"tools":["web_fetch"]}"#,
            "not json",
            "",
        ] {
            assert!(JsonBody::parse(body.as_bytes()).is_none(), "{body}");
        }
    }
}
