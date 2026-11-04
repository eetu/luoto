//! The egress policy: rules, explicit denies, and the decision function the gate runs for
//! every request. Default deny. The CLI compiles presets, agent/provider profiles and user
//! rules into one [`Policy`]; the gate only evaluates it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::creds::Injection;
use crate::glob::{glob_match, glob_match_any_case};
use crate::host::{WildcardRisk, host_matches, normalize_host, wildcard_risk};

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
}

impl Rule {
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

/// GitHub write guard-rails enforced by the gate on top of rules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct GithubGuard {
    /// `owner/repo`, lowercase.
    pub repos: Vec<String>,
    pub protected_branches: Vec<String>,
    /// GraphQL mutation root fields allowed; everything else that mutates is refused.
    pub graphql_mutations: Vec<String>,
    pub allow_tags: bool,
    pub allow_branch_delete: bool,
}

/// Azure DevOps write guard-rails enforced by the gate on top of rules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct AzureGuard {
    /// `org/project/repo` as their URLs write them, lowercase.
    pub repos: Vec<String>,
    pub protected_branches: Vec<String>,
    pub allow_tags: bool,
    pub allow_branch_delete: bool,
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
    pub generated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub rules: Vec<CompiledRule>,
    #[serde(default)]
    pub denies: Vec<DenyRule>,
    #[serde(default)]
    pub injections: Vec<Injection>,
    #[serde(default)]
    pub github: Option<GithubGuard>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_devops: Option<AzureGuard>,
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

    /// How to treat a CONNECT to `host:port`: tunnel only if a live tunnel rule covers it;
    /// everything else is intercepted (including denied hosts, so the client gets a
    /// readable 403 instead of a TLS failure).
    pub fn connect_mode(&self, host: &str, port: u16, now: DateTime<Utc>) -> Mode {
        if self
            .live_rules(host, port, now)
            .any(|r| r.rule.mode == Mode::Tunnel)
        {
            Mode::Tunnel
        } else {
            Mode::Inspect
        }
    }

    /// The tunnel rule covering host:port, if any (used to allow opaque tunnels).
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
            let path_hit = d.paths.is_empty() || d.paths.iter().any(|p| glob_match(p, req.path));
            if host_matches(&d.host, req.host) && method_hit && path_hit {
                return Decision::Deny(DenyReason::Explicit {
                    reason: d.reason.clone(),
                });
            }
        }

        let candidates: Vec<&CompiledRule> = self
            .rules
            .iter()
            .filter(|r| host_matches(&r.rule.host, req.host) && r.rule.port_matches(req.port))
            .collect();
        if candidates.is_empty() {
            return Decision::Deny(DenyReason::NoRule);
        }
        let live: Vec<&CompiledRule> = candidates
            .iter()
            .copied()
            .filter(|r| !r.rule.expired(now))
            .collect();
        if live.is_empty() {
            return Decision::Deny(DenyReason::Expired {
                rule: candidates[0].id.clone(),
            });
        }

        let mut path_ok_method_bad: Vec<&CompiledRule> = Vec::new();
        let mut ws_bad = false;
        let mut body_bad: Option<u64> = None;
        for r in &live {
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
            };
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
            guards.push(("github.com", "GitHub push guard"));
            guards.push(("api.github.com", "GitHub GraphQL guard"));
        }
        if self.azure_devops.is_some() {
            guards.push(("dev.azure.com", "Azure DevOps push guard"));
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
            let m = "`*` covers every host: even read access lets code leak data in URLs".into();
            issues.push(if origin == RuleOrigin::Sandbox {
                err(m)
            } else {
                risk(m)
            });
        }
        WildcardRisk::PublicSuffix => issues.push(err(format!(
            "`{}` spans a public suffix (unrelated owners); name exact hosts instead",
            rule.host
        ))),
        WildcardRisk::MultiTenant => {
            let m = format!(
                "`{}` covers a multi-tenant domain where anyone can host a subdomain",
                rule.host
            );
            issues.push(if origin == RuleOrigin::Sandbox {
                err(m)
            } else {
                risk(m)
            });
        }
    }
    if rule.host.contains('/') && origin == RuleOrigin::Sandbox {
        issues.push(err("the sandbox may not request address ranges".into()));
    }
    for p in &rule.paths {
        if !p.starts_with('/') && p != "**" {
            issues.push(err(format!("path pattern `{p}` must start with `/`")));
        }
    }
    if rule.mode == Mode::Tunnel && rule.access != Access::Level(AccessLevel::Write) {
        issues.push(risk(
            "tunnel mode cannot enforce methods or paths; it grants full access to the host".into(),
        ));
    }
    if rule.allow_private {
        let m = "allows dialing private/host addresses (e.g. services on your machine)".to_string();
        issues.push(if origin == RuleOrigin::Sandbox {
            err(m)
        } else {
            risk(m)
        });
    }
    if rule.access == Access::Level(AccessLevel::Write) && origin == RuleOrigin::Host {
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
        assert_eq!(
            p.connect_mode("registry.npmjs.org", 443, now),
            Mode::Inspect
        );
        p.rules.push(rule(
            "grpc",
            Rule {
                host: "grpc.example.com".into(),
                access: Access::Level(AccessLevel::Write),
                mode: Mode::Tunnel,
                ..Default::default()
            },
        ));
        assert_eq!(p.connect_mode("grpc.example.com", 443, now), Mode::Tunnel);
        assert_eq!(p.connect_mode("evil.example", 443, now), Mode::Inspect);
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
}
