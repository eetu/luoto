//! The in-sandbox API the gate serves at `http://gate:3128/_sandbox/…` for the `sandbox`
//! helper (and through it, MCP-capable agents). Read-mostly; the writes are filing an access
//! request, which only the host can resolve, and passing ssh-agent messages to the vault.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events::Event;
use crate::host::{is_never_dialed, is_private, normalize_host};
use crate::policy::{Access, AccessLevel, Mode, Rule, RuleOrigin, rule_error};

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
    /// `None`: HTTP(S)'s 80 and 443.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
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
    /// The env's egress is open (`luoto egress open`): any HTTP(S) host but the credentialed
    /// ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<OpenEgress>,
}

/// An env's open egress (`luoto egress open`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OpenEgress {
    /// When it closes; none: when the user closes it (`open = true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
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
    /// A port HTTP(S) doesn't use: the request is for an uninspected tunnel to `host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub access: AccessLevel,
    #[serde(default)]
    pub paths: Vec<String>,
    pub reason: String,
    /// Software to install; `host` is then empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<Install>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    Rejected,
}

impl std::fmt::Display for RequestStatus {
    /// Its serde name: `approved`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RequestStatus::Pending => "pending",
            RequestStatus::Approved => "approved",
            RequestStatus::Rejected => "rejected",
        })
    }
}

/// What the sandbox asks to have in the env besides a host: software, a preset's access, or a
/// variable with a plain value. Approved, it joins the env's config (`[deps] system`,
/// `[tools]`, `presets`, `[env]`), so it holds for every container the env gets. A secret is
/// never asked for from inside: the user adds one (`luoto var set NAME`), so the sandbox never
/// chooses which of theirs it gets.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Install {
    /// A package of the image's package manager (apt, apk or dnf).
    Package { name: String },
    /// A toolchain mise installs: `node` and `24`, `cargo:ripgrep` and `latest`.
    Tool { name: String, version: String },
    /// One of luoto's presets (`npm`, `pypi`, …): the hosts a registry or service needs.
    Preset { name: String },
    /// An environment variable with a plain value (`[env]`), which the user gives or accepts.
    Var {
        name: String,
        /// The value the sandbox suggests, which the user sees filled in and can change.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
    },
}

impl Install {
    /// The variable a request for one names.
    pub fn variable(&self) -> Option<&str> {
        match self {
            Install::Var { name, .. } => Some(name),
            _ => None,
        }
    }
}

/// Characters that reorder or hide text where it is shown: a suggested value can't carry them.
fn hides_text(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{061c}' | '\u{feff}')
}

/// The longest plain value a variable request may suggest.
pub const MAX_SUGGESTED_VALUE: usize = 1000;

impl Install {
    /// Names a package manager or mise takes as they are: no options, spaces or shell.
    pub fn check(&self) -> Result<(), String> {
        let plain = |s: &str, extra: &[u8], max: usize| {
            !s.is_empty()
                && s.len() <= max
                && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
        };
        match self {
            Install::Package { name } if !plain(name, b"+._-", 100) => {
                Err(format!("`{name}` is not a package name"))
            }
            Install::Tool { name, .. } if !plain(name, b"._/:@-", 100) => {
                Err(format!("`{name}` is not a mise tool name"))
            }
            Install::Tool { version, .. } if !plain(version, b"+._-", 50) => {
                Err(format!("`{version}` is not a version"))
            }
            Install::Preset { name } if crate::presets::get(name).is_none() => Err(format!(
                "`{name}` is not a preset (known: {})",
                crate::presets::names().collect::<Vec<_>>().join(", ")
            )),
            Install::Var { name, .. } => match crate::variable_refused(name) {
                Some(why) => Err(why),
                None => match self {
                    Install::Var { value: Some(v), .. }
                        if v.len() > MAX_SUGGESTED_VALUE
                            || v.chars().any(|c| c.is_control() || hides_text(c)) =>
                    {
                        Err(format!(
                            "a suggested value is one line of at most {MAX_SUGGESTED_VALUE} \
                             bytes of plain text"
                        ))
                    }
                    _ => Ok(()),
                },
            },
            _ => Ok(()),
        }
    }

    /// What it is, for people: `package postgresql-client`, `node 24 (mise)`. A tool from a
    /// mise backend that takes anyone's code (`ubi:`, `npm:`, `cargo:`, …), rather than mise's
    /// registry or aqua's, says so: approved, it is installed in every container the env gets.
    pub fn describe(&self) -> String {
        match self {
            Install::Package { name } => format!("package {name}"),
            Install::Tool { name, version } => match name.split_once(':') {
                Some((backend, _)) if backend != "aqua" => {
                    format!("{name} {version} (mise, an unvetted {backend} source)")
                }
                _ => format!("{name} {version} (mise)"),
            },
            Install::Preset { name } => format!("the {name} preset"),
            Install::Var { name, value: None } => format!("the variable {name}"),
            Install::Var {
                name,
                value: Some(v),
            } => format!("the variable {name}={v} (a plain value it suggests)"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AccessRequest {
    pub id: u64,
    /// Empty for an install request.
    pub host: String,
    /// Set for a tunnel request: `access` is then write, since a tunnel's bytes go unread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
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
    /// Software to install instead of access to a host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install: Option<Install>,
}

/// Limits on what the sandbox can file, so requests can't be used for approval fatigue.
pub const MAX_PENDING_REQUESTS: usize = 5;
pub const MAX_REASON_LEN: usize = 500;

/// The rule a request for `host` asks for, or why the sandbox may not ask for it: a host or a
/// wildcard the sandbox may name, never an address range or a private address; with `port`, an
/// uninspected tunnel to that one host and port, which HTTP(S)'s 80 and 443 never get.
pub fn requested_rule(
    host: &str,
    port: Option<u16>,
    access: AccessLevel,
    paths: &[String],
) -> Result<Rule, String> {
    let host = host.trim();
    let host = match host.strip_prefix("*.") {
        Some(rest) => normalize_host(rest).map(|d| format!("*.{d}")),
        None => normalize_host(host),
    }
    .map_err(|e| e.to_string())?;
    if let Ok(ip) = host.trim_start_matches("*.").parse::<IpAddr>() {
        if host.starts_with("*.") {
            return Err(format!("`{host}` is not a host pattern"));
        }
        if is_private(ip) || is_never_dialed(ip) {
            return Err(format!(
                "{ip} is a private address, which the sandbox may not ask for"
            ));
        }
    }
    let rule = match port {
        None => Rule {
            host,
            access: Access::Level(access),
            paths: paths.to_vec(),
            ..Default::default()
        },
        Some(80 | 443) => {
            return Err("ports 80 and 443 are HTTP(S): ask for the host without a port".into());
        }
        Some(0) => return Err("port 0 is not a port".into()),
        Some(_) if host.starts_with("*.") => {
            return Err("a tunnel goes to one host: name it exactly".into());
        }
        Some(_) if !paths.is_empty() => {
            return Err("a tunnel can't be limited to paths: the gate doesn't read it".into());
        }
        Some(port) => Rule {
            host,
            port: Some(port),
            access: Access::Level(AccessLevel::Write),
            mode: Mode::Tunnel,
            ..Default::default()
        },
    };
    match rule_error(&rule, RuleOrigin::Sandbox) {
        Some(e) => Err(e.message),
        None => Ok(rule),
    }
}

/// Less than a request asked for, granted by the host: read for write, some methods, some of
/// its paths. Never more: [`AccessRequest::grant`] refuses a narrowing that would widen.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Narrowing {
    /// Read-only (GET, HEAD, OPTIONS).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

impl Narrowing {
    pub fn is_empty(&self) -> bool {
        !self.read && self.methods.is_empty() && self.paths.is_empty()
    }
}

impl AccessRequest {
    /// The rule the request asks for, checked as the gate checked it when it was filed.
    pub fn rule(&self) -> Result<Rule, String> {
        if self.install.is_some() {
            return Err(format!(
                "request #{} asks for an install, not access",
                self.id
            ));
        }
        requested_rule(&self.host, self.port, self.access, &self.paths)
    }

    /// The rule granting the request, narrowed by `n`; refused if `n` would grant anything
    /// the request did not ask for.
    pub fn grant(&self, n: &Narrowing) -> Result<Rule, String> {
        let mut rule = self.rule()?;
        if n.is_empty() {
            return Ok(rule);
        }
        let id = self.id;
        if rule.mode == Mode::Tunnel {
            return Err(format!(
                "request #{id} asks for a tunnel, which can't be limited to methods or paths: \
                 approve it as asked or reject it"
            ));
        }
        if n.read && !n.methods.is_empty() {
            return Err("give read or methods, not both".into());
        }
        if n.read {
            rule.access = Access::Level(AccessLevel::Read);
        }
        if !n.methods.is_empty() {
            let mut methods: Vec<String> =
                n.methods.iter().map(|m| m.to_ascii_uppercase()).collect();
            methods.sort();
            methods.dedup();
            if let Some(m) = methods
                .iter()
                .find(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphabetic()))
            {
                return Err(format!("`{m}` is not an HTTP method"));
            }
            if let Some(m) = methods.iter().find(|m| !rule.access.allows(m)) {
                return Err(format!(
                    "{m} is more than request #{id} asked for ({})",
                    rule.access.describe()
                ));
            }
            rule.access = Access::Methods(methods);
        }
        if !n.paths.is_empty() {
            let asked = &rule.paths;
            if let Some(p) = n
                .paths
                .iter()
                .find(|p| !asked.is_empty() && !asked.iter().any(|a| crate::glob::covers(a, p)))
            {
                return Err(format!(
                    "path `{p}` reaches beyond the paths request #{id} asked for ({})",
                    asked.join(", ")
                ));
            }
            rule.paths = n.paths.clone();
        }
        match rule_error(&rule, RuleOrigin::Sandbox) {
            Some(e) => Err(e.message),
            None => Ok(rule),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asked(host: &str, port: Option<u16>, access: AccessLevel, paths: &[&str]) -> AccessRequest {
        AccessRequest {
            id: 3,
            host: host.into(),
            port,
            access,
            paths: paths.iter().map(|p| p.to_string()).collect(),
            reason: "r".into(),
            status: RequestStatus::Pending,
            created: Utc::now(),
            resolved: None,
            note: None,
            install: None,
        }
    }

    #[test]
    fn a_port_request_is_a_tunnel_to_one_public_host() {
        let r = requested_rule("DB.Example.com", Some(5432), AccessLevel::Read, &[]).unwrap();
        assert_eq!(
            (r.host.as_str(), r.port, r.mode, r.access),
            (
                "db.example.com",
                Some(5432),
                Mode::Tunnel,
                Access::Level(AccessLevel::Write)
            )
        );
        for (host, port, paths) in [
            ("db.example.com", 443, &[][..]),
            ("db.example.com", 80, &[][..]),
            ("db.example.com", 0, &[][..]),
            ("*.example.com", 5432, &[][..]),
            ("db.example.com", 5432, &["/x/**".to_string()][..]),
            ("10.0.0.0/8", 5432, &[][..]),
            ("10.1.2.3", 5432, &[][..]),
            ("127.0.0.1", 5432, &[][..]),
            ("[::1]", 5432, &[][..]),
            ("169.254.169.254", 5432, &[][..]),
            ("*", 5432, &[][..]),
            ("user@db.example.com", 5432, &[][..]),
        ] {
            assert!(
                requested_rule(host, Some(port), AccessLevel::Write, paths).is_err(),
                "{host}:{port} {paths:?}"
            );
        }
        assert!(requested_rule("203.0.113.9", Some(5432), AccessLevel::Write, &[]).is_err());
        assert!(requested_rule("8.8.8.8", Some(5432), AccessLevel::Write, &[]).is_ok());
    }

    #[test]
    fn host_requests_keep_their_checks() {
        assert!(requested_rule("docs.rs", None, AccessLevel::Read, &[]).is_ok());
        assert!(requested_rule("*.mycompany.dev", None, AccessLevel::Read, &[]).is_ok());
        for host in [
            "*",
            "*.github.io",
            "*.amazonaws.com",
            "*.10.0.0.1",
            "192.168.1.1",
        ] {
            assert!(
                requested_rule(host, None, AccessLevel::Read, &[]).is_err(),
                "{host}"
            );
        }
        let bad_path = ["v1/**".to_string()];
        assert!(requested_rule("docs.rs", None, AccessLevel::Read, &bad_path).is_err());
    }

    #[test]
    fn a_grant_narrows_and_never_widens() {
        let write = asked("api.example.com", None, AccessLevel::Write, &[]);
        let read = Narrowing {
            read: true,
            ..Default::default()
        };
        assert_eq!(
            write.grant(&read).unwrap().access,
            Access::Level(AccessLevel::Read)
        );
        let methods = |ms: &[&str]| Narrowing {
            methods: ms.iter().map(|m| m.to_string()).collect(),
            ..Default::default()
        };
        assert_eq!(
            write.grant(&methods(&["post", "GET"])).unwrap().access,
            Access::Methods(vec!["GET".into(), "POST".into()])
        );
        let paths = |ps: &[&str]| Narrowing {
            paths: ps.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        };
        assert_eq!(write.grant(&paths(&["/v1/**"])).unwrap().paths, ["/v1/**"]);
        assert!(write.grant(&paths(&["v1"])).is_err());
        assert!(write.grant(&methods(&["GET POST"])).is_err());
        assert!(
            write
                .grant(&Narrowing {
                    read: true,
                    methods: vec!["GET".into()],
                    ..Default::default()
                })
                .is_err()
        );

        let read_some = asked("docs.rs", None, AccessLevel::Read, &["/serde/**"]);
        assert_eq!(
            read_some.grant(&Narrowing::default()).unwrap(),
            read_some.rule().unwrap()
        );
        assert!(read_some.grant(&read).is_ok());
        assert!(read_some.grant(&methods(&["HEAD"])).is_ok());
        assert!(read_some.grant(&methods(&["POST"])).is_err());
        assert!(read_some.grant(&paths(&["/serde/latest/**"])).is_ok());
        assert!(read_some.grant(&paths(&["/serde"])).is_ok());
        assert!(read_some.grant(&paths(&["/tokio/**"])).is_err());
        assert!(read_some.grant(&paths(&["/**"])).is_err());

        let tunnel = asked("db.example.com", Some(5432), AccessLevel::Write, &[]);
        assert_eq!(
            tunnel.grant(&Narrowing::default()).unwrap().mode,
            Mode::Tunnel
        );
        assert!(tunnel.grant(&read).is_err());
        assert!(tunnel.grant(&paths(&["/x"])).is_err());

        let mut install = asked("", None, AccessLevel::Read, &[]);
        install.install = Some(Install::Package { name: "jq".into() });
        assert!(install.grant(&Narrowing::default()).is_err());
    }
}
