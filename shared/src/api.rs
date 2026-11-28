//! The in-sandbox API the gate serves at `http://gate:3128/_sandbox/…` for the `sandbox`
//! helper (and through it, MCP-capable agents). Read-mostly; the writes are filing an access
//! request, which only the host can resolve, and passing ssh-agent messages to the vault.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events::Event;
use crate::host::{host_matches, is_never_dialed, is_private, normalize_host, normalize_pattern};
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
    /// The one port the rule covers (default: 80 and 443).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Inspected or an uninspected tunnel; when not given, a request with a port is a tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    pub access: AccessLevel,
    #[serde(default)]
    pub paths: Vec<String>,
    /// The host is on the user's network or VPN: the rule asked for reaches it there.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub private: bool,
    /// Websocket upgrades too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ws: bool,
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
    /// The one port the rule covers (default: 80 and 443).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Inspected or a tunnel ([`AccessRequest::is_tunnel`]); a tunnel's `access` is write,
    /// since its bytes go unread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    pub access: AccessLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Asks to reach the host on the user's network or VPN (a rule's `allow_private`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub private: bool,
    /// Asks for websocket upgrades too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ws: bool,
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

/// Whether a request with `port` and `mode` asks for a tunnel: as its mode says, else (a
/// request that names none) whenever it names a port.
pub fn asks_tunnel(port: Option<u16>, mode: Option<Mode>) -> bool {
    match mode {
        Some(m) => m == Mode::Tunnel,
        None => port.is_some(),
    }
}

/// The rule a request asks for, or why it can't: what a rule of the user's may be, which they
/// approve seeing its risks ([`RuleOrigin::Request`]); an address on the user's network only
/// as `private`, never one the gate never dials; a tunnel ([`asks_tunnel`]) to the host on its
/// port (80 and 443 without one), never limited to paths. The rule leaves `allow_private` to
/// the user.
pub fn requested_rule(
    host: &str,
    port: Option<u16>,
    mode: Option<Mode>,
    access: AccessLevel,
    paths: &[String],
    private: bool,
    ws: bool,
) -> Result<Rule, String> {
    let host = normalize_pattern(host).ok_or_else(|| {
        format!(
            "`{}` is not a host, a wildcard over one or an address range",
            host.trim()
        )
    })?;
    // An address, or a range by its first: on the user's network (RFC 1918, CGNAT or
    // unique-local) only as `private`, never loopback or the like.
    let addr = host
        .parse::<IpAddr>()
        .ok()
        .or_else(|| host.parse::<ipnet::IpNet>().ok().map(|n| n.network()));
    if let Some(ip) = addr {
        let plain = crate::host::leaves_host(ip);
        if (is_private(ip) || is_never_dialed(ip)) && !(private && plain) {
            return Err(if plain {
                format!(
                    "{ip} is a private address: ask for it with private access if it is on the \
                     user's network or VPN"
                )
            } else {
                format!("{ip} is an address the sandbox may not ask for")
            });
        }
    }
    if port == Some(0) {
        return Err("port 0 is not a port".into());
    }
    let rule = if asks_tunnel(port, mode) {
        if !paths.is_empty() {
            return Err("a tunnel can't be limited to paths: the gate doesn't read it".into());
        }
        Rule {
            host,
            port,
            access: Access::Level(AccessLevel::Write),
            mode: Mode::Tunnel,
            ..Default::default()
        }
    } else {
        Rule {
            host,
            port,
            access: Access::Level(access),
            paths: paths.to_vec(),
            ws,
            ..Default::default()
        }
    };
    match rule_error(&rule, RuleOrigin::Request) {
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
    /// One exact host or address of the wildcard or range asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// A tunnel asked for, granted inspected: the gate reads what passes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub inspect: bool,
}

impl Narrowing {
    pub fn is_empty(&self) -> bool {
        !self.read
            && self.methods.is_empty()
            && self.paths.is_empty()
            && self.host.is_none()
            && !self.inspect
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
        requested_rule(
            &self.host,
            self.port,
            self.mode,
            self.access,
            &self.paths,
            self.private,
            self.ws,
        )
    }

    /// Whether it asks for an uninspected tunnel ([`asks_tunnel`]).
    pub fn is_tunnel(&self) -> bool {
        self.install.is_none() && asks_tunnel(self.port, self.mode)
    }

    /// Where it asks to go: the host, or `host:port` (an IPv6 address bracketed) with a port.
    pub fn target(&self) -> String {
        match self.port {
            Some(port) if self.host.contains(':') => format!("[{}]:{port}", self.host),
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    /// The rule granting the request, narrowed by `n`; refused if `n` would grant anything
    /// the request did not ask for.
    pub fn grant(&self, n: &Narrowing) -> Result<Rule, String> {
        let mut rule = self.rule()?;
        if n.is_empty() {
            return Ok(rule);
        }
        let id = self.id;
        if let Some(h) = &n.host {
            let exact = normalize_host(h).map_err(|_| format!("`{}` is not a host", h.trim()))?;
            if exact != rule.host && !host_matches(&rule.host, &exact) {
                return Err(format!(
                    "`{exact}` is not one of `{}`, which request #{id} asked for",
                    rule.host
                ));
            }
            rule.host = exact;
        }
        if n.inspect {
            if rule.mode != Mode::Tunnel {
                return Err(format!(
                    "request #{id} asks for no tunnel: the gate inspects it already"
                ));
            }
            rule.mode = Mode::Inspect;
        }
        if rule.mode == Mode::Tunnel && (n.read || !n.methods.is_empty() || !n.paths.is_empty()) {
            return Err(format!(
                "request #{id} asks for a tunnel, which can't be limited to methods or paths: \
                 approve it inspected, as asked, or reject it"
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
        match rule_error(&rule, RuleOrigin::Request) {
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
            mode: None,
            access,
            paths: paths.iter().map(|p| p.to_string()).collect(),
            private: false,
            ws: false,
            reason: "r".into(),
            status: RequestStatus::Pending,
            created: Utc::now(),
            resolved: None,
            note: None,
            install: None,
        }
    }

    /// A request as one filed before requests named their mode: a port is a tunnel.
    fn ask(
        host: &str,
        port: Option<u16>,
        access: AccessLevel,
        paths: &[String],
        private: bool,
    ) -> Result<Rule, String> {
        requested_rule(host, port, None, access, paths, private, false)
    }

    #[test]
    fn a_port_with_no_mode_is_a_tunnel_on_any_port() {
        let r = ask("DB.Example.com", Some(5432), AccessLevel::Read, &[], false).unwrap();
        assert_eq!(
            (r.host.as_str(), r.port, r.mode, r.access),
            (
                "db.example.com",
                Some(5432),
                Mode::Tunnel,
                Access::Level(AccessLevel::Write)
            )
        );
        // The user approves it seeing its risks, as a rule of their own.
        for (host, port) in [
            ("db.example.com", 443),
            ("db.example.com", 80),
            ("*.example.com", 5432),
            ("8.8.8.8", 5432),
        ] {
            assert!(
                ask(host, Some(port), AccessLevel::Write, &[], false).is_ok(),
                "{host}:{port}"
            );
        }
        for (host, port, paths) in [
            ("db.example.com", 0, &[][..]),
            ("db.example.com", 5432, &["/x/**".to_string()][..]),
            ("10.0.0.0/8", 5432, &[][..]),
            ("10.1.2.3", 5432, &[][..]),
            ("127.0.0.1", 5432, &[][..]),
            ("[::1]", 5432, &[][..]),
            ("169.254.169.254", 5432, &[][..]),
            ("203.0.113.9", 5432, &[][..]),
            ("user@db.example.com", 5432, &[][..]),
        ] {
            assert!(
                ask(host, Some(port), AccessLevel::Write, paths, false).is_err(),
                "{host}:{port} {paths:?}"
            );
        }
    }

    #[test]
    fn a_request_names_its_mode_its_port_and_websockets() {
        let paths = ["/repository/**".to_string()];
        let r = requested_rule(
            "nexus.corp.example",
            Some(8443),
            Some(Mode::Inspect),
            AccessLevel::Read,
            &paths,
            false,
            true,
        )
        .unwrap();
        assert_eq!((r.port, r.mode, r.ws), (Some(8443), Mode::Inspect, true));
        assert_eq!(r.paths, paths);
        // A tunnel on HTTPS's own ports, for a client that checks the server's own CA.
        let t = requested_rule(
            "k8s.example.com",
            None,
            Some(Mode::Tunnel),
            AccessLevel::Read,
            &[],
            false,
            false,
        )
        .unwrap();
        assert_eq!((t.port, t.mode), (None, Mode::Tunnel));
        assert!(asks_tunnel(Some(5432), None) && !asks_tunnel(Some(8443), Some(Mode::Inspect)));
    }

    #[test]
    fn a_private_address_is_asked_for_only_with_private_access() {
        let ask =
            |host: &str, private: bool| ask(host, Some(6443), AccessLevel::Write, &[], private);
        for host in ["10.10.0.8", "192.168.1.20", "100.64.0.9", "[fd12::8]"] {
            assert!(ask(host, false).is_err(), "{host}");
            let rule = ask(host, true).unwrap();
            assert!(!rule.allow_private, "{host}: the user's to give");
        }
        for host in [
            "127.0.0.1",
            "169.254.169.254",
            "169.254.1.2",
            "10.212.0.5",
            "192.0.2.1",
        ] {
            assert!(ask(host, true).is_err(), "{host}");
        }
    }

    #[test]
    fn host_requests_keep_their_checks() {
        // What a rule of the user's may be, its risks shown when it is approved.
        for host in [
            "docs.rs",
            "*.mycompany.dev",
            "*",
            "*.amazonaws.com",
            "8.8.8.0/24",
        ] {
            assert!(
                ask(host, None, AccessLevel::Read, &[], false).is_ok(),
                "{host}"
            );
        }
        // Never a public suffix, a wildcard over an address, or the user's network unasked.
        for host in ["*.github.io", "*.10.0.0.1", "192.168.1.1", "10.0.0.0/8"] {
            assert!(
                ask(host, None, AccessLevel::Read, &[], false).is_err(),
                "{host}"
            );
        }
        let bad_path = ["v1/**".to_string()];
        assert!(ask("docs.rs", None, AccessLevel::Read, &bad_path, false).is_err());
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
        let inspected = Narrowing {
            inspect: true,
            ..read.clone()
        };
        let rule = tunnel.grant(&inspected).unwrap();
        assert_eq!(
            (rule.mode, rule.port, rule.access),
            (Mode::Inspect, Some(5432), Access::Level(AccessLevel::Read))
        );
        assert!(write.grant(&inspected).is_err(), "inspected already");

        let host = |h: &str| Narrowing {
            host: Some(h.into()),
            ..Default::default()
        };
        let wildcard = asked("*.corp.example", None, AccessLevel::Read, &[]);
        assert_eq!(
            wildcard.grant(&host("API.corp.example")).unwrap().host,
            "api.corp.example"
        );
        for wider in ["corp.example", "*.corp.example.evil", "other.example", "*"] {
            assert!(wildcard.grant(&host(wider)).is_err(), "{wider}");
        }
        let range = asked("8.8.8.0/24", None, AccessLevel::Read, &[]);
        assert_eq!(range.grant(&host("8.8.8.8")).unwrap().host, "8.8.8.8");
        assert!(range.grant(&host("8.8.9.8")).is_err());

        let mut install = asked("", None, AccessLevel::Read, &[]);
        install.install = Some(Install::Package { name: "jq".into() });
        assert!(install.grant(&Narrowing::default()).is_err());
    }
}
