//! Egress rules and access requests: the core behind `luoto allow`, `revoke`, `approve` and
//! `reject` and the UI's rule and request routes.

use anyhow::{Context, Result, bail};
use chrono::{TimeDelta, Utc};
use luoto_shared::api::{AccessRequest, Install, Narrowing, RequestStatus};
use luoto_shared::ctl::GateCtl;
use luoto_shared::policy::{
    Access, AccessLevel, Mode, Policy, Rule, RuleOrigin, Severity, validate_rule,
};
use serde::Serialize;
use std::time::Duration;

use crate::config::{EnvFile, new_rule_id};
use crate::env::{self, Ctx};
use crate::runtime::States;
use crate::{ctl, names, sync};

/// A duration as every flag that takes one writes it: a whole number and its unit, s, m, h
/// or d (`30m`, `2h`, `1d`).
pub fn parse_duration(s: &str) -> Result<TimeDelta> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num
        .parse()
        .with_context(|| format!("bad duration `{s}` (30m, 2h, 1d)"))?;
    let d = match unit {
        "s" => TimeDelta::try_seconds(n),
        "m" => TimeDelta::try_minutes(n),
        "h" => TimeDelta::try_hours(n),
        "d" => TimeDelta::try_days(n),
        _ => bail!("bad duration `{s}`: a number and s, m, h or d (30m, 2h, 1d)"),
    };
    d.with_context(|| format!("duration `{s}` is too long"))
}

#[derive(clap::Args)]
pub struct AllowOpts {
    /// The host (`docs.rs`), a wildcard over its subdomains (`*.docs.rs`), or a URL; with a
    /// port (`k8s.example.com:6443`), only that port.
    pub host: String,
    /// Any method (default: read-only GET/HEAD/OPTIONS).
    #[arg(long)]
    pub write: bool,
    /// Specific methods instead of read/write (repeatable).
    #[arg(long = "method", value_name = "METHOD")]
    pub methods: Vec<String>,
    /// Path globs (repeatable), e.g. `/serde/**`.
    #[arg(long = "path", value_name = "GLOB")]
    pub paths: Vec<String>,
    /// Expire after this long (30m, 2h, 1d).
    #[arg(long = "for", value_name = "DURATION")]
    pub window: Option<String>,
    /// Opaque tunnel (no inspection) for any client and protocol: certificate-pinning
    /// clients, gRPC, a database with `--port`.
    #[arg(long)]
    pub tunnel: bool,
    /// Allow websocket upgrades.
    #[arg(long)]
    pub ws: bool,
    /// How long the host may stay silent before the gate closes the connection (30m, 2h, 1d;
    /// at most a day), for long polls such as `kubectl logs -f`.
    #[arg(long, value_name = "DURATION")]
    pub idle: Option<String>,
    /// Allow private/host addresses (e.g. a service on your machine).
    #[arg(long)]
    pub private: bool,
    /// The CA its certificate is signed by, a PEM file here (an internal service's): trusted
    /// for this host only, so the gate can inspect it.
    #[arg(long, value_name = "FILE")]
    pub ca: Option<std::path::PathBuf>,
    /// The one port it covers (default: 80 and 443).
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,
    /// Why the rule is there, kept with it.
    #[arg(long)]
    pub note: Option<String>,
    /// Accept risky rules (wildcards over shared domains, `*`, write) without asking.
    #[arg(long)]
    pub force: bool,
}

pub fn build_rule(o: &AllowOpts) -> Result<Rule> {
    let (host, port) = rule_target(&o.host, o.port)?;
    if let Some(idle) = &o.idle {
        luoto_shared::policy::parse_idle(idle).map_err(anyhow::Error::msg)?;
    }
    let access = if !o.methods.is_empty() {
        Access::Methods(o.methods.iter().map(|m| m.to_ascii_uppercase()).collect())
    } else if o.write || o.tunnel {
        Access::Level(AccessLevel::Write)
    } else {
        Access::Level(AccessLevel::Read)
    };
    Ok(Rule {
        id: Some(new_rule_id()),
        host,
        port,
        access,
        paths: o.paths.clone(),
        expires: o
            .window
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .map(|d| Utc::now() + d),
        mode: if o.tunnel {
            Mode::Tunnel
        } else {
            Mode::Inspect
        },
        ws: o.ws,
        max_body: None,
        allow_private: o.private,
        note: o.note.clone(),
        ignore_case: false,
        idle: o.idle.clone(),
        // Kept as a full path: the env file is read from anywhere.
        ca: o
            .ca
            .as_deref()
            .map(|p| {
                let p = crate::workspace::expand(&p.to_string_lossy());
                std::fs::canonicalize(&p)
                    .map(|p| p.to_string_lossy().into_owned())
                    .with_context(|| format!("the CA {}", p.display()))
            })
            .transpose()?,
    })
}

/// The port `target` names after its host `bare` (`host:7443`, a URL's), as `host_of` read it.
/// The host pattern a rule matches and its port, from what the user typed for one (`*`,
/// `*.example.com`, an address range, a name or address, each maybe with `:port`, or a URL)
/// and the port given apart, if any.
pub fn rule_target(typed: &str, port: Option<u16>) -> Result<(String, Option<u16>)> {
    use luoto_shared::host;
    let t = typed.trim();
    let (pattern, named) = match t.split_once('/') {
        // An address range, maybe with a port after its prefix length.
        Some((addr, len))
            if !t.contains("://")
                && addr
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok() =>
        {
            match len.split_once(':') {
                Some((len, p)) => (format!("{addr}/{len}"), Some(p)),
                None => (t.to_string(), None),
            }
        }
        _ => {
            let (h, p) = host::split_target(t);
            (h.to_string(), p)
        }
    };
    let named = named
        .map(|p| {
            p.parse::<u16>()
                .ok()
                .filter(|&n| n != 0)
                .with_context(|| format!("`{t}`: {p} is not a port"))
        })
        .transpose()?;
    let port = match (port, named) {
        (Some(p), Some(n)) if p != n => bail!("`{t}` names port {n} and --port {p}: give one"),
        (p, n) => p.or(n),
    };
    let pattern = match host::normalize_pattern(&pattern) {
        Some(p) => p,
        None if pattern.starts_with("*.") || pattern.contains('/') => {
            bail!("`{t}` is not a host, a wildcard over one or an address range")
        }
        None => host::normalize_host(&pattern)?,
    };
    Ok((pattern, port))
}

/// Whether `typed` names rule `r`: its id, or its host as `luoto allow` takes one
/// (`k8s.example.com:7443`, a URL, any case); with a port, only that port's rules.
pub fn named_by(r: &Rule, typed: &str) -> bool {
    let typed = typed.trim();
    if r.id.as_deref() == Some(typed) || r.host == typed {
        return true;
    }
    rule_target(typed, None).is_ok_and(|(host, port)| {
        luoto_shared::host::normalize_pattern(&r.host).is_some_and(|h| h == host)
            && port.is_none_or(|p| r.port == Some(p))
    })
}

/// `rule`'s host as a rule matches it, with the port it named, for a rule made elsewhere than
/// [`build_rule`] (the UI).
fn normalize(rule: &mut Rule) -> Result<()> {
    (rule.host, rule.port) = rule_target(&rule.host, rule.port)?;
    Ok(())
}

/// The risks of adding `rule` to an env with `policy`, or why it is refused: refused when
/// it is invalid, or a tunnel over a host where the gate strips credentials, guards writes or
/// applies a deny (see `Policy::tunnel_bypass`); a risk when it covers a host the gate puts
/// one of your credentials on. `origin` is who asked: you, or the sandbox's request, which shows
/// more of what it asks for as risks.
fn risks(policy: &Policy, rule: &Rule, origin: RuleOrigin) -> Result<Vec<String>> {
    let issues = validate_rule(rule, origin);
    if let Some(e) = issues.iter().find(|i| i.severity == Severity::Error) {
        bail!("{}", e.message);
    }
    if rule.mode == Mode::Tunnel
        && let Some(why) = policy.tunnel_bypass(&rule.host)
    {
        bail!("{why}");
    }
    let mut out: Vec<String> = issues.into_iter().map(|i| i.message).collect();
    out.extend(policy.credentials_reached(rule));
    Ok(out)
}

/// Risks a rule carries that the user has yet to accept; the CLI asks, the UI answers 409.
#[derive(Debug)]
pub struct Risks(pub Vec<String>);

impl std::fmt::Display for Risks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the rule has risks: {}", self.0.join("; "))
    }
}

impl std::error::Error for Risks {}

/// Add `rule` to the env, failing with [`Risks`] unless `force` accepts them. The rule as
/// added: with an id.
pub fn add_rule_checked(ctx: &Ctx, name: &str, rule: Rule, force: bool) -> Result<Rule> {
    add_checked(ctx, name, rule, force, RuleOrigin::Host)
}

fn add_checked(
    ctx: &Ctx,
    name: &str,
    mut rule: Rule,
    force: bool,
    origin: RuleOrigin,
) -> Result<Rule> {
    rule.id.get_or_insert_with(new_rule_id);
    normalize(&mut rule)?;
    let risks = risks(&env::plan(ctx, name)?.compiled.policy, &rule, origin)?;
    if !risks.is_empty() && !force {
        return Err(Risks(risks).into());
    }
    let mut f = EnvFile::load(&ctx.paths, name)?;
    f.add_rule(&rule)?;
    sync::reapply(ctx, name)?;
    Ok(rule)
}

/// What a host resolves to on this machine, asked as a rule for it is made: a rule reaches a
/// private address only with `allow_private`, and a normal-looking name may have one (a host on
/// the user's network or behind a VPN). The gate vets every address again when it dials.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Resolved {
    /// The private addresses it resolves to (your network, a VPN).
    pub private: Vec<String>,
    /// It resolves to an address the gate never dials (loopback, cloud metadata), whatever
    /// a rule says.
    pub never: bool,
}

/// How long [`resolve`] waits for this machine's resolver.
const RESOLVE_WAIT: Duration = Duration::from_secs(2);

/// [`Resolved`] for `host`: nothing for a wildcard, a name that doesn't resolve in time or one
/// that isn't a host.
pub fn resolve(host: &str) -> Resolved {
    let Ok(host) = luoto_shared::host::normalize_host(host) else {
        return Resolved::default();
    };
    let addrs: Vec<std::net::IpAddr> = if let Ok(ip) = host.parse() {
        vec![ip]
    } else {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::net::ToSocketAddrs;
            let found = (host.as_str(), 443)
                .to_socket_addrs()
                .map(|a| a.map(|s| s.ip()).collect::<Vec<_>>());
            let _ = tx.send(found.unwrap_or_default());
        });
        rx.recv_timeout(RESOLVE_WAIT).unwrap_or_default()
    };
    classify(&addrs)
}

fn classify(addrs: &[std::net::IpAddr]) -> Resolved {
    use luoto_shared::host::{is_never_dialed, is_private};
    let mut private: Vec<String> = addrs
        .iter()
        .filter(|ip| is_private(**ip) && !is_never_dialed(**ip))
        .map(ToString::to_string)
        .collect();
    private.dedup();
    Resolved {
        private,
        never: addrs.iter().any(|ip| is_never_dialed(*ip)),
    }
}

/// Replace the env's rule `id` with `rule`, under a new id (so past events' "allowed by rule"
/// stays true of the rule they name), failing with [`Risks`] unless `force` accepts them; a
/// refused rule leaves the old one in place. The rule as saved.
pub fn replace(ctx: &Ctx, name: &str, id: &str, mut rule: Rule, force: bool) -> Result<Rule> {
    let mut f = EnvFile::load(&ctx.paths, name)?;
    if !f.cfg.allow.iter().any(|r| r.id.as_deref() == Some(id)) {
        bail!(
            "`{name}` has no rule of yours with id `{}` (`luoto status -e {name}` lists them)",
            crate::text::display(id)
        );
    }
    rule.id = Some(new_rule_id());
    normalize(&mut rule)?;
    let risks = risks(
        &env::plan(ctx, name)?.compiled.policy,
        &rule,
        RuleOrigin::Host,
    )?;
    if !risks.is_empty() && !force {
        return Err(Risks(risks).into());
    }
    f.replace_rule(id, &rule)?;
    sync::reapply(ctx, name)?;
    Ok(rule)
}

/// `add(force)`, asking on a terminal to accept the [`Risks`] it reports.
pub fn accepting_risks<T>(force: bool, add: impl Fn(bool) -> Result<T>) -> Result<T> {
    match add(force) {
        Err(e) => match e.downcast::<Risks>() {
            Ok(Risks(risks)) => {
                for r in &risks {
                    crate::progress::warn(r);
                }
                if !crate::prompt::confirm("Accept these risks?") {
                    return Err(crate::prompt::declined("added", &with_force()));
                }
                add(true)
            }
            Err(e) => Err(e),
        },
        done => done,
    }
}

/// This command as it was given, with `--force`.
fn with_force() -> String {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .map(|a| crate::text::sh_quote(&crate::text::display(&a)))
        .collect();
    format!("{} {} --force", names::instance(), args.join(" "))
}

/// Remove the env's user rules with this id or host; how many there were.
pub fn remove(ctx: &Ctx, name: &str, id_or_host: &str) -> Result<usize> {
    let n = EnvFile::load(&ctx.paths, name)?.remove_rules(id_or_host)?;
    if n == 0 {
        bail!(
            "`{name}` has no rule of yours with id or host `{}` (`luoto status -e {name}` lists \
             them)",
            crate::text::display(id_or_host)
        );
    }
    sync::reapply(ctx, name)?;
    Ok(n)
}

/// The access requests filed with the env's gate; none while the gate is down.
/// What preset `name` opens, a line per rule (`registry.npmjs.org read-only`), for whoever
/// approves a request for it; `None` for a name that is no preset.
pub fn preset_hosts(name: &str) -> Option<Vec<String>> {
    use luoto_shared::policy::{Access, AccessLevel, Mode};
    let preset = luoto_shared::presets::get(name)?;
    Some(
        preset
            .rules
            .iter()
            .map(|r| {
                let host = match r.port {
                    Some(port) => format!("{}:{port}", r.host),
                    None => r.host.clone(),
                };
                let access = match (&r.mode, &r.access) {
                    (Mode::Tunnel, _) => "tunnel, uninspected".to_string(),
                    (_, Access::Level(AccessLevel::Read)) => "read-only".to_string(),
                    (_, Access::Level(AccessLevel::Write)) => "any method".to_string(),
                    (_, Access::Methods(ms)) => ms.join(", "),
                };
                // A preset's path lists run long; their count says they narrow it.
                match r.paths.len() {
                    0 => format!("{host} {access}"),
                    1 => format!("{host} {access}, only 1 path pattern"),
                    n => format!("{host} {access}, only {n} path patterns"),
                }
            })
            .collect(),
    )
}

pub fn requests(ctx: &Ctx, name: &str, states: &States) -> Result<Vec<AccessRequest>> {
    if !states.running(&names::gate(name)) {
        return Ok(Vec::new());
    }
    ctl::gate(&ctx.rt, name, &GateCtl::Requests)
}

pub fn request(ctx: &Ctx, name: &str, id: u64) -> Result<AccessRequest> {
    ctl::gate::<Vec<AccessRequest>>(&ctx.rt, name, &GateCtl::Requests)?
        .into_iter()
        .find(|r| r.id == id)
        .with_context(|| format!("no request #{id} in `{name}`"))
}

/// What a rule grants, for people: `docs.rs read-only (GET, HEAD, OPTIONS) paths /serde/**`,
/// `a tunnel to db.example.com:5432`. Its host and paths may come from the sandbox.
pub fn describe(rule: &Rule) -> String {
    let at = match rule.port {
        Some(port) => format!("{}:{port}", rule.host),
        None => rule.host.clone(),
    };
    if rule.mode == Mode::Tunnel {
        return format!("a tunnel to {}", crate::text::display(&at));
    }
    let paths = if rule.paths.is_empty() {
        String::new()
    } else {
        format!(" paths {}", rule.paths.join(","))
    };
    let ws = if rule.ws { ", websockets too" } else { "" };
    crate::text::display(&format!("{at} {}{paths}{ws}", rule.access.describe()))
}

/// What `luoto allow` takes to make `rule` again, without its access: the host, its port and
/// whether it tunnels (`k8s.example.com --port 7443 --tunnel`). Its host may come from the
/// sandbox.
pub fn allow_args(rule: &Rule) -> String {
    let mut args = crate::text::display(&rule.host);
    if let Some(port) = rule.port {
        args.push_str(&format!(" --port {port}"));
    }
    if rule.mode == Mode::Tunnel {
        args.push_str(" --tunnel");
    }
    if rule.ws {
        args.push_str(" --ws");
    }
    args
}

/// The rule a pending access request grants, narrowed by `narrow`; refused if `narrow` would
/// widen it.
pub fn grant(req: &AccessRequest, narrow: &Narrowing) -> Result<Rule> {
    if req.status != RequestStatus::Pending {
        bail!("request #{} is already {}", req.id, req.status);
    }
    req.grant(narrow).map_err(anyhow::Error::msg)
}

/// What approving a request did.
#[derive(Serialize)]
#[serde(untagged)]
pub enum Approved {
    /// The rule an access request became.
    Rule(Rule),
    /// What an install request did, for people.
    Installed { installed: String },
}

/// The rule an access request becomes under `policy`, narrowed by `narrow`, on the user's
/// network or VPN with `private`; refused when a `[[deny]]` takes all of it.
fn granted(
    policy: &Policy,
    req: &AccessRequest,
    narrow: &Narrowing,
    private: bool,
) -> Result<Rule> {
    if let Some(d) = policy.wholly_denied(&req.host) {
        bail!(
            "{} is refused by a [[deny]] rule ({}): approving request #{} would open nothing; \
             reject it, or remove the deny first",
            crate::text::display(&req.host),
            d.reason,
            req.id
        );
    }
    let mut rule = grant(req, narrow)?;
    rule.allow_private = private;
    Ok(rule)
}

/// What [`approve`] would ask the user to confirm for `req` so granted, or why it would refuse
/// it: the UI shows them before the user decides. Nothing for an install request.
pub fn approval_risks(
    ctx: &Ctx,
    name: &str,
    req: &AccessRequest,
    narrow: &Narrowing,
    private: bool,
) -> Result<Vec<String>> {
    if req.install.is_some() {
        return Ok(Vec::new());
    }
    let policy = env::plan(ctx, name)?.compiled.policy;
    let mut rule = granted(&policy, req, narrow, private)?;
    normalize(&mut rule)?;
    risks(&policy, &rule, RuleOrigin::Request)
}

/// Approve a pending request: an access request becomes a rule, narrowed by `narrow`,
/// reaching the host on the user's network or VPN with `private` (the user's answer, whatever
/// the request asked), and failing with [`Risks`] unless
/// `force`; an install request installs. A request for a variable is refused: only a terminal
/// asks for its value (`vars::approve`).
pub fn approve(
    ctx: &Ctx,
    name: &str,
    req: &AccessRequest,
    ttl: Option<&str>,
    narrow: &Narrowing,
    private: bool,
    force: bool,
) -> Result<Approved> {
    if let Some(var) = req.install.as_ref().and_then(Install::variable) {
        bail!(crate::vars::needs_terminal(name, req.id, var));
    }
    if req.install.is_some() {
        if !narrow.is_empty() || private {
            bail!(
                "request #{} asks for an install: there is no access to narrow or widen",
                req.id
            );
        }
        return approve_install(ctx, name, req).map(|installed| Approved::Installed { installed });
    }
    let policy = env::plan(ctx, name)?.compiled.policy;
    let mut rule = granted(&policy, req, narrow, private)?;
    rule.expires = ttl.map(parse_duration).transpose()?.map(|d| Utc::now() + d);
    rule.note = Some(format!("approved request #{}", req.id));
    let rule = add_checked(ctx, name, rule, force, RuleOrigin::Request)?;
    // The sandbox reads the note: it learns what it got, if less or more than it asked for.
    let mut notes = Vec::new();
    if !narrow.is_empty() {
        notes.push(format!("granted less: {}", describe(&rule)));
    }
    if rule.allow_private {
        notes.push("it reaches the host on the user's network or VPN".to_string());
    } else if req.private {
        notes.push("not on the user's network or VPN".to_string());
    }
    if policy.partly_denied(&req.host) {
        notes.push("[[deny]] rules still refuse some of it".to_string());
    }
    let note = (!notes.is_empty()).then(|| notes.join("; "));
    ctl::gate::<AccessRequest>(
        &ctx.rt,
        name,
        &GateCtl::Resolve {
            id: req.id,
            approved: true,
            note,
        },
    )?;
    Ok(Approved::Rule(rule))
}

/// Grant a pending install request: the package or toolchain joins the env's config, so every
/// recreated container gets it too, and is installed now. The request is approved either way;
/// its note tells the sandbox whether the install worked. What happened, for people.
fn approve_install(ctx: &Ctx, name: &str, req: &AccessRequest) -> Result<String> {
    if req.status != RequestStatus::Pending {
        bail!("request #{} is already {}", req.id, req.status);
    }
    let Some(install) = &req.install else {
        bail!("request #{} asks for access, not an install", req.id);
    };
    install.check().map_err(anyhow::Error::msg)?;
    let mut f = EnvFile::load(&ctx.paths, name)?;
    let what = crate::text::display(&install.describe());
    if let Install::Preset { name: preset } = install {
        let mut presets = f.cfg.presets.clone();
        crate::config::extend_unique(&mut presets, [preset.clone()]);
        f.set_list("presets", &presets)?;
        let note = match sync::reapply(ctx, name) {
            Ok(_) => "its hosts are open; the env's config keeps it".to_string(),
            Err(e) => format!("added to the env's config; applies on `luoto up` ({e:#})"),
        };
        ctl::gate::<AccessRequest>(
            &ctx.rt,
            name,
            &GateCtl::Resolve {
                id: req.id,
                approved: true,
                note: Some(note.clone()),
            },
        )?;
        return Ok(format!("approved: {what}: {note}"));
    }
    match install {
        Install::Package { name } => f.add_system_package(name)?,
        Install::Tool { name, version } => f.set_in_table("tools", name, version)?,
        Install::Preset { .. } | Install::Var { .. } => {}
    }
    let result = (|| {
        let p = crate::env::plan(ctx, name)?;
        let home = p
            .state
            .as_ref()
            .map_or("/home/dev".to_string(), |s| s.home().to_string());
        crate::deps::ensure(ctx, name, &p.cfg, &home)
    })();
    let note = match &result {
        Ok(()) => "installed; the env's config keeps it".to_string(),
        Err(e) => format!("added to the env's config, but installing failed: {e:#}"),
    };
    ctl::gate::<AccessRequest>(
        &ctx.rt,
        name,
        &GateCtl::Resolve {
            id: req.id,
            approved: true,
            note: Some(note.clone()),
        },
    )?;
    Ok(format!("approved: {what}: {note}"))
}

pub fn reject(ctx: &Ctx, name: &str, id: u64, note: Option<String>) -> Result<AccessRequest> {
    ctl::gate(
        &ctx.rt,
        name,
        &GateCtl::Resolve {
            id,
            approved: false,
            note,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(args: &[&str]) -> Result<Rule> {
        #[derive(clap::Parser)]
        struct Allow {
            #[command(flatten)]
            o: AllowOpts,
        }
        use clap::Parser;
        build_rule(&Allow::parse_from(std::iter::once("allow").chain(args.iter().copied())).o)
    }

    #[test]
    fn a_port_after_the_host_is_the_rules_port() {
        let r = allowed(&["k8s.example.com:7443", "--tunnel", "--private"]).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("k8s.example.com", Some(7443)));
        assert!(r.allow_private && r.mode == Mode::Tunnel);
        let r = allowed(&["https://k8s.example.com:7443/version"]).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("k8s.example.com", Some(7443)));
        let r = allowed(&["k8s.example.com:7443", "--port", "7443"]).unwrap();
        assert_eq!(r.port, Some(7443));
        assert_eq!(allowed(&["docs.rs"]).unwrap().port, None);
        let e = allowed(&["k8s.example.com:7443", "--port", "443"]).unwrap_err();
        assert!(e.to_string().contains("give one"), "{e}");
        assert!(allowed(&["k8s.example.com:99999"]).is_err());
    }

    #[test]
    fn a_rules_host_is_kept_as_the_gate_compares_it() {
        for (typed, host, port) in [
            ("API.Example.com.", "api.example.com", None),
            ("docs.rs/serde", "docs.rs", None),
            ("*.Example.com", "*.example.com", None),
            ("*.corp.example:8443", "*.corp.example", Some(8443)),
            ("10.0.0.0/8", "10.0.0.0/8", None),
            ("10.0.0.0/8:5432", "10.0.0.0/8", Some(5432)),
            ("fd00::1", "fd00::1", None),
            ("[fd00::1]:5432", "fd00::1", Some(5432)),
            ("*", "*", None),
        ] {
            let r = allowed(&[typed]).unwrap_or_else(|e| panic!("{typed}: {e}"));
            assert_eq!((r.host.as_str(), r.port), (host, port), "{typed}");
        }
        for typed in ["*.10.0.0.1", "10.0.0.0/99", "exa mple.com"] {
            assert!(allowed(&[typed]).is_err(), "{typed}");
        }
        let mut ui = Rule {
            host: "Api.Example.com:8443".into(),
            ..Default::default()
        };
        normalize(&mut ui).unwrap();
        assert_eq!((ui.host.as_str(), ui.port), ("api.example.com", Some(8443)));
    }

    #[test]
    fn a_rule_is_named_by_its_id_or_its_host_as_allow_takes_it() {
        let k8s = Rule {
            id: Some("r1".into()),
            host: "k8s.example.com".into(),
            port: Some(7443),
            ..Default::default()
        };
        for typed in [
            "r1",
            "k8s.example.com",
            "K8s.Example.com:7443",
            "https://k8s.example.com:7443/version",
        ] {
            assert!(named_by(&k8s, typed), "{typed}");
        }
        for typed in ["k8s.example.com:443", "example.com", "r2"] {
            assert!(!named_by(&k8s, typed), "{typed}");
        }
        // One kept as it was typed, before hosts were normalized.
        let old = Rule {
            host: "Docs.rs".into(),
            ..Default::default()
        };
        assert!(named_by(&old, "Docs.rs") && named_by(&old, "docs.rs"));
    }

    #[test]
    fn a_rule_is_named_again_as_luoto_allow_takes_it() {
        let tunnel = allowed(&["k8s.example.com:7443", "--tunnel"]).unwrap();
        assert_eq!(allow_args(&tunnel), "k8s.example.com --port 7443 --tunnel");
        assert_eq!(allow_args(&allowed(&["docs.rs"]).unwrap()), "docs.rs");
    }

    #[test]
    fn a_presets_hosts_are_listed_with_their_access_and_no_name_makes_some_up() {
        let npm = preset_hosts("npm").unwrap();
        assert!(
            npm.contains(&"registry.npmjs.org read-only".to_string()),
            "{npm:?}"
        );
        assert_eq!(
            npm.len(),
            luoto_shared::presets::get("npm").unwrap().rules.len()
        );
        // Every preset's every line names a host and what it may do there.
        for name in luoto_shared::presets::names() {
            for line in preset_hosts(name).unwrap() {
                assert!(
                    line.split_once(' ')
                        .is_some_and(|(h, a)| !h.is_empty() && !a.is_empty())
                );
            }
        }
        assert_eq!(preset_hosts("no-such-preset"), None);
    }

    #[test]
    fn a_name_on_a_private_address_is_told_and_one_never_dialed_is_flagged() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert_eq!(classify(&[ip("8.8.8.8")]), Resolved::default());
        let vpn = classify(&[ip("10.10.0.8"), ip("100.64.1.2")]);
        assert_eq!(vpn.private, ["10.10.0.8", "100.64.1.2"]);
        assert!(!vpn.never);
        // Loopback and metadata: no rule reaches them, so none is offered as private.
        let never = classify(&[ip("127.0.0.1"), ip("169.254.169.254")]);
        assert!(never.private.is_empty() && never.never);
        assert_eq!(resolve("10.1.2.3").private, ["10.1.2.3"]);
        assert_eq!(resolve("*.example.com"), Resolved::default());
    }

    #[test]
    fn ttls() {
        assert_eq!(parse_duration("30m").unwrap(), TimeDelta::minutes(30));
        assert_eq!(parse_duration("2h").unwrap(), TimeDelta::hours(2));
        assert_eq!(parse_duration("1d").unwrap(), TimeDelta::days(1));
        assert!(parse_duration("1y").is_err());
        assert!(parse_duration("30").is_err());
        assert!(parse_duration("-5m").is_err());
        assert!(parse_duration("99999999999999d").is_err());
    }

    #[test]
    fn a_rule_over_a_credentialed_host_says_whose_credential_it_reaches() {
        let cfg: crate::config::EnvConfig = toml::from_str(
            "[credentials.azure]\nsubscriptions = [\"0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0\"]\n\
             graph = true\n",
        )
        .unwrap();
        let policy = crate::compile::compile("t", &cfg, None, &[])
            .unwrap()
            .policy;
        let rule = |host: &str| Rule {
            host: host.into(),
            ..Rule::default()
        };
        let graph = risks(&policy, &rule("graph.microsoft.com"), RuleOrigin::Host).unwrap();
        assert_eq!(
            graph,
            ["requests it allows to graph.microsoft.com carry your `azure-graph` credential"]
        );
        let arm = risks(&policy, &rule("management.azure.com"), RuleOrigin::Host).unwrap();
        assert!(arm[0].contains("`azure-arm`"), "{arm:?}");
        assert!(
            risks(&policy, &rule("docs.rs"), RuleOrigin::Host)
                .unwrap()
                .is_empty()
        );
        let tunnel = Rule {
            mode: Mode::Tunnel,
            ..rule("graph.microsoft.com")
        };
        assert!(risks(&policy, &tunnel, RuleOrigin::Host).is_err());
    }

    #[test]
    fn a_granted_request_reads_as_what_it_grants() {
        let req = AccessRequest {
            id: 3,
            host: "api.example.com".into(),
            port: None,
            mode: None,
            access: AccessLevel::Write,
            paths: vec![],
            private: false,
            ws: false,
            reason: "r".into(),
            status: RequestStatus::Pending,
            created: Utc::now(),
            resolved: None,
            note: None,
            install: None,
        };
        let narrow = Narrowing {
            read: true,
            paths: vec!["/v1/**".into()],
            ..Default::default()
        };
        assert_eq!(
            describe(&grant(&req, &narrow).unwrap()),
            "api.example.com read-only (GET, HEAD, OPTIONS) paths /v1/**"
        );
        let tunnel = AccessRequest {
            host: "db.example.com".into(),
            port: Some(5432),
            ..req.clone()
        };
        assert_eq!(
            describe(&grant(&tunnel, &Narrowing::default()).unwrap()),
            "a tunnel to db.example.com:5432"
        );
        assert!(grant(&tunnel, &narrow).is_err());
        let done = AccessRequest {
            status: RequestStatus::Approved,
            ..req
        };
        assert!(grant(&done, &Narrowing::default()).is_err());
    }
}
