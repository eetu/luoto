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

use crate::config::{EnvFile, new_rule_id};
use crate::env::{self, Ctx};
use crate::runtime::States;
use crate::{ctl, names, sync};

pub fn parse_ttl(s: &str) -> Result<TimeDelta> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num
        .parse()
        .with_context(|| format!("bad duration `{s}` (use 30m, 1h, 2d)"))?;
    let d = match unit {
        "s" => TimeDelta::try_seconds(n),
        "m" | "" => TimeDelta::try_minutes(n),
        "h" => TimeDelta::try_hours(n),
        "d" => TimeDelta::try_days(n),
        _ => bail!("bad duration unit in `{s}` (use s, m, h, d)"),
    };
    d.with_context(|| format!("duration `{s}` is too long"))
}

#[derive(clap::Args)]
pub struct AllowOpts {
    pub host: String,
    /// Any method (default: read-only GET/HEAD/OPTIONS).
    #[arg(long)]
    pub write: bool,
    /// Specific methods instead of read/write (repeatable).
    #[arg(long = "method")]
    pub methods: Vec<String>,
    /// Path globs (repeatable), e.g. `/serde/**`.
    #[arg(long = "path")]
    pub paths: Vec<String>,
    /// Expire after a duration: 30m, 1h, 2d.
    #[arg(long)]
    pub ttl: Option<String>,
    /// Opaque tunnel (no inspection) for any client and protocol: certificate-pinning
    /// clients, gRPC, a database with --port.
    #[arg(long)]
    pub tunnel: bool,
    /// Allow websocket upgrades.
    #[arg(long)]
    pub ws: bool,
    /// How long the host may stay silent before the gate closes the connection (30m, 2h; at
    /// most 24h), for long polls such as `kubectl logs -f`.
    #[arg(long, value_name = "DURATION")]
    pub idle: Option<String>,
    /// Allow private/host addresses (e.g. a service on your machine).
    #[arg(long)]
    pub private: bool,
    /// The one port it covers (default: 80 and 443).
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub note: Option<String>,
    /// Accept risky rules (wildcards over shared domains, `*`, write) without asking.
    #[arg(long)]
    pub force: bool,
}

pub fn build_rule(o: &AllowOpts) -> Result<Rule> {
    let host = o.host.trim();
    let host = if host == "*" || host.contains('/') || host.starts_with("*.") {
        host.to_string()
    } else {
        luoto_shared::host::normalize_host(luoto_shared::host::host_of(host))?
    };
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
        port: o.port,
        access,
        paths: o.paths.clone(),
        expires: o
            .ttl
            .as_deref()
            .map(parse_ttl)
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
    })
}

/// The risks of adding `rule` to an env with `policy`, or why it is refused: refused when
/// it is invalid, or a tunnel over a host where the gate strips credentials, guards writes or
/// applies a deny (see `Policy::tunnel_bypass`); a risk when it covers a host the gate puts
/// one of your credentials on.
fn risks(policy: &Policy, rule: &Rule) -> Result<Vec<String>> {
    let issues = validate_rule(rule, RuleOrigin::Host);
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
pub fn add_rule_checked(ctx: &Ctx, name: &str, mut rule: Rule, force: bool) -> Result<Rule> {
    rule.id.get_or_insert_with(new_rule_id);
    let risks = risks(&env::plan(ctx, name)?.compiled.policy, &rule)?;
    if !risks.is_empty() && !force {
        return Err(Risks(risks).into());
    }
    let mut f = EnvFile::load(&ctx.paths, name)?;
    f.add_rule(&rule)?;
    sync::reapply(ctx, name)?;
    Ok(rule)
}

/// `add(force)`, asking on a terminal to accept the [`Risks`] it reports.
pub fn accepting_risks<T>(force: bool, add: impl Fn(bool) -> Result<T>) -> Result<T> {
    match add(force) {
        Err(e) => match e.downcast::<Risks>() {
            Ok(Risks(risks)) => {
                for r in &risks {
                    eprintln!("risk: {r}");
                }
                if !crate::prompt::confirm("Accept these risks?") {
                    bail!("not added (pass --force to accept these risks)");
                }
                add(true)
            }
            Err(e) => Err(e),
        },
        done => done,
    }
}

/// Remove the env's user rules with this id or host; how many there were.
pub fn remove(ctx: &Ctx, name: &str, id_or_host: &str) -> Result<usize> {
    let n = EnvFile::load(&ctx.paths, name)?.remove_rules(id_or_host)?;
    if n == 0 {
        bail!(
            "no user rule with id or host `{id_or_host}` (preset rules are changed by editing `presets`)"
        );
    }
    sync::reapply(ctx, name)?;
    Ok(n)
}

/// The access requests filed with the env's gate; none while the gate is down.
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
    crate::text::display(&format!("{at} {}{paths}", rule.access.describe()))
}

/// The rule a pending access request grants, narrowed by `narrow`; refused if `narrow` would
/// widen it.
pub fn grant(req: &AccessRequest, narrow: &Narrowing) -> Result<Rule> {
    if req.status != RequestStatus::Pending {
        bail!("request #{} is already {:?}", req.id, req.status);
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

/// Approve a pending request: an access request becomes a rule, narrowed by `narrow` and
/// failing with [`Risks`] unless `force`; an install request installs. A request for a
/// variable is refused: only a terminal asks for its value (`vars::approve`).
pub fn approve(
    ctx: &Ctx,
    name: &str,
    req: &AccessRequest,
    ttl: Option<&str>,
    narrow: &Narrowing,
    force: bool,
) -> Result<Approved> {
    if let Some(var) = req.install.as_ref().and_then(Install::variable) {
        bail!(crate::vars::needs_terminal(name, req.id, var));
    }
    if req.install.is_some() {
        if !narrow.is_empty() {
            bail!(
                "request #{} asks for an install: there is no access to narrow",
                req.id
            );
        }
        return approve_install(ctx, name, req).map(|installed| Approved::Installed { installed });
    }
    let policy = env::plan(ctx, name)?.compiled.policy;
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
    rule.expires = ttl.map(parse_ttl).transpose()?.map(|d| Utc::now() + d);
    rule.note = Some(format!("approved request #{}", req.id));
    let rule = add_rule_checked(ctx, name, rule, force)?;
    // The sandbox reads the note: it learns what it got, if less than it asked for.
    let mut notes = Vec::new();
    if !narrow.is_empty() {
        notes.push(format!("granted less: {}", describe(&rule)));
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
        bail!("request #{} is already {:?}", req.id, req.status);
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
        Install::Preset { .. } | Install::Var { .. } | Install::Secret { .. } => {}
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

    #[test]
    fn ttls() {
        assert_eq!(parse_ttl("30m").unwrap(), TimeDelta::minutes(30));
        assert_eq!(parse_ttl("2h").unwrap(), TimeDelta::hours(2));
        assert_eq!(parse_ttl("1d").unwrap(), TimeDelta::days(1));
        assert!(parse_ttl("1y").is_err());
        assert!(parse_ttl("-5m").is_err());
        assert!(parse_ttl("99999999999999d").is_err());
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
        let graph = risks(&policy, &rule("graph.microsoft.com")).unwrap();
        assert_eq!(
            graph,
            ["requests it allows to graph.microsoft.com carry your `azure-graph` credential"]
        );
        let arm = risks(&policy, &rule("management.azure.com")).unwrap();
        assert!(arm[0].contains("`azure-arm`"), "{arm:?}");
        assert!(risks(&policy, &rule("docs.rs")).unwrap().is_empty());
        let tunnel = Rule {
            mode: Mode::Tunnel,
            ..rule("graph.microsoft.com")
        };
        assert!(risks(&policy, &tunnel).is_err());
    }

    #[test]
    fn a_granted_request_reads_as_what_it_grants() {
        let req = AccessRequest {
            id: 3,
            host: "api.example.com".into(),
            port: None,
            access: AccessLevel::Write,
            paths: vec![],
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
