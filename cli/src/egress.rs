//! Open egress, for an env whose needs aren't known yet: what no rule allows goes out over
//! HTTP(S) for a while anyway, as rule `open` (`Policy::open`), and what it reached can be
//! kept as presets and rules afterwards. The core behind `luoto egress open|close|keep`,
//! `luoto init --open` and the UI's.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use chrono::{DateTime, Local, TimeDelta, TimeZone, Utc};
use luoto_shared::policy::{
    Access, AccessLevel, CompiledRule, Decision, Policy, RequestInfo, Rule, RuleOrigin, rule_error,
};
use luoto_shared::presets;

use crate::config::{EnvFile, extend_unique, new_rule_id};
use crate::env::Ctx;
use crate::events::Opened;
use crate::sync;

/// How long egress opens for unless told.
pub const WINDOW: &str = "1h";

/// A window (`--for`, `init --open=`): a duration as rules take one (30m, 2h, 1d), above zero.
pub fn parse_window(s: &str) -> Result<TimeDelta> {
    let d = crate::rules::parse_ttl(s)?;
    if d <= TimeDelta::zero() {
        bail!("`{s}`: give a duration above zero, such as 30m or 2h");
    }
    Ok(d)
}

/// Now plus `window`, in whole seconds, as the env's file says it.
pub fn until(window: TimeDelta) -> DateTime<Utc> {
    let t = Utc::now() + window;
    DateTime::from_timestamp(t.timestamp(), 0).unwrap_or(t)
}

/// Open the env's egress until `until`: its file says so, and a running env takes it at once.
/// Whether it was running.
pub fn open(ctx: &Ctx, name: &str, until: DateTime<Utc>) -> Result<bool> {
    EnvFile::load(&ctx.paths, name)?.set_open(Some(until))?;
    Ok(sync::reapply(ctx, name)?.is_some())
}

/// Close the env's egress, a window or `open = true`. Whether it was open.
pub fn close(ctx: &Ctx, name: &str) -> Result<bool> {
    let mut f = EnvFile::load(&ctx.paths, name)?;
    let was = f.cfg.egress.open_at(Utc::now()).ok().flatten().is_some();
    f.set_open(None)?;
    sync::reapply(ctx, name)?;
    Ok(was)
}

/// When open egress closes, for people, in local time: `until 14:05` today, `until Nov 12
/// 14:05` on another day, `until you close it`.
pub fn until_text(until: Option<DateTime<Utc>>) -> String {
    until_in(until, Utc::now(), &Local)
}

fn until_in<Tz: TimeZone>(until: Option<DateTime<Utc>>, now: DateTime<Utc>, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let Some(t) = until else {
        return "until you close it".into();
    };
    let t = t.with_timezone(tz);
    if t.date_naive() == now.with_timezone(tz).date_naive() {
        format!("until {}", t.format("%H:%M"))
    } else {
        format!("until {}", t.format("%b %-d %H:%M"))
    }
}

/// The env's open egress in a line of `up` and `status`, with the command that closes it.
pub fn state_line(name: &str, until: Option<DateTime<Utc>>, width: usize) -> String {
    crate::prompt::with_command(
        &format!("open {} to any HTTP(S) host", until_text(until)),
        &format!("`luoto egress close -e {name}`"),
        width,
    )
}

/// What `luoto egress keep` offers for the hosts open egress reached.
#[derive(Debug, Default, PartialEq)]
pub struct Proposal {
    /// Presets the env lacks, each with the hosts it covers.
    pub presets: Vec<(String, Vec<String>)>,
    /// A rule for each other host, per port it was reached on beyond 80 and 443: read, or
    /// write where a write went out.
    pub rules: Vec<Rule>,
}

impl Proposal {
    pub fn is_empty(&self) -> bool {
        self.presets.is_empty() && self.rules.is_empty()
    }
}

/// What to keep of `opened` in an env with `policy` and the presets `have`: none of what its
/// rules allow already, nor a host that gets a credential (open egress never reaches one).
pub fn propose(policy: &Policy, have: &[String], opened: &[Opened]) -> Proposal {
    let mut rules_only = policy.clone();
    rules_only.open = None;
    let left: Vec<&Opened> = opened
        .iter()
        .filter(|o| !policy.is_credentialed_host(&o.host) && !covered(&rules_only, o))
        .collect();
    let mut taken: BTreeSet<&str> = BTreeSet::new();
    let mut out = Proposal::default();
    for p in presets::all() {
        if have.contains(&p.name) {
            continue;
        }
        let of_preset = Policy {
            rules: p
                .rules
                .iter()
                .enumerate()
                .map(|(i, r)| CompiledRule {
                    id: format!("{}-{i}", p.name),
                    origin: format!("preset:{}", p.name),
                    rule: r.clone(),
                })
                .collect(),
            ..Default::default()
        };
        let hosts: Vec<&str> = left
            .iter()
            .filter(|o| !taken.contains(o.host.as_str()) && covered(&of_preset, o))
            .map(|o| o.host.as_str())
            .collect();
        if !hosts.is_empty() {
            taken.extend(&hosts);
            out.presets
                .push((p.name, hosts.into_iter().map(String::from).collect()));
        }
    }
    out.rules = left
        .iter()
        .filter(|o| !taken.contains(o.host.as_str()))
        .flat_map(|o| rules_for(o))
        .collect();
    out
}

/// Whether `policy` allows every request of `o`.
fn covered(policy: &Policy, o: &Opened) -> bool {
    let now = Utc::now();
    o.requests.iter().all(|(method, path, port)| {
        let req = RequestInfo {
            host: &o.host,
            port: *port,
            method,
            path,
            websocket: false,
            content_length: None,
        };
        matches!(policy.decide(&req, now), Decision::Allow { .. })
    })
}

/// A rule for each port `o` was reached on (one for 80 and 443): write if a write went out
/// on it, else read.
fn rules_for(o: &Opened) -> Vec<Rule> {
    let port_of = |p: u16| (!matches!(p, 80 | 443)).then_some(p);
    let ports: BTreeSet<Option<u16>> = o.requests.iter().map(|(_, _, p)| port_of(*p)).collect();
    ports
        .into_iter()
        .map(|port| {
            let write = o.requests.iter().any(|(m, _, p)| {
                port_of(*p) == port && !luoto_shared::policy::READ_METHODS.contains(&m.as_str())
            });
            Rule {
                host: o.host.clone(),
                port,
                access: Access::Level(if write {
                    AccessLevel::Write
                } else {
                    AccessLevel::Read
                }),
                note: Some("kept from open egress".into()),
                ..Default::default()
            }
        })
        .filter(|r| rule_error(r, RuleOrigin::Host).is_none())
        .collect()
}

/// A rule `luoto egress keep` offers, as its menu and summary name it: `docs.example`,
/// `db.example:8443`.
pub fn rule_target(r: &Rule) -> String {
    let host = crate::text::display(&r.host);
    match r.port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// Keep `presets` and `rules` in the env: its file has them, and a running env takes them at
/// once.
pub fn keep(ctx: &Ctx, name: &str, presets: &[String], rules: &[Rule]) -> Result<()> {
    let mut f = EnvFile::load(&ctx.paths, name)?;
    if !presets.is_empty() {
        let mut all = f.cfg.presets.clone();
        extend_unique(&mut all, presets.iter().cloned());
        f.set_list("presets", &all)?;
    }
    if !rules.is_empty() {
        let rules: Vec<Rule> = rules
            .iter()
            .map(|r| Rule {
                id: Some(new_rule_id()),
                ..r.clone()
            })
            .collect();
        f.add_rules(&rules)?;
    }
    sync::reapply(ctx, name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opened(host: &str, requests: &[(&str, &str, u16)]) -> Opened {
        Opened {
            host: host.into(),
            requests: requests
                .iter()
                .map(|(m, p, port)| (m.to_string(), p.to_string(), *port))
                .collect(),
            count: requests.len() as u64,
        }
    }

    #[test]
    fn a_window_is_a_duration_above_zero() {
        assert_eq!(parse_window(WINDOW).unwrap(), TimeDelta::hours(1));
        assert_eq!(parse_window("30m").unwrap(), TimeDelta::minutes(30));
        for bad in ["0m", "-1h", "soon", "1y"] {
            assert!(parse_window(bad).is_err(), "{bad}");
        }
        let u = until(TimeDelta::hours(1));
        assert_eq!(u.timestamp_subsec_nanos(), 0);
        assert!(u > Utc::now() + TimeDelta::minutes(59));
    }

    #[test]
    fn the_end_reads_as_a_time_today_or_a_date() {
        let now: DateTime<Utc> = "2026-11-11T10:00:00Z".parse().unwrap();
        let at = |s: &str| until_in(s.parse().ok(), now, &Utc);
        assert_eq!(at("2026-11-11T14:05:00Z"), "until 14:05");
        assert_eq!(at("2026-11-12T09:30:00Z"), "until Nov 12 09:30");
        assert_eq!(until_in(None, now, &Utc), "until you close it");
    }

    #[test]
    fn keep_offers_presets_then_a_rule_per_host() {
        let compiled = crate::compile::compile(
            "t",
            &toml::from_str(
                "presets = [\"github\"]\n[[allow]]\nhost = \"docs.example\"\n\
                 [credentials.custom.api]\nhost = \"api.example.com\"\nsecret = \"env:T\"\n",
            )
            .unwrap(),
            None,
            &[],
        )
        .unwrap();
        let have = vec!["github".to_string()];
        let reached = [
            opened("registry.npmjs.org", &[("GET", "/react", 443)]),
            opened("docs.example", &[("GET", "/a", 443)]),
            opened("api.example.com", &[("GET", "/v1", 443)]),
            opened("blog.example", &[("GET", "/", 443), ("HEAD", "/", 80)]),
            opened(
                "upload.example",
                &[("GET", "/", 443), ("PUT", "/f", 443), ("GET", "/", 8080)],
            ),
            opened("github.com", &[("GET", "/acme/web", 443)]),
        ];
        let p = propose(&compiled.policy, &have, &reached);
        assert_eq!(
            p.presets,
            [("npm".to_string(), vec!["registry.npmjs.org".to_string()])]
        );
        let rules: Vec<(String, &Access)> = p
            .rules
            .iter()
            .map(|r| (rule_target(r), &r.access))
            .collect();
        let read = Access::Level(AccessLevel::Read);
        let write = Access::Level(AccessLevel::Write);
        assert_eq!(
            rules,
            [
                ("blog.example".to_string(), &read),
                ("upload.example".to_string(), &write),
                ("upload.example:8080".to_string(), &read),
            ]
        );
        assert!(p.rules.iter().all(|r| r.id.is_none()));
        assert!(propose(&compiled.policy, &have, &reached[1..3]).is_empty());
    }
}
