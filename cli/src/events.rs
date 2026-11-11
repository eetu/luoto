//! Reading gate/vault events from the runtime's logs and summarising egress per host.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::process::Stdio;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use luoto_shared::events::{Event, EventKind, Intake, Verdict};
use luoto_shared::policy::{Mute, OPEN_RULE};
use serde::Serialize;

use crate::names;
use crate::runtime::Runtime;

/// Parse event lines out of mixed container output (diagnostics on stderr are skipped).
pub fn parse_lines(text: &str) -> Vec<Event> {
    text.lines()
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<Event>(l).ok())
        .filter(|e| e.seq > 0)
        .collect()
}

fn logs_args<'a>(container: &'a str, since: Option<&'a str>, follow: bool) -> Vec<&'a str> {
    let mut args = vec!["logs"];
    if follow {
        args.push("-f");
    }
    if let Some(s) = since {
        args.extend(["--since", s]);
    }
    args.push(container);
    args
}

pub fn read(rt: &Runtime, container: &str, since: Option<&str>) -> Result<Vec<Event>> {
    let _waiting = crate::progress::waiting("reading the gate's log");
    let out = rt
        .command()
        .args(logs_args(container, since, false))
        .stdin(Stdio::null())
        .output()
        .context("read logs")?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let mut events = parse_lines(&text);
    events.sort_by_key(|e| (e.ts, e.seq));
    Ok(events)
}

pub fn gate_events(rt: &Runtime, env: &str, since: Option<&str>) -> Result<Vec<Event>> {
    read(rt, &names::gate(env), since)
}

/// Follow a container's events, calling `f` for each (stops when `f` returns false).
pub fn follow(
    rt: &Runtime,
    container: &str,
    since: Option<&str>,
    mut f: impl FnMut(Event) -> bool,
) -> Result<()> {
    let mut child = rt
        .command()
        .args(logs_args(container, since, true))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("follow logs")?;
    let stdout = child.stdout.take().context("logs stdout")?;
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        if let Some(ev) = parse_lines(&line).into_iter().next()
            && !f(ev)
        {
            break;
        }
    }
    let _ = child.kill();
    Ok(())
}

/// An env's `[[mute]]` entries, as egress views apply them.
#[derive(Debug, Clone, Default)]
pub struct Mutes(Vec<Mute>);

impl Mutes {
    /// The valid entries of `entries` (`compile` reports the others).
    pub fn new(entries: &[Mute]) -> Self {
        Mutes(entries.iter().filter_map(|m| m.checked().ok()).collect())
    }

    /// Is `e` a denial a mute hides? A mute of a whole host also hides its lookups and the
    /// certificates its clients reject (the gate intercepts a denied host to explain itself).
    pub fn hides(&self, e: &Event) -> bool {
        let Some(host) = e.host.as_deref() else {
            return false;
        };
        self.0.iter().any(|m| match e.kind {
            Some(EventKind::Dns | EventKind::TlsReject) => m.covers(host, None),
            _ => e.verdict == Some(Verdict::Deny) && m.covers(host, e.path.as_deref()),
        })
    }

    /// Drop what the mutes hide from `events`, and the lookups of hosts left with nothing
    /// else; the number of denials dropped.
    pub fn hide(&self, events: &mut Vec<Event>) -> usize {
        let mut muted: BTreeSet<String> = BTreeSet::new();
        let mut denials = 0;
        events.retain(|e| {
            let hidden = self.hides(e);
            if hidden && e.verdict == Some(Verdict::Deny) {
                denials += 1;
                muted.extend(e.host.clone());
            }
            !hidden
        });
        let used: BTreeSet<&str> = events
            .iter()
            .filter(|e| e.kind != Some(EventKind::Dns))
            .filter_map(|e| e.host.as_deref())
            .collect();
        let lookups_only: BTreeSet<String> = muted
            .into_iter()
            .filter(|h| !used.contains(h.as_str()))
            .collect();
        events.retain(|e| {
            e.kind != Some(EventKind::Dns)
                || !e.host.as_ref().is_some_and(|h| lookups_only.contains(h))
        });
        denials
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HostSummary {
    pub host: String,
    pub allowed: u64,
    /// Of `allowed`, those open egress let out: no rule allowed them.
    pub opened: u64,
    pub denied: u64,
    /// Of `denied`, those a mute hides when they are not left out.
    pub muted: u64,
    pub dns_only: bool,
    pub methods: BTreeSet<String>,
    pub ports: BTreeSet<u16>,
    pub intakes: BTreeSet<String>,
    pub top_paths: Vec<(String, u64)>,
    pub last_reason: Option<String>,
    pub last_message: Option<String>,
    /// The path of the last denial, for a hint that allows that path, not the host.
    #[serde(skip)]
    pub last_denied_path: Option<String>,
    pub last_rule: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub wants_write: bool,
    pub tls_rejected: bool,
}

pub fn summarize(events: &[Event], mutes: &Mutes) -> Vec<HostSummary> {
    let mut by: BTreeMap<String, (HostSummary, BTreeMap<String, u64>)> = BTreeMap::new();
    for e in events {
        let Some(host) = e.host.clone() else { continue };
        if luoto_shared::events::is_selftest(&host) {
            continue;
        }
        let relevant = matches!(
            e.kind,
            Some(
                EventKind::Http
                    | EventKind::Tunnel
                    | EventKind::Direct
                    | EventKind::Dns
                    | EventKind::TlsReject
            )
        );
        if !relevant {
            continue;
        }
        let (s, paths) = by.entry(host.clone()).or_insert_with(|| {
            (
                HostSummary {
                    host,
                    dns_only: true,
                    ..Default::default()
                },
                BTreeMap::new(),
            )
        });
        s.first_seen = s.first_seen.min(e.ts).or(e.ts);
        s.last_seen = s.last_seen.max(e.ts);
        if e.kind == Some(EventKind::Dns) {
            s.intakes.insert("dns".into());
            continue;
        }
        s.dns_only = false;
        if let Some(i) = e.intake {
            s.intakes.insert(
                match i {
                    Intake::Proxy => "proxy",
                    Intake::Transparent => "transparent",
                    Intake::Dns => "dns",
                }
                .into(),
            );
        }
        if let Some(p) = e.port {
            s.ports.insert(p);
        }
        if let Some(m) = &e.method {
            s.methods.insert(m.clone());
        }
        match e.verdict {
            Some(Verdict::Allow) => {
                s.allowed += 1;
                s.opened += u64::from(e.rule.as_deref() == Some(OPEN_RULE));
                s.last_rule = e.rule.clone().or(s.last_rule.take());
            }
            Some(Verdict::Deny) => {
                s.denied += 1;
                s.muted += u64::from(mutes.hides(e));
                s.last_reason = e.reason.clone();
                s.last_message = e.message.clone();
                s.last_denied_path = e.path.clone();
                let write = e
                    .method
                    .as_deref()
                    .is_some_and(|m| !luoto_shared::policy::READ_METHODS.contains(&m));
                if e.reason.as_deref() == Some("method_not_allowed")
                    || (e.reason.as_deref() == Some("path_not_allowed") && write)
                {
                    s.wants_write = true;
                }
            }
            None => {}
        }
        if e.kind == Some(EventKind::TlsReject) {
            s.tls_rejected = true;
        }
        s.bytes_up += e.bytes_up.unwrap_or(0);
        s.bytes_down += e.bytes_down.unwrap_or(0);
        if let Some(p) = &e.path {
            *paths.entry(p.clone()).or_default() += 1;
        }
    }
    let mut out: Vec<HostSummary> = by
        .into_values()
        .map(|(mut s, paths)| {
            let mut v: Vec<(String, u64)> = paths.into_iter().collect();
            v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            v.truncate(5);
            s.top_paths = v;
            s
        })
        .collect();
    out.sort_by(|a, b| b.denied.cmp(&a.denied).then(b.last_seen.cmp(&a.last_seen)));
    out
}

/// Where a container's event stream stood when read: the last `seq` of each gate or vault run
/// (a restarted one counts from 1 under a new `run`). Reads that start at the same `since` see
/// the same lines up to it, whatever the VM's clock says.
#[derive(Debug, Default)]
pub struct Mark(BTreeMap<String, u64>);

impl Mark {
    pub fn of(events: &[Event]) -> Self {
        let mut last = BTreeMap::new();
        for e in events {
            let seq: &mut u64 = last.entry(e.run.clone()).or_default();
            *seq = (*seq).max(e.seq);
        }
        Mark(last)
    }

    /// The events written after the mark.
    pub fn after(&self, events: Vec<Event>) -> Vec<Event> {
        events
            .into_iter()
            .filter(|e| self.0.get(&e.run).is_none_or(|s| e.seq > *s))
            .collect()
    }
}

/// A host the gate denied, as the summary after `luoto run` shows it.
#[derive(Debug, PartialEq)]
pub struct Denied {
    pub host: String,
    pub count: u64,
    /// What was refused (`METHOD /path`, or `port N` for a connection), most often first.
    pub targets: Vec<(String, u64)>,
    /// The gate's explanation of the latest one.
    pub message: Option<String>,
}

/// The gate's denials in `events` per host, most denied first.
pub fn denials(events: &[Event]) -> Vec<Denied> {
    let mut by: BTreeMap<&str, (Denied, BTreeMap<String, u64>)> = BTreeMap::new();
    for e in events.iter().filter(|e| e.verdict == Some(Verdict::Deny)) {
        let Some(host) = e
            .host
            .as_deref()
            .filter(|h| !luoto_shared::events::is_selftest(h))
        else {
            continue;
        };
        let target = match (&e.method, &e.path, e.port) {
            (Some(m), Some(p), _) => format!("{m} {p}"),
            (Some(x), None, _) | (None, Some(x), _) => x.clone(),
            (None, None, Some(port)) => format!("port {port}"),
            (None, None, None) => String::new(),
        };
        let (d, targets) = by.entry(host).or_insert_with(|| {
            let d = Denied {
                host: host.to_string(),
                count: 0,
                targets: Vec::new(),
                message: None,
            };
            (d, BTreeMap::new())
        });
        d.count += 1;
        if !target.is_empty() {
            *targets.entry(target).or_default() += 1;
        }
        if e.message.is_some() {
            d.message = e.message.clone();
        }
    }
    let mut out: Vec<Denied> = by
        .into_values()
        .map(|(mut d, targets)| {
            d.targets = targets.into_iter().collect();
            d.targets.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            d
        })
        .collect();
    out.sort_by_key(|d| std::cmp::Reverse(d.count));
    out
}

/// The summary of `denied` for stderr, one line per host (the sandbox's strings escaped);
/// empty when there is none.
pub fn fmt_denials(env: &str, denied: &[Denied]) -> String {
    use crate::text::display;
    const TARGETS: usize = 3;
    if denied.is_empty() {
        return String::new();
    }
    let total: u64 = denied.iter().map(|d| d.count).sum();
    let hosts: Vec<String> = denied.iter().map(|d| display(&d.host)).collect();
    let width = hosts.iter().map(|h| h.chars().count()).max().unwrap_or(0);
    let mut out = format!(
        "the gate denied {total} attempt{} to reach {} host{} during the run:\n",
        if total == 1 { "" } else { "s" },
        denied.len(),
        if denied.len() == 1 { "" } else { "s" },
    );
    for (d, host) in denied.iter().zip(&hosts) {
        let mut what: Vec<String> = d
            .targets
            .iter()
            .take(TARGETS)
            .map(|(t, n)| match n {
                1 => display(t),
                n => format!("{} ({n})", display(t)),
            })
            .collect();
        if d.targets.len() > TARGETS {
            what.push(format!("{} more", d.targets.len() - TARGETS));
        }
        let why = d
            .message
            .as_deref()
            .map(|m| format!(": {}", display(m)))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {host:<width$} {:>5}  {}{why}\n",
            d.count,
            what.join(", ")
        ));
    }
    out.push_str(&format!(
        "`luoto egress -e {env} --denied` says how to allow each.\n"
    ));
    out
}

/// A request as [`Opened`] keeps it: method, path and port.
pub type Request = (String, String, u16);

/// A host open egress let requests out to, which no rule allowed.
#[derive(Debug, Clone, PartialEq)]
pub struct Opened {
    pub host: String,
    /// Each request once.
    pub requests: Vec<Request>,
    pub count: u64,
}

impl Opened {
    /// The methods it took, in order.
    pub fn methods(&self) -> Vec<&str> {
        let set: BTreeSet<&str> = self.requests.iter().map(|(m, _, _)| m.as_str()).collect();
        set.into_iter().collect()
    }
}

/// The hosts open egress let out to in `events`, most requests first.
pub fn opened(events: &[Event]) -> Vec<Opened> {
    let mut by: BTreeMap<&str, (u64, BTreeSet<Request>)> = BTreeMap::new();
    for e in events {
        if e.verdict != Some(Verdict::Allow) || e.rule.as_deref() != Some(OPEN_RULE) {
            continue;
        }
        let Some(host) = e.host.as_deref() else {
            continue;
        };
        let (n, reqs) = by.entry(host).or_default();
        *n += 1;
        reqs.insert((
            e.method.clone().unwrap_or_default(),
            e.path.clone().unwrap_or_default(),
            e.port.unwrap_or(443),
        ));
    }
    let mut out: Vec<Opened> = by
        .into_iter()
        .map(|(host, (count, requests))| Opened {
            host: host.to_string(),
            requests: requests.into_iter().collect(),
            count,
        })
        .collect();
    out.sort_by_key(|o| std::cmp::Reverse(o.count));
    out
}

/// After a run: the hosts reached only because egress is open, and the command that keeps
/// them; empty when there is none.
pub fn fmt_opened(env: &str, opened: &[Opened]) -> String {
    const SHOWN: usize = 5;
    if opened.is_empty() {
        return String::new();
    }
    let mut hosts: Vec<String> = opened
        .iter()
        .take(SHOWN)
        .map(|o| crate::text::display(&o.host))
        .collect();
    if opened.len() > SHOWN {
        hosts.push(format!("{} more", opened.len() - SHOWN));
    }
    format!(
        "{} host{} reached only because egress is open: {}\n\
         `luoto egress keep -e {env}` keeps them.\n",
        opened.len(),
        if opened.len() == 1 { "" } else { "s" },
        hosts.join(", ")
    )
}

pub fn fmt_event(e: &Event) -> String {
    let ts =
        e.ts.map(|t| t.format("%H:%M:%S").to_string())
            .unwrap_or_default();
    let verdict = match e.verdict {
        Some(Verdict::Allow) => "allow",
        Some(Verdict::Deny) => "DENY ",
        None => "     ",
    };
    let kind = e
        .kind
        .map(|k| format!("{k:?}").to_lowercase())
        .unwrap_or_default();
    let target = format!(
        "{} {}{}",
        e.method.as_deref().unwrap_or(""),
        e.host.as_deref().unwrap_or(""),
        e.path.as_deref().unwrap_or("")
    );
    let tail = match (&e.status, &e.message) {
        (_, Some(m)) if e.verdict == Some(Verdict::Deny) || e.kind != Some(EventKind::Http) => {
            format!("  — {m}")
        }
        (Some(s), _) => format!("  {s}"),
        _ => String::new(),
    };
    crate::text::display(&format!("{ts} {verdict} {kind:<9} {}{tail}", target.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_denials_first() {
        let text = r#"luoto-gate: some stderr line
{"seq":1,"run":"r","env":"e","kind":"dns","host":"evil.example","ts":"2026-11-03T10:00:00Z"}
{"seq":2,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"registry.npmjs.org","path":"/react","status":200,"bytes_down":100,"ts":"2026-11-03T10:00:01Z"}
{"seq":3,"run":"r","env":"e","kind":"http","verdict":"deny","method":"PUT","host":"registry.npmjs.org","path":"/react","reason":"method_not_allowed","ts":"2026-11-03T10:00:02Z"}
{"seq":4,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"docs.rs","path":"/serde","reason":"no_rule","ts":"2026-11-03T10:00:03Z"}
"#;
        let events = parse_lines(text);
        assert_eq!(events.len(), 4);
        let s = summarize(&events, &Mutes::default());
        assert_eq!(s.len(), 3);
        let npm = s.iter().find(|h| h.host == "registry.npmjs.org").unwrap();
        assert_eq!((npm.allowed, npm.denied), (1, 1));
        assert!(npm.wants_write);
        assert!(
            s.iter()
                .find(|h| h.host == "evil.example")
                .unwrap()
                .dns_only
        );
        let docs = s.iter().find(|h| h.host == "docs.rs").unwrap();
        assert_eq!(docs.last_denied_path.as_deref(), Some("/serde"));
        assert_eq!(npm.last_denied_path.as_deref(), Some("/react"));
    }

    #[test]
    fn what_open_egress_let_out_is_counted_per_host() {
        let text = r#"{"seq":1,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"registry.npmjs.org","path":"/react","rule":"npm-0"}
{"seq":2,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"docs.example","path":"/a","rule":"open"}
{"seq":3,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"docs.example","path":"/a","rule":"open"}
{"seq":4,"run":"r","env":"e","kind":"http","verdict":"allow","method":"PUT","host":"upload.example","port":8080,"path":"/f","rule":"open"}
{"seq":5,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"telemetry.example","path":"/","reason":"no_rule"}"#;
        let evs = parse_lines(text);
        let o = opened(&evs);
        assert_eq!(
            o,
            [
                Opened {
                    host: "docs.example".into(),
                    requests: vec![("GET".into(), "/a".into(), 443)],
                    count: 2,
                },
                Opened {
                    host: "upload.example".into(),
                    requests: vec![("PUT".into(), "/f".into(), 8080)],
                    count: 1,
                },
            ]
        );
        assert_eq!(o[1].methods(), ["PUT"]);
        let s = summarize(&evs, &Mutes::default());
        let docs = s.iter().find(|h| h.host == "docs.example").unwrap();
        assert_eq!((docs.allowed, docs.opened), (2, 2));
        let npm = s.iter().find(|h| h.host == "registry.npmjs.org").unwrap();
        assert_eq!((npm.allowed, npm.opened), (1, 0));
        assert_eq!(
            fmt_opened("web", &o),
            "2 hosts reached only because egress is open: docs.example, upload.example\n\
             `luoto egress keep -e web` keeps them.\n"
        );
        assert_eq!(fmt_opened("web", &[]), "");
    }

    #[test]
    fn a_mark_keeps_what_came_after_it_across_a_gate_restart() {
        let before = parse_lines(
            r#"{"seq":7,"run":"a","env":"e","kind":"http","host":"x.example"}
{"seq":8,"run":"a","env":"e","kind":"http","host":"x.example"}"#,
        );
        let now = parse_lines(
            r#"{"seq":7,"run":"a","env":"e","kind":"http","host":"x.example"}
{"seq":8,"run":"a","env":"e","kind":"http","host":"x.example"}
{"seq":9,"run":"a","env":"e","kind":"http","host":"y.example"}
{"seq":1,"run":"b","env":"e","kind":"http","host":"z.example"}"#,
        );
        let after = Mark::of(&before).after(now);
        let seen: Vec<(&str, u64)> = after.iter().map(|e| (e.run.as_str(), e.seq)).collect();
        assert_eq!(seen, [("a", 9), ("b", 1)]);
    }

    #[test]
    fn denials_count_per_host_with_what_was_refused() {
        let text = r#"{"seq":1,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"docs.rs","path":"/ok"}
{"seq":2,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"docs.rs","path":"/serde","message":"no rule allows docs.rs"}
{"seq":3,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"docs.rs","path":"/serde","message":"no rule allows docs.rs"}
{"seq":4,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"docs.rs","path":"/tokio","message":"no rule allows docs.rs"}
{"seq":5,"run":"r","env":"e","kind":"direct","verdict":"deny","host":"evil.example","port":22,"message":"no rule allows evil.example"}
{"seq":6,"run":"r","env":"e","kind":"dns","host":"looked.up"}
{"seq":7,"run":"r","env":"e","kind":"http","verdict":"deny","host":"selftest.luoto.invalid","path":"/"}"#;
        let d = denials(&parse_lines(text));
        assert_eq!(
            d,
            [
                Denied {
                    host: "docs.rs".into(),
                    count: 3,
                    targets: vec![("GET /serde".into(), 2), ("GET /tokio".into(), 1)],
                    message: Some("no rule allows docs.rs".into()),
                },
                Denied {
                    host: "evil.example".into(),
                    count: 1,
                    targets: vec![("port 22".into(), 1)],
                    message: Some("no rule allows evil.example".into()),
                },
            ]
        );
        assert_eq!(
            fmt_denials("web", &d),
            "the gate denied 4 attempts to reach 2 hosts during the run:\n\
             \x20 docs.rs          3  GET /serde (2), GET /tokio: no rule allows docs.rs\n\
             \x20 evil.example     1  port 22: no rule allows evil.example\n\
             `luoto egress -e web --denied` says how to allow each.\n"
        );
        assert_eq!(fmt_denials("web", &[]), "");
    }

    #[test]
    fn the_denial_summary_escapes_the_sandbox_and_folds_long_lists() {
        let d = Denied {
            host: "x\u{1b}[2J.example".into(),
            count: 5,
            targets: (1..=5).map(|i| (format!("GET /{i}"), 1)).collect(),
            message: Some("no\u{202e}pe".into()),
        };
        let line = fmt_denials("web", &[d]);
        assert!(line.contains("x\\u{1b}[2J.example"), "{line}");
        assert!(
            line.contains("GET /1, GET /2, GET /3, 2 more: no\\u{202e}pe"),
            "{line}"
        );
        assert!(!line.contains('\u{1b}') && !line.contains('\u{202e}'));
    }

    #[test]
    fn mutes_hide_denials_but_not_what_was_allowed() {
        let text = r#"{"seq":1,"run":"r","env":"e","kind":"dns","host":"t.example","ts":"2026-11-03T10:00:00Z"}
{"seq":2,"run":"r","env":"e","kind":"http","verdict":"deny","method":"POST","host":"t.example","path":"/v1/x","reason":"no_rule","ts":"2026-11-03T10:00:01Z"}
{"seq":3,"run":"r","env":"e","kind":"dns","host":"api.example","ts":"2026-11-03T10:00:02Z"}
{"seq":4,"run":"r","env":"e","kind":"http","verdict":"deny","method":"POST","host":"api.example","path":"/telemetry/1","reason":"no_rule","ts":"2026-11-03T10:00:03Z"}
{"seq":5,"run":"r","env":"e","kind":"http","verdict":"allow","method":"GET","host":"api.example","path":"/telemetry/2","ts":"2026-11-03T10:00:04Z"}
{"seq":6,"run":"r","env":"e","kind":"dns","host":"stats.example","ts":"2026-11-03T10:00:05Z"}
{"seq":7,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"stats.example","path":"/Telemetry/3","reason":"no_rule","ts":"2026-11-03T10:00:06Z"}
{"seq":8,"run":"r","env":"e","kind":"http","verdict":"deny","method":"GET","host":"evil.example","path":"/telemetry/4","reason":"no_rule","ts":"2026-11-03T10:00:07Z"}
"#;
        let mute = |host: &str, paths: &[&str]| Mute {
            host: host.into(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            note: None,
        };
        let mutes = Mutes::new(&[
            mute("T.Example", &[]),
            mute("*.example", &["/telemetry/**"]),
            mute("bad host", &[]),
        ]);
        let all = parse_lines(text);
        let marked = summarize(&all, &mutes);
        let api = marked.iter().find(|h| h.host == "api.example").unwrap();
        assert_eq!((api.denied, api.muted), (1, 1));

        let mut evs = all.clone();
        assert_eq!(mutes.hide(&mut evs), 4);
        let seqs: Vec<u64> = evs.iter().map(|e| e.seq).collect();
        // A path mute leaves the host's lookups while it has other traffic.
        assert_eq!(seqs, [3, 5]);
        let s = summarize(&evs, &mutes);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].allowed, s[0].denied), (1, 0));
    }
}
