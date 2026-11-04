//! Reading gate/vault events from the runtime's logs and summarising egress per host.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::process::Stdio;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use luoto_shared::events::{Event, EventKind, Intake, Verdict};
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

pub fn read(rt: &Runtime, container: &str, since: Option<&str>) -> Result<Vec<Event>> {
    let mut args = vec!["logs".to_string()];
    if let Some(s) = since {
        args.push("--since".into());
        args.push(s.into());
    }
    args.push(container.into());
    let out = rt
        .command()
        .args(&args)
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
    let mut args = vec!["logs".to_string(), "-f".into()];
    if let Some(s) = since {
        args.push("--since".into());
        args.push(s.into());
    }
    args.push(container.into());
    let mut child = rt
        .command()
        .args(&args)
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

#[derive(Debug, Clone, Serialize, Default)]
pub struct HostSummary {
    pub host: String,
    pub allowed: u64,
    pub denied: u64,
    pub dns_only: bool,
    pub methods: BTreeSet<String>,
    pub ports: BTreeSet<u16>,
    pub intakes: BTreeSet<String>,
    pub top_paths: Vec<(String, u64)>,
    pub last_reason: Option<String>,
    pub last_message: Option<String>,
    pub last_rule: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub wants_write: bool,
    pub tls_rejected: bool,
}

pub fn summarize(events: &[Event]) -> Vec<HostSummary> {
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
                s.last_rule = e.rule.clone().or(s.last_rule.take());
            }
            Some(Verdict::Deny) => {
                s.denied += 1;
                s.last_reason = e.reason.clone();
                s.last_message = e.message.clone();
                if e.reason.as_deref() == Some("method_not_allowed") {
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
        let s = summarize(&events);
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
    }
}
