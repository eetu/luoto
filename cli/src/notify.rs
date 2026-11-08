//! Desktop notifications from the watcher, so an access request doesn't wait unseen: one for
//! new requests, and one for the first denial at each host. The watcher follows each running
//! gate's events; the text shown came from the sandbox, so it is cleaned and capped, and
//! reaches the OS's notifier as an argument, never inside a script.

use std::collections::{HashMap, HashSet, VecDeque};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeDelta, Utc};
use luoto_shared::events::{Event, EventKind, Verdict, is_selftest};

use crate::events::Mutes;
use crate::runtime::Runtime;
use crate::{events, names, text};

/// Denied hosts remembered per env, the oldest forgotten first.
const MAX_HOSTS: usize = 512;
/// New hosts are gathered between notifications this far apart: code in the sandbox can be
/// denied at will.
const HOSTS_EVERY: Duration = Duration::from_secs(30);
/// Requests or hosts named in one notification; the rest are counted.
const NAMED: usize = 3;
/// Longest text from the sandbox shown, in characters.
const MAX_TEXT: usize = 100;

/// A notification.
#[derive(Debug, PartialEq, Eq)]
pub struct Note {
    pub title: String,
    pub body: String,
}

/// Items for one notification: the first few by name, the rest counted.
#[derive(Debug, Default)]
struct Batch {
    named: Vec<String>,
    more: usize,
}

impl Batch {
    fn push(&mut self, item: String) {
        if self.named.len() < NAMED {
            self.named.push(item);
        } else {
            self.more += 1;
        }
    }

    fn len(&self) -> usize {
        self.named.len() + self.more
    }

    fn is_empty(&self) -> bool {
        self.named.is_empty()
    }

    fn list(&self, sep: &str) -> String {
        let mut s = self.named.join(sep);
        if self.more > 0 {
            s.push_str(&format!(" and {} more", self.more));
        }
        s
    }
}

/// The last event taken in, so a follow that starts again skips what it has seen.
#[derive(Debug)]
struct Mark {
    run: String,
    seq: u64,
    ts: Option<DateTime<Utc>>,
}

/// One env's news.
#[derive(Debug, Default)]
struct EnvNews {
    /// Its history is read: what came before is known, not news.
    seeded: bool,
    last: Option<Mark>,
    denied: HashSet<String>,
    denied_order: VecDeque<String>,
    requests: Batch,
    hosts: Batch,
    hosts_told: Option<Instant>,
}

impl EnvNews {
    fn is_new(&self, ev: &Event) -> bool {
        match &self.last {
            None => true,
            Some(m) if m.run == ev.run => ev.seq > m.seq,
            Some(m) => match (ev.ts, m.ts) {
                (Some(t), Some(last)) => t > last,
                _ => true,
            },
        }
    }

    /// Take in one event; `announce` is off for history.
    fn take(&mut self, ev: &Event, announce: bool) {
        if !self.is_new(ev) {
            return;
        }
        self.last = Some(Mark {
            run: ev.run.clone(),
            seq: ev.seq,
            ts: ev.ts,
        });
        if ev.kind == Some(EventKind::Request) {
            if announce {
                self.requests.push(describe_request(ev));
            }
        } else if ev.verdict == Some(Verdict::Deny)
            && let Some(host) = ev.host.as_deref().map(str::to_ascii_lowercase)
            && !host.is_empty()
            && !is_selftest(&host)
            && self.remember(&host)
            && announce
        {
            self.hosts.push(clean(&host));
        }
    }

    /// Note a denied host; whether it is new.
    fn remember(&mut self, host: &str) -> bool {
        if self.denied.contains(host) {
            return false;
        }
        if self.denied_order.len() >= MAX_HOSTS
            && let Some(old) = self.denied_order.pop_front()
        {
            self.denied.remove(&old);
        }
        self.denied.insert(host.to_string());
        self.denied_order.push_back(host.to_string());
        true
    }

    /// What is due now: new requests at once, new hosts at most every [`HOSTS_EVERY`].
    fn due(&mut self, env: &str, now: Instant) -> Vec<Note> {
        let mut out = Vec::new();
        if !self.requests.is_empty() {
            out.push(requests_note(env, &std::mem::take(&mut self.requests)));
        }
        if !self.hosts.is_empty()
            && self
                .hosts_told
                .is_none_or(|t| now.duration_since(t) >= HOSTS_EVERY)
        {
            self.hosts_told = Some(now);
            out.push(hosts_note(env, &std::mem::take(&mut self.hosts)));
        }
        out
    }
}

/// Text from the sandbox fit for a notification: control and format characters (escape
/// sequences, bidi overrides) become spaces, runs of space one, and it ends at [`MAX_TEXT`]
/// characters.
fn clean(s: &str) -> String {
    let spaced: String = s
        .chars()
        .map(|c| {
            if c.is_control() || text::is_format(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let words = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if words.chars().count() <= MAX_TEXT {
        return words;
    }
    let mut cut: String = words.chars().take(MAX_TEXT - 1).collect();
    cut.push('…');
    cut
}

/// `read access to docs.rs: <reason>`, `a tunnel to db.example.com:5432: <reason>`; a request
/// without a host asks for software or a preset.
fn describe_request(ev: &Event) -> String {
    let what = match (ev.host.as_deref().filter(|h| !h.is_empty()), ev.port) {
        (Some(host), Some(port)) => format!("a tunnel to {}:{port}", clean(host)),
        (Some(host), None) => {
            let access = if ev.reason.as_deref() == Some("write") {
                "write"
            } else {
                "read"
            };
            format!("{access} access to {}", clean(host))
        }
        (None, _) => "software or a preset".to_string(),
    };
    match clean(ev.message.as_deref().unwrap_or_default()) {
        reason if reason.is_empty() => what,
        reason => format!("{what}: {reason}"),
    }
}

fn requests_note(env: &str, reqs: &Batch) -> Note {
    let title = match reqs.len() {
        1 => format!("{}: {env} asks for access", names::instance()),
        n => format!("{}: {env} has {n} new access requests", names::instance()),
    };
    Note {
        title,
        body: reqs.list("\n"),
    }
}

fn hosts_note(env: &str, hosts: &Batch) -> Note {
    let body = match hosts.len() {
        1 => format!("a first request to {} was denied", hosts.list(", ")),
        _ => format!("first requests to {} were denied", hosts.list(", ")),
    };
    Note {
        title: format!("{}: blocked in {env}", names::instance()),
        body,
    }
}

#[derive(Default)]
struct Inner {
    envs: HashMap<String, EnvNews>,
    following: HashSet<String>,
}

/// What the watcher has to tell, filled by one follower thread per running gate.
#[derive(Clone, Default)]
pub struct Notices(Arc<Mutex<Inner>>);

impl Notices {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Follow `env`'s gate events in the background, unless that runs already.
    pub fn follow(&self, rt: &Runtime, env: &str, mutes: Mutes) {
        if !self.lock().following.insert(env.to_string()) {
            return;
        }
        let (me, rt, env) = (self.clone(), rt.clone(), env.to_string());
        std::thread::spawn(move || {
            me.read(&rt, &env, &mutes);
            me.lock().following.remove(&env);
        });
    }

    fn read(&self, rt: &Runtime, env: &str, mutes: &Mutes) {
        let seeded = self.lock().envs.get(env).is_some_and(|n| n.seeded);
        if !seeded {
            // A day back: requests filed then, and hosts denied then, are not news.
            let from = (Utc::now() - TimeDelta::days(1)).timestamp().to_string();
            let Ok(history) = events::gate_events(rt, env, Some(&from)) else {
                return;
            };
            let mut inner = self.lock();
            let news = inner.envs.entry(env.to_string()).or_default();
            for ev in &history {
                news.take(ev, false);
            }
            news.seeded = true;
        }
        // A minute's overlap for the VM's clock; what was seen is skipped.
        let since = self
            .lock()
            .envs
            .get(env)
            .and_then(|n| n.last.as_ref())
            .and_then(|m| m.ts)
            .unwrap_or_else(Utc::now)
            - TimeDelta::minutes(1);
        let since = since.timestamp().to_string();
        let _ = events::follow(rt, &names::gate(env), Some(&since), |ev| {
            if let Some(news) = self.lock().envs.get_mut(env) {
                news.take(&ev, !mutes.hides(&ev));
            }
            true
        });
    }

    /// Post what is due, or drop it when `show` is off.
    pub fn flush(&self, show: bool) {
        let now = Instant::now();
        let due: Vec<Note> = self
            .lock()
            .envs
            .iter_mut()
            .flat_map(|(env, news)| news.due(env, now))
            .collect();
        if show {
            // To the watcher's log, so `luoto logs watcher` says what was shown.
            for n in &due {
                match post(n) {
                    Ok(true) => println!("{} notified: {}", Utc::now(), n.title),
                    Ok(false) => {}
                    Err(e) => println!("{} not notified ({e}): {}", Utc::now(), n.title),
                }
            }
        }
    }
}

/// Show `n`; whether this OS has a notifier. A missing one (no notify-send) only goes to the
/// log: a notification is a convenience.
fn post(n: &Note) -> std::io::Result<bool> {
    let Some(mut cmd) = notifier(std::env::consts::OS, n) else {
        return Ok(false);
    };
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || child.wait());
    Ok(true)
}

/// The OS's notifier with the note as its arguments, never as script source, so no text can
/// run. Linux notification servers read the body as markup, so it is escaped.
/// Whether the watcher shows desktop notifications: on in `config.toml` and a notifier here.
pub fn desktop(on: Option<bool>) -> bool {
    on != Some(false)
        && match std::env::consts::OS {
            "macos" => true,
            "linux" => std::env::var_os("PATH").is_some_and(|path| {
                std::env::split_paths(&path).any(|d| d.join("notify-send").is_file())
            }),
            _ => false,
        }
}

fn notifier(os: &str, n: &Note) -> Option<Command> {
    match os {
        "macos" => {
            let mut c = Command::new("osascript");
            c.args([
                "-e",
                "on run argv",
                "-e",
                "display notification (item 2 of argv) with title (item 1 of argv)",
                "-e",
                "end run",
                &n.title,
                &n.body,
            ]);
            Some(c)
        }
        "linux" => {
            let body = n
                .body
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            let mut c = Command::new("notify-send");
            c.args(["--app-name", names::instance(), "--", &n.title, &body]);
            Some(c)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, kind: EventKind, verdict: Option<Verdict>, host: &str) -> Event {
        Event {
            seq,
            run: "r1".into(),
            ts: Some(Utc::now()),
            env: "web".into(),
            kind: Some(kind),
            verdict,
            host: Some(host.into()),
            ..Default::default()
        }
    }

    fn denied(seq: u64, host: &str) -> Event {
        ev(seq, EventKind::Http, Some(Verdict::Deny), host)
    }

    fn request(seq: u64, host: &str, reason: &str) -> Event {
        Event {
            message: Some(reason.into()),
            reason: Some("read".into()),
            ..ev(seq, EventKind::Request, None, host)
        }
    }

    #[test]
    fn history_is_not_news_and_a_host_is_new_once() {
        let mut n = EnvNews::default();
        n.take(&denied(1, "old.example"), false);
        n.take(&request(2, "docs.rs", "old"), false);
        n.take(&denied(3, "old.example"), true);
        n.take(&denied(4, "New.example"), true);
        n.take(&denied(5, "new.example"), true);
        n.take(
            &ev(6, EventKind::Http, Some(Verdict::Allow), "ok.example"),
            true,
        );
        n.take(&denied(7, "probe.selftest.luoto.invalid"), true);
        assert_eq!(n.hosts.named, ["new.example"]);
        assert!(n.requests.is_empty());
    }

    #[test]
    fn a_follow_that_starts_again_skips_what_it_saw() {
        let mut n = EnvNews::default();
        n.take(&request(5, "docs.rs", "docs"), true);
        n.take(&request(5, "docs.rs", "docs"), true);
        n.take(&request(4, "crates.io", "older"), true);
        assert_eq!(n.requests.named, ["read access to docs.rs: docs"]);
        // A restarted gate numbers its events anew.
        let later = Event {
            run: "r2".into(),
            ts: Some(Utc::now() + TimeDelta::seconds(1)),
            ..request(1, "crates.io", "")
        };
        n.take(&later, true);
        assert_eq!(n.requests.len(), 2);
    }

    #[test]
    fn a_port_request_reads_as_a_tunnel() {
        let tunnel = Event {
            port: Some(5432),
            reason: Some("tunnel".into()),
            ..request(1, "db.example.com", "migrations")
        };
        assert_eq!(
            describe_request(&tunnel),
            "a tunnel to db.example.com:5432: migrations"
        );
    }

    #[test]
    fn requests_go_out_at_once_and_new_hosts_at_most_every_half_minute() {
        let mut n = EnvNews::default();
        let t0 = Instant::now();
        n.take(&request(1, "", "ripgrep for search"), true);
        n.take(&denied(2, "a.example"), true);
        let first = n.due("web", t0);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].body, "software or a preset: ripgrep for search");
        assert_eq!(first[1].body, "a first request to a.example was denied");
        for (i, h) in ["b", "c", "d", "e", "f"].iter().enumerate() {
            n.take(&denied(3 + i as u64, &format!("{h}.example")), true);
        }
        assert!(n.due("web", t0 + Duration::from_secs(5)).is_empty());
        let held = n.due("web", t0 + HOSTS_EVERY);
        assert_eq!(
            held[0].body,
            "first requests to b.example, c.example, d.example and 2 more were denied"
        );
    }

    #[test]
    fn the_hosts_remembered_stay_few() {
        let mut n = EnvNews::default();
        for i in 0..MAX_HOSTS + 10 {
            n.remember(&format!("h{i}.example"));
        }
        assert_eq!(n.denied.len(), MAX_HOSTS);
        assert!(n.remember("h0.example"), "the oldest is forgotten first");
    }

    #[test]
    fn sandbox_text_is_cleaned_and_capped() {
        assert_eq!(clean("a\u{1b}[2K\nb\u{202e}c  d"), "a [2K b c d");
        let long = clean(&"x".repeat(500));
        assert_eq!(long.chars().count(), MAX_TEXT);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn the_text_reaches_the_notifier_as_arguments() {
        let n = Note {
            title: "luoto: web asks for access".into(),
            body: "read access to x\" & do shell script \"id: <b>".into(),
        };
        let args = |c: Command| -> Vec<String> {
            c.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let mac = args(notifier("macos", &n).unwrap());
        assert_eq!(mac.last().unwrap(), &n.body);
        assert!(mac.iter().filter(|a| a.contains("do shell script")).count() == 1);
        let linux = args(notifier("linux", &n).unwrap());
        assert_eq!(
            linux.last().unwrap(),
            "read access to x\" &amp; do shell script \"id: &lt;b&gt;"
        );
        assert_eq!(linux[linux.len() - 3], "--");
        assert!(notifier("windows", &n).is_none());
    }
}
