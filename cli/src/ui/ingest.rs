//! Event history for the UI: follow every running gate's (and the vault's) event stream into
//! SQLite so egress history survives restarts and covers time the UI was closed, and
//! broadcast new events to connected browsers.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use luoto_shared::events::{Event, SELFTEST_DOMAIN};
use rusqlite::{Connection, params};
use tokio::sync::broadcast;

use crate::env::Ctx;
use crate::events::Mutes;
use crate::{config, events, names};

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    pub tx: broadcast::Sender<Event>,
}

/// History kept per env.
const RETAIN_DAYS: i64 = 7;

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS events (
               env TEXT NOT NULL, source TEXT NOT NULL, run TEXT NOT NULL, seq INTEGER NOT NULL,
               ts TEXT NOT NULL, host TEXT, json TEXT NOT NULL,
               PRIMARY KEY (env, source, run, seq));
             CREATE INDEX IF NOT EXISTS events_env_ts ON events(env, ts);",
        )?;
        let (tx, _) = broadcast::channel(1024);
        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
            tx,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert unless already stored; returns whether it was new.
    pub fn insert(&self, e: &Event) -> bool {
        let source = e
            .source
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_default();
        let ts = e.ts.unwrap_or_else(Utc::now).to_rfc3339();
        let Ok(json) = serde_json::to_string(e) else {
            return false;
        };
        self.lock()
            .execute(
                "INSERT OR IGNORE INTO events (env, source, run, seq, ts, host, json) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![e.env, source, e.run, e.seq as i64, ts, e.host, json],
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    pub fn last_ts(&self, env: &str, source: &str) -> Option<DateTime<Utc>> {
        self.lock()
            .query_row(
                "SELECT max(ts) FROM events WHERE env = ?1 AND source = ?2",
                params![env, source],
                |r| r.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|d| d.with_timezone(&Utc))
    }

    pub fn query(
        &self,
        env: &str,
        since: DateTime<Utc>,
        host: Option<&str>,
        limit: usize,
    ) -> Vec<Event> {
        let conn = self.lock();
        let mut out = Vec::new();
        let sql = if host.is_some() {
            "SELECT json FROM events WHERE env = ?1 AND ts >= ?2 AND host = ?3 ORDER BY ts DESC LIMIT ?4"
        } else {
            "SELECT json FROM events WHERE env = ?1 AND ts >= ?2 AND ?3 IS NULL ORDER BY ts DESC LIMIT ?4"
        };
        let Ok(mut stmt) = conn.prepare(sql) else {
            return out;
        };
        let rows = stmt.query_map(params![env, since.to_rfc3339(), host, limit as i64], |r| {
            r.get::<_, String>(0)
        });
        if let Ok(rows) = rows {
            for json in rows.flatten() {
                if let Ok(e) = serde_json::from_str::<Event>(&json) {
                    out.push(e);
                }
            }
        }
        out.reverse();
        out
    }

    /// Denied attempts in `env` since `since`, the self-test's probes and what `mutes` hides
    /// left out.
    pub fn denied_since(&self, env: &str, since: DateTime<Utc>, mutes: &Mutes) -> usize {
        let conn = self.lock();
        let Ok(mut stmt) = conn.prepare(
            "SELECT json FROM events WHERE env = ?1 AND ts >= ?2
               AND json_extract(json, '$.verdict') = 'deny'
               AND (host IS NULL OR (host <> ?3 AND substr(host, -length(?4)) <> ?4))",
        ) else {
            return 0;
        };
        let rows = stmt.query_map(
            params![
                env,
                since.to_rfc3339(),
                SELFTEST_DOMAIN,
                format!(".{SELFTEST_DOMAIN}")
            ],
            |r| r.get::<_, String>(0),
        );
        rows.map_or(0, |rows| {
            rows.flatten()
                .filter_map(|json| serde_json::from_str::<Event>(&json).ok())
                .filter(|e| !mutes.hides(e))
                .count()
        })
    }

    fn prune(&self) {
        let cutoff = (Utc::now() - chrono::TimeDelta::days(RETAIN_DAYS)).to_rfc3339();
        let _ = self
            .lock()
            .execute("DELETE FROM events WHERE ts < ?1", params![cutoff]);
    }
}

/// Keep one log follower per running gate (and the vault); restart them as containers come
/// and go.
pub fn spawn_supervisor(store: Store) {
    std::thread::spawn(move || {
        let active: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let mut ticks = 0u64;
        loop {
            if let Ok(ctx) = Ctx::load() {
                let states = ctx.rt.states().unwrap_or_default();
                let mut targets: Vec<(String, String, String)> = Vec::new();
                for env in config::list_envs(&ctx.paths).unwrap_or_default() {
                    targets.push((names::gate(&env), env, "gate".into()));
                }
                targets.push((names::vault(), String::new(), "vault".into()));
                for (container, env, source) in targets {
                    if !states.running(&container)
                        || !active
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(container.clone())
                    {
                        continue;
                    }
                    let store = store.clone();
                    let rt = ctx.rt.clone();
                    let active = active.clone();
                    std::thread::spawn(move || {
                        let since = store
                            .last_ts(&env, &source)
                            .map(|t| t.timestamp().to_string())
                            .unwrap_or_else(|| {
                                (Utc::now() - chrono::TimeDelta::days(1))
                                    .timestamp()
                                    .to_string()
                            });
                        let _ = events::follow(&rt, &container, Some(&since), |ev| {
                            if store.insert(&ev) {
                                let _ = store.tx.send(ev);
                            }
                            true
                        });
                        active
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&container);
                    });
                }
            }
            ticks += 1;
            if ticks.is_multiple_of(720) {
                store.prune();
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use luoto_shared::events::Verdict;

    use super::*;

    #[test]
    fn counts_recent_denials_without_the_selftest() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("events.db")).unwrap();
        let now = Utc::now();
        let ev = |seq, host: Option<&str>, verdict, minutes_ago| Event {
            seq,
            run: "r".into(),
            env: "e".into(),
            ts: Some(now - TimeDelta::minutes(minutes_ago)),
            host: host.map(str::to_string),
            verdict: Some(verdict),
            ..Default::default()
        };
        for e in [
            ev(1, Some("evil.example"), Verdict::Deny, 1),
            ev(2, None, Verdict::Deny, 1),
            ev(3, Some("notselftest.luoto.invalid"), Verdict::Deny, 1),
            ev(4, Some("ok.example"), Verdict::Allow, 1),
            ev(5, Some("probe.selftest.luoto.invalid"), Verdict::Deny, 1),
            ev(6, Some("selftest.luoto.invalid"), Verdict::Deny, 1),
            ev(7, Some("old.example"), Verdict::Deny, 60),
            ev(8, Some("telemetry.example"), Verdict::Deny, 1),
        ] {
            assert!(store.insert(&e));
        }
        let since = now - TimeDelta::minutes(15);
        let none = Mutes::default();
        assert_eq!(store.denied_since("e", since, &none), 4);
        assert_eq!(store.denied_since("other", since, &none), 0);
        let mutes = Mutes::new(&[luoto_shared::policy::Mute {
            host: "telemetry.example".into(),
            ..Default::default()
        }]);
        assert_eq!(store.denied_since("e", since, &mutes), 3);
    }
}
