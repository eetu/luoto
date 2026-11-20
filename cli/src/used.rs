//! When an env was last used, and what work it held as it stopped: two files in its state
//! folder, each written whole so the watcher and a command never read one to change it.
//! `used` is the time of its last `up`, of the watcher's last look that found something
//! running in it, or of its stop. `work.json` is what `luoto rm` would have named as it
//! stopped (`repos::unpushed`), kept until its next `up`: a stopped env can't be asked.

use std::path::PathBuf;

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::env::Ctx;
use crate::names;
use crate::paths::{Paths, write_private};
use crate::repos::Unpushed;
use crate::state::EnvState;

fn used_file(paths: &Paths, env: &str) -> PathBuf {
    paths.env_state(env).join("used")
}

fn work_file(paths: &Paths, env: &str) -> PathBuf {
    paths.env_state(env).join("work.json")
}

/// The env is in use now. Nothing for an env that has never started: its state folder is
/// its first `up`'s to make.
pub fn touch(paths: &Paths, env: &str) {
    if paths.env_state(env).is_dir() {
        let _ = write_private(&used_file(paths, env), Utc::now().to_rfc3339().as_bytes());
    }
}

/// The env starts: what it held at its last stop is no longer what it holds.
pub fn started(paths: &Paths, env: &str) {
    let _ = std::fs::remove_file(work_file(paths, env));
    touch(paths, env);
}

/// When an env was last used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Used {
    At(DateTime<Utc>),
    /// No record (an env last used by a luoto that kept none, or never started): when luoto
    /// last wrote a file of its own for it, which is no later than its last use.
    Unrecorded(Option<DateTime<Utc>>),
}

impl Used {
    /// The time its age is counted from.
    pub fn time(self) -> Option<DateTime<Utc>> {
        match self {
            Used::At(t) => Some(t),
            Used::Unrecorded(t) => t,
        }
    }

    /// For a table: `3d ago`, or `unknown` without a record.
    pub fn shown(self, now: DateTime<Utc>) -> String {
        match self {
            Used::At(t) => ago(now - t),
            Used::Unrecorded(_) => "unknown".into(),
        }
    }
}

pub fn of(paths: &Paths, env: &str) -> Used {
    let recorded = std::fs::read_to_string(used_file(paths, env))
        .ok()
        .and_then(|s| DateTime::parse_from_rfc3339(s.trim()).ok())
        .map(|t| t.with_timezone(&Utc));
    match recorded {
        Some(t) => Used::At(t),
        None => Used::Unrecorded(last_written(paths, env)),
    }
}

/// The newest of the env's config file and the files in its state folder.
fn last_written(paths: &Paths, env: &str) -> Option<DateTime<Utc>> {
    let state = std::fs::read_dir(paths.env_state(env))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path());
    std::iter::once(paths.env_config(env))
        .chain(state)
        .filter_map(|p| std::fs::metadata(p).ok()?.modified().ok())
        .max()
        .map(DateTime::<Utc>::from)
}

/// `5m ago`, `3h ago`, `45d ago`.
pub fn ago(d: TimeDelta) -> String {
    match (d.num_minutes(), d.num_hours(), d.num_days()) {
        (..1, ..) => "just now".into(),
        (m @ ..60, ..) => format!("{m}m ago"),
        (_, h @ ..48, _) => format!("{h}h ago"),
        (.., d) => format!("{d}d ago"),
    }
}

/// What an env held as it stopped.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Work {
    /// Its repos with work no remote has.
    #[serde(default)]
    pub unpushed: Vec<Unpushed>,
    /// Why they couldn't be asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The env is about to stop: while its dev container still runs, keep what its repos hold
/// that no remote has.
pub fn stopping(ctx: &Ctx, env: &str) {
    if !ctx.rt.is_running(&names::dev(env)) {
        return;
    }
    let repos = EnvState::load(&ctx.paths, env)
        .ok()
        .flatten()
        .map(|s| s.repos)
        .unwrap_or_default();
    let work = match crate::repos::unpushed(ctx, env, &repos) {
        Ok(unpushed) => Work {
            unpushed,
            error: None,
        },
        Err(e) => Work {
            unpushed: Vec::new(),
            error: Some(crate::text::lines(&format!("{e:#}"))),
        },
    };
    if let Ok(b) = serde_json::to_vec_pretty(&work) {
        let _ = write_private(&work_file(&ctx.paths, env), &b);
    }
}

/// What the stopped env held as it stopped; None when it stopped with no luoto there to ask
/// (a crash, a restart of this machine, a luoto that kept no record).
pub fn work(paths: &Paths, env: &str) -> Option<Work> {
    serde_json::from_slice(&std::fs::read(work_file(paths, env)).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(dir: &std::path::Path) -> Paths {
        let paths = Paths {
            config: dir.join("config"),
            data: dir.join("data"),
        };
        std::fs::create_dir_all(paths.envs_dir()).unwrap();
        paths
    }

    #[test]
    fn ages_read_in_the_unit_that_fits() {
        assert_eq!(ago(TimeDelta::seconds(20)), "just now");
        assert_eq!(ago(TimeDelta::minutes(59)), "59m ago");
        assert_eq!(ago(TimeDelta::hours(47)), "47h ago");
        assert_eq!(ago(TimeDelta::hours(48)), "2d ago");
        assert_eq!(ago(TimeDelta::days(400)), "400d ago");
        // A clock set back since.
        assert_eq!(ago(TimeDelta::minutes(-5)), "just now");
    }

    #[test]
    fn an_env_without_a_record_is_unknown_and_dated_by_its_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        std::fs::write(paths.env_config("web"), "").unwrap();
        // Never started: no state folder, and a use writes none.
        touch(&paths, "web");
        assert!(!paths.env_state("web").exists());
        let Used::Unrecorded(Some(t)) = of(&paths, "web") else {
            panic!("{:?}", of(&paths, "web"));
        };
        assert!(Utc::now() - t < TimeDelta::minutes(1));
        assert_eq!(of(&paths, "web").shown(Utc::now()), "unknown");
        assert_eq!(of(&paths, "gone"), Used::Unrecorded(None));
    }

    #[test]
    fn a_use_is_recorded_and_a_start_forgets_the_work_of_the_last_stop() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        std::fs::create_dir_all(paths.env_state("web")).unwrap();
        let old = "2020-01-01T00:00:00+00:00";
        std::fs::write(used_file(&paths, "web"), old).unwrap();
        assert_eq!(of(&paths, "web").time().unwrap().to_rfc3339(), old);
        let held = Work {
            unpushed: vec![Unpushed {
                path: "/workspace".into(),
                changed: 2,
                commits: 1,
                stashes: 0,
                elsewhere: 0,
                unread: false,
            }],
            error: None,
        };
        std::fs::write(work_file(&paths, "web"), serde_json::to_vec(&held).unwrap()).unwrap();
        assert_eq!(work(&paths, "web").unwrap().unpushed, held.unpushed);
        started(&paths, "web");
        assert!(work(&paths, "web").is_none());
        let Used::At(t) = of(&paths, "web") else {
            panic!("no record");
        };
        assert!(Utc::now() - t < TimeDelta::minutes(1));
    }
}
