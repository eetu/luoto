//! When an env counts as idle: its dev container runs nothing but its own init (no shell, no
//! editor session, no agent, no dev server). The watcher stops it after `idle_stop` (default
//! 30 minutes) of that.

use std::time::Duration;

use crate::config::{EnvConfig, GlobalConfig};
use crate::env::Ctx;
use crate::names;

pub const DEFAULT: &str = "30m";

/// Daemons that outlive the session that started them and mean nothing on their own.
const LINGERING: &[&str] = &[
    "gpg-agent",
    "ssh-agent",
    "keyboxd",
    "dirmngr",
    "dbus-daemon",
];

/// What marks, in its environment, a process luoto itself keeps in the dev container (the
/// watcher's look at its listening ports): it is no one's work there.
pub const PROBE: &str = "LUOTO_PROBE=1";

/// Lists the dev container's processes besides init (PID 1), what init keeps running (its
/// `sleep`, luoto's `sandbox` for the env's network link and ssh-agent), luoto's own probes
/// ([`PROBE`]) and the check itself, whose children it skips.
const PROCESSES: &str = r#"me=$$
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  case $p in 1|$me) continue ;; esac
  pp=
  while read -r k v; do [ "$k" = PPid: ] && pp=$v && break; done 2>/dev/null <"$d/status"
  c=
  read -r c 2>/dev/null <"$d/comm"
  [ -z "$c" ] && continue
  [ "$pp" = "$me" ] && continue
  [ "$pp" = 1 ] && { [ "$c" = sleep ] || [ "$c" = sandbox ]; } && continue
  tr '\0' '\n' 2>/dev/null <"$d/environ" | grep -qxF LUOTO_PROBE=1 && continue
  echo "$c"
done"#;

/// How long `cfg`'s env may idle before it stops; None when idle stop is off.
pub fn limit(global: &GlobalConfig, cfg: &EnvConfig) -> Option<Duration> {
    let s = cfg
        .idle_stop
        .as_deref()
        .or(global.idle_stop.as_deref())
        .unwrap_or(DEFAULT);
    if matches!(s, "off" | "never" | "0") {
        return None;
    }
    crate::rules::parse_ttl(s)
        .ok()
        .and_then(|d| d.to_std().ok())
}

/// What runs in the env's dev container besides its init; None if that can't be asked.
pub fn activity(ctx: &Ctx, env: &str) -> Option<Vec<String>> {
    let out = ctx.rt.pipe_sh(&names::dev(env), "0", PROCESSES, b"").ok()?;
    Some(
        out.lines()
            .map(str::trim)
            .filter(|c| !c.is_empty() && !LINGERING.contains(c))
            .map(str::to_string)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luotos_own_processes_in_the_env_are_no_activity() {
        assert!(PROCESSES.contains(&format!("grep -qxF {PROBE} && continue")));
        assert!(PROCESSES.contains(r#"[ "$c" = sandbox ]"#));
    }

    #[test]
    fn idle_stop_defaults_to_30_minutes_and_an_env_overrides_it() {
        let global = GlobalConfig::default();
        let mut cfg = EnvConfig::default();
        assert_eq!(limit(&global, &cfg), Some(Duration::from_secs(1800)));
        cfg.idle_stop = Some("2h".into());
        assert_eq!(limit(&global, &cfg), Some(Duration::from_secs(7200)));
        cfg.idle_stop = Some("off".into());
        assert_eq!(limit(&global, &cfg), None);
    }
}
