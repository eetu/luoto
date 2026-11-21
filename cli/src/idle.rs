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
/// watcher's look at its listening ports): it is no one's work there. Read only of a process
/// started from outside the container: one inside that sets or inherits it is not luoto's.
pub const PROBE: &str = "LUOTO_PROBE=1";

/// Lists the dev container's processes besides init (PID 1), what init keeps running (its
/// `sleep`, luoto's `sandbox` for the env's network link and ssh-agent), and what luoto runs
/// there itself: this check and its probes ([`PROBE`]), with what they started. A process is
/// luoto's by the one it descends from that came from outside the container (an `exec`: its
/// parent is 0, which nothing inside can be given), never by its own environment, which code
/// in the env sets as it likes.
const PROCESSES: &str = r#"me=$$
all=
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  case $p in *[!0-9]*) continue ;; esac
  pp=
  while read -r k v; do [ "$k" = PPid: ] && pp=$v && break; done 2>/dev/null <"$d/status"
  case $pp in ''|*[!0-9]*) continue ;; esac
  c=
  read -r c 2>/dev/null <"$d/comm"
  eval "pp_$p=\$pp c_$p=\$c"
  all="$all $p"
done
for p in $all; do
  [ "$p" = 1 ] && continue
  eval "pp=\$pp_$p c=\$c_$p"
  [ -z "$c" ] && continue
  [ "$pp" = 1 ] && { [ "$c" = sleep ] || [ "$c" = sandbox ]; } && continue
  r=$p n=0
  while :; do
    eval "q=\${pp_$r-}"
    case $q in 0) break ;; ''|1) r= && break ;; esac
    r=$q n=$((n + 1))
    [ "$n" -gt 64 ] && r= && break
  done
  if [ -n "$r" ]; then
    [ "$r" = "$me" ] && continue
    eval "m=\${probe_$r-}"
    if [ -z "$m" ]; then
      m=n
      tr '\0' '\n' 2>/dev/null <"/proc/$r/environ" | grep -qxF LUOTO_PROBE=1 && m=y
      eval "probe_$r=\$m"
    fi
    [ "$m" = y ] && continue
  fi
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
    // Files written while a bare number meant minutes keep meaning that.
    let minutes;
    let s = if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        minutes = format!("{s}m");
        &minutes
    } else {
        s
    };
    crate::rules::parse_duration(s)
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

    /// What the check lists for a process table: `(pid, parent, name, environment)` each.
    #[cfg(unix)]
    fn listed(table: &[(u32, u32, &str, &[&str])]) -> Vec<String> {
        let proc = tempfile::tempdir().unwrap();
        for (pid, parent, name, env) in table {
            let d = proc.path().join(pid.to_string());
            std::fs::create_dir(&d).unwrap();
            let status = format!("Name:\t{name}\nUmask:\t0022\nPPid:\t{parent}\nUid:\t0\n");
            std::fs::write(d.join("status"), status).unwrap();
            std::fs::write(d.join("comm"), format!("{name}\n")).unwrap();
            let environ: String = env.iter().map(|v| format!("{v}\0")).collect();
            std::fs::write(d.join("environ"), environ).unwrap();
        }
        // What isn't a process there is no process.
        std::fs::create_dir(proc.path().join("self")).unwrap();
        let script = PROCESSES.replace("/proc", &proc.path().display().to_string());
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let mut names: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn luotos_own_processes_in_the_env_are_no_activity() {
        assert!(PROCESSES.contains(&format!("grep -qxF {PROBE} && m=y")));
        let probe: &[&str] = &["PATH=/bin", PROBE];
        let init = [
            (1, 0, "init.sh", &[][..]),
            (5, 1, "sandbox", &[]),
            (9, 1, "sleep", &[]),
        ];
        assert!(listed(&init).is_empty());
        // The watcher's look at the env's ports, with what it started.
        let mut watched = init.to_vec();
        watched.extend([(20, 0, "sh", probe), (21, 20, "sleep", probe)]);
        assert!(listed(&watched).is_empty());
        // A session and what runs in it; a server left behind by one.
        let mut used = watched.clone();
        used.extend([
            (30, 0, "zsh", &["PATH=/bin"][..]),
            (31, 30, "node", &["PATH=/bin"]),
            (40, 1, "vite", &[]),
        ]);
        assert_eq!(listed(&used), ["node", "vite", "zsh"]);
    }

    #[cfg(unix)]
    #[test]
    fn the_mark_hides_nothing_that_code_in_the_env_started() {
        let probe: &[&str] = &[PROBE];
        // Set in a profile or inherited: every process of a session carries it, and so does a
        // daemon one of them left behind. None came from outside with it.
        let forged = [
            (1, 0, "init.sh", &[][..]),
            (30, 0, "zsh", &["PATH=/bin"]),
            (31, 30, "agent", probe),
            (32, 31, "cargo", probe),
            (40, 1, "server", probe),
            // A parent that is no process there: not one from outside.
            (50, 49, "orphan", probe),
        ];
        assert_eq!(
            listed(&forged),
            ["agent", "cargo", "orphan", "server", "zsh"]
        );
        // `LUOTO_PROBE=10`, or the mark inside another value, is no mark.
        let near = [
            (1, 0, "init.sh", &[][..]),
            (20, 0, "sh", &["LUOTO_PROBE=10"]),
            (22, 0, "bash", &["X=LUOTO_PROBE=1"]),
        ];
        assert_eq!(listed(&near), ["bash", "sh"]);
    }

    #[test]
    fn the_mark_is_no_name_an_env_may_set() {
        let name = PROBE.split('=').next().unwrap();
        assert!(luoto_shared::variable_refused(name).is_some());
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
