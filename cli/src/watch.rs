//! The background watcher: one per config dir, started by `up`, `down` and commands that work
//! in an env. Every 2 s it forwards the ports running envs listen on (see `ports`) and posts
//! desktop notifications (see `notify`); every 30 s it reads again the credentials upstreams
//! refused, from sources that need no one; every minute it stops envs that have been idle for
//! `idle_stop` (see `idle`), and luoto's VM once no env has run for that long. It exits when
//! nothing is left to watch, or when the luoto binary changes, so a new version starts its own.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use chrono::{DateTime, TimeDelta, Utc};

use crate::config::{self, EnvFile};
use crate::env::{self, Ctx};
use crate::paths::Paths;
use crate::{events, idle, machine, names, notify, ports, secrets, sync};

const TICK: Duration = Duration::from_secs(2);
const IDLE_EVERY: Duration = Duration::from_secs(60);
const CREDS_EVERY: Duration = Duration::from_secs(30);
/// How soon a refused credential is read again: code in the sandbox can make an upstream
/// refuse one at will.
const REREAD_AFTER: Duration = Duration::from_secs(600);
/// How long `stop` waits: past a tick and the slowest round of work in it.
const STOP_WAIT: Duration = Duration::from_secs(20);

/// Start the watcher in the background; a second one exits at once (it holds a lock).
pub fn spawn(ctx: &Ctx) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = std::fs::create_dir_all(&ctx.paths.data);
    let Ok(log) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ctx.paths.watch_log())
    else {
        return;
    };
    let Ok(err) = log.try_clone() else {
        return;
    };
    let mut c = Command::new(exe);
    c.arg("watch").stdin(Stdio::null()).stdout(log).stderr(err);
    // Out of the terminal's process group, so closing the terminal doesn't end it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        c.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    if let Ok(mut child) = c.spawn() {
        // Reaped by a thread, for long-running callers (`luoto ui`).
        std::thread::spawn(move || child.wait());
    }
}

fn lock_path(paths: &Paths) -> PathBuf {
    paths.data.join("watch.lock")
}

/// A watcher runs for this config dir: it holds its lock, so a shared one is refused.
pub fn running(paths: &Paths) -> bool {
    File::open(lock_path(paths))
        .is_ok_and(|f| matches!(f.try_lock_shared(), Err(TryLockError::WouldBlock)))
}

/// Take the watcher's lock. `running` holds it shared for an instant, so a watcher starting
/// then tries again before leaving it to the one that runs.
fn take_lock(path: &Path) -> Result<Option<File>> {
    let lock = File::create(path)?;
    for _ in 0..3 {
        if lock.try_lock().is_ok() {
            return Ok(Some(lock));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(None)
}

/// Stop the watcher of this config dir, if one runs, and wait until it has: a watcher leaves
/// once its lock file is gone. Whether one ran.
pub fn stop(paths: &Paths) -> Result<bool> {
    let path = lock_path(paths);
    let Ok(lock) = File::open(&path) else {
        return Ok(false);
    };
    if lock.try_lock_shared().is_ok() {
        return Ok(false);
    }
    std::fs::remove_file(&path)?;
    let deadline = Instant::now() + STOP_WAIT;
    while Instant::now() < deadline {
        // Ours once the watcher has exited: the lock goes with the process.
        if lock.try_lock_shared().is_ok() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    anyhow::bail!(
        "the background watcher did not stop within {} s",
        STOP_WAIT.as_secs()
    )
}

fn exe_stamp() -> Option<SystemTime> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.metadata().ok())
        .and_then(|m| m.modified().ok())
}

/// The watcher itself (`luoto watch`, started by `spawn`).
pub fn watch() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let lock_file = lock_path(&ctx.paths);
    let Some(_lock) = take_lock(&lock_file)? else {
        return Ok(ExitCode::SUCCESS);
    };
    let stamp = exe_stamp();
    let mut forwards: HashMap<(String, u16), ports::Forward> = HashMap::new();
    let mut refused: HashSet<(String, u16)> = HashSet::new();
    let mut recorded: Option<BTreeMap<String, ports::Watched>> = None;
    let notices = notify::Notices::default();
    let mut idle_since: HashMap<String, Instant> = HashMap::new();
    let mut idle_checked = Instant::now();
    let mut no_env_since: Option<Instant> = None;
    let mut creds_checked = Instant::now();
    let mut creds_since: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut reread: HashMap<String, Instant> = HashMap::new();
    loop {
        std::thread::sleep(TICK);
        // `stop` (luoto uninstall) removed it, and waits for this process to leave.
        if !lock_file.exists() {
            return Ok(ExitCode::SUCCESS);
        }
        // A new luoto takes over once nothing is forwarded: leaving now would cut the
        // connections of a running dev server.
        if exe_stamp() != stamp && forwards.is_empty() {
            return Ok(ExitCode::SUCCESS);
        }
        let ctx = Ctx::load()?;
        let states = ctx.rt.states().unwrap_or_default();
        if states.vm_stopped {
            return Ok(ExitCode::SUCCESS);
        }
        let running: Vec<String> = config::list_envs(&ctx.paths)?
            .into_iter()
            .filter(|e| states.running(&names::dev(e)))
            .collect();
        if running.is_empty() {
            forwards.clear();
            refused.clear();
            record(&ctx.paths, &forwards, &refused, &mut recorded);
            // Without a VM of luoto's own there is nothing left to stop.
            if !machine::is_luoto(ctx.rt.connection.as_deref()) {
                return Ok(ExitCode::SUCCESS);
            }
            let since = *no_env_since.get_or_insert_with(Instant::now);
            let limit = idle::limit(&ctx.global, &Default::default());
            if limit.is_some_and(|l| since.elapsed() >= l) {
                if env::stop_vm_if_unused(&ctx).unwrap_or(false) {
                    println!(
                        "{} stopped luoto's VM: no env ran for {limit:?}",
                        Utc::now()
                    );
                }
                return Ok(ExitCode::SUCCESS);
            }
            continue;
        }
        no_env_since = None;

        let notifying = ctx.global.notifications.unwrap_or(true);
        if notifying {
            for name in running.iter().filter(|e| states.running(&names::gate(e))) {
                notices.follow(&ctx.rt, name, env::mutes(&ctx, name).unwrap_or_default());
            }
        }
        notices.flush(notifying);

        // Forwards follow what each env listens on.
        let mut wanted: HashSet<(String, u16)> = HashSet::new();
        for name in &running {
            let auto = EnvFile::load(&ctx.paths, name)
                .ok()
                .and_then(|f| f.cfg.auto_forward)
                .or(ctx.global.auto_forward)
                .unwrap_or(true);
            if !auto {
                continue;
            }
            let dev = names::dev(name);
            let Some(open) = ports::listening(&ctx.rt, &dev) else {
                // A failed look (the runtime busy) keeps what is forwarded, and what is taken:
                // dropping a forward would refuse the next connections.
                let kept = forwards.keys().chain(refused.iter());
                wanted.extend(kept.filter(|(e, _)| e == name).cloned());
                continue;
            };
            for port in open.into_iter().filter(|p| ports::AUTO.contains(p)) {
                let key = (name.clone(), port);
                wanted.insert(key.clone());
                if forwards.contains_key(&key) || refused.contains(&key) {
                    continue;
                }
                match ports::Forward::start(&ctx.rt, &dev, port, port) {
                    Ok(f) => {
                        println!("{} localhost:{port} → `{name}`", Utc::now());
                        forwards.insert(key, f);
                    }
                    Err(e) => {
                        println!("{} not forwarding `{name}`:{port}: {e:#}", Utc::now());
                        refused.insert(key);
                    }
                }
            }
        }
        forwards.retain(|k, _| wanted.contains(k));
        refused.retain(|k| wanted.contains(k));
        record(&ctx.paths, &forwards, &refused, &mut recorded);

        if creds_checked.elapsed() >= CREDS_EVERY {
            creds_checked = Instant::now();
            reread_refused(&ctx, &running, &mut creds_since, &mut reread);
        }

        if idle_checked.elapsed() < IDLE_EVERY {
            continue;
        }
        idle_checked = Instant::now();
        for name in &running {
            let limit = EnvFile::load(&ctx.paths, name)
                .ok()
                .and_then(|f| idle::limit(&ctx.global, &f.cfg));
            let quiet = idle::activity(&ctx, name).is_some_and(|a| a.is_empty());
            let (Some(limit), true) = (limit, quiet) else {
                idle_since.remove(name);
                continue;
            };
            let since = *idle_since.entry(name.clone()).or_insert_with(Instant::now);
            if since.elapsed() < limit {
                continue;
            }
            idle_since.remove(name);
            match env::down(&ctx, name) {
                Ok(()) => println!("{} stopped `{name}`: idle for {limit:?}", Utc::now()),
                Err(e) => println!("{} could not stop `{name}`: {e:#}", Utc::now()),
            }
        }
    }
}

/// Write what is forwarded for `status` and the UI, when it changed.
fn record(
    paths: &Paths,
    forwards: &HashMap<(String, u16), ports::Forward>,
    refused: &HashSet<(String, u16)>,
    recorded: &mut Option<BTreeMap<String, ports::Watched>>,
) {
    let mut now: BTreeMap<String, ports::Watched> = BTreeMap::new();
    for (env, port) in forwards.keys() {
        now.entry(env.clone()).or_default().forwarded.insert(*port);
    }
    for (env, port) in refused {
        now.entry(env.clone()).or_default().taken.insert(*port);
    }
    if recorded.as_ref() == Some(&now) {
        return;
    }
    match ports::save_watched(paths, &now) {
        Ok(()) => *recorded = Some(now),
        Err(e) => println!("{} forwards not recorded: {e:#}", Utc::now()),
    }
}

/// Credentials an upstream refused (401) since the last look: read again from the secret
/// store when that needs no one there (`secrets::unattended`), else named in the log for
/// `luoto vault reload`. Each reference at most once per [`REREAD_AFTER`].
fn reread_refused(
    ctx: &Ctx,
    running: &[String],
    since: &mut HashMap<String, DateTime<Utc>>,
    tried: &mut HashMap<String, Instant>,
) {
    let mut due = BTreeSet::new();
    for name in running {
        let now = Utc::now();
        // A minute's overlap for the VM's clock; a 401 seen twice meets the limit.
        let from = *since.get(name).unwrap_or(&now) - TimeDelta::minutes(1);
        let Ok(evs) = events::gate_events(&ctx.rt, name, Some(&from.to_rfc3339())) else {
            continue;
        };
        since.insert(name.clone(), now);
        let refused: BTreeSet<&str> = evs
            .iter()
            .filter(|e| e.status == Some(401))
            .filter_map(|e| e.binding.as_deref())
            .flat_map(|b| b.split(','))
            .collect();
        if refused.is_empty() {
            continue;
        }
        let Ok(plan) = env::plan(ctx, name) else {
            continue;
        };
        for b in refused {
            let Some(spec) = plan.compiled.bindings.get(b) else {
                continue;
            };
            let r = spec.secret_ref();
            if tried.get(r).is_some_and(|t| t.elapsed() < REREAD_AFTER) {
                continue;
            }
            tried.insert(r.to_string(), Instant::now());
            if secrets::unattended(&ctx.global, r) {
                due.insert(r.to_string());
            } else {
                println!(
                    "{} `{name}`: an upstream refused credential `{b}` ({r}); if it changed, \
                     `luoto vault reload` reads it again",
                    Utc::now()
                );
            }
        }
    }
    if due.is_empty() {
        return;
    }
    let refs: Vec<&str> = due.iter().map(String::as_str).collect();
    match sync::reload(ctx, &due) {
        Ok(r) => {
            println!(
                "{} read refused secret(s) again ({}): {} changed",
                Utc::now(),
                refs.join(", "),
                r.changed
            );
            for f in r.failed {
                println!("{}   not read: {f}", Utc::now());
            }
        }
        Err(e) => println!("{} refused secrets not read again: {e:#}", Utc::now()),
    }
}
