//! The background watcher: one per config dir, started by `up`, `down` and commands that work
//! in an env. Every 2 s it forwards the ports running envs listen on (see `ports`); every
//! minute it stops envs that have been idle for `idle_stop` (see `idle`), and luoto's VM once
//! no env has run for that long. It exits when nothing is left to watch, or when the luoto
//! binary changes, so a new version starts its own.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use chrono::Utc;

use crate::config::{self, EnvFile};
use crate::env::{self, Ctx};
use crate::{idle, machine, names, ports};

const TICK: Duration = Duration::from_secs(2);
const IDLE_EVERY: Duration = Duration::from_secs(60);

/// Start the watcher in the background; a second one exits at once (it holds a lock).
pub fn spawn(ctx: &Ctx) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = std::fs::create_dir_all(&ctx.paths.data);
    let Ok(log) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ctx.paths.data.join("watch.log"))
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

fn exe_stamp() -> Option<SystemTime> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.metadata().ok())
        .and_then(|m| m.modified().ok())
}

/// The watcher itself (`luoto watch`, started by `spawn`).
pub fn watch() -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let lock = File::create(ctx.paths.data.join("watch.lock"))?;
    if lock.try_lock().is_err() {
        return Ok(ExitCode::SUCCESS);
    }
    let stamp = exe_stamp();
    let mut forwards: HashMap<(String, u16), ports::Forward> = HashMap::new();
    let mut refused: HashSet<(String, u16)> = HashSet::new();
    let mut idle_since: HashMap<String, Instant> = HashMap::new();
    let mut idle_checked = Instant::now();
    let mut no_env_since: Option<Instant> = None;
    loop {
        std::thread::sleep(TICK);
        // A new luoto takes over once nothing is forwarded: leaving now would cut the
        // connections of a running dev server.
        if exe_stamp() != stamp && forwards.is_empty() {
            return Ok(ExitCode::SUCCESS);
        }
        let ctx = Ctx::load()?;
        if machine::is_luoto(ctx.rt.connection.as_deref()) && !machine::running(&ctx.rt.bin) {
            return Ok(ExitCode::SUCCESS);
        }
        let running: Vec<String> = config::list_envs(&ctx.paths)?
            .into_iter()
            .filter(|e| ctx.rt.container_state(&names::dev(e)).as_deref() == Some("running"))
            .collect();
        if running.is_empty() {
            forwards.clear();
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
                // A failed look (the runtime busy) keeps what is forwarded: dropping it would
                // refuse the next connections.
                wanted.extend(forwards.keys().filter(|(e, _)| e == name).cloned());
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
