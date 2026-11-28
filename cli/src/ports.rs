//! Reaching servers in an env from this machine. A forward listens on localhost here and pipes
//! each connection into the env through `sandbox relay`, which connects from inside, so a
//! server bound to the env's own localhost (Vite, Next, …) works without flags. The watcher
//! forwards every port an env starts listening on and records them in `<data>/forwards.json`
//! for `status` and the UI; `luoto forward` does one by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::env::UID;
use crate::paths::{Paths, write_private};
use crate::runtime::{Flavor, Runtime, exec};

/// Where Linux's ephemeral range starts: a server asking for any free port lands at or above
/// it (an editor's remote server, a login's loopback callback). Forwarded too, but quietly:
/// summed up, never warned about when taken here.
pub const QUIET_FROM: u16 = 32768;
/// Quiet forwards per env at once, so a sandbox listening on thousands of ports can't use up
/// this machine's.
pub const MAX_QUIET: usize = 64;

/// Whether the watcher forwards `port` on its own: any above the privileged ones but luoto's
/// UI ports, so no env serves a page on the UI's origin.
pub fn forwards_on_its_own(port: u16) -> bool {
    port >= 1024 && !crate::names::ui_ports().contains(&port)
}

/// One env's ports as the watcher handles them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watched {
    /// Forwarded to the same port here.
    pub forwarded: BTreeSet<u16>,
    /// Listened on in the env, but something on this machine has the port.
    pub taken: BTreeSet<u16>,
}

fn watched_path(paths: &Paths) -> PathBuf {
    paths.data.join("forwards.json")
}

/// Record what the watcher forwards, by env.
pub fn save_watched(paths: &Paths, by_env: &BTreeMap<String, Watched>) -> Result<()> {
    write_private(&watched_path(paths), &serde_json::to_vec(by_env)?)
}

/// What the running watcher forwards for `env`; nothing when no watcher runs, as the file
/// outlives one that was killed.
fn watched(paths: &Paths, env: &str) -> Watched {
    if !crate::watch::running(paths) {
        return Watched::default();
    }
    std::fs::read(watched_path(paths))
        .ok()
        .and_then(|b| serde_json::from_slice::<BTreeMap<String, Watched>>(&b).ok())
        .and_then(|mut m| m.remove(env))
        .unwrap_or_default()
}

/// Where an env's servers answer on this machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EnvPorts {
    /// Published by the gate (`ports` in the env's config).
    pub published: BTreeSet<u16>,
    /// Forwarded by the watcher.
    pub forwarded: BTreeSet<u16>,
    /// Forwarded by the watcher from [`QUIET_FROM`] up: servers on a port picked for them.
    pub temporary: BTreeSet<u16>,
    /// Listened on in the env and not forwarded: the port is taken on this machine.
    pub taken: BTreeSet<u16>,
}

impl EnvPorts {
    /// Every port that answers here, in order.
    pub fn open(&self) -> BTreeSet<u16> {
        self.published.union(&self.forwarded).copied().collect()
    }
}

/// `env`'s ports: the gate's published ones while it runs, and the watcher's forwards.
pub fn of_env(paths: &Paths, env: &str, config_ports: &[u16], gate_running: bool) -> EnvPorts {
    let w = watched(paths, env);
    let published: BTreeSet<u16> = if gate_running {
        config_ports.iter().copied().collect()
    } else {
        BTreeSet::new()
    };
    let (temporary, forwarded) = w.forwarded.into_iter().partition(|p| *p >= QUIET_FROM);
    EnvPorts {
        // The gate's own publishing is what the watcher finds taken there.
        taken: w
            .taken
            .difference(&published)
            .copied()
            .filter(|p| *p < QUIET_FROM)
            .collect(),
        forwarded,
        temporary,
        published,
    }
}

/// The address a browser opens for `port`.
pub fn url(port: u16) -> String {
    format!("http://localhost:{port}")
}

/// TCP ports something listens on in the env's dev container; None if that can't be asked.
/// The sandbox writes what the look prints and decides how long it takes: both are bounded.
pub fn listening(rt: &Runtime, dev: &str) -> Option<BTreeSet<u16>> {
    let out = rt
        .run_limited(
            exec(dev).argv(["cat", "/proc/net/tcp", "/proc/net/tcp6"]),
            LISTENING_WAIT,
            LISTENING_CAP,
        )
        .ok()?;
    Some(parse_listening(&out))
}

/// How long one look at an env's ports may take.
const LISTENING_WAIT: Duration = Duration::from_secs(20);

/// The ports a dev container listens on, from one `exec` that prints its tables every 2 s
/// (Apple logs each `exec` in the VM's console log, which nothing caps, so a look per tick
/// would grow it all day). Dropping it ends the `exec` here; inside, the loop ends once a newer
/// one started, since a process the runtime runs outlives the `exec` that started it there.
pub struct Listening {
    child: std::process::Child,
    open: Arc<std::sync::Mutex<Option<BTreeSet<u16>>>>,
    /// The `exec` printed past [`LISTENING_CAP`]: its output is no longer read, and this look
    /// is over.
    cut: Arc<AtomicBool>,
}

/// The line that ends one printing of the tables.
const LISTENING_END: &str = "--luoto-end--";
/// The most one printing may hold: the sandbox writes what that `exec` prints.
const LISTENING_CAP: usize = 1 << 20;
/// Where the newest loop keeps its pid (the tmpfs every dev container has, root's).
const LISTENING_PID: &str = "/run/luoto/listening.pid";

/// The loop printing the tables every 2 s while `pid_file` names it. One that can't write or
/// read the file runs on.
fn listening_script(pid_file: &str) -> String {
    format!(
        "f={pid_file}; echo $$ >$f 2>/dev/null; \
         while [ \"$(cat $f 2>/dev/null || echo $$)\" = $$ ]; do \
         cat /proc/net/tcp /proc/net/tcp6; echo {LISTENING_END}; sleep 2; done"
    )
}

impl Listening {
    pub fn start(rt: &Runtime, dev: &str) -> Option<Self> {
        let script = listening_script(LISTENING_PID);
        let mut child = rt
            .command()
            .args(exec(dev).env(crate::idle::PROBE).sh(&script))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let out = child.stdout.take()?;
        let open: Arc<std::sync::Mutex<Option<BTreeSet<u16>>>> = Arc::default();
        let cut = Arc::new(AtomicBool::new(false));
        let (shared, over) = (open.clone(), cut.clone());
        std::thread::spawn(move || {
            if read_tables(out, &shared).is_none() {
                over.store(true, Ordering::Relaxed);
            }
        });
        Some(Listening { child, open, cut })
    }

    /// The ports of the latest printing; None before the first, or once the `exec` ended.
    pub fn current(&mut self) -> Option<BTreeSet<u16>> {
        if !self.alive() {
            return None;
        }
        self.open.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether the `exec` still runs and is read.
    pub fn alive(&mut self) -> bool {
        !self.cut.load(Ordering::Relaxed) && matches!(self.child.try_wait(), Ok(None))
    }
}

/// Read the tables a [`Listening`] loop prints into `open`, a printing at a time, until its
/// output ends (`Some`) or a printing passes [`LISTENING_CAP`] (`None`), a line too: reading
/// stops there, and the pipe's end closing ends the `exec`.
fn read_tables(out: impl Read, open: &std::sync::Mutex<Option<BTreeSet<u16>>>) -> Option<()> {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(out);
    let mut table = String::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let room = (LISTENING_CAP - table.len()) as u64 + 1;
        match (&mut reader).take(room).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return Some(()),
            Ok(_) => {}
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches('\n');
        if text == LISTENING_END {
            *open.lock().unwrap_or_else(|e| e.into_inner()) = Some(parse_listening(&table));
            table.clear();
        } else if table.len() + line.len() <= LISTENING_CAP {
            table.push_str(text);
            table.push('\n');
        } else {
            return None;
        }
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `/proc/net/tcp{,6}` rows in LISTEN state (`0A`), by local port.
fn parse_listening(table: &str) -> BTreeSet<u16> {
    table
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (_, port) = f.get(1)?.rsplit_once(':')?;
            (f.get(3) == Some(&"0A"))
                .then(|| u16::from_str_radix(port, 16).ok())
                .flatten()
        })
        .collect()
}

/// A running forward; dropping it closes its listeners (open connections finish).
pub struct Forward {
    stop: Arc<AtomicBool>,
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Forward {
    /// Listen on `local` at 127.0.0.1 (and ::1, when free) and relay to `env_port` in `dev`.
    pub fn start(rt: &Runtime, dev: &str, local: u16, env_port: u16) -> Result<Self> {
        if host_listens(local) {
            bail!("port {local} is taken on this machine");
        }
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, local))
            .with_context(|| format!("port {local} is taken on this machine"))?;
        // `localhost` resolves to ::1 first in most browsers.
        let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, local)).ok();
        let stop = Arc::new(AtomicBool::new(false));
        for l in std::iter::once(v4).chain(v6) {
            l.set_nonblocking(true)?;
            let (stop, rt, dev) = (stop.clone(), rt.clone(), dev.to_string());
            std::thread::spawn(move || accept(&l, &stop, &rt, &dev, env_port));
        }
        Ok(Forward { stop })
    }
}

/// Something on this machine answers on `port` at localhost. A host service on the port keeps
/// it: binding 127.0.0.1 succeeds beside one listening on 0.0.0.0 (or only on ::1) and would
/// take its local clients.
fn host_listens(port: u16) -> bool {
    [
        IpAddr::from(Ipv4Addr::LOCALHOST),
        IpAddr::from(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .any(|ip| {
        TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(300)).is_ok()
    })
}

fn accept(l: &TcpListener, stop: &AtomicBool, rt: &Runtime, dev: &str, port: u16) {
    while !stop.load(Ordering::Relaxed) {
        match l.accept() {
            Ok((s, _)) => {
                let _ = s.set_nonblocking(false);
                let (rt, dev) = (rt.clone(), dev.to_string());
                std::thread::spawn(move || {
                    // A browser closing a connection ends a relay without a message.
                    if let Err(e) = relay(&rt, &dev, port, s)
                        && !e.to_string().is_empty()
                    {
                        eprintln!("port {port}: {}", crate::text::lines(&format!("{e:#}")));
                    }
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// Pipe one connection to `port` in the env through `sandbox relay`.
fn relay(rt: &Runtime, dev: &str, port: u16, stream: TcpStream) -> Result<()> {
    let mut child = rt
        .command()
        .args(
            exec(dev)
                .stdin()
                .user(UID)
                .argv(["sandbox", "relay", &port.to_string()]),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start the relay in the env")?;
    let mut to_env = child.stdin.take().context("relay stdin")?;
    let mut from_env = child.stdout.take().context("relay stdout")?;
    let mut inbound = stream.try_clone()?;
    let mut outbound = stream;
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut inbound, &mut to_env);
    });
    if rt.flavor == Flavor::Apple {
        if !held_copy(&mut from_env, &outbound) {
            // The client went or stopped reading: the relay ends with the connection.
            let _ = outbound.shutdown(std::net::Shutdown::Both);
            let _ = child.kill();
            let _ = up.join();
            let _ = child.wait();
            return Ok(());
        }
    } else {
        let _ = std::io::copy(&mut from_env, &mut outbound);
    }
    let _ = outbound.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    // What `sandbox relay` says on failure, which the sandbox writes: at most a little of it.
    let mut err = Vec::new();
    if let Some(pipe) = child.stderr.take() {
        let _ = pipe.take(RELAY_ERR_CAP).read_to_end(&mut err);
    }
    let _ = child.kill();
    let status = child.wait()?;
    if !status.success() && !err.is_empty() {
        let err = String::from_utf8_lossy(&err);
        bail!("{}", err.trim().trim_start_matches("sandbox: "));
    }
    Ok(())
}

/// The most of a relay's error read.
const RELAY_ERR_CAP: u64 = 4 << 10;

/// What a relay holds for a client that isn't reading.
const HELD: usize = 4 << 20;
const CHUNK: usize = 64 << 10;

/// Copy `from` (the env's side of a relay) to `to` through a thread holding up to [`HELD`],
/// so `from` is read whatever the client does: on Apple a VM stalls whole while its exec output
/// waits for this Mac to read it. True when `from` ended; false when `to` failed, or held
/// [`HELD`] it didn't read, which ends it.
fn held_copy(from: &mut impl Read, to: &TcpStream) -> bool {
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(HELD / CHUNK);
    let Ok(mut out) = to.try_clone() else {
        return false;
    };
    let writer = std::thread::spawn(move || {
        for chunk in rx {
            if out.write_all(&chunk).is_err() {
                break;
            }
        }
    });
    let mut buf = vec![0u8; CHUNK];
    let ended = loop {
        match from.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => {
                if tx.try_send(buf[..n].to_vec()).is_err() {
                    break false;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break true,
        }
    };
    drop(tx);
    if !ended {
        let _ = to.shutdown(std::net::Shutdown::Both);
    }
    let _ = writer.join();
    ended
}

/// `LOCAL:ENV`, or one port for both; never a local port of luoto's UI.
pub fn parse_spec(spec: &str) -> Result<(u16, u16)> {
    let parse = |p: &str| {
        p.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .with_context(|| format!("`{spec}`: ports are 1-65535, as PORT or LOCAL:ENV"))
    };
    let (local, env) = match spec.split_once(':') {
        Some((l, e)) => (parse(l)?, parse(e)?),
        None => parse(spec).map(|p| (p, p))?,
    };
    ui_port_refused(local)?;
    Ok((local, env))
}

/// A page an env serves on luoto's UI port would share the UI's origin, where it can act as
/// the UI: no env is published or forwarded there.
pub fn ui_port_refused(port: u16) -> Result<()> {
    if crate::names::ui_ports().contains(&port) {
        bail!(
            "port {port} is `luoto ui`'s, where a page the env serves could act as the UI; \
             forward it to another (`LOCAL:{port}`)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_look_at_the_ports_reads_its_tables_and_stops_at_a_line_without_end() {
        let open = std::sync::Mutex::new(None);
        let table = "  sl  local_address rem_address   st\n   0: 00000000:1435 00000000:0000 0A\n";
        let printed = format!("{table}{LISTENING_END}\n");
        assert_eq!(read_tables(printed.as_bytes(), &open), Some(()));
        assert_eq!(*open.lock().unwrap(), Some(BTreeSet::from([5173])));
        // The sandbox writes what the look prints: a line that never ends is read only so far.
        let endless = std::io::repeat(b'x');
        assert_eq!(read_tables(endless, &open), None);
    }

    #[test]
    fn a_relay_keeps_reading_the_env_and_ends_a_client_that_stopped_reading() {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let to = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut client, _) = l.accept().unwrap();
        let data: Vec<u8> = (0..=255u8).cycle().take(3 << 20).collect();
        let reader = std::thread::spawn(move || {
            let mut got = Vec::new();
            client.read_to_end(&mut got).unwrap();
            got
        });
        assert!(held_copy(&mut data.as_slice(), &to));
        to.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(reader.join().unwrap() == data);

        // A client that never reads, and an env that never stops writing.
        let to = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (_idle, _) = l.accept().unwrap();
        assert!(!held_copy(&mut std::io::repeat(7), &to));
    }

    #[test]
    fn a_host_service_on_any_address_keeps_its_port() {
        let l = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(host_listens(port), "0.0.0.0:{port} answers at 127.0.0.1");
    }

    use super::*;

    /// The loop runs in a Linux container: here, under a Unix host's `sh`.
    #[cfg(unix)]
    #[test]
    fn a_listening_loop_ends_once_a_newer_one_started() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("listening.pid");
        let script = listening_script(pid.to_str().unwrap());
        let start = || {
            Command::new("sh")
                .args(["-c", &script])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let wait_until = |what: &str, done: &mut dyn FnMut() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !done() {
                assert!(Instant::now() < deadline, "{what}");
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        let mut older = start();
        wait_until("the loop wrote its pid", &mut || pid.exists());
        let mut newer = start();
        wait_until("the older loop runs on", &mut || {
            older.try_wait().unwrap().is_some()
        });
        assert!(newer.try_wait().unwrap().is_none(), "the newer loop ended");
        let _ = newer.kill();
        let _ = newer.wait();
    }

    #[test]
    fn listening_ports_come_from_both_tables() {
        let table = "  sl  local_address rem_address   st\n\
             0: 00000000:1F90 00000000:0000 0A 0\n\
             1: 0100007F:A3D2 0100007F:1F90 01 0\n\
             0: 00000000000000000000000001000000:1435 00000000000000000000000000000000:0000 0A 0\n";
        assert_eq!(parse_listening(table), BTreeSet::from([8080, 5173]));
    }

    #[test]
    fn every_port_but_privileged_ones_and_the_uis_is_forwarded() {
        for port in [1024, 5173, 32767, 32768, 54815, 65535] {
            assert!(forwards_on_its_own(port), "{port}");
        }
        for port in [0, 22, 80, 1023, 47878, 47879] {
            assert!(!forwards_on_its_own(port), "{port}");
        }
    }

    #[test]
    fn forwards_are_listed_only_while_the_watcher_runs() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        let web = Watched {
            forwarded: BTreeSet::from([5173, 54815]),
            taken: BTreeSet::from([3000, 40001]),
        };
        save_watched(&paths, &BTreeMap::from([("web".to_string(), web)])).unwrap();
        let stopped = of_env(&paths, "web", &[8080], false);
        assert_eq!(stopped, EnvPorts::default());

        let lock = std::fs::File::create(paths.data.join("watch.lock")).unwrap();
        lock.try_lock().unwrap();
        let p = of_env(&paths, "web", &[8080], true);
        assert_eq!(p.open(), BTreeSet::from([5173, 8080]));
        // A port picked for a server is forwarded quietly, and not warned about when taken.
        assert_eq!(p.temporary, BTreeSet::from([54815]));
        assert_eq!(p.taken, BTreeSet::from([3000]));
        let published = of_env(&paths, "web", &[3000], true);
        assert_eq!(published.open(), BTreeSet::from([3000, 5173]));
        assert!(published.taken.is_empty());
        assert_eq!(of_env(&paths, "api", &[], true), EnvPorts::default());
    }

    #[test]
    fn specs_map_one_or_two_ports() {
        assert_eq!(parse_spec("5173").unwrap(), (5173, 5173));
        assert_eq!(parse_spec("8080:5173").unwrap(), (8080, 5173));
        assert!(parse_spec("0").is_err());
        // The UI's own port never serves an env's page; another port reaches the env's 47878.
        for ui in crate::names::ui_ports() {
            assert!(parse_spec(&ui.to_string()).is_err());
            assert!(parse_spec(&format!("{ui}:3000")).is_err());
            assert_eq!(parse_spec(&format!("9000:{ui}")).unwrap(), (9000, ui));
        }
    }
}
