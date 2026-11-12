//! The host's part of an env without a network card (Apple): join the dev's published tun
//! socket to the gate's, byte for byte, and the gate's vault uplinks to the vault's socket. It
//! never reads what it carries; when either side drops, both are closed (the dev is cut off)
//! and joined again once both accept.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// How often a blocked read looks at the stop flag.
const POLL: Duration = Duration::from_millis(200);
const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(2);

/// A splice running on its own thread until stopped or dropped.
pub struct Link {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Link {
    /// Keep `a` and `b` (unix socket paths) joined.
    pub fn start(a: PathBuf, b: PathBuf) -> Link {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || run(&a, &b, &flag));
        Link {
            stop,
            thread: Some(thread),
        }
    }
}

/// Dropping a link closes both sides and waits for its thread to end.
impl Drop for Link {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Join `a` and `b` until `stop` is set: connect both, copy each way, and when either side
/// ends close both and connect again, waiting longer after each attempt that carried nothing.
/// A container's published socket accepts before anything listens inside and then ends at
/// once, so a join that ends empty counts as not ready.
pub fn run(a: &Path, b: &Path, stop: &AtomicBool) {
    let mut backoff = BACKOFF_MIN;
    while !stop.load(Ordering::Relaxed) {
        let carried = match connect(a, b) {
            Ok((x, y)) => splice(x, y, stop),
            Err(_) => false,
        };
        if carried {
            backoff = BACKOFF_MIN;
        }
        sleep(backoff, stop);
        if !carried {
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }
}

fn connect(a: &Path, b: &Path) -> io::Result<(UnixStream, UnixStream)> {
    let x = UnixStream::connect(a)?;
    let y = UnixStream::connect(b)?;
    for s in [&x, &y] {
        s.set_read_timeout(Some(POLL))?;
    }
    Ok((x, y))
}

/// Whether any byte went either way.
fn splice(x: UnixStream, y: UnixStream, stop: &AtomicBool) -> bool {
    let ended = AtomicBool::new(false);
    std::thread::scope(|s| {
        let there = s.spawn(|| copy(&x, &y, stop, &ended));
        let back = copy(&y, &x, stop, &ended);
        there.join().unwrap_or(false) || back
    })
}

/// Copy `from` to `to` until either ends or `stop` is set; then shut both, which ends the
/// copy the other way too. Whether any byte went.
fn copy(mut from: &UnixStream, mut to: &UnixStream, stop: &AtomicBool, ended: &AtomicBool) -> bool {
    let mut buf = vec![0u8; 256 * 1024];
    let mut carried = false;
    while !stop.load(Ordering::Relaxed) && !ended.load(Ordering::Relaxed) {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                carried = true;
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }
    ended.store(true, Ordering::Relaxed);
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
    carried
}

/// The links of one env's gate to the vault on Apple: [`UPLINKS`] at a time open to the gate's
/// uplink socket, each joined to the vault's socket once the gate writes on it, under the env's
/// name (the line the vault reads first). One carries one connection of the gate's vault
/// client, and is opened again once it closes.
pub struct Uplinks {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

/// Idle links per gate: its vault calls at once, beyond which a call waits for one to close.
pub const UPLINKS: usize = 4;

impl Uplinks {
    pub fn start(gate: PathBuf, vault: PathBuf, env: String) -> Uplinks {
        let stop = Arc::new(AtomicBool::new(false));
        let threads = (0..UPLINKS)
            .map(|_| {
                let (gate, vault, env, stop) =
                    (gate.clone(), vault.clone(), env.clone(), stop.clone());
                std::thread::spawn(move || uplink(&gate, &vault, &env, &stop))
            })
            .collect();
        Uplinks { stop, threads }
    }
}

impl Drop for Uplinks {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn uplink(gate: &Path, vault: &Path, env: &str, stop: &AtomicBool) {
    let mut backoff = BACKOFF_MIN;
    while !stop.load(Ordering::Relaxed) {
        let used = UnixStream::connect(gate).is_ok_and(|g| join_to_vault(g, vault, env, stop));
        if used {
            backoff = BACKOFF_MIN;
            continue;
        }
        sleep(backoff, stop);
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// Wait for the gate's first bytes on `g`, then join it to the vault, after the env's line.
/// Whether the gate wrote on it.
fn join_to_vault(g: UnixStream, vault: &Path, env: &str, stop: &AtomicBool) -> bool {
    if g.set_read_timeout(Some(POLL)).is_err() {
        return false;
    }
    let mut buf = vec![0u8; 16 * 1024];
    let n = loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        match (&g).read(&mut buf) {
            Ok(0) => return false,
            Ok(n) => break n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return false,
        }
    };
    // Unreachable, the vault fails this call: dropping `g` closes it unanswered.
    let Ok(v) = UnixStream::connect(vault) else {
        return true;
    };
    let mut first = format!("{env}\n").into_bytes();
    first.extend_from_slice(&buf[..n]);
    if v.set_read_timeout(Some(POLL)).is_err() || (&v).write_all(&first).is_err() {
        return true;
    }
    splice(g, v, stop);
    true
}

fn sleep(d: Duration, stop: &AtomicBool) {
    let mut left = d;
    while !left.is_zero() && !stop.load(Ordering::Relaxed) {
        let step = left.min(POLL);
        std::thread::sleep(step);
        left -= step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn read_n(s: &mut UnixStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0; n];
        s.read_exact(&mut buf).unwrap();
        buf
    }

    #[test]
    fn joins_both_ways_and_rejoins_after_a_drop() {
        let dir = tempfile::tempdir().unwrap();
        let (pa, pb) = (dir.path().join("a.sock"), dir.path().join("b.sock"));
        let (la, lb) = (
            UnixListener::bind(&pa).unwrap(),
            UnixListener::bind(&pb).unwrap(),
        );
        let link = Link::start(pa, pb);

        let (mut a, _) = la.accept().unwrap();
        let (mut b, _) = lb.accept().unwrap();
        a.write_all(b"from a").unwrap();
        assert_eq!(read_n(&mut b, 6), b"from a");
        let big: Vec<u8> = (0..1_000_000u32).map(|i| i as u8).collect();
        let mut w = b.try_clone().unwrap();
        let sent = big.clone();
        let writer = std::thread::spawn(move || w.write_all(&sent).unwrap());
        assert_eq!(read_n(&mut a, big.len()), big);
        writer.join().unwrap();

        // One side gone: the other is closed, and both are joined anew.
        drop(a);
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(b.read(&mut [0; 8]).unwrap(), 0);
        let (mut a, _) = la.accept().unwrap();
        let (mut b, _) = lb.accept().unwrap();
        b.write_all(b"again").unwrap();
        assert_eq!(read_n(&mut a, 5), b"again");

        a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        drop(link);
        assert_eq!(a.read(&mut [0; 8]).unwrap(), 0);
    }

    #[test]
    fn an_uplink_names_its_env_once_the_gate_writes_and_is_opened_again_after_use() {
        let dir = tempfile::tempdir().unwrap();
        let (pg, pv) = (dir.path().join("g.sock"), dir.path().join("v.sock"));
        let (lg, lv) = (
            UnixListener::bind(&pg).unwrap(),
            UnixListener::bind(&pv).unwrap(),
        );
        let links = Uplinks::start(pg, pv, "web".into());
        let mut idle: Vec<UnixStream> = (0..UPLINKS).map(|_| lg.accept().unwrap().0).collect();

        let mut g = idle.pop().unwrap();
        g.write_all(b"POST /").unwrap();
        let (mut v, _) = lv.accept().unwrap();
        assert_eq!(read_n(&mut v, 10), b"web\nPOST /");
        v.write_all(b"200").unwrap();
        assert_eq!(read_n(&mut g, 3), b"200");
        // The vault's side closes: so does the gate's, and a new link comes in its place.
        drop(v);
        g.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(g.read(&mut [0; 8]).unwrap(), 0);
        let _fresh = lg.accept().unwrap();
        drop(links);
    }

    /// For trying a real link by hand: joins `LUOTO_TUNLINK_A` to `LUOTO_TUNLINK_B` for an
    /// hour, or `LUOTO_TUNLINK_SECS`.
    #[test]
    #[ignore = "needs two live sockets"]
    fn join_from_env() {
        let path = |v| PathBuf::from(std::env::var(v).unwrap());
        let link = Link::start(path("LUOTO_TUNLINK_A"), path("LUOTO_TUNLINK_B"));
        let secs = std::env::var("LUOTO_TUNLINK_SECS").map_or(3600, |s| s.parse().unwrap());
        std::thread::sleep(Duration::from_secs(secs));
        drop(link);
    }
}
