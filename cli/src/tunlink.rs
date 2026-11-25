//! The host's part of an env without a network card (Apple): join the dev's published tun
//! socket to the gate's, a packet at a time, and the gate's vault uplinks to the vault's
//! socket, byte for byte. Of what it carries it reads only the tun link's frame lengths; when
//! either side drops, both are closed (the dev is cut off) and joined again once both accept.
//!
//! Each side is read whatever the other does. A VM serves its published sockets, `exec`
//! streams and its own agent from one vsock device, which stalls whole, a vCPU with it, while
//! one write waits for a reader on this Mac: a join that stopped reading one VM while it
//! waited on the other froze both, each waiting on the other through it. What a side isn't
//! taking is held up to [`HELD`]; past that the tun link drops whole packets, as a wire does,
//! and an uplink ends.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use luoto_shared::frame;

/// How often a blocked read or write looks at the stop flag.
const POLL: Duration = Duration::from_millis(200);
const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(2);
/// What one direction holds for a side that isn't reading.
pub const HELD: usize = 4 << 20;
/// How long a stream's last bytes may take to go once its sender closed.
const FLUSH: Duration = Duration::from_secs(10);

/// What a direction does with what it read once [`HELD`] is full.
#[derive(Clone, Copy, PartialEq)]
enum Full {
    /// Drop it, in whole packets: the tun link carries IP, whose senders send again.
    Drop,
    /// End the connection: a byte stream can't lose bytes.
    End,
}

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
            Ok((x, y)) => splice(x, y, Full::Drop, stop),
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
        polled(s)?;
    }
    Ok((x, y))
}

/// Reads and writes on `s` wake every [`POLL`] to look at the stop flags.
fn polled(s: &UnixStream) -> io::Result<()> {
    s.set_read_timeout(Some(POLL))?;
    s.set_write_timeout(Some(POLL))
}

fn waited(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Whether any byte went either way.
fn splice(x: UnixStream, y: UnixStream, full: Full, stop: &AtomicBool) -> bool {
    let ended = AtomicBool::new(false);
    std::thread::scope(|s| {
        let there = s.spawn(|| pump(&x, &y, full, stop, &ended));
        let back = pump(&y, &x, full, stop, &ended);
        there.join().unwrap_or(false) || back
    })
}

/// Carry `from` to `to` until either ends or `stop` is set; then shut both, which ends the
/// other way too. `from` is read on this thread and `to` written on another, so a `to` that
/// isn't reading never holds `from` up. Whether any byte went.
fn pump(
    from: &UnixStream,
    to: &UnixStream,
    full: Full,
    stop: &AtomicBool,
    ended: &AtomicBool,
) -> bool {
    let held = &Held::default();
    let (written, all_written) = std::sync::mpsc::channel::<()>();
    let carried = std::thread::scope(|s| {
        s.spawn(move || {
            while let Some(chunk) = held.pop(stop, ended) {
                if write_out(to, &chunk, stop, ended).is_err() {
                    ended.store(true, Ordering::Relaxed);
                    break;
                }
            }
            let _ = written.send(());
        });
        let (carried, closed) = fill(from, held, full, stop, ended);
        held.finish();
        // A stream's last bytes still go, for a while: a reply read just before its sender
        // closed. Packets left over are dropped with the link.
        if closed && full == Full::End {
            let _ = all_written.recv_timeout(FLUSH);
        }
        ended.store(true, Ordering::Relaxed);
        carried
    });
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
    carried
}

/// Read `from` into `held` until it ends, `stop` or `ended` is set, or (with [`Full::End`])
/// `held` is full. Whether any byte came, and whether `from` ended.
fn fill(
    mut from: &UnixStream,
    held: &Held,
    full: Full,
    stop: &AtomicBool,
    ended: &AtomicBool,
) -> (bool, bool) {
    let mut buf = vec![0u8; 256 * 1024];
    let mut packets = (full == Full::Drop).then(|| frame::Decoder::new(frame::MAX_FRAME));
    let mut carried = false;
    while !stop.load(Ordering::Relaxed) && !ended.load(Ordering::Relaxed) {
        let n = match from.read(&mut buf) {
            Ok(0) => return (carried, true),
            Ok(n) => n,
            Err(e) if waited(&e) => continue,
            Err(_) => break,
        };
        carried = true;
        let chunk = match &mut packets {
            None => buf[..n].to_vec(),
            Some(d) => {
                d.push(&buf[..n]);
                // A stream out of step: end it, as the tun's own ends do.
                let Ok(whole) = whole_packets(d) else { break };
                whole
            }
        };
        if !chunk.is_empty() && !held.push(chunk) && full == Full::End {
            break;
        }
    }
    (carried, false)
}

/// The whole packets `d` holds, framed as they came.
fn whole_packets(d: &mut frame::Decoder) -> Result<Vec<u8>, frame::FrameError> {
    let mut out = Vec::new();
    while let Some(p) = d.next_frame()? {
        frame::encode(p, &mut out)?;
    }
    Ok(out)
}

/// Write all of `data` to `to`, giving up once `stop` or `ended` is set.
fn write_out(
    mut to: &UnixStream,
    mut data: &[u8],
    stop: &AtomicBool,
    ended: &AtomicBool,
) -> io::Result<()> {
    while !data.is_empty() {
        if stop.load(Ordering::Relaxed) || ended.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        match to.write(data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(e) if waited(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// What one direction read and hasn't written yet, up to [`HELD`] bytes.
#[derive(Default)]
struct Held {
    chunks: Mutex<Chunks>,
    ready: Condvar,
}

#[derive(Default)]
struct Chunks {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    finished: bool,
}

impl Held {
    fn lock(&self) -> MutexGuard<'_, Chunks> {
        self.chunks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hold `chunk`, unless that would pass [`HELD`]: then it is dropped, and false.
    fn push(&self, chunk: Vec<u8>) -> bool {
        let mut c = self.lock();
        if c.bytes + chunk.len() > HELD {
            return false;
        }
        c.bytes += chunk.len();
        c.queue.push_back(chunk);
        self.ready.notify_one();
        true
    }

    /// No more chunks come: [`pop`](Self::pop) ends once what is held is taken.
    fn finish(&self) {
        self.lock().finished = true;
        self.ready.notify_one();
    }

    /// The next chunk to write; None once finished and empty, or when `stop` or `ended` is set.
    fn pop(&self, stop: &AtomicBool, ended: &AtomicBool) -> Option<Vec<u8>> {
        let mut c = self.lock();
        loop {
            if stop.load(Ordering::Relaxed) || ended.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(chunk) = c.queue.pop_front() {
                c.bytes -= chunk.len();
                return Some(chunk);
            }
            if c.finished {
                return None;
            }
            c = self
                .ready
                .wait_timeout(c, POLL)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
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
    if polled(&g).is_err() {
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
            Err(e) if waited(&e) => {}
            Err(_) => return false,
        }
    };
    // Unreachable, the vault fails this call: dropping `g` closes it unanswered.
    let Ok(v) = UnixStream::connect(vault) else {
        return true;
    };
    let mut first = format!("{env}\n").into_bytes();
    first.extend_from_slice(&buf[..n]);
    if polled(&v).is_err() || write_out(&v, &first, stop, &AtomicBool::new(false)).is_err() {
        return true;
    }
    splice(g, v, Full::End, stop);
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

    fn framed(packets: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in packets {
            frame::encode(p, &mut out).unwrap();
        }
        out
    }

    fn joined(dir: &Path) -> (Link, UnixListener, UnixListener) {
        let (pa, pb) = (dir.join("a.sock"), dir.join("b.sock"));
        let (la, lb) = (
            UnixListener::bind(&pa).unwrap(),
            UnixListener::bind(&pb).unwrap(),
        );
        (Link::start(pa, pb), la, lb)
    }

    #[test]
    fn joins_both_ways_and_rejoins_after_a_drop() {
        let dir = tempfile::tempdir().unwrap();
        let (link, la, lb) = joined(dir.path());

        let (mut a, _) = la.accept().unwrap();
        let (mut b, _) = lb.accept().unwrap();
        let hello = framed(&[b"from a"]);
        a.write_all(&hello).unwrap();
        assert_eq!(read_n(&mut b, hello.len()), hello);
        let packets: Vec<Vec<u8>> = (0..700u32).map(|i| vec![i as u8; 1400]).collect();
        let big = framed(&packets.iter().map(Vec::as_slice).collect::<Vec<_>>());
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
        let again = framed(&[b"again"]);
        b.write_all(&again).unwrap();
        assert_eq!(read_n(&mut a, again.len()), again);

        a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        drop(link);
        assert_eq!(a.read(&mut [0; 8]).unwrap(), 0);
    }

    /// Both ends write far more than anything holds before they read, as two VMs' vsock
    /// devices do under load: a join that stopped reading one end while it waited on the other
    /// left both stuck writing.
    #[test]
    fn an_end_that_isnt_reading_never_stops_the_other_being_read() {
        let dir = tempfile::tempdir().unwrap();
        let (link, la, lb) = joined(dir.path());
        let ends = [la.accept().unwrap().0, lb.accept().unwrap().0];
        let packet = [7u8; 1400];
        let bulk = framed(&vec![&packet[..]; 1000]);
        let rounds = (3 * HELD) / bulk.len() + 1;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (done, finished) = std::sync::mpsc::channel();
        for mut end in ends {
            let (barrier, done, bulk) = (barrier.clone(), done.clone(), bulk.clone());
            std::thread::spawn(move || {
                for _ in 0..rounds {
                    end.write_all(&bulk).unwrap();
                }
                // Take what came through, then send one last packet each way.
                barrier.wait();
                end.set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut d = frame::Decoder::new(frame::MAX_FRAME);
                let mut buf = vec![0u8; 1 << 16];
                let mut whole = 0;
                let mut take = |end: &mut UnixStream, until_end: bool| loop {
                    match end.read(&mut buf) {
                        Ok(0) => panic!("the join closed"),
                        Ok(n) => d.push(&buf[..n]),
                        Err(e) if waited(&e) && !until_end => return,
                        Err(e) => panic!("{e}"),
                    }
                    while let Some(p) = d.next_frame().unwrap() {
                        if p == &b"end"[..] {
                            return;
                        }
                        assert_eq!(p, &packet[..], "only whole packets arrive");
                        whole += 1;
                    }
                };
                take(&mut end, false);
                barrier.wait();
                end.write_all(&framed(&[b"end"])).unwrap();
                end.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                take(&mut end, true);
                done.send(whole).unwrap();
            });
        }
        for _ in 0..2 {
            let Ok(whole) = finished.recv_timeout(Duration::from_secs(30)) else {
                // Its threads are stuck too: joining them would never end.
                std::mem::forget(link);
                panic!("both ends stuck writing");
            };
            assert!(
                whole > 0 && whole < rounds * 1000,
                "{whole} of {}",
                rounds * 1000
            );
        }
        drop(link);
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
        // The vault answers and closes at once: all of the answer arrives, then the gate's
        // side closes too, and a new link comes in its place.
        let answer: Vec<u8> = (0..1_000_000u32).map(|i| i as u8).collect();
        let sent = answer.clone();
        let vault = std::thread::spawn(move || v.write_all(&sent).unwrap());
        assert_eq!(read_n(&mut g, answer.len()), answer);
        vault.join().unwrap();
        g.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(g.read(&mut [0; 8]).unwrap(), 0);
        let _fresh = lg.accept().unwrap();
        drop(links);
    }

    /// A vault that stops reading ends the uplink: the gate is never left waiting to write.
    #[test]
    fn an_uplink_ends_rather_than_stop_reading_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let (pg, pv) = (dir.path().join("g.sock"), dir.path().join("v.sock"));
        let (lg, lv) = (
            UnixListener::bind(&pg).unwrap(),
            UnixListener::bind(&pv).unwrap(),
        );
        let links = Uplinks::start(pg, pv, "web".into());
        let mut g = lg.accept().unwrap().0;
        g.write_all(b"POST /").unwrap();
        let (_v, _) = lv.accept().unwrap();
        g.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
        let chunk = vec![0u8; 1 << 20];
        let e = (0..3 * HELD / chunk.len() + 2)
            .try_for_each(|_| g.write_all(&chunk))
            .unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ),
            "{e}"
        );
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
