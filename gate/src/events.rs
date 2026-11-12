//! Event emitter: numbered JSON lines on stdout (or the event file, `eventlog.rs`), and the
//! latest denials for the in-sandbox API. One writer thread owns the output so lines never
//! interleave; the queue to it is bounded, so a log reader that falls behind costs events,
//! never memory or a request's time.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use luoto_shared::events::{Event, EventKind, Intake, Source, Verdict};

use anyhow::Context;

use crate::config::Config;
use crate::eventlog::EventFile;
use crate::state::lock;

/// Denials kept for `/_sandbox/status`.
const DENIALS: usize = 20;
/// Lines waiting for stdout: a few MiB at most, and stdout takes thousands a second, so only
/// a stalled log reader fills it.
const QUEUE: usize = 4096;

/// What every event carries from its emitter.
struct Stamp {
    env: String,
    run: String,
    seq: AtomicU64,
}

impl Stamp {
    fn line(&self, ev: &mut Event) -> Option<String> {
        ev.seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        ev.run = self.run.clone();
        ev.ts = Some(Utc::now());
        ev.env = self.env.clone();
        ev.source = Some(Source::Gate);
        let mut line = serde_json::to_string(ev).ok()?;
        line.push('\n');
        Some(line)
    }
}

pub struct Emitter {
    stamp: Arc<Stamp>,
    tx: SyncSender<String>,
    /// Lines dropped on a full queue and not yet reported.
    dropped: Arc<AtomicU64>,
    denials: Mutex<VecDeque<Event>>,
}

impl Emitter {
    /// Events to stdout, or to the event file the config names.
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let env = cfg.env.clone();
        Ok(match &cfg.events_file {
            Some(path) => {
                let file = EventFile::open(path, cfg.events_mb * 1024 * 1024)
                    .with_context(|| format!("open {}", path.display()))?;
                Self::with_writer(env, QUEUE, file)
            }
            None => Self::with_writer(env, QUEUE, std::io::stdout()),
        })
    }

    fn with_writer<W: Write + Send + 'static>(env: String, queue: usize, out: W) -> Self {
        let stamp = Arc::new(Stamp {
            env,
            run: hex::encode(rand::random::<[u8; 8]>()),
            seq: AtomicU64::new(0),
        });
        let dropped = Arc::new(AtomicU64::new(0));
        let (tx, rx) = sync_channel::<String>(queue);
        let (s, d) = (stamp.clone(), dropped.clone());
        std::thread::spawn(move || write_lines(rx, out, &s, &d));
        Emitter {
            stamp,
            tx,
            dropped,
            denials: Mutex::new(VecDeque::with_capacity(DENIALS)),
        }
    }

    /// Queue `ev` for stdout without waiting: on a full queue it is dropped and counted.
    pub fn emit(&self, mut ev: Event) {
        if let Some(line) = self.stamp.line(&mut ev)
            && let Err(TrySendError::Full(_)) = self.tx.try_send(line)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        if ev.verdict == Some(Verdict::Deny) {
            let mut denials = lock(&self.denials);
            if denials.len() == DENIALS {
                denials.pop_front();
            }
            denials.push_back(ev);
        }
    }

    /// A connection refused before any request on it: by its destination, its TLS or what it
    /// speaks.
    pub fn deny_conn(
        &self,
        kind: EventKind,
        intake: Intake,
        host: &str,
        port: u16,
        code: &str,
        message: String,
    ) {
        self.emit(Event {
            kind: Some(kind),
            intake: Some(intake),
            verdict: Some(Verdict::Deny),
            host: Some(host.to_string()),
            port: Some(port),
            reason: Some(code.to_string()),
            message: Some(message),
            ..Default::default()
        });
    }

    /// The latest denials, newest first.
    pub fn recent_denials(&self) -> Vec<Event> {
        lock(&self.denials).iter().rev().cloned().collect()
    }
}

/// Write each queued line, and after it how many were dropped since the last such note: the
/// queue has room again by then, and the note bypasses it.
fn write_lines<W: Write>(rx: Receiver<String>, mut out: W, stamp: &Stamp, dropped: &AtomicU64) {
    while let Ok(line) = rx.recv() {
        let _ = out.write_all(line.as_bytes()).and_then(|()| out.flush());
        let n = dropped.swap(0, Ordering::Relaxed);
        if n == 0 {
            continue;
        }
        let what = if n == 1 { "event" } else { "events" };
        let mut note = Event {
            kind: Some(EventKind::Lifecycle),
            message: Some(format!(
                "{n} {what} dropped: the event queue was full, as the log was not read fast enough"
            )),
            ..Default::default()
        };
        if let Some(line) = stamp.line(&mut note) {
            let _ = out.write_all(line.as_bytes()).and_then(|()| out.flush());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Condvar;
    use std::time::{Duration, Instant};

    /// A writer that holds every write until opened, then keeps what was written.
    #[derive(Clone, Default)]
    struct Valve {
        open: Arc<(Mutex<bool>, Condvar)>,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Valve {
        fn open(&self) {
            let (open, cv) = &*self.open;
            *open.lock().unwrap() = true;
            cv.notify_all();
        }

        fn events(&self) -> Vec<Event> {
            let out = self.out.lock().unwrap();
            String::from_utf8_lossy(&out)
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    impl Write for Valve {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let (open, cv) = &*self.open;
            let mut is_open = open.lock().unwrap();
            while !*is_open {
                is_open = cv.wait(is_open).unwrap();
            }
            self.out.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_stalled_log_drops_events_and_then_says_how_many() {
        let valve = Valve::default();
        let events = Emitter::with_writer("t".into(), 2, valve.clone());
        let started = Instant::now();
        for _ in 0..10 {
            events.emit(Event {
                kind: Some(EventKind::Dns),
                verdict: Some(Verdict::Deny),
                ..Default::default()
            });
        }
        assert!(started.elapsed() < Duration::from_secs(1), "emit waited");
        assert_eq!(events.recent_denials().len(), 10);
        valve.open();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let evs = valve.events();
            let written = evs
                .iter()
                .filter(|e| e.kind == Some(EventKind::Dns))
                .count();
            if let Some(note) = evs.iter().find(|e| e.kind == Some(EventKind::Lifecycle)) {
                let dropped = 10 - written;
                // At most the queue and the line in the writer's hands got through.
                assert!(dropped >= 7, "{dropped} dropped");
                let message = note.message.as_deref().unwrap();
                if message.starts_with(&format!("{dropped} events dropped")) {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "{evs:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
