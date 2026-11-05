//! Event emitter: numbered JSON lines on stdout, and the latest denials for the in-sandbox
//! API. One writer thread owns stdout so lines never interleave.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use luoto_shared::events::{Event, EventKind, Intake, Source, Verdict};
use tokio::sync::mpsc;

use crate::state::lock;

/// Denials kept for `/_sandbox/status`.
const DENIALS: usize = 20;

pub struct Emitter {
    env: String,
    run: String,
    seq: AtomicU64,
    tx: mpsc::UnboundedSender<String>,
    denials: Mutex<VecDeque<Event>>,
}

impl Emitter {
    pub fn new(env: String) -> Self {
        let run = hex::encode(rand::random::<[u8; 8]>());
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        std::thread::spawn(move || {
            let stdout = std::io::stdout();
            while let Some(line) = rx.blocking_recv() {
                let mut out = stdout.lock();
                let _ = out.write_all(line.as_bytes());
                let _ = out.write_all(b"\n");
                let _ = out.flush();
            }
        });
        Emitter {
            env,
            run,
            seq: AtomicU64::new(0),
            tx,
            denials: Mutex::new(VecDeque::with_capacity(DENIALS)),
        }
    }

    pub fn emit(&self, mut ev: Event) {
        ev.seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        ev.run = self.run.clone();
        ev.ts = Some(Utc::now());
        ev.env = self.env.clone();
        ev.source = Some(Source::Gate);
        if let Ok(line) = serde_json::to_string(&ev) {
            let _ = self.tx.send(line);
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
