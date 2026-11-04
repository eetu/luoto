//! Event emitter: numbered JSON lines on stdout plus an in-memory ring for the in-sandbox
//! API and `ctl recent`. One writer task owns stdout so lines never interleave.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use luoto_shared::events::{Event, Source, Verdict};
use tokio::sync::mpsc;

const RING: usize = 1000;

pub struct Emitter {
    env: String,
    pub run: String,
    seq: AtomicU64,
    tx: mpsc::UnboundedSender<String>,
    recent: Mutex<VecDeque<Event>>,
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
            recent: Mutex::new(VecDeque::with_capacity(RING)),
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
        let mut ring = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() == RING {
            ring.pop_front();
        }
        ring.push_back(ev);
    }

    pub fn last_seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    pub fn recent(&self, limit: usize) -> Vec<Event> {
        let ring = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter().rev().take(limit).cloned().collect()
    }

    pub fn recent_denials(&self, limit: usize) -> Vec<Event> {
        let ring = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter()
            .rev()
            .filter(|e| e.verdict == Some(Verdict::Deny))
            .take(limit)
            .cloned()
            .collect()
    }
}
