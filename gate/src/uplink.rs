//! The gate's vault socket on Apple, where a socket can only be published into a container:
//! luoto's watcher keeps a few links open to the gate's uplink socket, and joins each, once
//! the gate writes on it, to the vault's socket under the env's name. Every connection the
//! vault client makes here takes one idle link; when either side closes, both do.

use std::collections::VecDeque;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

/// How long a vault call waits for a link before it fails (the watcher opens new ones within
/// a tick of the gate starting, and one at once after each that is used).
const WAIT: Duration = Duration::from_secs(8);
/// Idle links kept; the watcher holds fewer.
const IDLE: usize = 16;

/// A listener on a new socket at `path`, made as root before the gate drops privileges and
/// given to `owner`.
pub fn listen(path: &Path, owner: Option<u32>) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    if let Some(uid) = owner {
        std::os::unix::fs::chown(path, Some(uid), Some(uid))
            .with_context(|| format!("chown {}", path.display()))?;
    }
    Ok(listener)
}

#[derive(Default)]
struct Idle {
    links: Mutex<VecDeque<UnixStream>>,
    ready: Notify,
}

impl Idle {
    fn links(&self) -> std::sync::MutexGuard<'_, VecDeque<UnixStream>> {
        self.links.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The oldest link still open.
    fn pop(&self) -> Option<UnixStream> {
        let mut links = self.links();
        while let Some(l) = links.pop_front() {
            if open(&l) {
                return Some(l);
            }
        }
        None
    }

    fn push(&self, link: UnixStream) {
        let mut links = self.links();
        links.retain(open);
        if links.len() < IDLE {
            links.push_back(link);
        }
        drop(links);
        self.ready.notify_one();
    }

    async fn take(&self) -> Option<UnixStream> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let ready = self.ready.notified();
            if let Some(l) = self.pop() {
                return Some(l);
            }
            tokio::time::timeout_at(deadline, ready).await.ok()?;
        }
    }
}

/// Idle, a link has nothing to read: one that reads as ended was closed by the host, and one
/// with bytes waiting was not opened by luoto's watcher.
fn open(link: &UnixStream) -> bool {
    matches!(link.try_read(&mut [0u8; 1]), Err(e) if e.kind() == ErrorKind::WouldBlock)
}

/// Serve the vault client's connections on `local` over the links that come on `uplinks`.
pub async fn serve(local: UnixListener, uplinks: UnixListener) {
    let idle = Arc::new(Idle::default());
    let pool = idle.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((link, _)) = uplinks.accept().await {
                pool.push(link);
            }
        }
    });
    loop {
        let Ok((mut conn, _)) = local.accept().await else {
            continue;
        };
        let idle = idle.clone();
        tokio::spawn(async move {
            // None: the client's connection closes unanswered, and the request fails closed.
            if let Some(mut link) = idle.take().await {
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut link).await;
            }
        });
    }
}
