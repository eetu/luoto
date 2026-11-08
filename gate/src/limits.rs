//! What a sandbox can't exhaust in the gate: its open connections (one cap shared by the
//! proxy, the transparent catch-all and DNS over TCP), its file descriptors, and how long a
//! connection may sit still. The event queue's bound is in `events.rs`, leaf certificate
//! lifetimes in `ca.rs`.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use luoto_shared::events::{Event, EventKind, Intake, Verdict};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::state::State;

/// Client connections open at once over every intake: far above the tens a package manager
/// or browser keeps open, low enough that all their buffers fit in the gate's memory.
pub const MAX_CONNS: usize = 1024;
/// Descriptors one client connection holds: its own and its upstream's.
const FDS_PER_CONN: usize = 2;
/// Descriptors kept back for the listeners, the ctl socket, DNS lookups and the vault.
const RESERVED_FDS: usize = 128;
/// From a request's last byte to its response head: non-streaming model API calls answer
/// within ten minutes.
pub const RESPONSE_HEAD: Duration = Duration::from_secs(10 * 60);
/// No byte either way while a response streams: SSE pings, git's keepalives and CDNs' read
/// timeouts (about 100 s) all come well inside it.
pub const IDLE: Duration = Duration::from_secs(5 * 60);
/// No byte either way through a tunnel or an upgraded connection: SSH and websocket sessions
/// sit quiet for long stretches.
pub const TUNNEL_IDLE: Duration = Duration::from_secs(60 * 60);
/// For the sandbox's TLS ClientHello, and again for the rest of the handshake: clients send
/// theirs at once.
pub const HANDSHAKE: Duration = Duration::from_secs(15);
/// A DNS-over-TCP connection without a query: clients send theirs at once, and RFC 7766 has
/// servers close idle ones within seconds.
pub const DNS_TCP_IDLE: Duration = Duration::from_secs(10);
/// Past the handler's own response-head limit, so its 504 and event come first.
pub const HEAD_GRACE: Duration = Duration::from_secs(5);
/// After a failed accept (out of descriptors or memory): long enough not to spin, short
/// enough to take the next connection soon after one closes.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// Refusals at the cap are reported at most this often, so a flood makes few events.
const REPORT_EVERY: Duration = Duration::from_secs(5);

/// The limits in force; integration tests shrink them (`LUOTO_TEST_LIMITS`).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub conns: usize,
    pub response_head: Duration,
    pub idle: Duration,
    pub tunnel_idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            conns: MAX_CONNS,
            response_head: RESPONSE_HEAD,
            idle: IDLE,
            tunnel_idle: TUNNEL_IDLE,
        }
    }
}

impl Limits {
    /// The defaults with `conns=2,idle_ms=300,…` applied.
    #[cfg(feature = "test-hooks")]
    pub fn parse(spec: &str) -> Self {
        let mut limits = Limits::default();
        for (key, value) in spec.split(',').filter_map(|kv| kv.split_once('=')) {
            let Ok(n) = value.trim().parse::<u64>() else {
                continue;
            };
            let ms = Duration::from_millis(n);
            match key.trim() {
                "conns" => limits.conns = usize::try_from(n).unwrap_or(usize::MAX),
                "response_head_ms" => limits.response_head = ms,
                "idle_ms" => limits.idle = ms,
                "tunnel_idle_ms" => limits.tunnel_idle = ms,
                _ => {}
            }
        }
        limits
    }

    /// The connection cap lowered to what `fds` open files allow.
    pub fn fit(mut self, fds: Option<usize>) -> Self {
        if let Some(fds) = fds {
            let room = fds.saturating_sub(RESERVED_FDS) / FDS_PER_CONN;
            self.conns = self.conns.min(room).max(1);
        }
        self
    }
}

/// Raise the soft limit on open files to the hard one and return it: runtimes start
/// containers with a soft limit as low as 1024.
pub fn raise_nofile() -> Option<usize> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit and setrlimit only read and write the rlimit owned by this frame.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return None;
    }
    if lim.rlim_cur < lim.rlim_max {
        let raised = libc::rlimit {
            rlim_cur: lim.rlim_max,
            rlim_max: lim.rlim_max,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            lim = raised;
        }
    }
    Some(usize::try_from(lim.rlim_cur).unwrap_or(usize::MAX))
}

/// The next connection on `listener`. Accepting fails when the gate is out of descriptors or
/// memory, and retrying at once would spin.
pub async fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(conn) => return conn,
            Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
        }
    }
}

const INTAKES: [Intake; 3] = [Intake::Proxy, Intake::Transparent, Intake::Dns];

fn index(intake: Intake) -> usize {
    match intake {
        Intake::Proxy => 0,
        Intake::Transparent => 1,
        Intake::Dns => 2,
    }
}

/// The cap on open client connections, and the refusals not yet reported.
pub struct Conns {
    slots: Arc<Semaphore>,
    max: usize,
    refused: [AtomicU64; 3],
    reporting: AtomicBool,
}

/// A place among the open connections. Every task serving the connection holds a clone; the
/// place frees when the last one ends.
#[derive(Clone)]
pub struct Slot {
    _permit: Arc<OwnedSemaphorePermit>,
}

impl Conns {
    pub fn new(max: usize) -> Self {
        Conns {
            slots: Arc::new(Semaphore::new(max)),
            max,
            refused: Default::default(),
            reporting: AtomicBool::new(false),
        }
    }

    pub fn max(&self) -> usize {
        self.max
    }

    /// A place for a new connection, or `None` at the cap (counted as refused).
    fn take(&self, intake: Intake) -> Option<Slot> {
        match self.slots.clone().try_acquire_owned() {
            Ok(permit) => Some(Slot {
                _permit: Arc::new(permit),
            }),
            Err(_) => {
                self.refused[index(intake)].fetch_add(1, Ordering::SeqCst);
                None
            }
        }
    }

    /// Whether the caller is to report refusals: only one reporter runs at a time.
    fn start_report(&self) -> bool {
        !self.reporting.swap(true, Ordering::SeqCst)
    }

    /// Refusals since the last call, by intake.
    fn take_refused(&self) -> Vec<(Intake, u64)> {
        INTAKES
            .into_iter()
            .map(|i| (i, self.refused[index(i)].swap(0, Ordering::SeqCst)))
            .filter(|(_, n)| *n > 0)
            .collect()
    }

    /// Stop reporting, unless refusals came in after the last `take_refused` while this
    /// reporter still ran: then whoever wins `reporting` reports them. True when this one ends.
    fn end_report(&self) -> bool {
        self.reporting.store(false, Ordering::SeqCst);
        let pending = self.refused.iter().any(|r| r.load(Ordering::SeqCst) > 0);
        !pending || !self.start_report()
    }
}

/// A place for a new connection on `intake`, or `None` at the cap, which is reported as an
/// event.
pub fn admit(state: &Arc<State>, intake: Intake) -> Option<Slot> {
    let slot = state.conns.take(intake);
    if slot.is_none() && state.conns.start_report() {
        tokio::spawn(report_refusals(state.clone()));
    }
    slot
}

/// The refusals so far at once, then the rest every `REPORT_EVERY` while they go on.
async fn report_refusals(state: Arc<State>) {
    loop {
        let refused = state.conns.take_refused();
        if refused.is_empty() {
            if state.conns.end_report() {
                return;
            }
            continue;
        }
        for (intake, n) in refused {
            let what = if n == 1 { "connection" } else { "connections" };
            state.events.emit(Event {
                kind: Some(EventKind::Lifecycle),
                intake: Some(intake),
                verdict: Some(Verdict::Deny),
                reason: Some("conn_limit".into()),
                message: Some(format!(
                    "refused {n} {what}: {} connections were open, the gate's limit",
                    state.conns.max()
                )),
                ..Default::default()
            });
        }
        tokio::time::sleep(REPORT_EVERY).await;
    }
}

/// When a connection last moved a byte, how many it moved, and whether it is handling a
/// request.
pub struct Activity {
    origin: Instant,
    /// Milliseconds from `origin` to the last byte.
    last: AtomicU64,
    read: AtomicU64,
    written: AtomicU64,
    busy: AtomicUsize,
    changed: Notify,
}

impl Activity {
    pub fn new() -> Arc<Self> {
        Arc::new(Activity {
            origin: Instant::now(),
            last: AtomicU64::new(0),
            read: AtomicU64::new(0),
            written: AtomicU64::new(0),
            busy: AtomicUsize::new(0),
            changed: Notify::new(),
        })
    }

    pub fn touch(&self) {
        let now = self.origin.elapsed().as_millis() as u64;
        self.last.store(now, Ordering::Relaxed);
    }

    fn still(&self) -> Duration {
        let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(last)
    }

    /// Bytes read from and written to the watched stream.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.read.load(Ordering::Relaxed),
            self.written.load(Ordering::Relaxed),
        )
    }

    /// The connection is handling a request until the guard drops.
    pub fn busy(self: &Arc<Self>) -> Busy {
        self.busy.fetch_add(1, Ordering::SeqCst);
        Busy(self.clone())
    }

    /// Resolves once nothing has moved for `idle`, or for `busy` while a request is handled.
    pub async fn stalled(&self, idle: Duration, busy: Duration) {
        loop {
            let changed = self.changed.notified();
            let limit = if self.busy.load(Ordering::SeqCst) > 0 {
                busy
            } else {
                idle
            };
            let still = self.still();
            if still >= limit {
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(limit - still) => {}
                () = changed => {}
            }
        }
    }
}

pub struct Busy(Arc<Activity>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.busy.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

/// A stream that records its progress in an [`Activity`].
pub struct Watched<IO> {
    io: IO,
    activity: Arc<Activity>,
}

impl<IO> Watched<IO> {
    pub fn new(io: IO, activity: Arc<Activity>) -> Self {
        Watched { io, activity }
    }

    fn moved(&self, counter: &AtomicU64, n: usize) {
        if n > 0 {
            counter.fetch_add(n as u64, Ordering::Relaxed);
            self.activity.touch();
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Watched<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        this.moved(&this.activity.read, buf.filled().len() - before);
        polled
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Watched<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = polled {
            this.moved(&this.activity.written, n);
        }
        polled
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = polled {
            this.moved(&this.activity.written, n);
        }
        polled
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// How a [`pipe`] ended.
#[derive(Debug, PartialEq, Eq)]
pub enum End {
    Closed,
    Idle,
    Stopped,
}

/// What went through a [`pipe`]: bytes from and to the client, and how it ended.
pub struct Piped {
    pub up: u64,
    pub down: u64,
    pub end: End,
}

/// Copy both ways between `client` and `upstream` until either closes, `idle` passes without
/// a byte either way, or `stop` resolves. Every byte passes the client's side, so that is
/// the side watched.
pub async fn pipe<C, U>(
    client: C,
    upstream: &mut U,
    idle: Duration,
    stop: impl Future<Output = ()>,
) -> Piped
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity::new();
    let mut client = Watched::new(client, activity.clone());
    let end = tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut client, upstream) => End::Closed,
        () = activity.stalled(idle, idle) => End::Idle,
        () = stop => End::Stopped,
    };
    let (up, down) = activity.bytes();
    Piped { up, down, end }
}

/// `d` for a message: "10 minutes", "1 hour", "300 ms".
pub fn spell(d: Duration) -> String {
    let s = d.as_secs();
    if s == 0 || d.subsec_millis() != 0 {
        return format!("{} ms", d.as_millis());
    }
    let (n, unit) = if s.is_multiple_of(3600) {
        (s / 3600, "hour")
    } else if s.is_multiple_of(60) {
        (s / 60, "minute")
    } else {
        (s, "second")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn the_cap_refuses_counts_and_frees() {
        let conns = Conns::new(2);
        let a = conns.take(Intake::Proxy).unwrap();
        let _b = conns.take(Intake::Transparent).unwrap();
        assert!(conns.take(Intake::Proxy).is_none());
        assert!(conns.start_report(), "the first refusal starts a report");
        assert!(conns.take(Intake::Dns).is_none());
        assert!(conns.take(Intake::Proxy).is_none());
        assert!(!conns.start_report(), "one reporter at a time");
        assert_eq!(
            conns.take_refused(),
            vec![(Intake::Proxy, 2), (Intake::Dns, 1)]
        );
        assert!(conns.take_refused().is_empty());
        // A clone keeps the place: an upgraded connection outlives the task that took it.
        let a2 = a.clone();
        drop(a);
        assert!(conns.take(Intake::Proxy).is_none());
        drop(a2);
        assert!(conns.take(Intake::Proxy).is_some());
    }

    #[test]
    fn a_refusal_after_the_last_report_is_not_lost() {
        let conns = Conns::new(0);
        assert!(conns.start_report());
        assert!(conns.take_refused().is_empty());
        // Counted while the reporter still ran, so its admit did not start another.
        assert!(conns.take(Intake::Proxy).is_none());
        assert!(!conns.start_report());
        assert!(!conns.end_report(), "the reporter carries on");
        assert_eq!(conns.take_refused(), vec![(Intake::Proxy, 1)]);
        assert!(conns.end_report());
        assert!(conns.start_report(), "the next refusal starts a new report");
    }

    #[test]
    fn the_cap_fits_the_descriptors() {
        let limits = Limits::default();
        assert_eq!(limits.fit(None).conns, MAX_CONNS);
        assert_eq!(limits.fit(Some(1 << 20)).conns, MAX_CONNS);
        assert_eq!(limits.fit(Some(1024)).conns, (1024 - RESERVED_FDS) / 2);
        assert_eq!(limits.fit(Some(10)).conns, 1);
    }

    #[test]
    fn durations_read_as_words() {
        assert_eq!(spell(RESPONSE_HEAD), "10 minutes");
        assert_eq!(spell(TUNNEL_IDLE), "1 hour");
        assert_eq!(spell(Duration::from_secs(90)), "90 seconds");
        assert_eq!(spell(Duration::from_millis(300)), "300 ms");
    }

    #[tokio::test]
    async fn a_busy_connection_waits_longer_and_reports_its_bytes() {
        let short = Duration::from_millis(50);
        let long = Duration::from_secs(30);
        let activity = Activity::new();
        let busy = activity.busy();
        let still = tokio::time::timeout(Duration::from_millis(300), activity.stalled(short, long));
        assert!(still.await.is_err(), "stalled while busy");
        // Done with the request: the short limit applies again, and has long passed.
        drop(busy);
        tokio::time::timeout(Duration::from_millis(100), activity.stalled(short, long))
            .await
            .expect("not stalled once idle");

        let (mut near, far) = tokio::io::duplex(64);
        let mut far = Watched::new(far, activity.clone());
        near.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        far.read_exact(&mut buf).await.unwrap();
        far.write_all(b"pong!").await.unwrap();
        assert_eq!(activity.bytes(), (4, 5));
        assert!(activity.still() < short);
    }

    #[tokio::test]
    async fn a_pipe_ends_when_quiet_or_stopped() {
        let idle = Duration::from_millis(100);
        let (client, mut sandbox) = tokio::io::duplex(64);
        let (mut upstream, mut server) = tokio::io::duplex(64);
        let started = Instant::now();
        let piping =
            tokio::spawn(
                async move { pipe(client, &mut upstream, idle, std::future::pending()).await },
            );
        sandbox.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        server.read_exact(&mut buf).await.unwrap();
        server.write_all(b"hi").await.unwrap();
        let piped = piping.await.unwrap();
        assert_eq!((piped.up, piped.down, piped.end), (5, 2, End::Idle));
        assert!(started.elapsed() >= idle);

        let (client, _sandbox) = tokio::io::duplex(64);
        let (mut upstream, _server) = tokio::io::duplex(64);
        let stop = tokio::time::sleep(Duration::from_millis(10));
        let piped = pipe(client, &mut upstream, Duration::from_secs(30), stop).await;
        assert_eq!(piped.end, End::Stopped);
    }
}
