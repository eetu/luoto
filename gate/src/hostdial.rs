//! Apple's `container`: the gate's VM leaves through macOS's NAT, which translates only out of
//! the Mac's primary interface, so a host the Mac routes over a VPN never answers. A private address a rule allows (`host::leaves_host`) is dialed by luoto's watcher on
//! the Mac instead, over links it keeps open to `dial.sock`: a dial takes one, names the vetted
//! address on one line (`dial 10.10.0.8:443`), and reads one answer line (`ok`, `refused …`,
//! `failed …`) before the link carries the connection. One dial per link.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::uplink::{Idle, pool};

/// An answer line's longest; the watcher writes far less.
const MAX_ANSWER: usize = 256;

pub struct HostDial {
    idle: Arc<Idle>,
}

#[derive(Debug, PartialEq)]
pub enum HostDialError {
    /// No link came in time: the watcher isn't running.
    NoLink,
    /// The watcher won't dial the address (this Mac's own, a runtime network): the gate dials
    /// it itself, as without a dialer.
    Refused(String),
    /// The watcher tried and couldn't connect.
    Failed(String),
}

impl HostDial {
    /// Dials over the links that come on `listener`.
    pub fn serve(listener: UnixListener) -> Self {
        Self {
            idle: pool(listener),
        }
    }

    /// A connection to `addr` from the Mac, within `timeout` of the link's answer.
    pub async fn dial(
        &self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<UnixStream, HostDialError> {
        let mut link = self.idle.take().await.ok_or(HostDialError::NoLink)?;
        let asked = async {
            link.write_all(format!("dial {addr}\n").as_bytes()).await?;
            answer(&mut link).await
        };
        let line = match tokio::time::timeout(timeout, asked).await {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => return Err(HostDialError::Failed(format!("link to this Mac: {e}"))),
            Err(_) => return Err(HostDialError::Failed("connect timed out".into())),
        };
        match line.split_once(' ').unwrap_or((line.as_str(), "")) {
            ("ok", "") => Ok(link),
            ("refused", why) => Err(HostDialError::Refused(why.into())),
            ("failed", why) => Err(HostDialError::Failed(why.into())),
            _ => Err(HostDialError::Failed(
                "unreadable answer from this Mac".into(),
            )),
        }
    }
}

/// One line, read a byte at a time so nothing after it is taken from the connection.
async fn answer(link: &mut UnixStream) -> std::io::Result<String> {
    let mut line = Vec::new();
    loop {
        let b = link.read_u8().await?;
        if b == b'\n' {
            break;
        }
        if line.len() == MAX_ANSWER {
            return Err(std::io::Error::other("answer too long"));
        }
        line.push(b);
    }
    String::from_utf8(line).map_err(|_| std::io::Error::other("answer not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dialer whose links come from a fake watcher that answers each dial with `answer`,
    /// then sends `hello`; the line it was asked comes back on the channel.
    async fn dialer(
        answer: &'static str,
        hello: &'static [u8],
    ) -> (
        HostDial,
        tokio::sync::mpsc::UnboundedReceiver<String>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dial.sock");
        let dial = HostDial::serve(UnixListener::bind(&path).unwrap());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut link = UnixStream::connect(&path).await.unwrap();
        tokio::spawn(async move {
            let mut asked = Vec::new();
            while let Ok(b) = link.read_u8().await {
                if b == b'\n' {
                    break;
                }
                asked.push(b);
            }
            let _ = tx.send(String::from_utf8(asked).unwrap());
            link.write_all(answer.as_bytes()).await.unwrap();
            link.write_all(hello).await.unwrap();
            let mut rest = Vec::new();
            let _ = link.read_to_end(&mut rest).await;
        });
        (dial, rx, dir)
    }

    const ADDR: &str = "10.10.0.8:443";

    #[tokio::test]
    async fn an_answered_dial_carries_the_connection_from_the_next_byte() {
        let (dial, mut asked, _dir) = dialer("ok\n", b"hello").await;
        let mut conn = dial
            .dial(ADDR.parse().unwrap(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(asked.recv().await.unwrap(), "dial 10.10.0.8:443");
        let mut got = [0u8; 5];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
    }

    #[tokio::test]
    async fn a_refusal_and_a_failure_say_why() {
        let (dial, _, _dir) = dialer("refused this Mac's own address\n", b"").await;
        let e = dial
            .dial(ADDR.parse().unwrap(), Duration::from_secs(5))
            .await;
        assert_eq!(
            e.unwrap_err(),
            HostDialError::Refused("this Mac's own address".into())
        );
        let (dial, _, _dir) = dialer("failed connect timed out\n", b"").await;
        let e = dial
            .dial(ADDR.parse().unwrap(), Duration::from_secs(5))
            .await;
        assert_eq!(
            e.unwrap_err(),
            HostDialError::Failed("connect timed out".into())
        );
        let (dial, _, _dir) = dialer("okay\n", b"").await;
        let e = dial
            .dial(ADDR.parse().unwrap(), Duration::from_secs(5))
            .await;
        assert!(matches!(e, Err(HostDialError::Failed(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_watcher_a_dial_fails_as_no_link() {
        let dir = tempfile::tempdir().unwrap();
        let dial = HostDial::serve(UnixListener::bind(dir.path().join("dial.sock")).unwrap());
        let e = dial
            .dial(ADDR.parse().unwrap(), Duration::from_secs(5))
            .await;
        assert_eq!(e.unwrap_err(), HostDialError::NoLink);
    }
}
