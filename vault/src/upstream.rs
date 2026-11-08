//! The vault's own requests out: token mints at GitHub's API and at Microsoft Entra ID. Over
//! HTTPS only; `test-hooks` builds also reach the integration tests' plain-HTTP servers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

/// The longest a mint may take, from connecting to the answer's last byte. A token endpoint
/// answers in a second or two; the gate waits 20 s for the vault, so a mint ends first and its
/// error reaches the request.
const TIMEOUT: Duration = Duration::from_secs(15);
/// The most of an answer the vault reads: a token response is a few KiB.
const MAX_BODY: usize = 64 << 10;

/// POST `body` (of `content_type`) to `url` with `headers`; the status and body of the answer.
pub async fn post(
    tls: &Arc<rustls::ClientConfig>,
    url: &str,
    headers: &[(&str, &str)],
    content_type: &str,
    body: String,
) -> Result<(u16, String)> {
    post_within(TIMEOUT, tls, url, headers, content_type, body).await
}

async fn post_within(
    limit: Duration,
    tls: &Arc<rustls::ClientConfig>,
    url: &str,
    headers: &[(&str, &str)],
    content_type: &str,
    body: String,
) -> Result<(u16, String)> {
    let uri: http::Uri = url.parse().context("token endpoint url")?;
    let host = uri
        .host()
        .context("token endpoint url has no host")?
        .to_string();
    tokio::time::timeout(limit, send(tls, &uri, &host, headers, content_type, body))
        .await
        .map_err(|_| anyhow!("{host} gave no answer within {} s", limit.as_secs()))?
}

async fn send(
    tls: &Arc<rustls::ClientConfig>,
    uri: &http::Uri,
    host: &str,
    headers: &[(&str, &str)],
    content_type: &str,
    body: String,
) -> Result<(u16, String)> {
    let https = uri.scheme_str() != Some("http");
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    #[cfg(not(any(test, feature = "test-hooks")))]
    if !https {
        anyhow::bail!("tokens are minted over https only");
    }
    let tcp = TcpStream::connect((host, port)).await?;
    let mut req = http::Request::post(uri.path())
        .header(http::header::HOST, host)
        .header(http::header::USER_AGENT, "luoto-vault")
        .header(http::header::CONTENT_TYPE, content_type);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let req = req.body(Full::new(bytes::Bytes::from(body)))?;
    let resp = if https {
        let name = ServerName::try_from(host.to_string())?;
        let stream = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(name, tcp)
            .await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(conn);
        sender.send_request(req).await?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(conn);
        sender.send_request(req).await?
    };
    let status = resp.status().as_u16();
    let bytes = Limited::new(resp.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|e| anyhow!("reading {host}'s answer (at most {MAX_BODY} bytes): {e}"))?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A server that reads one request and answers `head` and then `body_len` bytes, or
    /// nothing at all.
    async fn server(answer: Option<(&'static str, usize)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            match answer {
                Some((head, len)) => {
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&vec![b'a'; len]).await;
                }
                None => tokio::time::sleep(Duration::from_secs(60)).await,
            }
        });
        format!("http://{addr}/token")
    }

    async fn post_to(url: &str, limit: Duration) -> Result<(u16, String)> {
        let tls = Arc::new(crate::state::client_tls());
        post_within(limit, &tls, url, &[], "text/plain", "x".into()).await
    }

    #[tokio::test]
    async fn an_answer_is_capped_in_size_and_time() {
        let ok = server(Some(("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", 2))).await;
        let (status, body) = post_to(&ok, TIMEOUT).await.unwrap();
        assert_eq!((status, body.as_str()), (200, "aa"));

        let len = MAX_BODY + 1;
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n").leak();
        let big = server(Some((head, len))).await;
        let e = post_to(&big, TIMEOUT).await.unwrap_err().to_string();
        assert!(e.contains("at most 65536 bytes"), "{e}");

        let silent = server(None).await;
        let started = std::time::Instant::now();
        let e = post_to(&silent, Duration::from_millis(300))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("gave no answer"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
