//! The vault's own requests out: token mints at GitHub's API and at Microsoft Entra ID. Over
//! HTTPS only; `test-hooks` builds also reach the integration tests' plain-HTTP servers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

/// POST `body` (of `content_type`) to `url` with `headers`; the status and body of the answer.
pub async fn post(
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
    let https = uri.scheme_str() != Some("http");
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    #[cfg(not(feature = "test-hooks"))]
    if !https {
        anyhow::bail!("tokens are minted over https only");
    }
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .context("connect timed out")??;
    let mut req = http::Request::post(uri.path())
        .header(http::header::HOST, &host)
        .header(http::header::USER_AGENT, "luoto-vault")
        .header(http::header::CONTENT_TYPE, content_type);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let req = req.body(Full::new(bytes::Bytes::from(body)))?;
    let resp = if https {
        let name = ServerName::try_from(host.clone())?;
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
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}
