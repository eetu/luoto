//! Minimal blocking HTTP client for the gate's in-sandbox API (plain HTTP on the internal
//! network; keeps the helper a small static binary with no TLS or async stack).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub fn addr() -> String {
    std::env::var("LUOTO_GATE")
        .unwrap_or_else(|_| format!("{}:{}", luoto_shared::GATE_HOST, luoto_shared::PROXY_PORT))
}

pub struct Reply {
    pub status: u16,
    pub body: String,
}

pub fn request(method: &str, path: &str, body: Option<&str>) -> Result<Reply> {
    let addr = addr();
    let sock = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve gate {addr} (are you inside a luoto sandbox?)"))?
        .next()
        .context("gate has no address")?;
    let mut stream = TcpStream::connect_timeout(&sock, Duration::from_secs(5))
        .with_context(|| format!("connect to gate {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        luoto_shared::GATE_HOST,
        body.len()
    );
    stream.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .context("malformed gate response")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .context("malformed status line")?;
    let chunked = head.lines().any(|l| {
        l.to_ascii_lowercase().starts_with("transfer-encoding:")
            && l.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        dechunk(rest)
    } else {
        rest.to_string()
    };
    Ok(Reply { status, body })
}

fn dechunk(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some((size, after)) = rest.split_once("\r\n") {
        let Ok(n) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if n == 0 || after.len() < n {
            break;
        }
        out.push_str(&after[..n]);
        rest = after[n..].trim_start_matches("\r\n");
    }
    out
}

pub fn get_json<T: DeserializeOwned>(path: &str) -> Result<T> {
    let r = request("GET", path, None)?;
    if r.status != 200 {
        bail!("gate returned {}: {}", r.status, r.body.trim());
    }
    serde_json::from_str(&r.body).context("parse gate response")
}

pub fn post_json<B: Serialize, T: DeserializeOwned>(
    path: &str,
    body: &B,
) -> Result<(u16, std::result::Result<T, String>)> {
    let r = request("POST", path, Some(&serde_json::to_string(body)?))?;
    if (200..300).contains(&r.status) {
        Ok((
            r.status,
            Ok(serde_json::from_str(&r.body).context("parse gate response")?),
        ))
    } else {
        Ok((r.status, Err(r.body.trim().to_string())))
    }
}
