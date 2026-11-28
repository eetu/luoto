//! Keep a credential the gate put on a request from coming back in its response: refused in a
//! header; taken out of a JSON body that echoes it (Gitea and GitLab copy the request's
//! `Authorization` into their LFS batch answer, for the client to send on, and the gate adds
//! it to that request itself); anything else that carries it is refused, before the response
//! starts when its first frame does, else by ending the stream.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue};
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame};

use crate::body::{Body, BodyError, prefixed};

/// A JSON response is read whole up to this, so an echo in it can be taken out (LFS batch
/// answers); any other is screened as it streams, this far.
const SCREEN_JSON: usize = 1 << 20;
const SCREEN_HEAD: usize = 64 << 10;
/// The shortest start of a credential held back at the end of a frame until the next shows
/// whether the rest follows. A shorter start goes on at once, so a small message never waits
/// on the next; that many bytes less one (a token's public prefix) is the most of a
/// credential that reaches the client before the rest is caught.
const HOLD_FROM: usize = 4;

const CARRIED: &str = "the response carried the request's credential back";

pub async fn screen(
    headers: &mut HeaderMap,
    body: Body,
    placed: &[String],
) -> Result<Body, String> {
    let placed: Vec<Vec<u8>> = placed.iter().map(|p| p.as_bytes().to_vec()).collect();
    if headers.values().any(|v| carries(&placed, v.as_bytes())) {
        return Err(CARRIED.into());
    }
    if is_json(headers) {
        return whole_json(headers, body, &placed).await;
    }
    let mut screened = Screened {
        inner: body,
        placed,
        out: VecDeque::new(),
        held: BytesMut::new(),
        sent: BytesMut::new(),
        scanned: 0,
        ended: false,
    };
    screened.first().await?;
    Ok(screened.boxed())
}

fn carries(placed: &[Vec<u8>], b: &[u8]) -> bool {
    placed.iter().any(|p| b.windows(p.len()).any(|w| w == p))
}

/// `application/json` and `…+json`; not a stream of JSON lines (`x-ndjson`), screened as any
/// other stream.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|t| {
            t.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .is_some_and(|t| t.ends_with("/json") || t.ends_with("+json"))
}

async fn whole_json(
    headers: &mut HeaderMap,
    mut body: Body,
    placed: &[Vec<u8>],
) -> Result<Body, String> {
    let mut head = BytesMut::new();
    let mut ended = false;
    let mut rest = None;
    while head.len() < SCREEN_JSON {
        match body.frame().await {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => head.extend_from_slice(&data),
                Err(frame) => {
                    if frame
                        .trailers_ref()
                        .is_some_and(|t| t.values().any(|v| carries(placed, v.as_bytes())))
                    {
                        return Err(CARRIED.into());
                    }
                    ended = true;
                    rest = Some(queued([frame]));
                    break;
                }
            },
            Some(Err(e)) => return Err(format!("reading the response: {e}")),
            None => {
                ended = true;
                break;
            }
        }
    }
    let rest = rest.unwrap_or(body);
    if !carries(placed, &head) {
        return Ok(prefixed(head.freeze(), rest));
    }
    if ended && let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&head) {
        redact(&mut v, &|b| carries(placed, b));
        let out = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
        if !carries(placed, &out) {
            headers.insert(CONTENT_LENGTH, HeaderValue::from(out.len()));
            return Ok(prefixed(out.into(), rest));
        }
    }
    Err(CARRIED.into())
}

/// Drop every object member whose string value `carries` the credential, and blank such
/// strings in arrays.
fn redact(v: &mut serde_json::Value, carries: &dyn Fn(&[u8]) -> bool) {
    match v {
        serde_json::Value::Object(m) => {
            m.retain(|_, x| !x.as_str().is_some_and(|s| carries(s.as_bytes())));
            for x in m.values_mut() {
                redact(x, carries);
            }
        }
        serde_json::Value::Array(a) => {
            for x in a.iter_mut() {
                if x.as_str().is_some_and(|s| carries(s.as_bytes())) {
                    *x = serde_json::Value::String(String::new());
                } else {
                    redact(x, carries);
                }
            }
        }
        _ => {}
    }
}

/// A response screened as it streams, its first `SCREEN_HEAD` bytes and its trailers.
struct Screened {
    inner: Body,
    placed: Vec<Vec<u8>>,
    /// Frames screened and not yet taken.
    out: VecDeque<Frame<Bytes>>,
    /// The end of the last frame, held back: the start of a credential, `HOLD_FROM` bytes or
    /// more.
    held: BytesMut,
    /// The last bytes that went on, fewer than `HOLD_FROM`: a credential they start is caught
    /// when its rest arrives.
    sent: BytesMut,
    scanned: usize,
    ended: bool,
}

impl Screened {
    /// Screen up to the first frame that goes on: the response starts only after it, so a
    /// credential there is refused before the client sees any of the response.
    async fn first(&mut self) -> Result<(), String> {
        while self.out.is_empty() && !self.ended {
            match self.inner.frame().await {
                Some(Ok(frame)) => self.take(frame)?,
                Some(Err(e)) => return Err(format!("reading the response: {e}")),
                None => self.end(),
            }
        }
        Ok(())
    }

    fn take(&mut self, frame: Frame<Bytes>) -> Result<(), String> {
        match frame.into_data() {
            Ok(data) => self.data(data),
            Err(frame) => {
                if frame
                    .trailers_ref()
                    .is_some_and(|t| t.values().any(|v| carries(&self.placed, v.as_bytes())))
                {
                    return Err(CARRIED.into());
                }
                self.release();
                self.out.push_back(frame);
                Ok(())
            }
        }
    }

    fn data(&mut self, data: Bytes) -> Result<(), String> {
        if self.scanned >= SCREEN_HEAD {
            self.release();
            self.out.push_back(Frame::data(data));
            return Ok(());
        }
        self.scanned += data.len();
        let mut window = BytesMut::with_capacity(self.sent.len() + self.held.len() + data.len());
        window.extend_from_slice(&self.sent);
        window.extend_from_slice(&self.held);
        window.extend_from_slice(&data);
        if carries(&self.placed, &window) {
            return Err(CARRIED.into());
        }
        let hold = if self.scanned >= SCREEN_HEAD {
            0
        } else {
            starts_a_credential(&self.placed, &window)
        };
        let mut fresh = window.split_off(self.sent.len());
        self.held = fresh.split_off(fresh.len() - hold.min(fresh.len()));
        self.send(fresh);
        Ok(())
    }

    /// What is held goes on: what follows can't complete a credential it starts.
    fn release(&mut self) {
        let held = self.held.split();
        self.send(held);
    }

    fn send(&mut self, bytes: BytesMut) {
        if bytes.is_empty() {
            return;
        }
        self.sent.extend_from_slice(&bytes);
        let keep = self.sent.len().min(HOLD_FROM - 1);
        self.sent = self.sent.split_off(self.sent.len() - keep);
        self.out.push_back(Frame::data(bytes.freeze()));
    }

    fn end(&mut self) {
        self.release();
        self.ended = true;
    }
}

/// How many bytes `window` ends with that start a credential, if `HOLD_FROM` or more: the
/// longest such start of any.
fn starts_a_credential(placed: &[Vec<u8>], window: &[u8]) -> usize {
    placed
        .iter()
        .filter_map(|p| {
            (HOLD_FROM..p.len())
                .rev()
                .find(|&k| k <= window.len() && window.ends_with(&p[..k]))
        })
        .max()
        .unwrap_or(0)
}

impl HttpBody for Screened {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        loop {
            if let Some(frame) = this.out.pop_front() {
                return Poll::Ready(Some(Ok(frame)));
            }
            if this.ended {
                return Poll::Ready(None);
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Err(e) = this.take(frame) {
                        this.ended = true;
                        this.out.clear();
                        return Poll::Ready(Some(Err(BodyError(e.into()))));
                    }
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => this.end(),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.out.is_empty() && self.held.is_empty() && (self.ended || self.inner.is_end_stream())
    }
}

/// `frames`, then the end.
fn queued(frames: impl IntoIterator<Item = Frame<Bytes>>) -> Body {
    Queued(frames.into_iter().collect()).boxed()
}

struct Queued(VecDeque<Frame<Bytes>>);

impl HttpBody for Queued {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    const TOKEN: &str = "ghp_secrettoken";

    /// A response whose frames the test sends as it goes.
    struct Chan(mpsc::UnboundedReceiver<Frame<Bytes>>);

    impl HttpBody for Chan {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
            self.0.poll_recv(cx).map(|f| f.map(Ok))
        }
    }

    fn streaming() -> (mpsc::UnboundedSender<Frame<Bytes>>, Body) {
        let (tx, rx) = mpsc::unbounded_channel();
        (tx, Chan(rx).boxed())
    }

    fn data(s: &str) -> Frame<Bytes> {
        Frame::data(Bytes::copy_from_slice(s.as_bytes()))
    }

    fn trailers(k: &'static str, v: &str) -> Frame<Bytes> {
        let mut t = HeaderMap::new();
        t.insert(k, HeaderValue::from_str(v).unwrap());
        Frame::trailers(t)
    }

    async fn screened(
        first: &[&str],
    ) -> (mpsc::UnboundedSender<Frame<Bytes>>, Result<Body, String>) {
        let (tx, body) = streaming();
        for f in first {
            tx.send(data(f)).unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
        let r = screen(&mut headers, body, &[TOKEN.to_string()]).await;
        (tx, r)
    }

    /// The next frame's data, `Err` for an error, `None` at the end.
    async fn next(body: &mut Body) -> Option<Result<String, String>> {
        match body.frame().await? {
            Ok(f) => match f.into_data() {
                Ok(d) => Some(Ok(String::from_utf8(d.to_vec()).unwrap())),
                Err(f) => Some(Ok(format!("trailers {:?}", f.into_trailers().unwrap()))),
            },
            Err(e) => Some(Err(e.to_string())),
        }
    }

    #[tokio::test]
    async fn a_message_goes_on_without_waiting_for_the_next() {
        let (_tx, body) = screened(&["one message"]).await;
        let mut body = body.unwrap();
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), next(&mut body));
        assert_eq!(first.await.unwrap(), Some(Ok("one message".into())));
    }

    #[tokio::test]
    async fn a_credential_in_the_first_frame_is_refused_before_the_response() {
        let (_tx, body) = screened(&[&format!("x{TOKEN}x")]).await;
        assert_eq!(body.err().as_deref(), Some(CARRIED));
    }

    #[tokio::test]
    async fn a_credential_split_across_frames_ends_the_stream() {
        // Its first four bytes are held until the next frame shows the rest.
        let (tx, body) = screened(&["abc ghp_"]).await;
        let mut body = body.unwrap();
        assert_eq!(next(&mut body).await, Some(Ok("abc ".into())));
        tx.send(data("secrettoken and on")).unwrap();
        assert_eq!(next(&mut body).await, Some(Err(CARRIED.into())));
        assert_eq!(next(&mut body).await, None);
    }

    #[tokio::test]
    async fn at_most_three_bytes_of_a_credential_get_through() {
        let (tx, body) = screened(&["abc ghp"]).await;
        let mut body = body.unwrap();
        assert_eq!(next(&mut body).await, Some(Ok("abc ghp".into())));
        // Its start went on, so the next bytes are held as part of it.
        tx.send(data("_sec")).unwrap();
        tx.send(data("rettoken")).unwrap();
        assert_eq!(next(&mut body).await, Some(Err(CARRIED.into())));
    }

    #[tokio::test]
    async fn a_held_start_goes_on_when_nothing_completes_it() {
        let (tx, body) = screened(&["abc ghp_s"]).await;
        let mut body = body.unwrap();
        assert_eq!(next(&mut body).await, Some(Ok("abc ".into())));
        tx.send(data("ome other words")).unwrap();
        assert_eq!(
            next(&mut body).await,
            Some(Ok("ghp_some other words".into()))
        );
        tx.send(data("ghp_se")).unwrap();
        tx.send(trailers("grpc-status", "0")).unwrap();
        drop(tx);
        assert_eq!(next(&mut body).await, Some(Ok("ghp_se".into())));
        assert_eq!(
            next(&mut body).await,
            Some(Ok("trailers {\"grpc-status\": \"0\"}".into()))
        );
        assert_eq!(next(&mut body).await, None);
    }

    #[tokio::test]
    async fn trailers_are_screened() {
        let (tx, body) = screened(&["ok"]).await;
        let mut body = body.unwrap();
        assert_eq!(next(&mut body).await, Some(Ok("ok".into())));
        tx.send(trailers("grpc-message", TOKEN)).unwrap();
        assert_eq!(next(&mut body).await, Some(Err(CARRIED.into())));
    }

    #[tokio::test]
    async fn past_the_screened_start_frames_go_on_as_they_come() {
        let (tx, body) = screened(&[&"a".repeat(SCREEN_HEAD - 2)]).await;
        let mut body = body.unwrap();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap().len(),
            SCREEN_HEAD - 2
        );
        tx.send(data("abghp_")).unwrap();
        tx.send(data(TOKEN)).unwrap();
        assert_eq!(next(&mut body).await, Some(Ok("abghp_".into())));
        assert_eq!(next(&mut body).await, Some(Ok(TOKEN.into())));
    }

    #[test]
    fn json_is_a_document_not_a_stream_of_lines() {
        let is = |t: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(CONTENT_TYPE, HeaderValue::from_static(t));
            is_json(&h)
        };
        assert!(is("application/json; charset=utf-8"));
        assert!(is("application/vnd.git-lfs+json"));
        assert!(!is("application/x-ndjson"));
        assert!(!is("application/grpc"));
    }

    #[tokio::test]
    async fn an_echoed_credential_is_taken_out_of_json_and_trailers_kept() {
        let (tx, body) = streaming();
        tx.send(data(&format!(
            r#"{{"header":{{"Authorization":"token {TOKEN}","Accept":"x"}},"list":["{TOKEN}","ok"]}}"#
        )))
        .unwrap();
        tx.send(trailers("x-done", "1")).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut body = screen(&mut headers, body, &[TOKEN.to_string()])
            .await
            .unwrap();
        let out = next(&mut body).await.unwrap().unwrap();
        assert_eq!(out, r#"{"header":{"Accept":"x"},"list":["","ok"]}"#);
        assert_eq!(headers[CONTENT_LENGTH], out.len().to_string());
        assert_eq!(
            next(&mut body).await,
            Some(Ok("trailers {\"x-done\": \"1\"}".into()))
        );
    }

    #[test]
    fn an_echoed_credential_is_taken_out_of_nested_json() {
        // Gitea's LFS batch answer, with the request's Authorization copied in.
        let mut v: serde_json::Value = serde_json::from_str(
            r#"{"objects":[{"oid":"ab","actions":{"upload":{"href":"https://f/x.git/info/lfs/objects/ab",
            "header":{"Authorization":"Basic ZGV2OnNlY3JldHRva2Vu","Accept":"x"}}}}],
            "list":["Basic ZGV2OnNlY3JldHRva2Vu","ok"]}"#,
        )
        .unwrap();
        let placed = [b"secrettoken".to_vec(), b"ZGV2OnNlY3JldHRva2Vu".to_vec()];
        let carries = |b: &[u8]| carries(&placed, b);
        redact(&mut v, &carries);
        let out = serde_json::to_string(&v).unwrap();
        assert!(!carries(out.as_bytes()), "{out}");
        assert!(out.contains("\"Accept\":\"x\"") && out.contains("objects/ab"));
    }
}
