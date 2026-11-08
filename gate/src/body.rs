//! Body plumbing: one boxed body type, size limits, a metered body that reports bytes and
//! duration when the response finishes, and a watched one that records progress.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body as HttpBody, Frame, SizeHint};

use crate::limits::Activity;

/// Concrete body error. (A bare `Box<dyn Error>` as the body error trips a higher-ranked
/// lifetime inference bug in hyper's server bounds inside spawned tasks.)
#[derive(Debug)]
pub struct BodyError(pub Box<dyn std::error::Error + Send + Sync>);

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for BodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

pub type Body = BoxBody<Bytes, BodyError>;

pub fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|e| match e {}).boxed()
}

pub fn empty() -> Body {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

pub fn boxed<B>(b: B) -> Body
where
    B: HttpBody<Data = Bytes> + Send + Sync + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    b.map_err(|e| BodyError(Box::new(e))).boxed()
}

/// `prefix`, already read from a body, then the rest of that body.
pub fn prefixed(prefix: Bytes, rest: Body) -> Body {
    Prefixed {
        prefix: Some(prefix),
        rest,
    }
    .boxed()
}

struct Prefixed {
    prefix: Option<Bytes>,
    rest: Body,
}

impl HttpBody for Prefixed {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if let Some(p) = self.prefix.take()
            && !p.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(p))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.as_ref().is_none_or(|p| p.is_empty()) && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let inner = self.rest.size_hint();
        let extra = self.prefix.as_ref().map_or(0, |p| p.len() as u64);
        let mut h = SizeHint::new();
        if let Some(u) = inner.upper() {
            h.set_upper(u + extra);
        }
        h.set_lower(inner.lower() + extra);
        h
    }
}

/// Collect at most `limit` bytes; more is an error.
pub async fn collect_limited(body: Body, limit: usize) -> Result<Bytes, BodyError> {
    let limited = http_body_util::Limited::new(body, limit);
    match limited.collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) => Err(BodyError(e)),
    }
}

#[derive(Debug)]
pub struct TooLarge(pub u64);

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request body exceeds the {}-byte cap", self.0)
    }
}

impl std::error::Error for TooLarge {}

/// Does an error chain contain a body-cap violation?
pub fn is_too_large(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = cur {
        if err.is::<TooLarge>() {
            return true;
        }
        cur = err.source();
    }
    false
}

/// Fails the stream once more than `max` bytes have passed (chunked uploads have no
/// Content-Length to check up front).
pub struct Capped {
    inner: Body,
    seen: u64,
    max: u64,
}

impl Capped {
    pub fn new(inner: Body, max: u64) -> Self {
        Capped {
            inner,
            seen: 0,
            max,
        }
    }
}

impl HttpBody for Capped {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.seen += data.len() as u64;
                    if this.seen > this.max {
                        return Poll::Ready(Some(Err(BodyError(Box::new(TooLarge(this.max))))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Counts bytes and calls `done(bytes)` exactly once, when the body ends or is dropped.
pub struct Metered {
    inner: Body,
    bytes: u64,
    done: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
}

impl Metered {
    pub fn new(inner: Body, done: impl FnOnce(u64) + Send + Sync + 'static) -> Self {
        Metered {
            inner,
            bytes: 0,
            done: Some(Box::new(done)),
        }
    }

    fn finish(&mut self) {
        if let Some(done) = self.done.take() {
            done(self.bytes);
        }
    }
}

impl HttpBody for Metered {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                }
            }
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => this.finish(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Metered {
    fn drop(&mut self) {
        self.finish();
    }
}

/// `inner`, recording each frame's arrival in `activity`.
pub fn watched(inner: Body, activity: Arc<Activity>) -> Body {
    Watched { inner, activity }.boxed()
}

struct Watched {
    inner: Body,
    activity: Arc<Activity>,
}

impl HttpBody for Watched {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(_))) = &polled {
            self.activity.touch();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
