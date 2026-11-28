//! gRPC end to end, against the container runtime this build's instance uses (`luoto-dev`),
//! with its images built (`just images`): `just e2e`. It makes one env there, named
//! `e2e-grpc-<pid>`, and removes it again.
//!
//! What only the whole stack shows: a gRPC client installed in luoto's base image (grpcio,
//! which offers only HTTP/2 and trusts no CA but the ones it is pointed at) through the real
//! gate image, inspected, to a server on this machine with a CA of its own, as an internal
//! service or a workspace's endpoint is reached; messages of a stream as they are sent, and a
//! call no rule allows refused the way the client reads it.

#![cfg(unix)]

use std::convert::Infallible;
use std::pin::Pin;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Request, Response, Version};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc;

const LUOTO: &str = env!("CARGO_BIN_EXE_luoto");
/// How a dev container names this machine.
const THIS_MACHINE: &str = "host.docker.internal";

fn luoto(args: &[&str]) -> Output {
    Command::new(LUOTO)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// stdout and stderr of a luoto that must have exited with `code`.
fn said(args: &[&str], code: i32) -> String {
    let out = luoto(args);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(code), "luoto {args:?}:\n{text}");
    text
}

/// Removes the env however the test ends.
struct Env(String);

impl Drop for Env {
    fn drop(&mut self) {
        let _ = luoto(&["rm", "-e", &self.0, "--yes"]);
    }
}

type GrpcBody = BoxBody<Bytes, Infallible>;

/// A response body whose frames are sent as it goes.
struct Chan(mpsc::UnboundedReceiver<Frame<Bytes>>);

impl hyper::body::Body for Chan {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|f| f.map(Ok))
    }
}

/// One gRPC message: uncompressed, its length, its bytes.
fn message(payload: &[u8]) -> Frame<Bytes> {
    let mut b = BytesMut::with_capacity(5 + payload.len());
    b.put_u8(0);
    b.put_u32(payload.len() as u32);
    b.put_slice(payload);
    Frame::data(b.freeze())
}

fn grpc_ok() -> Frame<Bytes> {
    let mut t = HeaderMap::new();
    t.insert("grpc-status", HeaderValue::from_static("0"));
    Frame::trailers(t)
}

/// `/test.Echo/Unary` answers with the request; `/test.Echo/Stream` with three messages
/// 300 ms apart. Each request's HTTP version goes into `seen`.
async fn answer(
    req: Request<Incoming>,
    seen: Arc<Mutex<Vec<(Version, String)>>>,
) -> Result<Response<GrpcBody>, Infallible> {
    seen.lock()
        .unwrap()
        .push((req.version(), req.uri().path().to_string()));
    let (tx, rx) = mpsc::unbounded_channel();
    match req.uri().path() {
        "/test.Echo/Unary" => {
            let got = req.into_body().collect().await.unwrap().to_bytes();
            let _ = tx.send(Frame::data(got));
            let _ = tx.send(grpc_ok());
        }
        "/test.Echo/Stream" => {
            tokio::spawn(async move {
                for i in 0..3 {
                    if i > 0 {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    let _ = tx.send(message(format!("msg {i}").as_bytes()));
                }
                let _ = tx.send(grpc_ok());
            });
        }
        _ => {
            let mut t = HeaderMap::new();
            t.insert("grpc-status", HeaderValue::from_static("12"));
            let _ = tx.send(Frame::trailers(t));
        }
    }
    Ok(Response::builder()
        .header("content-type", "application/grpc")
        .body(Chan(rx).boxed())
        .unwrap())
}

/// A CA of the server's own and its certificate for this machine's name: the CA's PEM, and
/// the server's TLS config.
fn server_tls() -> (String, rustls::ServerConfig) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca.distinguished_name
        .push(DnType::CommonName, "e2e grpc CA");
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca, ca_key);
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![THIS_MACHINE.to_string()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    (ca_cert.pem(), cfg)
}

/// The client, in the env: unary, a stream timed message by message, then a call no rule
/// allows. Messages are raw bytes, so no generated code is needed.
const CLIENT: &str = r#"
import sys, time, grpc
ch = grpc.secure_channel(sys.argv[1], grpc.ssl_channel_credentials())
print("unary", ch.unary_unary("/test.Echo/Unary")(b"hello", timeout=60).decode())
t, gaps = time.time(), []
for m in ch.unary_stream("/test.Echo/Stream")(b"", timeout=60):
    gaps.append(time.time() - t)
    t = time.time()
print("stream", len(gaps), "least gap", round(min(gaps[1:]), 2))
try:
    ch.unary_unary("/other.Svc/Get")(b"", timeout=60)
    print("allowed")
except grpc.RpcError as e:
    print("denied", e.code().name, "|", e.details().replace("\n", " | "))
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a container runtime and luoto's images; run with `just e2e`"]
async fn a_grpc_client_in_the_env_is_inspected_on_its_way_to_an_internal_service() {
    let (ca_pem, tls) = server_tls();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, ca_pem).unwrap();

    // Every interface: the env reaches this machine at the runtime's gateway.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req| answer(req, log.clone()));
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });

    let env = Env(format!("e2e-grpc-{}", std::process::id()));
    let name = env.0.clone();
    let target = format!("{THIS_MACHINE}:{port}");
    let ca = ca.display().to_string();
    let out = tokio::task::spawn_blocking(move || {
        said(
            &["init", "--virtual", "--name", &name, "--preset", "pypi", "--yes"],
            0,
        );
        let port = port.to_string();
        let allow = [
            "allow", "-e", &name, THIS_MACHINE, "--port", &port, "--write", "--private",
            "--ca", &ca, "--path", "/test.Echo/*", "--force",
        ];
        said(&allow, 0);
        let script = format!(
            "set -e\npython3 -m venv /tmp/g\n/tmp/g/bin/pip install -q grpcio\n\
             cat > /tmp/client.py <<'EOF'\n{CLIENT}\nEOF\n/tmp/g/bin/python /tmp/client.py {target}\n"
        );
        said(&["shell", "-e", &name, "--", "sh", "-c", &script], 0)
    })
    .await
    .unwrap();

    assert!(out.contains("unary hello"), "{out}");
    // Each message as it was sent, none held for the next.
    let least: f64 = out
        .split("least gap ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
        .unwrap_or_else(|| panic!("no stream timing in:\n{out}"));
    assert!(out.contains("stream 3 ") && least >= 0.2, "{out}");
    assert!(
        out.contains("denied PERMISSION_DENIED | luoto: egress blocked"),
        "{out}"
    );
    assert!(out.contains("--path"), "the denial names the fix:\n{out}");
    // The gate spoke HTTP/2 to the server, and the refused call never reached it.
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [
            (Version::HTTP_2, "/test.Echo/Unary".to_string()),
            (Version::HTTP_2, "/test.Echo/Stream".to_string())
        ]
    );
}
