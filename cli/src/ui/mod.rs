//! `luoto ui`: the local web UI. One process, bound to 127.0.0.1, serving the embedded SPA
//! and a JSON API over the same core functions as the CLI.
//!
//! The UI can grant network access, so it is guarded like a credential: a per-run random
//! token (delivered in the URL fragment, never sent in a request line) on every API call, a
//! Host check against DNS rebinding, an Origin check on writes, and a strict CSP.

mod api;
mod ingest;

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;
use subtle::ConstantTimeEq;
use tower_http::set_header::SetResponseHeaderLayer;

use crate::paths::Paths;

#[derive(RustEmbed)]
#[folder = "../frontend/dist"]
#[allow_missing = true]
struct Spa;

#[derive(Clone)]
pub struct Ui {
    token: Arc<String>,
    port: u16,
    pub store: ingest::Store,
}

pub fn serve(port: u16, open_browser: bool) -> Result<ExitCode> {
    // What the UI starts (an `up`) must not wait on this terminal.
    crate::prompt::never_ask();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(port, open_browser))?;
    Ok(ExitCode::SUCCESS)
}

async fn run(port: u16, open_browser: bool) -> Result<()> {
    let paths = Paths::get()?;
    let store = ingest::Store::open(&paths.events_db())?;
    ingest::spawn_supervisor(store.clone());
    let ui = Ui {
        token: Arc::new(hex::encode(rand::random::<[u8; 24]>())),
        port,
        store,
    };
    if Spa::get("index.html").is_none() {
        eprintln!(
            "note: the UI bundle is not built into this binary (run `just ui-build`); the API still works"
        );
    }
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("bind 127.0.0.1:{port} (is `luoto ui` already running?)"))?;
    let url = format!("http://127.0.0.1:{port}/#token={}", ui.token);
    println!(
        "luoto ui: {url}\n(the token in the link is required; keep it to yourself — Ctrl-C to stop)"
    );
    if open_browser {
        let _ = open::that_detached(&url);
    }
    axum::serve(listener, app(ui)).await?;
    Ok(())
}

fn app(ui: Ui) -> Router {
    Router::new()
        .nest("/api", api::routes())
        .fallback(spa)
        .layer(middleware::from_fn_with_state(ui.clone(), guard))
        .layer(csp_layer())
        .with_state(ui)
}

/// Host check on everything, bearer token on /api, same-origin on writes.
async fn guard(State(ui): State<Ui>, req: Request, next: Next) -> Response {
    let allowed_hosts = [
        format!("127.0.0.1:{}", ui.port),
        format!("localhost:{}", ui.port),
    ];
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !allowed_hosts.iter().any(|h| h == host) {
        return (StatusCode::MISDIRECTED_REQUEST, "unexpected Host").into_response();
    }
    if req.uri().path().starts_with("/api") {
        let token = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        if !bool::from(token.as_bytes().ct_eq(ui.token.as_bytes())) {
            return (
                StatusCode::UNAUTHORIZED,
                "missing or wrong token — open the link printed by `luoto ui`",
            )
                .into_response();
        }
        if req.method() != Method::GET {
            if let Some(origin) = req
                .headers()
                .get(header::ORIGIN)
                .and_then(|v| v.to_str().ok())
                && !allowed_hosts
                    .iter()
                    .any(|h| origin == format!("http://{h}"))
            {
                return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
            }
            let json = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("application/json"));
            if !json && req.method() != Method::DELETE {
                return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON only").into_response();
            }
        }
    }
    next.run(req).await
}

async fn spa(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if !path.is_empty()
        && let Some(f) = Spa::get(path)
    {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref().to_string())],
            f.data.into_owned(),
        )
            .into_response();
    }
    match Spa::get("index.html") {
        Some(f) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
            f.data.into_owned(),
        )
            .into_response(),
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(
                "UI bundle not built; run `just ui-build` and rebuild luoto",
            ))
            .unwrap_or_default(),
    }
}

/// Same-origin CSP with a hash for each inline script in the served shell (SvelteKit boots
/// from an inline script whose content changes per build).
fn csp_layer() -> SetResponseHeaderLayer<HeaderValue> {
    let hashes: String = Spa::get("index.html")
        .map(|f| inline_scripts(&String::from_utf8_lossy(&f.data)))
        .unwrap_or_default()
        .iter()
        .map(|body| format!(" '{}'", sha256_b64(body)))
        .collect();
    let csp = format!(
        "default-src 'self'; script-src 'self'{hashes}; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
         font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; \
         frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"
    );
    SetResponseHeaderLayer::if_not_present(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp)
            .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'")),
    )
}

fn inline_scripts(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(found) = lower[cursor..].find("<script") {
        let open = cursor + found;
        let Some(rel) = lower[open..].find('>') else {
            break;
        };
        let body_start = open + rel + 1;
        let Some(rel_end) = lower[body_start..].find("</script") else {
            break;
        };
        let body_end = body_start + rel_end;
        if !lower[open..body_start].contains(" src=") {
            out.push(html[body_start..body_end].to_string());
        }
        cursor = body_end;
    }
    out
}

fn sha256_b64(s: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(s.as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::{HeaderMap, HeaderName};
    use tower::ServiceExt;

    use super::*;

    const PORT: u16 = 7878;
    const HOST: &str = "127.0.0.1:7878";
    const ORIGIN: &str = "http://127.0.0.1:7878";
    const BEARER: &str = "Bearer 0123456789abcdef";
    /// A write route that answers 400 before its handler runs: the request id isn't a number.
    /// Passing the guard, a write here touches nothing.
    const WRITE: &str = "/api/envs/e/requests/x/approve";

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl Reply {
        fn csp(&self) -> &str {
            self.headers
                .get(header::CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
        }
    }

    async fn send(method: Method, path: &str, headers: &[(HeaderName, &str)]) -> Reply {
        let dir = tempfile::tempdir().unwrap();
        let ui = Ui {
            token: Arc::new(BEARER.trim_start_matches("Bearer ").into()),
            port: PORT,
            store: ingest::Store::open(&dir.path().join("events.db")).unwrap(),
        };
        let mut req = axum::http::Request::builder().method(method).uri(path);
        for (name, value) in headers {
            req = req.header(name, *value);
        }
        let resp = app(ui)
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        Reply {
            status,
            headers,
            body: body.to_vec(),
        }
    }

    async fn get(path: &str, headers: &[(HeaderName, &str)]) -> Reply {
        send(Method::GET, path, headers).await
    }

    /// A JSON write with the token and `origin`.
    async fn write_from(origin: Option<&str>) -> Reply {
        let mut headers = vec![
            (header::HOST, HOST),
            (header::AUTHORIZATION, BEARER),
            (header::CONTENT_TYPE, "application/json"),
        ];
        headers.extend(origin.map(|o| (header::ORIGIN, o)));
        send(Method::POST, WRITE, &headers).await
    }

    #[tokio::test]
    async fn another_host_is_refused_on_every_route() {
        // A DNS-rebound page reaches the port under its own name.
        for host in [
            "evil.example:7878",
            "127.0.0.1:7879",
            "127.0.0.1",
            "localhost",
        ] {
            for path in ["/", "/index.html", "/api/meta"] {
                let r = get(
                    path,
                    &[(header::HOST, host), (header::AUTHORIZATION, BEARER)],
                )
                .await;
                assert_eq!(r.status, StatusCode::MISDIRECTED_REQUEST, "{host}{path}");
            }
        }
        let r = get("/api/meta", &[(header::AUTHORIZATION, BEARER)]).await;
        assert_eq!(r.status, StatusCode::MISDIRECTED_REQUEST, "no Host");
        for host in [HOST, "localhost:7878"] {
            let r = get(
                "/api/meta",
                &[(header::HOST, host), (header::AUTHORIZATION, BEARER)],
            )
            .await;
            assert_eq!(r.status, StatusCode::OK, "{host}");
        }
    }

    #[tokio::test]
    async fn api_reads_need_the_token_and_no_origin() {
        let token = BEARER.trim_start_matches("Bearer ");
        let wrong = [
            None,
            Some("Bearer 0123456789abcdee"),
            Some("Bearer "),
            Some(token),
            Some("Basic MDEyMzQ1Njc4OWFiY2RlZg=="),
        ];
        for auth in wrong {
            let mut headers = vec![(header::HOST, HOST)];
            headers.extend(auth.map(|a| (header::AUTHORIZATION, a)));
            let r = get("/api/meta", &headers).await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{auth:?}");
        }
        let r = get(
            "/api/meta",
            &[(header::HOST, HOST), (header::AUTHORIZATION, BEARER)],
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        let meta: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert!(meta["presets"].is_array(), "{meta}");
        // The page itself is public: the token reaches it in the URL fragment.
        let r = get("/", &[(header::HOST, HOST)]).await;
        assert_ne!(r.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn writes_are_refused_from_another_origin() {
        for origin in [
            "http://evil.example",
            "null",
            "http://127.0.0.1:7879",
            "https://127.0.0.1:7878",
            "http://127.0.0.1:7878.evil.example",
            "http://localhost",
        ] {
            let r = write_from(Some(origin)).await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{origin}");
        }
        // The page's own origin, under either name, and clients that send none (curl).
        for origin in [Some(ORIGIN), Some("http://localhost:7878"), None] {
            let r = write_from(origin).await;
            assert_eq!(
                r.status,
                StatusCode::BAD_REQUEST,
                "{origin:?} reaches the route"
            );
        }
    }

    #[tokio::test]
    async fn writes_a_plain_form_could_send_are_refused() {
        for content_type in [
            Some("text/plain"),
            Some("application/x-www-form-urlencoded"),
            Some("multipart/form-data; boundary=x"),
            None,
        ] {
            let mut headers = vec![
                (header::HOST, HOST),
                (header::AUTHORIZATION, BEARER),
                (header::ORIGIN, ORIGIN),
            ];
            headers.extend(content_type.map(|c| (header::CONTENT_TYPE, c)));
            let r = send(Method::POST, WRITE, &headers).await;
            assert_eq!(
                r.status,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{content_type:?}"
            );
        }
    }

    #[tokio::test]
    async fn every_response_carries_the_csp() {
        let replies = [
            get("/", &[(header::HOST, HOST)]).await,
            get("/", &[(header::HOST, "evil.example")]).await,
            get(
                "/api/meta",
                &[(header::HOST, HOST), (header::AUTHORIZATION, BEARER)],
            )
            .await,
            get("/api/meta", &[(header::HOST, HOST)]).await,
        ];
        for r in &replies {
            let csp = r.csp();
            for directive in [
                "default-src 'self'",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "object-src 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ] {
                assert!(csp.contains(directive), "{}: {csp}", r.status);
            }
        }
    }

    #[tokio::test]
    async fn the_page_and_its_assets_are_served_under_a_csp_that_admits_only_their_scripts() {
        let Some(index) = Spa::get("index.html") else {
            // A build without the UI bundle (CI's Rust jobs) says so.
            assert_eq!(
                get("/", &[(header::HOST, HOST)]).await.status,
                StatusCode::NOT_FOUND
            );
            return;
        };
        let r = get("/", &[(header::HOST, HOST)]).await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(r.body, index.data.as_ref());
        let script_src = r
            .csp()
            .split(';')
            .map(str::trim)
            .find(|d| d.starts_with("script-src "))
            .unwrap()
            .to_string();
        assert!(!script_src.contains("unsafe"), "{script_src}");
        // SvelteKit boots from an inline script: the CSP admits it by its hash.
        let inline = inline_scripts(&String::from_utf8_lossy(&index.data));
        assert!(!inline.is_empty());
        for body in inline {
            assert!(
                script_src.contains(&format!("'{}'", sha256_b64(&body))),
                "{script_src}"
            );
        }

        let asset = Spa::iter().find(|p| p.ends_with(".js")).unwrap();
        let r = get(&format!("/{asset}"), &[(header::HOST, HOST)]).await;
        assert_eq!(r.status, StatusCode::OK, "{asset}");
        assert_eq!(r.headers[header::CONTENT_TYPE], "text/javascript");
        assert_eq!(r.body, Spa::get(&asset).unwrap().data.as_ref());
        assert!(r.csp().contains("default-src 'self'"));
    }
}
