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
    let app = Router::new()
        .nest("/api", api::routes())
        .fallback(spa)
        .layer(middleware::from_fn_with_state(ui.clone(), guard))
        .layer(csp_layer())
        .with_state(ui.clone());
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
    axum::serve(listener, app).await?;
    Ok(())
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
