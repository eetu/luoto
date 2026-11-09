//! Responses the gate writes itself. A denial explains what was blocked and exactly how the
//! user can allow it — the text is read by humans and by agents in the sandbox alike.

use http::{HeaderValue, Response, StatusCode, header};
use luoto_shared::policy::{DenyReason, READ_METHODS};
use serde::Serialize;

use crate::body::{Body, empty, full};

/// `path` is the request's canonical path (empty for a CONNECT).
pub fn deny(
    env: &str,
    method: &str,
    url: &str,
    host: &str,
    path: &str,
    reason: &DenyReason,
) -> Response<Body> {
    let message = reason.message(host);
    let fix = fix(env, method, host, path, reason);
    let body = format!(
        "luoto: egress blocked by the sandbox policy of env \"{env}\"\n\
         request: {method} {url}\n\
         reason:  {message}\n\n\
         {fix}\n\n\
         Agents: this is an intentional security boundary (see /opt/luoto/AGENTS.md).\n\
         Do not try to work around it; explain to the user what you need and why.\n"
    );
    let mut resp = Response::new(if method == "HEAD" {
        empty()
    } else {
        full(body)
    });
    *resp.status_mut() = if matches!(reason, DenyReason::InvalidHost) {
        StatusCode::MISDIRECTED_REQUEST
    } else {
        StatusCode::FORBIDDEN
    };
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    h.insert(
        "x-proxy-error",
        HeaderValue::from_static("blocked-by-luoto"),
    );
    if let Ok(v) = HeaderValue::from_str(reason.code()) {
        h.insert("x-luoto-denied", v);
    }
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            b"Forbidden by luoto sandbox policy",
        ));
    resp
}

/// How the user can allow what `reason` denied.
fn fix(env: &str, method: &str, host: &str, path: &str, reason: &DenyReason) -> String {
    let write = if reason.wants_write() { " --write" } else { "" };
    match reason {
        // The host is open on other paths (a relay such as the Go module proxy may be open only
        // for some): allowing all of it would undo that, so the fix names a path, and the
        // method too, or the next denial would offer writes to the whole host.
        DenyReason::PathNotAllowed => {
            let glob = luoto_shared::host::path_glob(path).unwrap_or_else(|| "<path glob>".into());
            let write = if READ_METHODS.contains(&method) {
                ""
            } else {
                " --write"
            };
            format!(
                "To allow this path, the user can run on the host:\n  \
                 luoto allow -e {env} {host} --path '{glob}'{write}\n\
                 or approve it in `luoto ui`. From inside the sandbox, request it with:\n  \
                 sandbox request {host} --path '{glob}'{write} --reason \"<why this is needed>\""
            )
        }
        DenyReason::Locked => {
            "The user must run `luoto vault unlock` on the host (or use `luoto ui`).".to_string()
        }
        DenyReason::Explicit { .. } | DenyReason::Guard { .. } | DenyReason::InvalidHost => {
            "This is a fixed guard-rail of the sandbox; it cannot be lifted by a rule.".to_string()
        }
        DenyReason::PrivateAddress => format!(
            "Private/host addresses need an explicit rule on the host:\n  luoto allow -e {env} {host} --private"
        ),
        _ => format!(
            "To allow it, the user can run on the host:\n  luoto allow -e {env} {host}{write}\n\
             or approve it in `luoto ui`. From inside the sandbox, request it with:\n  \
             sandbox request {host}{write} --reason \"<why this is needed>\""
        ),
    }
}

pub fn plain(status: StatusCode, text: impl Into<String>) -> Response<Body> {
    let mut resp = Response::new(full(text.into()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

pub fn json(status: StatusCode, value: &impl Serialize) -> Response<Body> {
    let bytes = serde_json::to_vec(value).unwrap_or_else(|_| b"null".to_vec());
    let mut resp = Response::new(full(bytes));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_denial_offers_that_path_not_the_host() {
        let f = fix(
            "web",
            "GET",
            "proxy.golang.org",
            "/filippo.io/edwards25519/@v/list",
            &DenyReason::PathNotAllowed,
        );
        assert!(
            f.contains(
                "luoto allow -e web proxy.golang.org --path '/filippo.io/edwards25519/@v/**'\n"
            ),
            "{f}"
        );
        assert!(
            f.contains("sandbox request proxy.golang.org --path '/filippo.io/edwards25519/@v/**'")
        );
        let post = fix(
            "web",
            "POST",
            "api.example",
            "/v1/items/x",
            &DenyReason::PathNotAllowed,
        );
        assert!(
            post.contains("luoto allow -e web api.example --path '/v1/items/**' --write\n"),
            "{post}"
        );
        let hostile = fix(
            "web",
            "GET",
            "h.example",
            "/a/b'; rm -rf ~; '",
            &DenyReason::PathNotAllowed,
        );
        assert!(
            hostile.contains("--path '<path glob>'") && !hostile.contains("rm -rf"),
            "{hostile}"
        );
        let host = fix("web", "GET", "docs.rs", "/x", &DenyReason::NoRule);
        assert!(host.contains("luoto allow -e web docs.rs\n"), "{host}");
    }
}
