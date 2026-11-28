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
    let fix = fix(env, method, url, host, path, reason);
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

/// How the user can allow what `reason` denied. A CONNECT denied for its address is a tunnel
/// rule's (`url` is `host:port`): any other is decided inside, per request.
fn fix(env: &str, method: &str, url: &str, host: &str, path: &str, reason: &DenyReason) -> String {
    let port = luoto_shared::host::split_target(url)
        .1
        .and_then(|p| p.parse::<u16>().ok());
    let at = |p: u16| match host.contains(':') {
        true => format!("[{host}]:{p}"),
        false => format!("{host}:{p}"),
    };
    // A rule without a port covers 80 and 443 only; another is named after the host, as
    // `luoto allow` takes it.
    let other_port = port.filter(|p| *p != 80 && *p != 443);
    let target = other_port.map_or_else(|| host.to_string(), at);
    // `sandbox request` takes `host:port` as a tunnel: what the gate read on another port is
    // asked for by its URL, inspected there.
    let scheme = url
        .split_once("://")
        .map(|(s, _)| if s == "http" { "http" } else { "https" });
    let ask = match (other_port, scheme) {
        (Some(_), Some(s)) => format!("{s}://{target}/"),
        _ => target.clone(),
    };
    let write = if reason.wants_write() || (method != "CONNECT" && !READ_METHODS.contains(&method))
    {
        " --write"
    } else {
        ""
    };
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
        DenyReason::PrivateAddress => {
            let (allow, asked) = match port.filter(|_| method == "CONNECT") {
                Some(p) => (format!("{host} --port {p} --tunnel --private"), at(p)),
                None => (format!("{target} --private"), ask),
            };
            format!(
                "A private address (the user's network, a VPN, this machine) needs a rule that \
                 reaches it. The user can run on the host:\n  luoto allow -e {env} {allow}\n\
                 From inside the sandbox, request it with private access:\n  \
                 sandbox request {asked} --private --reason \"<why; on your network or VPN>\""
            )
        }
        DenyReason::WebSocketNotAllowed => format!(
            "To allow websocket upgrades to it, the user can run on the host:\n  \
             luoto allow -e {env} {target} --ws\n\
             From inside the sandbox, request them with:\n  \
             sandbox request {ask} --ws --reason \"<why this is needed>\""
        ),
        _ => {
            let (asked, ask) = match (other_port, scheme) {
                (Some(_), None) => ("a tunnel to it", target.clone()),
                _ => ("it", format!("{ask}{write}")),
            };
            format!(
                "To allow it, the user can run on the host:\n  luoto allow -e {env} {target}{write}\n\
                 or approve it in `luoto ui`. From inside the sandbox, request {asked} with:\n  \
                 sandbox request {ask} --reason \"<why this is needed>\""
            )
        }
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

    /// `fix` for a request inside a connection: its URL plays no part.
    fn fix_for(env: &str, method: &str, host: &str, path: &str, reason: &DenyReason) -> String {
        fix(env, method, "", host, path, reason)
    }

    #[test]
    fn a_private_address_denial_names_the_rule_that_reaches_it() {
        let reason = DenyReason::PrivateAddress;
        let http = fix_for("web", "GET", "k8s.internal", "/version", &reason);
        assert!(
            http.contains("luoto allow -e web k8s.internal --private\n"),
            "{http}"
        );
        assert!(
            http.contains("sandbox request k8s.internal --private --reason"),
            "{http}"
        );
        let tunnel = fix(
            "web",
            "CONNECT",
            "k8s.internal:7443",
            "k8s.internal",
            "",
            &reason,
        );
        assert!(
            tunnel.contains("luoto allow -e web k8s.internal --port 7443 --tunnel --private\n"),
            "{tunnel}"
        );
        assert!(
            tunnel.contains("sandbox request k8s.internal:7443 --private --reason"),
            "{tunnel}"
        );
        let https = fix(
            "web",
            "CONNECT",
            "k8s.internal:443",
            "k8s.internal",
            "",
            &reason,
        );
        assert!(https.contains("--port 443 --tunnel --private"), "{https}");
        assert!(
            https.contains("sandbox request k8s.internal:443 --private --reason"),
            "{https}"
        );
    }

    #[test]
    fn a_path_denial_offers_that_path_not_the_host() {
        let f = fix_for(
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
        let post = fix_for(
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
        let hostile = fix_for(
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
        let host = fix_for("web", "GET", "docs.rs", "/x", &DenyReason::NoRule);
        assert!(host.contains("luoto allow -e web docs.rs\n"), "{host}");
    }

    #[test]
    fn the_fix_names_the_port_method_and_upgrade_the_request_needs() {
        let url = "https://nexus.corp:8443/repository/npm/";
        let port = fix("web", "GET", url, "nexus.corp", "/x", &DenyReason::NoRule);
        assert!(
            port.contains("luoto allow -e web nexus.corp:8443\n"),
            "{port}"
        );
        assert!(
            port.contains("sandbox request https://nexus.corp:8443/ --reason"),
            "{port}"
        );
        let tunnel = fix(
            "web",
            "CONNECT",
            "db.example:5432",
            "db.example",
            "",
            &DenyReason::NoRule,
        );
        assert!(
            tunnel.contains(
                "request a tunnel to it with:\n  sandbox request db.example:5432 --reason"
            ),
            "{tunnel}"
        );
        let https = fix(
            "web",
            "GET",
            "https://docs.rs/x",
            "docs.rs",
            "/x",
            &DenyReason::NoRule,
        );
        assert!(https.contains("luoto allow -e web docs.rs\n"), "{https}");
        let post = fix_for("web", "POST", "api.example", "/v1", &DenyReason::NoRule);
        assert!(
            post.contains("luoto allow -e web api.example --write\n")
                && post.contains("sandbox request api.example --write --reason"),
            "{post}"
        );
        let upload = fix_for(
            "web",
            "PUT",
            "uploads.github.com",
            "/x",
            &DenyReason::BodyTooLarge { max: 1 },
        );
        assert!(upload.contains("uploads.github.com --write\n"), "{upload}");
        let ws = fix(
            "web",
            "GET",
            "http://localhost.dev:5173/",
            "localhost.dev",
            "/",
            &DenyReason::WebSocketNotAllowed,
        );
        assert!(
            ws.contains("luoto allow -e web localhost.dev:5173 --ws\n")
                && ws.contains("sandbox request http://localhost.dev:5173/ --ws --reason"),
            "{ws}"
        );
        let private = fix(
            "web",
            "GET",
            "http://[fd00::5]:8080/",
            "fd00::5",
            "/",
            &DenyReason::PrivateAddress,
        );
        assert!(
            private.contains("luoto allow -e web [fd00::5]:8080 --private\n")
                && private.contains("sandbox request http://[fd00::5]:8080/ --private --reason"),
            "{private}"
        );
    }
}
