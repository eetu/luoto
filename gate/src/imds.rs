//! The Azure instance metadata service (IMDS) as the sandbox sees it, for an env with
//! `[credentials.azure]`: the gate answers its managed identity token endpoint itself, for
//! the audiences the env is granted, and never dials 169.254.169.254. The token it hands out
//! is a placeholder: the real token's header and the claims tools read ([`CLAIMS`]) with a
//! signature that can't verify, so tools read true claims (object ID, tenant, expiry) while the
//! real token leaves only on the Azure hosts where the gate adds it (`creds.rs`).

use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::Utc;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use luoto_shared::azure_identity::{Audience, IMDS_HOST, IMDS_TOKEN_PATH};
use luoto_shared::creds::CredentialError;
use luoto_shared::events::{Event, EventKind, Verdict, clip_path};
use luoto_shared::policy::Policy;
use serde_json::{Map, Value, json};

use crate::body::{Body, full};
use crate::handler::{ConnCtx, Target, host_agrees};
use crate::state::State;

/// What replaces a token's signature in its placeholder.
const SIGNATURE: &str = "luoto: the gate adds the real token";
/// The claims a placeholder keeps: what the tools that take a managed identity's token read.
/// `az login --identity` reads the tenant; terraform's azurerm (`azurerm_client_config`) the
/// object, application and tenant IDs and the identity type; the Azure SDKs only the times.
/// The rest (names, the client's address, roles and scopes) stays with the real token.
const CLAIMS: &[&str] = &[
    "aud", "iss", "iat", "nbf", "exp", "tid", "oid", "sub", "appid", "azp", "idtyp", "ver",
];
/// The most of a client's `resource` an answer or event repeats.
const MAX_RESOURCE: usize = 200;

/// Whether the gate answers this request as IMDS: the env has an Azure identity and the
/// request is for 169.254.169.254:80 under `/metadata`. Other paths there go on to the policy,
/// which never dials that address.
pub fn answers(policy: &Policy, target: &Target, path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    policy.azure.is_some()
        && !target.tls
        && target.port == 80
        && target.host == IMDS_HOST
        && (path == "/metadata" || path.starts_with("/metadata/"))
}

/// One answer: its status and JSON body, and how the event records it.
struct Answer {
    status: StatusCode,
    body: Value,
    /// The deny reason, for a request refused for want of a grant or the vault.
    refused: Option<&'static str>,
    message: String,
    binding: Option<String>,
}

impl Answer {
    fn error(status: StatusCode, error: &str, description: String) -> Self {
        Answer {
            status,
            body: json!({ "error": error, "error_description": description }),
            refused: None,
            message: description,
            binding: None,
        }
    }

    fn refused(mut self, reason: &'static str) -> Self {
        self.refused = Some(reason);
        self
    }
}

pub async fn answer(
    state: &State,
    ctx: &ConnCtx,
    req: Request<Incoming>,
    target: &Target,
) -> Response<Body> {
    let started = Instant::now();
    ctx.activity.set_rule_idle(None);
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let a = token(state, &req, target).await;
    let mut ev = Event {
        kind: Some(EventKind::Http),
        intake: Some(ctx.intake),
        method: Some(method),
        host: Some(IMDS_HOST.into()),
        port: Some(80),
        path: Some(clip_path(&path)),
        status: Some(a.status.as_u16()),
        binding: a.binding,
        ms: Some(started.elapsed().as_millis() as u64),
        ..Default::default()
    };
    match a.refused {
        Some(reason) => {
            ev.verdict = Some(Verdict::Deny);
            ev.reason = Some(reason.into());
            ev.message = Some(a.message);
        }
        None => {
            ev.verdict = Some(Verdict::Allow);
            ev.message = Some(format!("answered by the gate: {}", a.message));
        }
    }
    state.events.emit(ev);
    let mut resp = Response::new(full(serde_json::to_vec(&a.body).unwrap_or_default()));
    *resp.status_mut() = a.status;
    let h = resp.headers_mut();
    h.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

async fn token(state: &State, req: &Request<Incoming>, target: &Target) -> Answer {
    let bad = |d: &str| Answer::error(StatusCode::BAD_REQUEST, "invalid_request", d.into());
    if !host_agrees(req.headers(), target) {
        return bad("invalid or ambiguous destination").refused("invalid_host");
    }
    if !req.uri().path().eq_ignore_ascii_case(IMDS_TOKEN_PATH) {
        return Answer::error(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("luoto answers only IMDS's managed identity tokens ({IMDS_TOKEN_PATH})"),
        );
    }
    if req.method() != Method::GET {
        return Answer::error(
            StatusCode::METHOD_NOT_ALLOWED,
            "invalid_request",
            "the token endpoint takes GET".into(),
        );
    }
    // Clients probe for IMDS without the header and take this answer as its presence.
    let metadata = req
        .headers()
        .get("metadata")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if !metadata {
        return bad("Required metadata header not specified");
    }
    let query = req.uri().query().unwrap_or("");
    let Some(resource) = param(query, "resource").or_else(|| param(query, "scope")) else {
        return bad("Required audience variable not specified");
    };
    let resource: String = resource.chars().take(MAX_RESOURCE).collect();
    let policy = state.policy();
    let granted = Audience::parse(&resource).and_then(|aud| {
        let binding = policy.azure.as_ref()?.audiences.get(&aud)?;
        Some((aud, binding.clone()))
    });
    let Some((aud, binding)) = granted else {
        let env = &state.cfg.env;
        return Answer::error(
            StatusCode::BAD_REQUEST,
            "invalid_resource",
            format!(
                "luoto: env `{env}` has no Azure credential for resource `{resource}`. The user \
                 grants Resource Manager (subscriptions), Key Vault (key_vaults), Storage \
                 (storage_accounts) and Microsoft Graph (graph) under [credentials.azure] in \
                 the env's config on the host"
            ),
        )
        .refused("guard");
    };
    let Some(vault) = state.vault() else {
        return bad("luoto: the env has no vault yet; the user runs `luoto up` on the host")
            .refused("locked");
    };
    let token = match vault.get(&binding).await {
        Ok(t) => t,
        Err(CredentialError::Locked) => {
            return bad(
                "luoto: the vault is locked; the user must run `luoto vault unlock` on the host",
            )
            .refused("locked");
        }
        Err(CredentialError::NotBound) => {
            let env = &state.cfg.env;
            return bad(&format!(
                "luoto: credential `{binding}` is not registered with the vault; the user runs \
                 `luoto up -e {env}` on the host"
            ))
            .refused("not_bound");
        }
        Err(CredentialError::Failed(m)) => {
            let mut a = Answer::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                format!("luoto: no token for {}: {m}", aud.resource()),
            );
            a.binding = Some(binding);
            return a;
        }
    };
    let (Some(placeholder), Some(claims)) = (placeholder(&token), claims(&token)) else {
        return Answer::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            format!(
                "luoto: the token for {} is not a JWT, so no placeholder can carry its claims",
                aud.resource()
            ),
        );
    };
    let now = Utc::now().timestamp();
    let time = |k: &str| claims.get(k).and_then(Value::as_i64);
    let expires_on = time("exp").unwrap_or(now + 3599);
    let expires_in = (expires_on - now).max(0).to_string();
    let client_id = ["appid", "azp"]
        .iter()
        .find_map(|k| claims.get(*k).and_then(Value::as_str))
        .unwrap_or_default();
    Answer {
        status: StatusCode::OK,
        body: json!({
            "access_token": placeholder,
            "client_id": client_id,
            "expires_in": expires_in,
            "expires_on": expires_on.to_string(),
            "ext_expires_in": expires_in,
            "not_before": time("nbf").unwrap_or(now).to_string(),
            "resource": resource,
            "token_type": "Bearer",
        }),
        refused: None,
        message: format!(
            "managed identity token for {} (a placeholder: the gate adds the real token)",
            aud.resource()
        ),
        binding: Some(binding),
    }
}

/// `token` with only the [`CLAIMS`] tools read and a signature that can't verify; its header
/// as it is. `None` unless it is a signed JWT (three parts, its claims a JSON object).
pub fn placeholder(token: &str) -> Option<String> {
    let mut parts = token.split('.');
    let (Some(header), Some(_), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if header.is_empty() {
        return None;
    }
    let mut kept = claims(token)?;
    kept.retain(|k, _| CLAIMS.contains(&k.as_str()));
    let payload = B64URL.encode(serde_json::to_vec(&Value::Object(kept)).ok()?);
    Some(format!("{header}.{payload}.{}", B64URL.encode(SIGNATURE)))
}

/// The claims of JWT `token`.
fn claims(token: &str) -> Option<Map<String, Value>> {
    let payload = token.split('.').nth(1)?;
    let bytes = B64URL.decode(payload.trim_end_matches('=')).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// The first value of query parameter `name`, percent-decoded.
fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (decode(k)? == name).then(|| decode(v)).flatten()
    })
}

fn decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: &Value) -> String {
        let header = B64URL.encode(br#"{"typ":"JWT","alg":"RS256","kid":"k1"}"#);
        let payload = B64URL.encode(serde_json::to_vec(claims).unwrap());
        format!("{header}.{payload}.c2lnbmF0dXJlLW9mLXRoZS1yZWFsLXRva2Vu")
    }

    #[test]
    fn the_placeholder_keeps_the_claims_tools_read_and_cannot_verify() {
        let kept = json!({"aud": "https://management.azure.com/", "iss": "https://sts/t-1/",
            "iat": 1_899_990_000, "nbf": 1_899_990_000, "exp": 1_900_000_000, "tid": "t-1",
            "oid": "o-1", "sub": "s-1", "appid": "a-1", "azp": "a-1", "idtyp": "user",
            "ver": "1.0"});
        let mut all = kept.clone();
        for (k, v) in [
            ("name", json!("Eetu")),
            ("upn", json!("eetu@example.com")),
            ("unique_name", json!("eetu@example.com")),
            ("ipaddr", json!("203.0.113.7")),
            ("wids", json!(["62e90394-69f5-4237-9190-012177145e10"])),
            ("scp", json!("user_impersonation")),
            ("xms_tcdt", json!(1_600_000_000)),
        ] {
            all[k] = v;
        }
        let real = jwt(&all);
        let p = placeholder(&real).unwrap();
        let (real_header, _) = real.split_once('.').unwrap();
        let (p_header, _) = p.split_once('.').unwrap();
        assert_eq!(p_header, real_header);
        let (_, real_sig) = real.rsplit_once('.').unwrap();
        let (_, p_sig) = p.rsplit_once('.').unwrap();
        assert!(!p.contains(real_sig));
        assert_eq!(B64URL.decode(p_sig).unwrap(), SIGNATURE.as_bytes());
        assert_eq!(Value::Object(super::claims(&p).unwrap()), kept);
    }

    #[test]
    fn only_a_signed_jwt_gets_a_placeholder() {
        let payload = B64URL.encode(br#"{"exp":1}"#);
        for not in [
            "opaque-token".to_string(),
            format!("h.{payload}"),
            format!("h.{payload}.s.extra"),
            format!(".{payload}.s"),
            "h.bm90IGpzb24.s".to_string(),
            format!("h.{}.s", B64URL.encode(b"[1]")),
        ] {
            assert_eq!(placeholder(&not), None, "{not}");
        }
        assert!(placeholder(&format!("h.{payload}.s")).is_some());
    }

    #[test]
    fn only_plain_http_to_the_metadata_address_under_metadata_is_answered() {
        let azure = Policy {
            azure: Some(Default::default()),
            ..Default::default()
        };
        let target = |host: &str, port, tls| Target {
            host: host.into(),
            port,
            tls,
        };
        let imds = target(IMDS_HOST, 80, false);
        assert!(answers(&azure, &imds, IMDS_TOKEN_PATH));
        assert!(answers(&azure, &imds, "/METADATA/instance"));
        assert!(answers(&azure, &imds, "/metadata"));
        assert!(!answers(&azure, &imds, "/metadatax"));
        assert!(!answers(&azure, &imds, "/latest/meta-data/"));
        assert!(!answers(
            &azure,
            &target(IMDS_HOST, 443, true),
            IMDS_TOKEN_PATH
        ));
        assert!(!answers(
            &azure,
            &target(IMDS_HOST, 8080, false),
            IMDS_TOKEN_PATH
        ));
        assert!(!answers(
            &azure,
            &target("169.254.169.253", 80, false),
            IMDS_TOKEN_PATH
        ));
        // Without Azure credentials the address is the policy's, which never dials it.
        assert!(!answers(&Policy::default(), &imds, IMDS_TOKEN_PATH));
    }

    #[test]
    fn query_parameters_are_decoded_as_clients_encode_them() {
        let q = "api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F&x=a+b";
        assert_eq!(
            param(q, "resource").as_deref(),
            Some("https://management.azure.com/")
        );
        assert_eq!(param(q, "x").as_deref(), Some("a b"));
        assert_eq!(param(q, "scope"), None);
        assert_eq!(
            param("scope=https://vault.azure.net/.default", "scope").as_deref(),
            Some("https://vault.azure.net/.default")
        );
        assert_eq!(param("resource=%zz", "resource"), None);
        assert_eq!(param("resource=%e2%82", "resource"), None);
    }
}
