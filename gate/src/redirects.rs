//! Redirect permits: a GET or HEAD response from where the policy lets a service redirect
//! (`Policy::redirects`) that sends the client to a URL on one of its targets lets that exact
//! URL through, for GET and HEAD, for [`TTL`]. The sandbox never picks the URL: the upstream
//! named it in a response to a request the policy allowed. Kept in memory only, and dropped
//! when a policy is applied.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use http::Uri;
use luoto_shared::host::{canonical_path, host_matches, normalize_host};

/// How long a redirect's URL stays open: a download and its ranged retries.
pub const TTL: Duration = Duration::from_secs(600);
/// The most permits kept; the one expiring first goes to make room.
const MAX: usize = 4096;

/// One URL a redirect named: scheme, host, port, canonical path and query in one spelling
/// ([`decode`]).
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
}

impl Url {
    /// A request's URL as permits compare it; `query` with or without its `?`.
    pub fn of(tls: bool, host: &str, port: u16, path: &str, query: &str) -> Url {
        Url {
            tls,
            host: host.to_ascii_lowercase(),
            port,
            path: path.to_string(),
            query: decode(query.strip_prefix('?').unwrap_or(query)),
        }
    }

    /// The URL `location` names when it is absolute, on one of `to`, and over HTTPS (plain
    /// HTTP only where `plain` says so: the integration tests' local servers).
    pub fn redirect(location: &str, to: &[&str], plain: impl Fn(&str) -> bool) -> Option<Url> {
        let uri: Uri = location.trim().parse().ok()?;
        let authority = uri.authority()?;
        if authority.as_str().contains('@') {
            return None;
        }
        let host = normalize_host(authority.host()).ok()?;
        if !to.iter().any(|p| host_matches(p, &host)) {
            return None;
        }
        let tls = match uri.scheme_str()? {
            "https" => true,
            "http" if plain(&host) => false,
            _ => return None,
        };
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let path = canonical_path(uri.path()).ok()?;
        Some(Url::of(tls, &host, port, &path, uri.query().unwrap_or("")))
    }
}

/// A query in one spelling, so a client that escapes it differently from the upstream still
/// names the same one: split on `&` and each pair's first `=` before anything is decoded (an
/// escaped `&` or `=` stays data), each piece decoded to its bytes and escaped again the same
/// way.
fn decode(s: &str) -> String {
    let escape = |b: &[u8]| -> String {
        b.iter()
            .map(|&c| {
                if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                    (c as char).to_string()
                } else {
                    format!("%{c:02X}")
                }
            })
            .collect()
    };
    s.split('&')
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => format!("{}={}", escape(&unescape(k)), escape(&unescape(v))),
            None => escape(&unescape(pair)),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// `%XX` escapes decoded, to bytes.
fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[derive(Default)]
pub struct Permits {
    open: Mutex<Open>,
}

/// The permits, and the generation of the policy they were granted under: applying a policy
/// clears them and moves it on, so a response to a request the old one allowed grants nothing.
#[derive(Default)]
struct Open {
    by_url: HashMap<Url, Permit>,
    generation: u64,
}

struct Permit {
    until: Instant,
    /// The rule whose response named the URL, for the request's event.
    from: String,
    /// The URL may be on a private address (`Redirect::allow_private`).
    private: bool,
}

/// What a permit lets through: the rule that named the URL, and whether it may be private.
#[derive(Clone, Debug, PartialEq)]
pub struct Granted {
    pub from: String,
    pub private: bool,
}

impl Permits {
    /// The policy generation a request starts under, taken before it reads the policy.
    pub fn generation(&self) -> u64 {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .generation
    }

    /// Open `url` for [`TTL`], unless a policy was applied since `generation`.
    pub fn grant(&self, url: Url, from: &str, private: bool, generation: u64, now: Instant) {
        let mut guard = self.open.lock().unwrap_or_else(|e| e.into_inner());
        if guard.generation != generation {
            return;
        }
        let open = &mut guard.by_url;
        open.retain(|_, p| p.until > now);
        if open.len() >= MAX && !open.contains_key(&url) {
            let first = open
                .iter()
                .min_by_key(|(_, p)| p.until)
                .map(|(u, _)| u.clone());
            if let Some(first) = first {
                open.remove(&first);
            }
        }
        open.insert(
            url,
            Permit {
                until: now + TTL,
                from: from.to_string(),
                private,
            },
        );
    }

    /// What named `url`, while its permit lasts, for GET and HEAD.
    pub fn allows(&self, method: &str, url: &Url, now: Instant) -> Option<Granted> {
        if method != "GET" && method != "HEAD" {
            return None;
        }
        let open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.by_url
            .get(url)
            .filter(|p| p.until > now)
            .map(|p| Granted {
                from: p.from.clone(),
                private: p.private,
            })
    }

    /// Drop every permit: a policy was applied.
    pub fn clear(&self) {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.by_url.clear();
        open.generation += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORAGE: &[&str] = &["*.blob.core.windows.net"];
    const LOCATION: &str =
        "https://abcvsblobprodweu1.blob.core.windows.net/b-1/F00.blob?sv=2019&sig=a%2Bb%3D&se=x";

    fn no_plain(_: &str) -> bool {
        false
    }

    #[test]
    fn a_redirect_names_one_exact_url_on_its_targets_over_https() {
        let url = Url::redirect(LOCATION, STORAGE, no_plain).unwrap();
        assert_eq!(
            (url.tls, url.host.as_str(), url.port, url.path.as_str()),
            (
                true,
                "abcvsblobprodweu1.blob.core.windows.net",
                443,
                "/b-1/F00.blob"
            )
        );
        assert_eq!(url.query, "sv=2019&sig=a%2Bb%3D&se=x");
        for refused in [
            "https://evil.example/b-1/F00.blob",
            "https://blob.core.windows.net.evil.example/x",
            "http://abc.blob.core.windows.net/x",
            "/relative/path",
            "https://user@abc.blob.core.windows.net/x",
            "https://abc.blob.core.windows.net/a/../b",
            "ftp://abc.blob.core.windows.net/x",
        ] {
            assert!(
                Url::redirect(refused, STORAGE, no_plain).is_none(),
                "{refused}"
            );
        }
        assert!(Url::redirect("http://store.test/x", &["store.test"], |_| true).is_some());
    }

    #[test]
    fn a_permit_opens_its_url_for_reads_until_it_expires() {
        let permits = Permits::default();
        let now = Instant::now();
        let url = Url::redirect(LOCATION, STORAGE, no_plain).unwrap();
        permits.grant(url, "azure-feeds", false, 0, now);
        let host = "abcvsblobprodweu1.blob.core.windows.net";
        // The client may escape the query its own way.
        let asked = Url::of(true, host, 443, "/b-1/F00.blob", "?sv=2019&sig=a+b%3D&se=x");
        assert_eq!(
            permits.allows("GET", &asked, now),
            Some(Granted {
                from: "azure-feeds".into(),
                private: false
            })
        );
        assert!(permits.allows("HEAD", &asked, now + TTL / 2).is_some());
        assert!(permits.allows("PUT", &asked, now).is_none());
        assert!(permits.allows("GET", &asked, now + TTL).is_none());
        let other = Url::of(true, host, 443, "/b-1/F00.blob", "?sv=2019&sig=other&se=x");
        assert!(permits.allows("GET", &other, now).is_none());
        let plain = Url::of(
            false,
            host,
            443,
            "/b-1/F00.blob",
            "?sv=2019&sig=a+b%3D&se=x",
        );
        assert!(permits.allows("GET", &plain, now).is_none());
        permits.clear();
        assert!(permits.allows("GET", &asked, now).is_none());
    }

    #[test]
    fn an_escaped_separator_stays_data() {
        let permits = Permits::default();
        let now = Instant::now();
        let at = |q: &str| Url::of(true, "s.blob.core.windows.net", 443, "/x", q);
        permits.grant(at("a=x%26b%3Dy"), "r", false, 0, now);
        assert!(permits.allows("GET", &at("a=x%26b%3dy"), now).is_some());
        assert!(permits.allows("GET", &at("a=x&b=y"), now).is_none());
        // Bytes that aren't UTF-8 stay themselves, never one replacement character.
        permits.grant(at("s=%FF"), "r", false, 0, now);
        assert!(permits.allows("GET", &at("s=%FE"), now).is_none());
    }

    #[test]
    fn a_policy_applied_since_the_request_began_grants_nothing() {
        let permits = Permits::default();
        let now = Instant::now();
        let url = Url::of(true, "s.blob.core.windows.net", 443, "/x", "sig=a");
        let before = permits.generation();
        permits.clear();
        permits.grant(url.clone(), "r", false, before, now);
        assert!(permits.allows("GET", &url, now).is_none());
        permits.grant(url.clone(), "r", false, permits.generation(), now);
        assert!(permits.allows("GET", &url, now).is_some());
    }

    #[test]
    fn a_permit_reaches_a_private_address_only_where_its_redirect_said() {
        let permits = Permits::default();
        let now = Instant::now();
        let store = |p: &str| Url::of(true, "minio.acme.internal", 443, p, "X-Amz-Signature=a");
        permits.grant(store("/own"), "git-1-feeds", true, 0, now);
        permits.grant(store("/public"), "azure-feeds", false, 0, now);
        assert!(permits.allows("GET", &store("/own"), now).unwrap().private);
        assert!(
            !permits
                .allows("GET", &store("/public"), now)
                .unwrap()
                .private
        );
    }

    #[test]
    fn permits_are_bounded_dropping_the_first_to_expire() {
        let permits = Permits::default();
        let start = Instant::now();
        let url = |i: usize| Url::of(true, "s.blob.core.windows.net", 443, &format!("/{i}"), "");
        for i in 0..=MAX {
            permits.grant(
                url(i),
                "r",
                false,
                0,
                start + Duration::from_millis(i as u64),
            );
        }
        let now = start + Duration::from_millis(MAX as u64);
        assert!(permits.allows("GET", &url(0), now).is_none());
        assert!(permits.allows("GET", &url(1), now).is_some());
        assert!(permits.allows("GET", &url(MAX), now).is_some());
    }
}
