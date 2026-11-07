//! Destination host handling: one canonical form, matching, wildcard safety, and the
//! private-address guard. Everything that compares or dials a host goes through here so
//! policy and connection never disagree about what a name means.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostError {
    #[error("empty host")]
    Empty,
    #[error("host contains userinfo")]
    Userinfo,
    #[error("invalid host name: {0}")]
    Invalid(String),
    #[error("invalid port in authority: {0}")]
    Port(String),
}

/// Canonical host: lowercase ASCII (IDNA-encoded), no trailing dot, IPv6 without brackets.
pub fn normalize_host(raw: &str) -> Result<String, HostError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(HostError::Empty);
    }
    if raw.contains('@') {
        return Err(HostError::Userinfo);
    }
    let unbracketed = raw
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(raw);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let without_dot = unbracketed.strip_suffix('.').unwrap_or(unbracketed);
    if without_dot.is_empty() || without_dot.ends_with('.') {
        return Err(HostError::Invalid(raw.to_string()));
    }
    let ascii = idna::domain_to_ascii(without_dot).map_err(|_| HostError::Invalid(raw.into()))?;
    let valid = !ascii.is_empty()
        && ascii.len() <= 253
        && ascii.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !valid {
        return Err(HostError::Invalid(raw.to_string()));
    }
    Ok(ascii)
}

/// Split `host[:port]` / `[v6]:port` into a canonical host and optional port.
pub fn split_authority(authority: &str) -> Result<(String, Option<u16>), HostError> {
    let authority = authority.trim();
    if authority.contains('@') {
        return Err(HostError::Userinfo);
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (v6, after) = rest
            .split_once(']')
            .ok_or_else(|| HostError::Invalid(authority.into()))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(parse_port(p)?),
            None if after.is_empty() => None,
            None => return Err(HostError::Invalid(authority.into())),
        };
        return Ok((normalize_host(v6)?, port));
    }
    match authority.rsplit_once(':') {
        // A bare IPv6 literal without brackets has several colons; treat as host only.
        Some((host, _)) if host.contains(':') => Ok((normalize_host(authority)?, None)),
        Some((host, port)) => Ok((normalize_host(host)?, Some(parse_port(port)?))),
        None => Ok((normalize_host(authority)?, None)),
    }
}

fn parse_port(p: &str) -> Result<u16, HostError> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(HostError::Port(p.to_string())),
        Ok(n) => Ok(n),
    }
}

/// Does a rule host pattern cover `host`? Patterns: `*`, `*.example.com` (subdomains only,
/// not the apex), an IP, a CIDR, or an exact name. `host` must already be canonical.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    if pattern.contains('/') {
        return match (pattern.parse::<IpNet>(), host.parse::<IpAddr>()) {
            (Ok(net), Ok(ip)) => net.contains(&ip),
            _ => false,
        };
    }
    pattern == host
}

/// Domains whose subdomains belong to unrelated tenants but which are not on the Public
/// Suffix List. A wildcard over one of these hands any tenant (an attacker included) a
/// destination, and with attacker-run DNS, a lookup channel.
pub const MULTI_TENANT: &[&str] = &[
    "amazonaws.com",
    "cloudfront.net",
    "googleapis.com",
    "googleusercontent.com",
    "azurewebsites.net",
    "blob.core.windows.net",
    "azureedge.net",
    "trafficmanager.net",
    "herokuapp.com",
    "ngrok.io",
    "ngrok.app",
    "ngrok-free.app",
    "trycloudflare.com",
    "serveo.net",
    "loca.lt",
    "sentry.io",
    "ingest.sentry.io",
    "akamaized.net",
    "fastly.net",
    "firebaseio.com",
    "web.app",
    "netlify.app",
    "supabase.co",
    "workers.dev",
    "pages.dev",
    "vercel.app",
    "github.io",
    "githubusercontent.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WildcardRisk {
    /// Not a wildcard, or a wildcard under an ordinary registrable domain.
    None,
    /// `*` — every host. Reads alone become an exfiltration channel (query strings).
    Everything,
    /// `*.x` where `x` is itself a public suffix (`*.com`, `*.github.io`).
    PublicSuffix,
    /// `*.x` where `x` is a known multi-tenant domain.
    MultiTenant,
}

pub fn wildcard_risk(pattern: &str) -> WildcardRisk {
    if pattern == "*" {
        return WildcardRisk::Everything;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return WildcardRisk::None;
    };
    let is_suffix = psl::suffix(suffix.as_bytes())
        .map(|s| s.as_bytes() == suffix.as_bytes())
        .unwrap_or(true);
    if is_suffix || !suffix.contains('.') {
        return WildcardRisk::PublicSuffix;
    }
    let multi = MULTI_TENANT
        .iter()
        .any(|m| suffix == *m || suffix.ends_with(&format!(".{m}")));
    if multi {
        WildcardRisk::MultiTenant
    } else {
        WildcardRisk::None
    }
}

/// Addresses the gate must never dial unless a rule names them explicitly: loopback,
/// RFC 1918, link-local (cloud metadata), CGNAT, unique-local v6, the podman/docker host
/// gateways, multicast, and v4 addresses smuggled inside v6 forms (mapped, NAT64, 6to4).
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking (our fake IPs)
        || o[0] >= 240 // reserved
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    let seg = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
    if seg[0] == 0x64 && seg[1] == 0xff9b {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            seg[6] as u8,
            (seg[7] >> 8) as u8,
            seg[7] as u8,
        );
        return seg[2] == 1 || is_private_v4(v4);
    }
    // 6to4 2002::/16 embeds a v4 address
    if seg[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        );
        return is_private_v4(v4);
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80 // link local fe80::/10
        || (seg[0] & 0xffc0) == 0xfec0 // site local (deprecated)
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation
        || (seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0) // discard 100::/64
        || ip.to_ipv4().is_some_and(|v4| ip.segments()[..6] == [0; 6] && is_private_v4(v4))
}

/// Addresses the gate never dials, even for a rule that allows private ones: itself
/// (loopback, unspecified), cloud metadata, multicast, luoto's own vault and env networks
/// (10.212.0.0/16, 10.213.0.0/16) and the gate's fake addresses.
pub fn is_never_dialed(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => {
                return v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_multicast()
                    || v6 == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
            }
        },
    };
    let o = v4.octets();
    v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_multicast()
        || v4.is_broadcast()
        || o == [169, 254, 169, 254]
        || (o[0] == 10 && (o[1] == 212 || o[1] == 213))
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
}

/// A request path as the gate matches and forwards it. Percent-encoded unreserved characters
/// (`%66` for `f`, `%2e` for `.`) are decoded, since RFC 3986 makes them the same path. A path
/// with a dot segment, an empty segment or a backslash, in any spelling, is refused: servers
/// resolve those differently, so a rule or credential matched on one path could reach another.
pub fn canonical_path(raw: &str) -> Result<String, &'static str> {
    if raw == "*" {
        return Ok(raw.to_string());
    }
    if !raw.starts_with('/') {
        return Err("no leading /");
    }
    let b = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = raw.get(i + 1..i + 3).ok_or("a cut-off percent escape")?;
                let v = u8::from_str_radix(hex, 16).map_err(|_| "a malformed percent escape")?;
                if v.is_ascii_alphanumeric() || b"-._~".contains(&v) {
                    out.push(v as char);
                } else if v == b'\\' {
                    return Err("a backslash");
                } else {
                    out.push('%');
                    out.push_str(hex);
                }
                i += 3;
            }
            b'\\' => return Err("a backslash"),
            c if c.is_ascii() => {
                out.push(c as char);
                i += 1;
            }
            _ => return Err("a non-ASCII byte"),
        }
    }
    let segments: Vec<&str> = out[1..].split('/').collect();
    let last = segments.len() - 1;
    for (n, s) in segments.iter().enumerate() {
        if *s == "." || *s == ".." {
            return Err("a dot segment");
        }
        if s.is_empty() && n != last {
            return Err("an empty segment");
        }
    }
    Ok(out)
}

/// The host in what a user typed for one: a bare name, `host:port`, or a URL.
pub fn host_of(target: &str) -> &str {
    let t = target.trim();
    let no_scheme = t.split_once("://").map_or(t, |(_, r)| r);
    let authority = no_scheme.split(['/', '?', '#']).next().unwrap_or(no_scheme);
    authority
        .rsplit_once(':')
        .filter(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .map_or(authority, |(h, _)| h)
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_paths_are_canonical_or_refused() {
        use super::canonical_path as c;
        assert_eq!(c("/").unwrap(), "/");
        assert_eq!(c("/v1/messages").unwrap(), "/v1/messages");
        assert_eq!(c("/repos/o/r/").unwrap(), "/repos/o/r/");
        assert_eq!(c("/v1/%66iles").unwrap(), "/v1/files");
        assert_eq!(c("/a/%7Euser").unwrap(), "/a/~user");
        // Reserved escapes stay as they are: npm's scoped packages need `%2f`.
        assert_eq!(c("/@scope%2fpkg").unwrap(), "/@scope%2fpkg");
        assert_eq!(c("*").unwrap(), "*");
        for bad in [
            "/v1//files",
            "/v1/./files",
            "/v1/x/../files",
            "/info/lfs/%2e%2e/x",
            "/info/lfs/.%2E/x",
            "/a/..",
            "/a\\b",
            "/a%5cb",
            "/a%5Cb",
            "/a%2",
            "/a%zz",
            "v1/files",
        ] {
            assert!(c(bad).is_err(), "{bad} must be refused");
        }
    }

    use super::*;

    #[test]
    fn normalizes_case_dot_and_idna() {
        assert_eq!(normalize_host("Docs.RS.").unwrap(), "docs.rs");
        assert_eq!(
            normalize_host("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(normalize_host("[::1]").unwrap(), "::1");
        assert_eq!(normalize_host("user@evil.com"), Err(HostError::Userinfo));
        assert!(normalize_host("a..b").is_err());
        assert!(normalize_host("bad host").is_err());
        assert!(normalize_host("evil.com\n{\"kind\":\"allow\"}").is_err());
    }

    #[test]
    fn splits_authorities() {
        assert_eq!(
            split_authority("GitHub.com:443").unwrap(),
            ("github.com".into(), Some(443))
        );
        assert_eq!(
            split_authority("[2001:db8::1]:8443").unwrap(),
            ("2001:db8::1".into(), Some(8443))
        );
        assert_eq!(
            split_authority("example.com").unwrap(),
            ("example.com".into(), None)
        );
        assert!(split_authority("github.com@evil.com:443").is_err());
        assert!(split_authority("example.com:0").is_err());
        assert!(split_authority("example.com:99999").is_err());
    }

    #[test]
    fn matches_patterns() {
        assert!(host_matches("*.example.com", "a.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
        assert!(host_matches("docs.rs", "docs.rs"));
        assert!(!host_matches("docs.rs", "evil-docs.rs"));
        assert!(host_matches("10.0.0.0/8", "10.1.2.3"));
        assert!(!host_matches("10.0.0.0/8", "11.1.2.3"));
        assert!(host_matches("*", "anything.test"));
    }

    #[test]
    fn classifies_wildcards() {
        assert_eq!(wildcard_risk("docs.rs"), WildcardRisk::None);
        assert_eq!(wildcard_risk("*"), WildcardRisk::Everything);
        assert_eq!(wildcard_risk("*.com"), WildcardRisk::PublicSuffix);
        assert_eq!(wildcard_risk("*.co.uk"), WildcardRisk::PublicSuffix);
        assert_eq!(wildcard_risk("*.github.io"), WildcardRisk::PublicSuffix);
        assert_eq!(
            wildcard_risk("*.s3.amazonaws.com"),
            WildcardRisk::PublicSuffix
        );
        assert_eq!(wildcard_risk("*.amazonaws.com"), WildcardRisk::MultiTenant);
        assert_ne!(wildcard_risk("*.trycloudflare.com"), WildcardRisk::None);
        assert_eq!(wildcard_risk("*.sentry.io"), WildcardRisk::MultiTenant);
        assert_eq!(wildcard_risk("*.mycompany.dev"), WildcardRisk::None);
    }

    #[test]
    fn some_addresses_stay_closed_to_private_rules() {
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "10.212.1.1",
            "10.213.7.2",
            "198.18.0.5",
            "::1",
            "::ffff:127.0.0.1",
            "fd00:ec2::254",
        ] {
            assert!(is_never_dialed(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["10.1.2.3", "192.168.127.254", "169.254.1.2", "fd12::1"] {
            assert!(!is_never_dialed(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn private_guard_covers_smuggled_forms() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.127.254",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "198.18.0.5",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.1.1",
            "64:ff9b::c0a8:7ffe",
            "2002:c0a8:0101::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip} should be private");
        }
        for ip in [
            "1.1.1.1",
            "140.82.112.3",
            "2606:4700::1111",
            "64:ff9b::0808:0808",
        ] {
            assert!(!is_private(ip.parse().unwrap()), "{ip} should be public");
        }
    }

    #[test]
    fn host_of_takes_the_host_from_what_was_typed() {
        assert_eq!(host_of("https://docs.rs/serde/latest"), "docs.rs");
        assert_eq!(host_of("docs.rs"), "docs.rs");
        assert_eq!(host_of("http://example.com:8080/x"), "example.com");
        assert_eq!(host_of("*.example.com"), "*.example.com");
        assert_eq!(host_of("example.com:"), "example.com:");
    }
}
