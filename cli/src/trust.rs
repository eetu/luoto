//! CAs trusted besides the public roots: by the gate, which verifies every upstream, and by the
//! dev container, for what reaches it unread (a tunnel). `cas` in config.toml covers every host
//! (a company network that inspects TLS, roots this Mac trusts); an env's `[cas.<name>]` covers
//! the hosts it names (an internal service's CA, usually from a project's `[needs.ca.<name>]`).

use luoto_shared::host::{WildcardRisk, normalize_pattern, wildcard_risk};
use sha2::{Digest, Sha256};

/// A certificate as people check it.
#[derive(Clone, Debug, PartialEq)]
pub struct Cert {
    /// Its common name, else its whole subject.
    pub subject: String,
    /// SHA-256 of its DER, lowercase hex.
    pub sha256: String,
    pub not_after: time::Date,
    pub ca: bool,
    pub self_signed: bool,
    /// The certificate alone, as PEM.
    pub pem: String,
}

impl Cert {
    /// `Corp Root CA (SHA-256 1a2b3c4d5e6f7a8b…)`.
    pub fn named(&self) -> String {
        format!(
            "{} (SHA-256 {}…)",
            crate::text::display(&self.subject),
            &self.sha256[..16]
        )
    }
}

/// The certificates in PEM text; anything else in it (a key) is left out.
pub fn certs(text: &str) -> Result<Vec<Cert>, String> {
    let mut out = Vec::new();
    for block in text.split_inclusive("-----END CERTIFICATE-----") {
        let Some(at) = block.find("-----BEGIN CERTIFICATE-----") else {
            continue;
        };
        let pem_text = format!("{}\n", block[at..].trim_end());
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
            .map_err(|e| format!("not a PEM certificate ({e})"))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| format!("not an X.509 certificate ({e})"))?;
        let subject = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map_or_else(|| cert.subject().to_string(), str::to_string);
        out.push(Cert {
            subject,
            sha256: hex::encode(Sha256::digest(&pem.contents)),
            not_after: cert.validity().not_after.to_datetime().date(),
            ca: cert.is_ca(),
            self_signed: cert.subject() == cert.issuer(),
            pem: pem_text,
        });
    }
    if out.is_empty() {
        return Err("holds no PEM certificate".into());
    }
    Ok(out)
}

/// Domains no stranger can hold a name in, though they have one label.
const PRIVATE_SUFFIXES: &[&str] = &["internal", "local", "lan", "home.arpa", "corp"];

/// A host an env's CA covers, as the gate compares it: an exact host or address, or a wildcard
/// under a domain of one owner's (`*.corp.example`), never `*`, a range or a public suffix.
pub fn scope(pattern: &str) -> Result<String, String> {
    let p = normalize_pattern(pattern)
        .filter(|p| p != "*" && !p.contains('/'))
        .ok_or_else(|| {
            format!(
                "`{}` is not a host or a wildcard over one",
                crate::text::display(pattern)
            )
        })?;
    let private = p.strip_prefix("*.").is_some_and(|d| {
        PRIVATE_SUFFIXES
            .iter()
            .any(|s| d == *s || d.ends_with(&format!(".{s}")))
    });
    match wildcard_risk(&p) {
        WildcardRisk::None => Ok(p),
        _ if private => Ok(p),
        _ => Err(format!(
            "`{p}` spans names others can hold; name your own domain (`*.corp.example`)"
        )),
    }
}

/// The root CAs this Mac trusts besides the public ones, as a company's device management
/// installs them: self-signed CA certificates in its keychains that macOS takes as anchors.
#[cfg(target_os = "macos")]
pub fn mac_roots() -> Vec<Cert> {
    use std::process::{Command, Stdio};
    let Ok(out) = Command::new("security")
        .args(["find-certificate", "-a", "-p"])
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    let today = time::OffsetDateTime::now_utc().date();
    let mut seen = std::collections::BTreeSet::new();
    let found = certs(&String::from_utf8_lossy(&out.stdout)).unwrap_or_default();
    let candidates: Vec<Cert> = found
        .into_iter()
        .filter(|c| c.ca && c.self_signed && c.not_after >= today && seen.insert(c.sha256.clone()))
        .collect();
    let Ok(dir) = tempdir() else {
        return Vec::new();
    };
    let roots = candidates
        .into_iter()
        .filter(|c| {
            let file = dir.join(format!("{}.pem", c.sha256));
            std::fs::write(&file, &c.pem).is_ok()
                && Command::new("security")
                    .args(["verify-cert", "-p", "basic", "-L", "-q", "-c"])
                    .arg(&file)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
        })
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    roots
}

#[cfg(target_os = "macos")]
fn tempdir() -> std::io::Result<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("luoto-roots-{}", rand::random::<u64>()));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A self-signed CA certificate named `cn`, as PEM.
    pub(crate) fn ca_pem(cn: &str) -> String {
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn a_pem_file_gives_its_certificates_and_nothing_else() {
        let text = format!(
            "-----BEGIN PRIVATE KEY-----\nKKKK\n-----END PRIVATE KEY-----\n{}{}",
            ca_pem("Corp Root CA"),
            ca_pem("Corp Issuing CA")
        );
        let found = certs(&text).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].subject, "Corp Root CA");
        assert!(found[0].ca && found[0].self_signed);
        assert_eq!(found[0].sha256.len(), 64);
        assert!(!found.iter().any(|c| c.pem.contains("KEY")));
        assert!(found[1].named().starts_with("Corp Issuing CA (SHA-256 "));
        assert!(certs("no certificate here").is_err());
    }

    #[test]
    fn a_cas_scope_is_a_domain_of_one_owners() {
        for (typed, want) in [
            ("*.Corp.Example.com.", "*.corp.example.com"),
            ("nexus.corp.example", "nexus.corp.example"),
            ("10.20.0.5", "10.20.0.5"),
            ("*.internal", "*.internal"),
            ("*.svc.home.arpa", "*.svc.home.arpa"),
        ] {
            assert_eq!(scope(typed).as_deref(), Ok(want), "{typed}");
        }
        for typed in [
            "*",
            "*.com",
            "*.co.uk",
            "*.blob.core.windows.net",
            "10.0.0.0/8",
            "",
        ] {
            assert!(scope(typed).is_err(), "{typed}");
        }
    }
}
