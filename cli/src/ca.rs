//! Per-env CA. The certificate is trusted only inside that env's dev container; the key goes
//! to that env's gate. Never install it on the host. `up` renews it before it ends, and hands
//! the new one to the gate, the tools volume and, by a restart, the dev container.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::paths::write_private;

/// How long a CA is valid.
const LIFETIME: Duration = Duration::days(730);
/// `up` renews a CA with less than this left: an env brought up at least every two months
/// never meets an expired one, and no leaf the gate mints before then (30 days) outlives it.
const RENEW_MARGIN: Duration = Duration::days(60);

pub struct EnvCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub not_after: OffsetDateTime,
}

impl EnvCa {
    /// What the gate reports of the CA it has (`GateStatus::ca_pem_sha256`).
    pub fn pem_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.cert_pem.as_bytes()))
    }
}

/// What `ensure` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Made {
    Kept,
    New,
    /// Replaced a CA that ends, or ended, at this time.
    Renewed(OffsetDateTime),
}

/// Whether a CA valid until `not_after` is renewed at `now`.
fn due(not_after: OffsetDateTime, now: OffsetDateTime) -> bool {
    not_after - now < RENEW_MARGIN
}

/// The env's CA in `dir` (its state folder): made on the first `up`, renewed when less than
/// `RENEW_MARGIN` is left.
pub fn ensure(dir: &Path, env: &str) -> Result<(EnvCa, Made)> {
    ensure_at(dir, env, OffsetDateTime::now_utc())
}

fn ensure_at(dir: &Path, env: &str, now: OffsetDateTime) -> Result<(EnvCa, Made)> {
    let made = match load(dir)? {
        Some(ca) if !due(ca.not_after, now) => return Ok((ca, Made::Kept)),
        Some(ca) => Made::Renewed(ca.not_after),
        None => Made::New,
    };
    let ca = generate(env, now)?;
    // Key first: interrupted in between, the old certificate stays, and is renewed again.
    write_private(&dir.join("ca.key"), ca.key_pem.as_bytes())?;
    write_private(&dir.join("ca.crt"), ca.cert_pem.as_bytes())?;
    Ok((ca, made))
}

/// The env's CA in `dir`; `None` before its first `up`.
pub fn load(dir: &Path) -> Result<Option<EnvCa>> {
    let crt = dir.join("ca.crt");
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(&crt),
        std::fs::read_to_string(dir.join("ca.key")),
    ) else {
        return Ok(None);
    };
    let not_after = not_after(&cert_pem).with_context(|| {
        format!(
            "{}: remove it and the ca.key beside it, and `luoto up` makes a new CA",
            crt.display()
        )
    })?;
    Ok(Some(EnvCa {
        cert_pem,
        key_pem,
        not_after,
    }))
}

fn not_after(cert_pem: &str) -> Result<OffsetDateTime> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| anyhow!("not a PEM certificate ({e})"))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| anyhow!("not an X.509 certificate ({e})"))?;
    Ok(cert.validity().not_after.to_datetime())
}

fn generate(env: &str, now: OffsetDateTime) -> Result<EnvCa> {
    let kp = KeyPair::generate().context("generate CA key")?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("luoto sandbox CA ({env})"));
    dn.push(DnType::OrganizationName, "luoto");
    params.distinguished_name = dn;
    params.not_before = now - Duration::days(1);
    params.not_after = now + LIFETIME;
    let cert_pem = params.self_signed(&kp).context("self-sign CA")?.pem();
    Ok(EnvCa {
        not_after: not_after(&cert_pem)?,
        cert_pem,
        key_pem: kp.serialize_pem(),
    })
}

/// What `up` says after renewing the env's CA.
pub fn renewal_note(old_not_after: OffsetDateTime, new: &EnvCa) -> String {
    format!(
        "the env CA {} on {}, so a new one valid until {} replaces it; the gate signs with it at once",
        if old_not_after <= OffsetDateTime::now_utc() {
            "expired"
        } else {
            "expires"
        },
        old_not_after.date(),
        new.not_after.date()
    )
}

/// What `status` and `doctor` say of the env's CA in `dir`: only when it is due for renewal,
/// or can't be read.
pub fn notice(dir: &Path, env: &str) -> Option<String> {
    match load(dir) {
        Ok(Some(ca)) => due_notice(ca.not_after, OffsetDateTime::now_utc(), env),
        Ok(None) => None,
        Err(e) => Some(format!("unreadable: {e:#}")),
    }
}

fn due_notice(not_after: OffsetDateTime, now: OffsetDateTime, env: &str) -> Option<String> {
    if !due(not_after, now) {
        return None;
    }
    let date = not_after.date();
    let renew = format!("`luoto up -e {env}` renews it");
    Some(if not_after <= now {
        format!("EXPIRED on {date}, so HTTPS in the env fails; {renew}")
    } else {
        let left = match (not_after - now).whole_days() {
            0 => "within a day".to_string(),
            1 => "in 1 day".to_string(),
            n => format!("in {n} days"),
        };
        format!("expires on {date} ({left}); {renew}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::Issuer;
    use x509_parser::prelude::{FromDer, X509Certificate};

    #[test]
    fn renewal_is_due_within_the_margin_and_after_the_end() {
        let now = OffsetDateTime::now_utc();
        assert!(!due(now + LIFETIME, now));
        assert!(!due(now + RENEW_MARGIN, now));
        assert!(due(now + RENEW_MARGIN - Duration::seconds(1), now));
        assert!(due(now, now));
        assert!(due(now - Duration::days(3), now));

        assert_eq!(due_notice(now + RENEW_MARGIN, now, "web"), None);
        let soon = due_notice(now + Duration::days(20), now, "web").unwrap();
        assert!(soon.contains("in 20 days") && soon.contains("luoto up -e web"));
        let past = due_notice(now - Duration::days(1), now, "web").unwrap();
        assert!(past.starts_with("EXPIRED on"));
    }

    #[test]
    fn a_ca_is_kept_until_its_renewal_is_due() {
        let dir = tempfile::tempdir().unwrap();
        let now = OffsetDateTime::now_utc();
        assert!(load(dir.path()).unwrap().is_none());
        let (first, made) = ensure_at(dir.path(), "web", now).unwrap();
        assert_eq!(made, Made::New);
        assert!(first.not_after - now > LIFETIME - Duration::seconds(2));
        let (kept, made) = ensure_at(dir.path(), "web", first.not_after - RENEW_MARGIN).unwrap();
        assert_eq!(made, Made::Kept);
        assert_eq!(
            (kept.cert_pem, kept.key_pem),
            (first.cert_pem, first.key_pem)
        );
    }

    /// A leaf for `example.com` that `ca`'s key signs, as the gate mints them.
    fn leaf_der(ca: &EnvCa) -> Vec<u8> {
        let key = KeyPair::from_pem(&ca.key_pem).unwrap();
        let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, key).unwrap();
        let mut params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params.use_authority_key_identifier_extension = true;
        params
            .signed_by(&KeyPair::generate().unwrap(), &issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    #[test]
    fn a_ca_near_or_past_its_end_is_replaced_by_one_that_chains_new_leaves() {
        for left in [Duration::days(59), Duration::days(-10)] {
            let dir = tempfile::tempdir().unwrap();
            let now = OffsetDateTime::now_utc();
            // Made long enough ago that `left` remains of it.
            let (old, _) = ensure_at(dir.path(), "web", now + left - LIFETIME).unwrap();
            let (new, made) = ensure_at(dir.path(), "web", now).unwrap();
            assert_eq!(made, Made::Renewed(old.not_after));
            assert_ne!(new.key_pem, old.key_pem);
            assert_ne!(new.pem_sha256(), old.pem_sha256());
            assert!(new.not_after - now > LIFETIME - Duration::seconds(2));
            let on_disk = load(dir.path()).unwrap().unwrap();
            assert_eq!(
                (on_disk.cert_pem.as_str(), on_disk.key_pem.as_str()),
                (new.cert_pem.as_str(), new.key_pem.as_str())
            );

            let (_, new_pem) = x509_parser::pem::parse_x509_pem(new.cert_pem.as_bytes()).unwrap();
            let (_, old_pem) = x509_parser::pem::parse_x509_pem(old.cert_pem.as_bytes()).unwrap();
            let (new_cert, old_cert) =
                (new_pem.parse_x509().unwrap(), old_pem.parse_x509().unwrap());
            assert!(new_cert.is_ca());
            assert_eq!(new_cert.subject(), old_cert.subject());
            let der = leaf_der(&new);
            let (_, leaf) = X509Certificate::from_der(&der).unwrap();
            assert_eq!(leaf.issuer(), new_cert.subject());
            assert!(leaf.verify_signature(Some(new_cert.public_key())).is_ok());
            assert!(leaf.verify_signature(Some(old_cert.public_key())).is_err());
        }
    }
}
