//! The env CA: mints leaf certificates for intercepted hosts and caches TLS server configs,
//! each for a day, so a long-running gate never serves an expired leaf.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use lru::LruCache;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::state::lock;

/// How long a leaf is valid: clients check it only at the handshake, and it is served for at
/// most `LEAF_REFRESH`, so it always has weeks left.
const LEAF_LIFETIME: Duration = Duration::days(30);
/// A leaf is valid from this long before it was minted, for a client clock a little behind.
const LEAF_BACKDATE: Duration = Duration::days(1);
/// How long a minted leaf is served before a new one: minting takes well under a millisecond.
const LEAF_REFRESH: Duration = Duration::days(1);

struct Leaf {
    config: Arc<ServerConfig>,
    minted: OffsetDateTime,
}

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pub cert_pem: String,
    /// Hex SHA-256 of `cert_pem`, which the host compares with the env's current CA.
    pub pem_sha256: String,
    cache: Mutex<LruCache<String, Leaf>>,
}

impl Ca {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("parse CA key")?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key).context("parse CA cert")?;
        Ok(Ca {
            issuer,
            cert_pem: cert_pem.to_string(),
            pem_sha256: hex::encode(Sha256::digest(cert_pem.as_bytes())),
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(2048).expect("nonzero"))),
        })
    }

    /// TLS server config presenting a leaf for `host` (DNS name or IP literal).
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        self.server_config_at(host, OffsetDateTime::now_utc())
    }

    fn server_config_at(&self, host: &str, now: OffsetDateTime) -> Result<Arc<ServerConfig>> {
        if let Some(leaf) = lock(&self.cache).get(host) {
            // A clock that went back counts as stale too.
            let age = now - leaf.minted;
            if age >= Duration::ZERO && age < LEAF_REFRESH {
                return Ok(leaf.config.clone());
            }
        }
        let config = Arc::new(self.mint(host, now)?);
        let leaf = Leaf {
            config: config.clone(),
            minted: now,
        };
        lock(&self.cache).put(host.to_string(), leaf);
        Ok(config)
    }

    fn mint(&self, host: &str, now: OffsetDateTime) -> Result<ServerConfig> {
        let leaf_key = KeyPair::generate().context("leaf key")?;
        let leaf = leaf_params(host, now)?
            .signed_by(&leaf_key, &self.issuer)
            .context("sign leaf")?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], key_der)
            .context("server config")?;
        // HTTP/1.1 only towards the sandbox: one framing to parse and police.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(cfg)
    }
}

fn leaf_params(host: &str, now: OffsetDateTime) -> Result<CertificateParams> {
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SanType::IpAddress(ip),
        Err(_) => SanType::DnsName(host.try_into().context("leaf SAN")?),
    }];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);
    params.distinguished_name = dn;
    params.not_before = now - LEAF_BACKDATE;
    params.not_after = now + LEAF_LIFETIME;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa};

    fn ca() -> Ca {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = params.self_signed(&key).unwrap();
        Ca::from_pem(&cert.pem(), &key.serialize_pem()).unwrap()
    }

    #[test]
    fn a_cached_leaf_is_minted_again_before_it_ages() {
        let ca = ca();
        let t0 = OffsetDateTime::now_utc();
        let first = ca.server_config_at("example.com", t0).unwrap();
        let later = t0 + Duration::hours(23);
        assert!(Arc::ptr_eq(
            &first,
            &ca.server_config_at("example.com", later).unwrap()
        ));
        let next_day = t0 + LEAF_REFRESH;
        let fresh = ca.server_config_at("example.com", next_day).unwrap();
        assert!(!Arc::ptr_eq(&first, &fresh));
        let clock_back = next_day - Duration::hours(1);
        let again = ca.server_config_at("example.com", clock_back).unwrap();
        assert!(!Arc::ptr_eq(&fresh, &again));
    }

    #[test]
    fn a_leaf_outlives_its_time_in_the_cache_by_weeks() {
        let now = OffsetDateTime::now_utc();
        let p = leaf_params("example.com", now).unwrap();
        assert!(p.not_before < now - Duration::hours(12));
        // Served until `LEAF_REFRESH` after minting, with this much left at the latest.
        assert!(p.not_after - (now + LEAF_REFRESH) >= Duration::days(28));
        assert!(leaf_params("10.0.0.1", now).is_ok());
    }
}
