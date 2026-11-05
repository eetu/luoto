//! The env CA: mints leaf certificates for intercepted hosts and caches TLS server configs.

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
use time::{Duration, OffsetDateTime};

use crate::state::lock;

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pub cert_pem: String,
    cache: Mutex<LruCache<String, Arc<ServerConfig>>>,
}

impl Ca {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("parse CA key")?;
        let issuer = Issuer::from_ca_cert_pem(cert_pem, key).context("parse CA cert")?;
        Ok(Ca {
            issuer,
            cert_pem: cert_pem.to_string(),
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(2048).expect("nonzero"))),
        })
    }

    /// TLS server config presenting a leaf for `host` (DNS name or IP literal).
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if let Some(cfg) = lock(&self.cache).get(host) {
            return Ok(cfg.clone());
        }
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(host.try_into().context("leaf SAN")?),
        }];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(30);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let leaf_key = KeyPair::generate().context("leaf key")?;
        let leaf = params
            .signed_by(&leaf_key, &self.issuer)
            .context("sign leaf")?;

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], key_der)
            .context("server config")?;
        // HTTP/1.1 only towards the sandbox: one framing to parse and police.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        lock(&self.cache).put(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}
