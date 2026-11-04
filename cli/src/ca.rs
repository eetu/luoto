//! Per-env CA. The certificate is trusted only inside that env's dev container; the key goes
//! to that env's gate. Never install it on the host.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

use crate::paths::write_private;

pub struct EnvCa {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn ensure(dir: &Path, env: &str) -> Result<EnvCa> {
    let crt = dir.join("ca.crt");
    let key = dir.join("ca.key");
    if let (Ok(cert_pem), Ok(key_pem)) =
        (std::fs::read_to_string(&crt), std::fs::read_to_string(&key))
    {
        return Ok(EnvCa { cert_pem, key_pem });
    }
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
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(730);
    let cert = params.self_signed(&kp).context("self-sign CA")?;
    let ca = EnvCa {
        cert_pem: cert.pem(),
        key_pem: kp.serialize_pem(),
    };
    write_private(&key, ca.key_pem.as_bytes())?;
    std::fs::write(&crt, &ca.cert_pem).with_context(|| format!("write {}", crt.display()))?;
    Ok(ca)
}
