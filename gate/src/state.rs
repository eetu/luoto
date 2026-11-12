//! Shared gate state. Policy, CA and vault settings live in the state volume so a restarted
//! gate serves immediately; secrets do not — credentials are fetched from the vault.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use anyhow::{Context, Result};
use luoto_shared::policy::Policy;
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};

use crate::ca::Ca;
use crate::config::Config;
use crate::creds::VaultClient;
use crate::dns::FakeIps;
use crate::events::Emitter;
use crate::limits::Conns;
use crate::requests::Requests;

/// The gate's locks ignore poisoning: a panic in one connection's task must not stop the gate
/// serving the rest.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn read<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(PoisonError::into_inner)
}

pub fn write<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Serialize, Deserialize)]
pub struct VaultSettings {
    pub token: String,
}

pub struct State {
    pub cfg: Config,
    pub events: Emitter,
    pub conns: Conns,
    policy: RwLock<Arc<Policy>>,
    ca: RwLock<Option<Arc<Ca>>>,
    vault: RwLock<Option<Arc<VaultClient>>>,
    requests: Mutex<Requests>,
    pub fake_ips: Mutex<FakeIps>,
    pub client_tls: Arc<ClientConfig>,
    /// For a host with its own CA (a self-hosted forge): the public roots and that CA, which no
    /// other host's certificate may chain to.
    pub host_tls: std::collections::HashMap<String, Arc<ClientConfig>>,
}

impl State {
    pub fn load(cfg: Config) -> Result<Arc<Self>> {
        let dir = cfg.state_dir.clone();
        let policy = read_json::<Policy>(&dir.join("policy.json"))?.unwrap_or_else(|| Policy {
            env: cfg.env.clone(),
            ..Default::default()
        });
        let ca = match (
            std::fs::read_to_string(dir.join("ca.crt")),
            std::fs::read_to_string(dir.join("ca.key")),
        ) {
            (Ok(cert), Ok(key)) => Some(Arc::new(Ca::from_pem(&cert, &key)?)),
            _ => None,
        };
        let vault = read_json::<VaultSettings>(&dir.join("vault.json"))?
            .map(|v| Arc::new(VaultClient::new(cfg.vault_socket.clone(), v.token)));
        let client_tls = Arc::new(upstream_tls(&cfg, None)?);
        let host_tls = cfg
            .upstream_cas
            .iter()
            .map(|(host, pem)| {
                Ok((
                    host.to_ascii_lowercase(),
                    Arc::new(upstream_tls(&cfg, Some(pem.as_bytes()))?),
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Arc::new(State {
            events: Emitter::new(&cfg)?,
            conns: Conns::new(cfg.limits.conns),
            policy: RwLock::new(Arc::new(policy)),
            ca: RwLock::new(ca),
            vault: RwLock::new(vault),
            requests: Mutex::new(Requests::default()),
            fake_ips: Mutex::new(FakeIps::new()),
            client_tls,
            host_tls,
            cfg,
        }))
    }

    pub fn policy(&self) -> Arc<Policy> {
        read(&self.policy).clone()
    }

    pub fn ca(&self) -> Option<Arc<Ca>> {
        read(&self.ca).clone()
    }

    pub fn vault(&self) -> Option<Arc<VaultClient>> {
        read(&self.vault).clone()
    }

    pub fn requests(&self) -> MutexGuard<'_, Requests> {
        lock(&self.requests)
    }

    pub fn set_policy(&self, policy: Policy) -> Result<()> {
        write_private(
            &self.cfg.state_dir.join("policy.json"),
            serde_json::to_vec_pretty(&policy)?.as_slice(),
        )?;
        *write(&self.policy) = Arc::new(policy);
        if let Some(v) = self.vault() {
            v.flush();
        }
        Ok(())
    }

    /// Install the env's CA, a renewed one too: the leaves cached under the CA it replaces go
    /// with that CA, so none of them is served again.
    pub fn set_ca(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        let ca = Ca::from_pem(cert_pem, key_pem)?;
        write_private(&self.cfg.state_dir.join("ca.crt"), cert_pem.as_bytes())?;
        write_private(&self.cfg.state_dir.join("ca.key"), key_pem.as_bytes())?;
        *write(&self.ca) = Some(Arc::new(ca));
        Ok(())
    }

    pub fn set_vault(&self, token: String) -> Result<()> {
        let settings = VaultSettings { token };
        write_private(
            &self.cfg.state_dir.join("vault.json"),
            serde_json::to_vec(&settings)?.as_slice(),
        )?;
        let client = VaultClient::new(self.cfg.vault_socket.clone(), settings.token);
        *write(&self.vault) = Some(Arc::new(client));
        Ok(())
    }

    pub fn is_self(&self, host: &str) -> bool {
        host == luoto_shared::GATE_HOST || host == self.cfg.gate_ip.to_string()
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// Atomic write with owner-only permissions.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

fn upstream_tls(cfg: &Config, extra: Option<&[u8]>) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut pems = Vec::new();
    if let Some(path) = &cfg.upstream_ca {
        pems.push(std::fs::read(path).with_context(|| format!("read {}", path.display()))?);
    }
    pems.extend(extra.map(<[u8]>::to_vec));
    for pem in &pems {
        for cert in rustls_pki_types::pem::PemObject::pem_slice_iter(pem) {
            let cert: rustls_pki_types::CertificateDer<'static> = cert?;
            roots.add(cert)?;
        }
    }
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}
