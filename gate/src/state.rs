//! Shared gate state. Policy, CA and vault settings live in the state volume so a restarted
//! gate serves immediately; secrets do not — credentials are fetched from the vault.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use anyhow::{Context, Result};
use luoto_shared::host::host_matches;
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
    /// For the hosts the policy names CAs for (a self-hosted forge's, a rule's `ca`, an env's
    /// `[cas]`, config.toml's for every host): the public roots and those CAs, which no other
    /// host's certificate may chain to. Built from each policy applied.
    host_tls: RwLock<HostTls>,
    /// Apple: the host's dialer for private addresses (`hostdial.rs`), set once at start.
    pub host_dial: std::sync::OnceLock<crate::hostdial::HostDial>,
    pub redirects: crate::redirects::Permits,
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
        let host_tls = RwLock::new(host_tls(&cfg, &policy)?);
        let last_request = std::fs::read_to_string(dir.join(REQUEST_IDS))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        Ok(Arc::new(State {
            events: Emitter::new(&cfg)?,
            conns: Conns::new(cfg.limits.conns),
            policy: RwLock::new(Arc::new(policy)),
            ca: RwLock::new(ca),
            vault: RwLock::new(vault),
            requests: Mutex::new(Requests::continuing(last_request)),
            fake_ips: Mutex::new(FakeIps::new()),
            client_tls,
            host_tls,
            host_dial: std::sync::OnceLock::new(),
            redirects: Default::default(),
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

    /// File a request from the sandbox, its number kept in the state volume so a restarted
    /// gate numbers on from it.
    pub fn file_request(
        &self,
        new: luoto_shared::api::NewAccessRequest,
    ) -> Result<luoto_shared::api::AccessRequest, String> {
        let mut requests = self.requests();
        let created = requests.create(new)?;
        let last = requests.last_id().to_string();
        // A number not kept costs only that guarantee, never the request.
        let _ = write_private(&self.cfg.state_dir.join(REQUEST_IDS), last.as_bytes());
        Ok(created)
    }

    /// The TLS settings to verify `host` with: with the CAs the policy names for it.
    pub fn tls_for(&self, host: &str) -> Arc<ClientConfig> {
        let tls = read(&self.host_tls);
        key_for(tls.keys().map(String::as_str), &host.to_ascii_lowercase())
            .and_then(|k| tls.get(k).cloned())
            .unwrap_or_else(|| self.client_tls.clone())
    }

    pub fn set_policy(&self, policy: Policy) -> Result<()> {
        // Built first: a CA that doesn't parse leaves the policy in force as it was.
        let tls = host_tls(&self.cfg, &policy)?;
        write_private(
            &self.cfg.state_dir.join("policy.json"),
            serde_json::to_vec_pretty(&policy)?.as_slice(),
        )?;
        *write(&self.policy) = Arc::new(policy);
        *write(&self.host_tls) = tls;
        self.redirects.clear();
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

/// The state file holding the last request number a gate of this env gave.
const REQUEST_IDS: &str = "requests.last";

/// By the policy's CA keys: an exact host, a wildcard (`*.corp.example`) or every host (`*`).
type HostTls = std::collections::HashMap<String, Arc<ClientConfig>>;

/// One verifier per key the policy names CAs under, each with the CAs of every key covering
/// it, so the most specific key matching a host ([`key_for`]) has all that apply.
fn host_tls(cfg: &Config, policy: &Policy) -> Result<HostTls> {
    let cas: std::collections::BTreeMap<String, &str> = policy
        .upstream_cas
        .iter()
        .map(|(k, pem)| (k.to_ascii_lowercase(), pem.as_str()))
        .collect();
    cas.keys()
        .map(|key| {
            let pem = covering(&cas, key);
            let tls = upstream_tls(cfg, Some(pem.as_bytes()))
                .with_context(|| format!("the CA for {key}"))?;
            Ok((key.clone(), Arc::new(tls)))
        })
        .collect()
}

/// The CAs that apply under `key`: its own, every wildcard over it and those for every host.
fn covering(cas: &std::collections::BTreeMap<String, &str>, key: &str) -> String {
    let name = key.strip_prefix("*.").unwrap_or(key);
    cas.iter()
        .filter(|(k, _)| *k == key || *k == "*" || (k.starts_with("*.") && host_matches(k, name)))
        .map(|(_, pem)| *pem)
        .collect()
}

/// The most specific of `keys` matching `host`: the host itself, else the narrowest wildcard
/// over it, else `*`.
fn key_for<'a>(keys: impl Iterator<Item = &'a str>, host: &str) -> Option<&'a str> {
    keys.filter(|k| *k == host || *k == "*" || (k.starts_with("*.") && host_matches(k, host)))
        .max_by_key(|k| match *k {
            "*" => 0,
            k if k == host => usize::MAX,
            k => k.len(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_gets_the_cas_of_every_key_covering_it_and_no_other() {
        let cas: std::collections::BTreeMap<String, &str> = [
            ("*", "EVERY "),
            ("*.corp.example", "CORP "),
            ("*.eu.corp.example", "EU "),
            ("api.eu.corp.example", "API "),
            ("forge.other", "FORGE "),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let keys = || cas.keys().map(String::as_str);
        for (host, key, pems) in [
            (
                "api.eu.corp.example",
                "api.eu.corp.example",
                ["API", "EU", "CORP", "EVERY"].as_slice(),
            ),
            (
                "web.eu.corp.example",
                "*.eu.corp.example",
                &["EU", "CORP", "EVERY"],
            ),
            ("db.corp.example", "*.corp.example", &["CORP", "EVERY"]),
            ("forge.other", "forge.other", &["FORGE", "EVERY"]),
            ("corp.example", "*", &["EVERY"]),
            ("github.com", "*", &["EVERY"]),
        ] {
            let k = key_for(keys(), host).unwrap();
            assert_eq!(k, key, "{host}");
            let held = covering(&cas, k);
            for p in ["EVERY", "CORP", "EU", "API", "FORGE"] {
                assert_eq!(held.contains(p), pems.contains(&p), "{host}: {p} in {held}");
            }
        }
        let none = ["forge.other"];
        assert_eq!(key_for(none.into_iter(), "github.com"), None);
    }
}
