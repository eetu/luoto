//! What the vault holds, in memory only: root secrets by source ref, each env's token hash
//! and bindings, the tokens minted for them, and the SSH sessions bound on agent connections.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use luoto_shared::creds::{AgentRequest, BindingSpec, CredentialError, CredentialValue};
use luoto_shared::ctl::{VaultEnvSummary, VaultStatus};
use luoto_shared::events::{Event, Source};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{agent, github};

struct EnvEntry {
    token_sha256: [u8; 32],
    bindings: BTreeMap<String, BindingSpec>,
    /// New on every bind and wipe: a token minted under an older one is not kept or handed out.
    generation: u64,
}

#[derive(Default)]
struct Inner {
    secrets: HashMap<String, String>,
    envs: HashMap<String, EnvEntry>,
    minted: HashMap<(String, String), (String, DateTime<Utc>)>,
    /// The last generation given out; none repeats, across unbinds too.
    generation: u64,
}

impl Inner {
    fn next_generation(&mut self) -> u64 {
        self.generation += 1;
        self.generation
    }

    fn generation_of(&self, env: &str) -> Option<u64> {
        self.envs.get(env).map(|e| e.generation)
    }
}

/// Mints one request tries while the env's bindings keep changing under them.
const MINT_ATTEMPTS: usize = 3;

pub struct Vault {
    started: DateTime<Utc>,
    run: String,
    seq: AtomicU64,
    inner: Mutex<Inner>,
    tls: Arc<rustls::ClientConfig>,
    /// SSH sessions bound on each env's agent connections.
    sessions: Mutex<agent::Sessions>,
}

/// TLS towards GitHub's API, for minting App tokens.
pub fn client_tls() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls
}

impl Vault {
    pub fn new(tls: rustls::ClientConfig) -> Self {
        Vault {
            started: Utc::now(),
            run: hex::encode(rand::random::<[u8; 8]>()),
            seq: AtomicU64::new(0),
            inner: Mutex::default(),
            tls: Arc::new(tls),
            sessions: Mutex::default(),
        }
    }

    pub fn emit(&self, mut ev: Event) {
        ev.seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        ev.run = self.run.clone();
        ev.ts = Some(Utc::now());
        ev.source = Some(Source::Vault);
        if let Ok(line) = serde_json::to_string(&ev) {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn env_for_token(&self, token: &str) -> Option<String> {
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let inner = self.lock();
        inner
            .envs
            .iter()
            .find(|(_, e)| bool::from(e.token_sha256.ct_eq(&hash)))
            .map(|(name, _)| name.clone())
    }

    pub async fn issue(
        &self,
        env: &str,
        binding: &str,
    ) -> Result<CredentialValue, CredentialError> {
        let key = (env.to_string(), binding.to_string());
        for _ in 0..MINT_ATTEMPTS {
            let (spec, secret, generation) = {
                let inner = self.lock();
                let entry = inner.envs.get(env).ok_or(CredentialError::NotBound)?;
                let spec = entry
                    .bindings
                    .get(binding)
                    .ok_or(CredentialError::NotBound)?;
                // The key signs in the vault (`/v1/ssh-agent`); it is never handed out.
                if let BindingSpec::SshAgent { .. } = spec {
                    return Err(CredentialError::NotBound);
                }
                let secret = inner
                    .secrets
                    .get(spec.secret_ref())
                    .ok_or(CredentialError::Locked)?
                    .clone();
                if let BindingSpec::GithubApp { .. } = spec
                    && let Some((tok, exp)) = inner.minted.get(&key)
                    && *exp - Utc::now() > chrono::TimeDelta::minutes(10)
                {
                    return Ok(CredentialValue {
                        value: tok.clone(),
                        expires_at: Some(*exp),
                    });
                }
                (spec.clone(), secret, entry.generation)
            };
            let BindingSpec::GithubApp {
                app_id,
                installation_id,
                repos,
                permissions,
                api_base,
                ..
            } = &spec
            else {
                return Ok(CredentialValue {
                    value: secret,
                    expires_at: None,
                });
            };
            let (token, exp) = github::installation_token(
                &self.tls,
                api_base,
                app_id,
                *installation_id,
                &secret,
                repos,
                permissions,
            )
            .await
            .map_err(|e| CredentialError::Failed(format!("{e:#}")))?;
            let mut inner = self.lock();
            // Bound or wiped again during the mint: this token has the old scope.
            if inner.generation_of(env) != Some(generation) {
                continue;
            }
            inner.minted.insert(key, (token.clone(), exp));
            return Ok(CredentialValue {
                value: token,
                expires_at: Some(exp),
            });
        }
        Err(CredentialError::Failed(
            "the env's credentials kept changing while a token was minted".into(),
        ))
    }

    /// One ssh-agent message for `env`: the reply and what it did.
    pub fn agent(
        &self,
        env: &str,
        req: &AgentRequest,
    ) -> Result<(Vec<u8>, agent::Note), CredentialError> {
        let (pem, host_lines) = {
            let inner = self.lock();
            let Some(BindingSpec::SshAgent { key_ref, host_keys }) = inner
                .envs
                .get(env)
                .and_then(|e| e.bindings.get(&req.binding))
            else {
                return Err(CredentialError::NotBound);
            };
            let pem = inner
                .secrets
                .get(key_ref)
                .ok_or(CredentialError::Locked)?
                .clone();
            (pem, host_keys.clone())
        };
        let key = agent::Key::from_openssh(&pem).map_err(CredentialError::Failed)?;
        let msg = B64
            .decode(&req.message.message)
            .map_err(|_| CredentialError::Failed("agent message is not base64".into()))?;
        let hosts = agent::host_keys(&host_lines);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        Ok(sessions.with_conn(env, &req.message.conn, |bound| {
            agent::handle(&key, &hosts, bound, &msg)
        }))
    }

    pub fn status(&self) -> VaultStatus {
        let inner = self.lock();
        let mut loaded_refs: Vec<String> = inner.secrets.keys().cloned().collect();
        loaded_refs.sort();
        let mut envs: Vec<VaultEnvSummary> = inner
            .envs
            .iter()
            .map(|(name, e)| VaultEnvSummary {
                env: name.clone(),
                bindings: e.bindings.keys().cloned().collect(),
                missing: e
                    .bindings
                    .values()
                    .map(BindingSpec::secret_ref)
                    .filter(|r| !inner.secrets.contains_key(*r))
                    .map(str::to_string)
                    .collect(),
            })
            .collect();
        envs.sort_by(|a, b| a.env.cmp(&b.env));
        VaultStatus {
            version: luoto_shared::VERSION.into(),
            started: self.started,
            locked: inner.secrets.is_empty(),
            loaded_refs,
            envs,
        }
    }

    /// Merge resolved secrets into memory; how many were new or changed. A changed one (a
    /// rotated token, a new App key) also retires every minted token, as one could come from
    /// the old key.
    pub fn load(&self, secrets: BTreeMap<String, String>) -> usize {
        let mut inner = self.lock();
        let mut n = 0;
        let mut rotated = false;
        for (r, value) in secrets {
            match inner.secrets.get_mut(&r) {
                Some(old) if *old == value => {}
                Some(old) => {
                    // SAFETY: zero bytes keep the String valid UTF-8.
                    unsafe { old.as_bytes_mut().fill(0) };
                    *old = value;
                    rotated = true;
                    n += 1;
                }
                None => {
                    inner.secrets.insert(r, value);
                    n += 1;
                }
            }
        }
        if rotated {
            inner.minted.clear();
            let generation = inner.next_generation();
            for e in inner.envs.values_mut() {
                e.generation = generation;
            }
        }
        n
    }

    /// Register or replace `env`: its gate's token hash and its bindings.
    pub fn bind(&self, env: &str, token_sha256: [u8; 32], bindings: BTreeMap<String, BindingSpec>) {
        let mut inner = self.lock();
        inner.minted.retain(|(e, _), _| e != env);
        let generation = inner.next_generation();
        inner.envs.insert(
            env.to_string(),
            EnvEntry {
                token_sha256,
                bindings,
                generation,
            },
        );
    }

    pub fn unbind(&self, env: &str) {
        let mut inner = self.lock();
        inner.envs.remove(env);
        inner.minted.retain(|(e, _), _| e != env);
    }

    /// Wipe every secret and minted token from memory.
    pub fn wipe(&self) {
        let mut inner = self.lock();
        for v in inner.secrets.values_mut() {
            // Overwrite before dropping so the plaintext does not linger in freed memory.
            // SAFETY: zero bytes keep the String valid UTF-8.
            unsafe { v.as_bytes_mut().fill(0) };
        }
        inner.secrets.clear();
        inner.minted.clear();
        let generation = inner.next_generation();
        for e in inner.envs.values_mut() {
            e.generation = generation;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_and_wipes_never_repeat_a_generation() {
        let v = Vault::new(client_tls());
        let bind = || v.bind("e", [0; 32], BTreeMap::new());
        let generation = || v.lock().generation_of("e");
        let mut seen = Vec::new();
        bind();
        seen.extend(generation());
        bind();
        seen.extend(generation());
        v.wipe();
        seen.extend(generation());
        v.unbind("e");
        assert_eq!(generation(), None);
        bind();
        seen.extend(generation());
        assert_eq!(seen.len(), 4);
        assert!(
            seen.is_sorted() && seen.windows(2).all(|w| w[0] != w[1]),
            "{seen:?}"
        );
    }

    #[test]
    fn a_changed_secret_retires_minted_tokens() {
        let v = Vault::new(client_tls());
        v.bind("e", [0; 32], BTreeMap::new());
        let load = |val: &str| v.load(BTreeMap::from([("op://a/b/c".into(), val.into())]));
        let mint = || {
            v.lock()
                .minted
                .insert(("e".into(), "github".into()), ("ghs_x".into(), Utc::now()));
        };
        assert_eq!(load("one"), 1);
        mint();
        let before = v.lock().generation_of("e");
        assert_eq!(load("one"), 0);
        assert_eq!(v.lock().minted.len(), 1);
        assert_eq!(load("two"), 1);
        assert!(v.lock().minted.is_empty());
        assert_ne!(v.lock().generation_of("e"), before);
        assert_eq!(v.lock().secrets["op://a/b/c"], "two");
    }
}
