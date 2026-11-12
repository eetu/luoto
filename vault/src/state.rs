//! What the vault holds, in memory only: root secrets by source ref, each env's token hash
//! and bindings, the tokens minted for them, and the SSH sessions bound on agent connections.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use luoto_shared::creds::{AgentRequest, BindingSpec, CredentialError, CredentialValue};
use luoto_shared::ctl::{VaultEnvSummary, VaultStatus};
use luoto_shared::events::{Event, Source};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{agent, entra, github};

struct EnvEntry {
    token_sha256: [u8; 32],
    bindings: BTreeMap<String, BindingSpec>,
    /// New on every bind and wipe: a token minted under an older one is not kept or handed out.
    generation: u64,
}

/// An env and one of its bindings.
type Key = (String, String);

#[derive(Default)]
struct Inner {
    secrets: HashMap<String, String>,
    envs: HashMap<String, EnvEntry>,
    minted: HashMap<Key, (String, DateTime<Utc>)>,
    /// The last mint that failed for each binding: its error, when, and the env's generation
    /// then (a new one, from a bind, a wipe or a changed secret, tries again at once).
    failed: HashMap<Key, (String, Instant, u64)>,
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
/// How long a failed mint's error is the answer. Code in the sandbox makes the gate ask for a
/// token with every request to the host, and a mint that fails (a revoked secret, throttling,
/// a removed App installation) would post to Entra ID or GitHub as often: this keeps it to
/// two a minute per binding, while a new secret (`luoto vault reload`) is tried at once.
const MINT_RETRY_AFTER: Duration = Duration::from_secs(30);

pub struct Vault {
    started: DateTime<Utc>,
    run: String,
    seq: AtomicU64,
    inner: Mutex<Inner>,
    tls: Arc<rustls::ClientConfig>,
    /// SSH sessions bound on each env's agent connections.
    sessions: Mutex<agent::Sessions>,
    /// One mint at a time for each binding: requests that come meanwhile take its token.
    minting: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>,
}

/// TLS towards where tokens are minted: GitHub's API and Microsoft Entra ID.
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
            minting: Mutex::default(),
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

    /// Whether `token` is the one `env` was bound with.
    pub fn token_is(&self, env: &str, token: &str) -> bool {
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.lock()
            .envs
            .get(env)
            .is_some_and(|e| bool::from(e.token_sha256.ct_eq(&hash)))
    }

    pub async fn issue(
        &self,
        env: &str,
        binding: &str,
    ) -> Result<CredentialValue, CredentialError> {
        let key = (env.to_string(), binding.to_string());
        let turn = self
            .minting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .clone();
        let _turn = turn.lock().await;
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
                if let BindingSpec::GithubApp { .. } | BindingSpec::AzureServicePrincipal { .. } =
                    spec
                {
                    if let Some((tok, exp)) = inner.minted.get(&key)
                        && *exp - Utc::now() > chrono::TimeDelta::minutes(10)
                    {
                        return Ok(CredentialValue {
                            value: tok.clone(),
                            expires_at: Some(*exp),
                        });
                    }
                    if let Some((why, at, generation)) = inner.failed.get(&key)
                        && *generation == entry.generation
                        && at.elapsed() < MINT_RETRY_AFTER
                    {
                        return Err(CredentialError::Failed(why.clone()));
                    }
                }
                (spec.clone(), secret, entry.generation)
            };
            let minted = match &spec {
                BindingSpec::GithubApp {
                    app_id,
                    installation_id,
                    repos,
                    permissions,
                    api_base,
                    ..
                } => {
                    github::installation_token(
                        &self.tls,
                        api_base,
                        app_id,
                        *installation_id,
                        &secret,
                        repos,
                        permissions,
                    )
                    .await
                }
                BindingSpec::AzureServicePrincipal {
                    tenant,
                    client_id,
                    audience,
                    ..
                } => {
                    entra::client_credentials(&self.tls, tenant, client_id, &secret, audience).await
                }
                BindingSpec::Static { .. } | BindingSpec::SshAgent { .. } => {
                    return Ok(CredentialValue {
                        value: secret,
                        expires_at: None,
                    });
                }
            };
            let mut inner = self.lock();
            // Bound or wiped again during the mint: this token has the old scope, and an error
            // may be the old secret's.
            if inner.generation_of(env) != Some(generation) {
                continue;
            }
            let (token, exp) = match minted {
                Ok(t) => t,
                Err(e) => {
                    let why = format!("{e:#}");
                    let failed = (why.clone(), Instant::now(), generation);
                    inner.failed.insert(key, failed);
                    return Err(CredentialError::Failed(why));
                }
            };
            inner.failed.remove(&key);
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
    /// rotated token, a new App key) also retires the tokens minted from it, as one could
    /// come from the old key; tokens minted from other secrets stay (`azcli:` tokens change
    /// every hour). With `held_only`, refs it doesn't hold are left out: a renewal read before
    /// a lock must not fill the wiped vault again.
    pub fn load(&self, secrets: BTreeMap<String, String>, held_only: bool) -> usize {
        let mut inner = self.lock();
        let mut n = 0;
        let mut rotated: BTreeSet<String> = BTreeSet::new();
        for (r, value) in secrets {
            match inner.secrets.get_mut(&r) {
                Some(old) if *old == value => {}
                Some(old) => {
                    // SAFETY: zero bytes keep the String valid UTF-8.
                    unsafe { old.as_bytes_mut().fill(0) };
                    *old = value;
                    rotated.insert(r);
                    n += 1;
                }
                None if held_only => {}
                None => {
                    inner.secrets.insert(r, value);
                    n += 1;
                }
            }
        }
        if !rotated.is_empty() {
            let generation = inner.next_generation();
            let Inner { envs, minted, .. } = &mut *inner;
            for (env, entry) in envs.iter_mut() {
                let from_rotated: Vec<&String> = entry
                    .bindings
                    .iter()
                    .filter(|(_, spec)| rotated.contains(spec.secret_ref()))
                    .map(|(b, _)| b)
                    .collect();
                if from_rotated.is_empty() {
                    continue;
                }
                minted.retain(|(e, b), _| !(e == env && from_rotated.contains(&b)));
                entry.generation = generation;
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
        inner.failed.retain(|(e, _), _| e != env);
        drop(inner);
        self.minting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(e, _), _| e != env);
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
    fn a_renewal_changes_only_what_the_vault_holds() {
        let v = Vault::new(client_tls());
        let arm = "azcli:https://management.azure.com/";
        let secrets = |val: &str| BTreeMap::from([(arm.to_string(), val.to_string())]);
        assert_eq!(v.load(secrets("t1"), true), 0);
        assert!(v.status().locked);
        assert_eq!(v.load(secrets("t1"), false), 1);
        assert_eq!(v.load(secrets("t2"), true), 1);
        assert_eq!(v.lock().secrets[arm], "t2");
        // Locked while it was read: the vault stays empty.
        v.wipe();
        assert_eq!(v.load(secrets("t3"), true), 0);
        assert!(v.status().locked && v.status().loaded_refs.is_empty());
    }

    #[test]
    fn a_changed_secret_retires_the_tokens_minted_from_it() {
        let v = Vault::new(client_tls());
        let static_ref = |r: &str| BindingSpec::Static {
            secret_ref: r.into(),
        };
        v.bind(
            "e",
            [0; 32],
            BTreeMap::from([
                ("github".into(), static_ref("op://a/b/c")),
                (
                    "azure-arm".into(),
                    static_ref("azcli:https://management.azure.com/"),
                ),
            ]),
        );
        let load = |r: &str, val: &str| v.load(BTreeMap::from([(r.into(), val.into())]), false);
        let mint = || {
            v.lock()
                .minted
                .insert(("e".into(), "github".into()), ("ghs_x".into(), Utc::now()));
        };
        assert_eq!(load("op://a/b/c", "one"), 1);
        assert_eq!(load("azcli:https://management.azure.com/", "t1"), 1);
        mint();
        let before = v.lock().generation_of("e");
        assert_eq!(load("op://a/b/c", "one"), 0);
        assert_eq!(v.lock().minted.len(), 1);
        // Another secret's change (an hourly az token) keeps it.
        assert_eq!(load("azcli:https://management.azure.com/", "t2"), 1);
        assert_eq!(v.lock().minted.len(), 1);
        let kept = v.lock().generation_of("e");
        assert_eq!(load("op://a/b/c", "two"), 1);
        assert!(v.lock().minted.is_empty());
        assert_ne!(v.lock().generation_of("e"), kept);
        assert_ne!(v.lock().generation_of("e"), before);
        assert_eq!(v.lock().secrets["op://a/b/c"], "two");
    }
}
