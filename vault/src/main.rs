//! luoto-vault: one per runtime VM. Holds root secrets in memory only (pushed by `luoto
//! vault unlock`), knows which env may use which binding, and hands each gate only its own
//! credentials — static values as-is, GitHub tokens minted per env. `luoto-vault ctl`
//! forwards one control request from stdin (host → vault via `exec -i`).

mod agent;
mod github;

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::io::{Read, Write as _};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use luoto_shared::api::AgentMessage;
use luoto_shared::creds::{AgentRequest, BindingSpec, CredentialValue};
use luoto_shared::ctl::{
    CTL_SOCKET, CredentialRequest, CtlResponse, VaultCtl, VaultEnvSummary, VaultStatus,
};
use luoto_shared::events::{Event, EventKind, Source, Verdict};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};

struct EnvEntry {
    token_sha256: [u8; 32],
    bindings: BTreeMap<String, BindingSpec>,
    /// New on every Bind and Lock: a token minted under an older one is not kept or handed out.
    generation: u64,
}

#[derive(Default)]
struct Inner {
    secrets: HashMap<String, String>,
    envs: HashMap<String, EnvEntry>,
    minted: HashMap<(String, String), (String, DateTime<Utc>)>,
    /// The last generation given out; none repeats, across Unbind too.
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

struct Vault {
    started: DateTime<Utc>,
    run: String,
    seq: AtomicU64,
    inner: Mutex<Inner>,
    tls: Arc<rustls::ClientConfig>,
    /// SSH sessions bound on each env's agent connections.
    sessions: Mutex<agent::Sessions>,
}

enum Issue {
    Value(CredentialValue),
    Locked,
    Forbidden,
    Failed(String),
}

impl Vault {
    fn emit(&self, mut ev: Event) {
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

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn env_for_token(&self, token: &str) -> Option<String> {
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let inner = self.lock();
        inner
            .envs
            .iter()
            .find(|(_, e)| bool::from(e.token_sha256.ct_eq(&hash)))
            .map(|(name, _)| name.clone())
    }

    async fn issue(&self, env: &str, binding: &str) -> Issue {
        for _ in 0..MINT_ATTEMPTS {
            let (spec, secret, generation) = {
                let inner = self.lock();
                let Some(entry) = inner.envs.get(env) else {
                    return Issue::Forbidden;
                };
                let Some(spec) = entry.bindings.get(binding).cloned() else {
                    return Issue::Forbidden;
                };
                // The key signs in the vault (`/v1/ssh-agent`); it is never handed out.
                if let BindingSpec::SshAgent { .. } = spec {
                    return Issue::Forbidden;
                }
                let refs = spec.refs();
                let Some(secret) = refs.first().and_then(|r| inner.secrets.get(*r)).cloned() else {
                    return Issue::Locked;
                };
                if let BindingSpec::GithubApp { .. } = spec
                    && let Some((tok, exp)) =
                        inner.minted.get(&(env.to_string(), binding.to_string()))
                    && *exp - Utc::now() > chrono::TimeDelta::minutes(10)
                {
                    return Issue::Value(CredentialValue {
                        value: tok.clone(),
                        expires_at: Some(*exp),
                    });
                }
                (spec, secret, entry.generation)
            };
            let (app_id, installation_id, repos, permissions, api_base) = match spec {
                BindingSpec::Static { .. } => {
                    return Issue::Value(CredentialValue {
                        value: secret,
                        expires_at: None,
                    });
                }
                BindingSpec::SshAgent { .. } => return Issue::Forbidden,
                BindingSpec::GithubApp {
                    app_id,
                    installation_id,
                    repos,
                    permissions,
                    api_base,
                    ..
                } => (app_id, installation_id, repos, permissions, api_base),
            };
            let minted = github::installation_token(
                &self.tls,
                &api_base,
                &app_id,
                installation_id,
                &secret,
                &repos,
                &permissions,
            )
            .await;
            let (token, exp) = match minted {
                Ok(t) => t,
                Err(e) => return Issue::Failed(format!("{e:#}")),
            };
            let mut inner = self.lock();
            // Bound or locked again during the mint: this token has the old scope.
            if inner.generation_of(env) != Some(generation) {
                continue;
            }
            inner
                .minted
                .insert((env.to_string(), binding.to_string()), (token.clone(), exp));
            return Issue::Value(CredentialValue {
                value: token,
                expires_at: Some(exp),
            });
        }
        Issue::Failed("the env's credentials kept changing while a token was minted".into())
    }

    /// One ssh-agent message for `env`: the reply and what it did.
    fn agent(&self, env: &str, req: &AgentRequest) -> Result<(Vec<u8>, agent::Note), Issue> {
        let (pem, host_lines) = {
            let inner = self.lock();
            let Some(BindingSpec::SshAgent { key_ref, host_keys }) = inner
                .envs
                .get(env)
                .and_then(|e| e.bindings.get(&req.binding))
                .cloned()
            else {
                return Err(Issue::Forbidden);
            };
            let Some(pem) = inner.secrets.get(&key_ref).cloned() else {
                return Err(Issue::Locked);
            };
            (pem, host_keys)
        };
        let key = agent::Key::from_openssh(&pem).map_err(Issue::Failed)?;
        let msg = B64
            .decode(&req.message.message)
            .map_err(|_| Issue::Failed("agent message is not base64".into()))?;
        let hosts = agent::host_keys(&host_lines);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        Ok(sessions.with_conn(env, &req.message.conn, |bound| {
            agent::handle(&key, &hosts, bound, &msg)
        }))
    }

    fn status(&self) -> VaultStatus {
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
                    .flat_map(|b| b.refs())
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

    fn ctl(&self, op: VaultCtl) -> CtlResponse {
        match op {
            VaultCtl::Status => CtlResponse::ok(self.status()),
            VaultCtl::Load { secrets } => {
                let n = secrets.len();
                self.lock().secrets.extend(secrets);
                self.emit(Event {
                    kind: Some(EventKind::Lifecycle),
                    message: Some(format!("unlocked: {n} secret(s) loaded")),
                    ..Default::default()
                });
                CtlResponse::ok(n)
            }
            VaultCtl::Bind {
                env,
                token_sha256,
                bindings,
            } => {
                let Ok(raw) = hex::decode(&token_sha256) else {
                    return CtlResponse::err("token_sha256 is not hex");
                };
                let Ok(hash) = <[u8; 32]>::try_from(raw.as_slice()) else {
                    return CtlResponse::err("token_sha256 must be 32 bytes");
                };
                let mut inner = self.lock();
                inner.minted.retain(|(e, _), _| e != &env);
                let names: Vec<String> = bindings.keys().cloned().collect();
                let generation = inner.next_generation();
                inner.envs.insert(
                    env.clone(),
                    EnvEntry {
                        token_sha256: hash,
                        bindings,
                        generation,
                    },
                );
                drop(inner);
                self.emit(Event {
                    kind: Some(EventKind::Lifecycle),
                    env: env.clone(),
                    message: Some(format!("bindings registered: {}", names.join(", "))),
                    ..Default::default()
                });
                CtlResponse::ok(true)
            }
            VaultCtl::Unbind { env } => {
                let mut inner = self.lock();
                inner.envs.remove(&env);
                inner.minted.retain(|(e, _), _| e != &env);
                CtlResponse::ok(true)
            }
            VaultCtl::Lock => {
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
                drop(inner);
                self.emit(Event {
                    kind: Some(EventKind::Lifecycle),
                    message: Some("locked: all secrets wiped from memory".into()),
                    ..Default::default()
                });
                CtlResponse::ok(true)
            }
        }
    }
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r
}

async fn http(
    vault: Arc<Vault>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    if req.method() != http::Method::POST || (path != "/v1/credential" && path != "/v1/ssh-agent") {
        return Ok(reply(StatusCode::NOT_FOUND, "not found"));
    }
    let token = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let Some(env) = vault.env_for_token(&token) else {
        return Ok(reply(StatusCode::FORBIDDEN, "unknown token"));
    };
    let limit = if path == "/v1/ssh-agent" {
        1 << 18
    } else {
        4096
    };
    let body = match Limited::new(req.into_body(), limit).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return Ok(reply(StatusCode::BAD_REQUEST, "body")),
    };
    if path == "/v1/ssh-agent" {
        return Ok(agent_reply(&vault, &env, &body));
    }
    let Ok(cr) = serde_json::from_slice::<CredentialRequest>(&body) else {
        return Ok(reply(StatusCode::BAD_REQUEST, "invalid request"));
    };
    let issued = vault.issue(&env, &cr.binding).await;
    let mut ev = Event {
        kind: Some(EventKind::Creds),
        env: env.clone(),
        binding: Some(cr.binding.clone()),
        ..Default::default()
    };
    let resp = match issued {
        Issue::Value(v) => {
            ev.verdict = Some(Verdict::Allow);
            ev.message = Some(match v.expires_at {
                Some(e) => format!("issued, expires {}", e.format("%H:%M:%S UTC")),
                None => "issued".into(),
            });
            reply(StatusCode::OK, serde_json::to_vec(&v).unwrap_or_default())
        }
        Issue::Locked => {
            ev.verdict = Some(Verdict::Deny);
            ev.reason = Some("locked".into());
            ev.message = Some("vault is locked; run `luoto vault unlock`".into());
            reply(StatusCode::LOCKED, "locked")
        }
        Issue::Forbidden => {
            ev.verdict = Some(Verdict::Deny);
            ev.reason = Some("not_bound".into());
            ev.message = Some("binding is not registered for this env".into());
            reply(StatusCode::NOT_FOUND, "binding not registered for this env")
        }
        Issue::Failed(msg) => {
            ev.verdict = Some(Verdict::Deny);
            ev.reason = Some("mint_failed".into());
            ev.message = Some(msg.clone());
            reply(StatusCode::BAD_GATEWAY, msg)
        }
    };
    vault.emit(ev);
    Ok(resp)
}

/// Answer one ssh-agent message, with an event for each bind, login and refusal.
fn agent_reply(vault: &Vault, env: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let Ok(req) = serde_json::from_slice::<AgentRequest>(body) else {
        return reply(StatusCode::BAD_REQUEST, "invalid request");
    };
    if !agent::conn_id_ok(&req.message.conn) {
        return reply(StatusCode::BAD_REQUEST, "invalid agent connection id");
    }
    let mut ev = Event {
        kind: Some(EventKind::Creds),
        env: env.to_string(),
        binding: Some(req.binding.clone()),
        ..Default::default()
    };
    let resp = match vault.agent(env, &req) {
        Ok((msg, note)) => {
            match note {
                agent::Note::Listed => {}
                agent::Note::Bound(host) => {
                    ev.verdict = Some(Verdict::Allow);
                    ev.host = Some(host.clone());
                    ev.message = Some(format!("ssh session to {host} bound"));
                }
                agent::Note::Signed(host) => {
                    ev.verdict = Some(Verdict::Allow);
                    ev.host = Some(host.clone());
                    ev.message = Some(format!("ssh login to {host} signed"));
                }
                agent::Note::Refused(why) => {
                    ev.verdict = Some(Verdict::Deny);
                    ev.reason = Some("ssh_agent".into());
                    ev.message = Some(why);
                }
            }
            let out = AgentMessage {
                conn: req.message.conn.clone(),
                message: B64.encode(msg),
            };
            reply(StatusCode::OK, serde_json::to_vec(&out).unwrap_or_default())
        }
        Err(Issue::Locked) => {
            ev.verdict = Some(Verdict::Deny);
            ev.reason = Some("locked".into());
            ev.message = Some("vault is locked; run `luoto vault unlock`".into());
            reply(StatusCode::LOCKED, "locked")
        }
        Err(Issue::Failed(msg)) => {
            ev.verdict = Some(Verdict::Deny);
            ev.reason = Some("ssh_agent".into());
            ev.message = Some(msg.clone());
            reply(StatusCode::BAD_GATEWAY, msg)
        }
        Err(_) => reply(StatusCode::NOT_FOUND, "no SSH key bound for this env"),
    };
    if ev.verdict.is_some() {
        vault.emit(ev);
    }
    resp
}

async fn serve() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let addr: SocketAddr = std::env::var("LUOTO_VAULT_ADDR")
        .unwrap_or_else(|_| format!("127.0.0.1:{}", luoto_shared::VAULT_PORT))
        .parse()
        .context("LUOTO_VAULT_ADDR")?;
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let ctl_path = std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into());
    if let Some(parent) = std::path::Path::new(&ctl_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&ctl_path);
    let ctl = UnixListener::bind(&ctl_path).with_context(|| format!("bind {ctl_path}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&ctl_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];

    // Keep secrets out of core dumps and ptrace.
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctl call with valid constant arguments.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    let vault = Arc::new(Vault {
        started: Utc::now(),
        run: hex::encode(rand::random::<[u8; 8]>()),
        seq: AtomicU64::new(0),
        inner: Mutex::new(Inner::default()),
        tls: Arc::new(tls),
        sessions: Mutex::new(agent::Sessions::default()),
    });
    vault.emit(Event {
        kind: Some(EventKind::Lifecycle),
        message: Some(format!("vault {} started (locked)", luoto_shared::VERSION)),
        ..Default::default()
    });

    let v = vault.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = ctl.accept().await else {
                continue;
            };
            let v = v.clone();
            tokio::spawn(async move {
                let (r, mut w) = stream.into_split();
                let mut line = String::new();
                if BufReader::new(r.take(16 << 20))
                    .read_line(&mut line)
                    .await
                    .is_err()
                {
                    return;
                }
                let resp = match serde_json::from_str::<VaultCtl>(&line) {
                    Ok(op) => v.ctl(op),
                    Err(e) => CtlResponse::err(format!("bad request: {e}")),
                };
                let mut out = serde_json::to_vec(&resp).unwrap_or_default();
                out.push(b'\n');
                let _ = w.write_all(&out).await;
            });
        }
    });

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let v = vault.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| http(v.clone(), req));
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

fn ctl_client() -> ExitCode {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return ExitCode::from(2);
    }
    let socket = std::env::var("LUOTO_CTL_SOCKET").unwrap_or_else(|_| CTL_SOCKET.into());
    let mut stream = match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("luoto-vault ctl: connect {socket}: {e}");
            return ExitCode::from(2);
        }
    };
    let line = input.trim().replace('\n', " ");
    if stream.write_all(format!("{line}\n").as_bytes()).is_err() {
        return ExitCode::from(2);
    }
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    print!("{out}");
    match serde_json::from_str::<CtlResponse>(&out) {
        Ok(r) if r.ok => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("ctl") => ctl_client(),
        Some("version" | "--version") => {
            println!("luoto-vault {}", luoto_shared::VERSION);
            ExitCode::SUCCESS
        }
        None | Some("run") => {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("luoto-vault: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(serve()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("luoto-vault: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("usage: luoto-vault [run|ctl|version] (got `{other}`)");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> Vault {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        Vault {
            started: Utc::now(),
            run: "test".into(),
            seq: AtomicU64::new(0),
            inner: Mutex::new(Inner::default()),
            tls: Arc::new(tls),
            sessions: Mutex::new(agent::Sessions::default()),
        }
    }

    #[test]
    fn binds_and_locks_never_repeat_a_generation() {
        let v = vault();
        let bind = || {
            let op = VaultCtl::Bind {
                env: "e".into(),
                token_sha256: "00".repeat(32),
                bindings: BTreeMap::new(),
            };
            assert!(v.ctl(op).ok);
        };
        let generation = || v.lock().generation_of("e");
        let mut seen = Vec::new();
        bind();
        seen.extend(generation());
        bind();
        seen.extend(generation());
        v.ctl(VaultCtl::Lock);
        seen.extend(generation());
        v.ctl(VaultCtl::Unbind { env: "e".into() });
        assert_eq!(generation(), None);
        bind();
        seen.extend(generation());
        assert_eq!(seen.len(), 4);
        assert!(
            seen.is_sorted() && seen.windows(2).all(|w| w[0] != w[1]),
            "{seen:?}"
        );
    }
}
