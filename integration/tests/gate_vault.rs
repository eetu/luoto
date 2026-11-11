//! The real gate and vault binaries, spawned locally, in front of wiremock, HTTPS and plain
//! TCP upstreams. `#[ignore]`d because they build and spawn binaries: `just it`.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use chrono::{TimeDelta, Utc};
use luoto_shared::azure_identity::{Audience, AzureIdentity};
use luoto_shared::creds::{BindingSpec, Injection, Placement};
use luoto_shared::ctl::{GateCtl, VaultCtl};
use luoto_shared::policy::{
    Access, AccessLevel, BodyDeny, CompiledRule, GithubGuard, Mode, Policy, Rule,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use sha2::{Digest, Sha256};
use wiremock::matchers::{any, header, header_exists, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

const ENV: &str = "it";
const TOKEN: &str = "test-env-token";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let ok = Command::new(env!("CARGO"))
            .current_dir(root())
            .args([
                "build",
                "-q",
                "-p",
                "luoto-gate",
                "-p",
                "luoto-vault",
                "--features",
                "luoto-gate/test-hooks,luoto-vault/test-hooks",
            ])
            .status()
            .unwrap()
            .success();
        assert!(ok, "building gate/vault failed");
    });
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn ctl(sock: &Path, op: &impl serde::Serialize) -> serde_json::Value {
    let mut s = UnixStream::connect(sock).unwrap();
    s.write_all(format!("{}\n", serde_json::to_string(op).unwrap()).as_bytes())
        .unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["ok"], true, "ctl failed: {line}");
    v
}

struct Reply {
    status: u16,
    /// Lower-cased, so header names compare without case.
    head: String,
    body: String,
}

impl Reply {
    /// The JSON object in the body.
    fn json(&self) -> serde_json::Value {
        let (a, b) = (self.body.find('{').unwrap(), self.body.rfind('}').unwrap());
        serde_json::from_str(&self.body[a..=b]).unwrap()
    }

    fn denied(&self, code: &str) -> bool {
        self.head.contains(&format!("x-luoto-denied: {code}"))
    }
}

/// Write `raw` to `port` and read the reply until the server closes.
fn send(port: u16, raw: &[u8]) -> Reply {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    exchange(&mut s, raw)
}

/// Read a message head, up to and including its blank line.
fn read_head(s: &mut impl Read) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// Write `raw` on `s` and read the reply until the server closes.
fn exchange(s: &mut (impl Read + Write), raw: &[u8]) -> Reply {
    s.write_all(raw).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Reply {
        status,
        head: head.to_ascii_lowercase(),
        body: body.to_string(),
    }
}

fn rule(id: &str, host: &str, access: Access, paths: &[&str]) -> CompiledRule {
    CompiledRule {
        id: id.into(),
        origin: "test".into(),
        rule: Rule {
            host: host.into(),
            access,
            paths: paths.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        },
    }
}

fn read(id: &str, host: &str) -> CompiledRule {
    rule(id, host, Access::Level(AccessLevel::Read), &[])
}

/// A vault and a gate for env `it`, whose names `resolve` maps to local servers.
struct Env {
    vault_sock: PathBuf,
    gate_sock: PathBuf,
    vault_port: u16,
    gate_port: u16,
    _gate: Proc,
    _vault: Proc,
    _dir: tempfile::TempDir,
}

impl Env {
    fn start(resolve: &[(&str, SocketAddr)]) -> Env {
        Env::start_with(resolve, &[])
    }

    /// With the gate's limits shrunk by `limits` (`conns=2,idle_ms=300,…`).
    fn start_limited(resolve: &[(&str, SocketAddr)], limits: &str) -> Env {
        Env::start_with(resolve, &[("LUOTO_TEST_LIMITS", limits)])
    }

    /// With `gate_env` added to the gate's environment.
    fn start_with(resolve: &[(&str, SocketAddr)], gate_env: &[(&str, &str)]) -> Env {
        Env::start_both(resolve, gate_env, &[])
    }

    /// With `gate_env` and `vault_env` added to the gate's and the vault's environments.
    fn start_both(
        resolve: &[(&str, SocketAddr)],
        gate_env: &[(&str, &str)],
        vault_env: &[(&str, &str)],
    ) -> Env {
        build();
        let dir = tempfile::tempdir().unwrap();
        let vault_sock = dir.path().join("v.sock");
        let gate_sock = dir.path().join("g.sock");
        let vault_port = free_port();
        let gate_port = free_port();
        let bin = root().join("target/debug");
        let vault = Proc(
            Command::new(bin.join("luoto-vault"))
                .env("LUOTO_VAULT_ADDR", format!("127.0.0.1:{vault_port}"))
                .env("LUOTO_CTL_SOCKET", &vault_sock)
                .envs(vault_env.iter().copied())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let resolve: Vec<String> = resolve.iter().map(|(h, a)| format!("{h}={a}")).collect();
        let gate = Proc(
            Command::new(bin.join("luoto-gate"))
                .env("LUOTO_ENV", ENV)
                .env("LUOTO_GATE_IP", "10.255.255.1")
                .env("LUOTO_PROXY_ADDR", format!("127.0.0.1:{gate_port}"))
                .env("LUOTO_STATE_DIR", dir.path().join("gate"))
                .env("LUOTO_CTL_SOCKET", &gate_sock)
                .env("LUOTO_TEST_RESOLVE", resolve.join(","))
                .envs(gate_env.iter().copied())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(&vault_sock);
        wait_for(&gate_sock);
        let env = Env {
            vault_sock,
            gate_sock,
            vault_port,
            gate_port,
            _gate: gate,
            _vault: vault,
            _dir: dir,
        };
        env.gate(&GateCtl::SetVault {
            url: format!("http://127.0.0.1:{vault_port}"),
            token: TOKEN.into(),
        });
        env
    }

    fn gate(&self, op: &GateCtl) -> serde_json::Value {
        ctl(&self.gate_sock, op)
    }

    fn vault(&self, op: &VaultCtl) -> serde_json::Value {
        ctl(&self.vault_sock, op)
    }

    fn apply(&self, policy: Policy) {
        let policy = Box::new(Policy {
            env: ENV.into(),
            ..policy
        });
        self.gate(&GateCtl::ApplyPolicy { policy });
    }

    /// Register the env's bindings with the vault and unlock it with `secrets`.
    fn credentials(&self, bindings: &[(&str, BindingSpec)], secrets: &[(&str, &str)]) {
        let bindings: BTreeMap<String, BindingSpec> = bindings
            .iter()
            .map(|(name, spec)| (name.to_string(), spec.clone()))
            .collect();
        self.vault(&VaultCtl::Bind {
            env: ENV.into(),
            token_sha256: hex::encode(Sha256::digest(TOKEN.as_bytes())),
            bindings,
        });
        let secrets = secrets
            .iter()
            .map(|(r, v)| (r.to_string(), v.to_string()))
            .collect();
        self.vault(&VaultCtl::Load {
            secrets,
            held_only: false,
        });
    }

    /// One request through the proxy, absolute-form, with the URL's host as `Host` unless
    /// `headers` names one.
    fn request(&self, method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let host = url.trim_start_matches("http://").split('/').next().unwrap();
        let mut req = format!("{method} {url} HTTP/1.1\r\n");
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            req.push_str(&format!("Host: {host}\r\n"));
        }
        req.push_str(&format!(
            "Connection: close\r\nContent-Length: {}\r\n",
            body.len()
        ));
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        let mut raw = req.into_bytes();
        raw.extend_from_slice(body);
        send(self.gate_port, &raw)
    }

    fn get(&self, url: &str) -> Reply {
        self.request("GET", url, &[], b"")
    }

    /// A GET to `host` in TLS through a CONNECT tunnel, trusting only `ca`, with the host as
    /// SNI and as `Host` unless `headers` names one.
    fn https(&self, ca: &TestCa, host: &str, path: &str, headers: &[(&str, &str)]) -> Reply {
        let mut tls = connect_tls(self.gate_port, &format!("{host}:443"), host, ca).unwrap();
        let mut req = format!("GET {path} HTTP/1.1\r\nConnection: close\r\n");
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            req.push_str(&format!("Host: {host}\r\n"));
        }
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        exchange(&mut tls, req.as_bytes())
    }

    /// What the vault answers the env's gate for `binding`.
    fn credential(&self, binding: &str) -> Reply {
        let body = serde_json::json!({ "binding": binding }).to_string();
        let raw = format!(
            "POST /v1/credential HTTP/1.1\r\nHost: vault\r\nAuthorization: Bearer {TOKEN}\r\n\
             Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        send(self.vault_port, raw.as_bytes())
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn the_policy_decides_and_private_addresses_are_never_dialed() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    Mock::given(method("POST"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&upstream)
        .await;
    let env = Env::start(&[("api.test", *upstream.address())]);
    let mut loopback = read("loopback", "127.0.0.1");
    loopback.rule.port = Some(upstream.address().port());
    env.apply(Policy {
        rules: vec![
            read("read", "api.test"),
            rule(
                "post",
                "api.test",
                Access::Methods(vec!["POST".into()]),
                &["/ok"],
            ),
            loopback,
        ],
        ..Default::default()
    });

    assert_eq!(env.get("http://api.test/ok").status, 200);
    assert_eq!(
        env.request("POST", "http://api.test/ok", &[], b"").status,
        201
    );
    let r = env.request("DELETE", "http://api.test/ok", &[], b"");
    assert!(
        r.status == 403 && r.denied("method_not_allowed"),
        "{}",
        r.head
    );
    let r = env.get("http://unknown.test/");
    assert!(r.status == 403 && r.denied("no_rule"), "{}", r.head);

    // Even with a rule, a private address is never dialed.
    let r = env.get(&format!(
        "http://127.0.0.1:{}/ok",
        upstream.address().port()
    ));
    assert!(r.status == 403 && r.denied("private_address"), "{}", r.head);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn credentials_replace_whatever_the_sandbox_sent() {
    let upstream = MockServer::start().await;
    // Only the real key opens /secret; the attacker's own header must never arrive.
    Mock::given(method("GET"))
        .and(path("/secret"))
        .and(header("x-api-key", "real-secret"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/secret"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&upstream)
        .await;
    // The same for a key in the query: the sandbox's own `key` must never arrive.
    Mock::given(method("GET"))
        .and(path("/qsecret"))
        .and(query_param("key", "attacker"))
        .respond_with(ResponseTemplate::new(418))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/qsecret"))
        .and(query_param("key", "real-secret"))
        .and(query_param("alt", "json"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/qsecret"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&upstream)
        .await;
    let env = Env::start(&[("api.test", *upstream.address())]);
    env.credentials(
        &[(
            "t.key",
            BindingSpec::Static {
                secret_ref: "env:X".into(),
            },
        )],
        &[("env:X", "real-secret")],
    );
    env.apply(credentialed_policy());

    let r = env.request(
        "GET",
        "http://api.test/secret",
        &[
            ("x-api-key", "attacker"),
            ("authorization", "Bearer attacker"),
        ],
        b"",
    );
    assert_eq!(r.status, 200, "{}", r.head);
    // Listing the credential's header in `Connection` doesn't strip the injected one.
    let r = env.request(
        "GET",
        "http://api.test/secret",
        &[("connection", "x-api-key")],
        b"",
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let r = env.get("http://api.test/qsecret?key=attacker&alt=json");
    assert_eq!(r.status, 200, "{}", r.head);
}

/// `api.test` readable, with the `t.key` credential on `/secret` (a header) and `/qsecret`
/// (the `key` query parameter).
fn credentialed_policy() -> Policy {
    let injection = |path: &str, place| Injection {
        binding: "t.key".into(),
        host: "api.test".into(),
        paths: vec![path.into()],
        methods: Vec::new(),
        ignore_case: false,
        place,
    };
    Policy {
        rules: vec![read("read", "api.test")],
        injections: vec![
            injection(
                "/secret",
                Placement::Header {
                    name: "x-api-key".into(),
                    format: "{secret}".into(),
                },
            ),
            injection(
                "/qsecret",
                Placement::Query {
                    param: "key".into(),
                },
            ),
        ],
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn locking_the_vault_fails_credentialed_requests_closed() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let env = Env::start(&[("api.test", *upstream.address())]);
    env.credentials(
        &[(
            "t.key",
            BindingSpec::Static {
                secret_ref: "env:X".into(),
            },
        )],
        &[("env:X", "real-secret")],
    );
    env.apply(credentialed_policy());
    assert_eq!(env.get("http://api.test/secret").status, 200);

    env.vault(&VaultCtl::Lock);
    env.gate(&GateCtl::FlushCredentials);
    let r = env.get("http://api.test/secret");
    assert!(r.status == 403 && r.denied("locked"), "{}", r.head);
    // Egress without credentials keeps working while locked.
    assert_eq!(env.get("http://api.test/ok").status, 200);
    // A renewal read before the lock leaves it locked.
    let renewed = env.vault(&VaultCtl::Load {
        secrets: BTreeMap::from([("env:X".to_string(), "renewed".to_string())]),
        held_only: true,
    });
    assert_eq!(renewed["data"], 0, "{renewed}");
    let r = env.get("http://api.test/secret");
    assert!(r.status == 403 && r.denied("locked"), "{}", r.head);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn open_egress_lets_out_what_no_rule_allows_and_nothing_more() {
    let upstream = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let at = *upstream.address();
    let env = Env::start(&[
        ("api.test", at),
        ("open.test", at),
        ("muted.test", at),
        ("selftest.luoto.invalid", at),
    ]);
    env.credentials(
        &[(
            "t.key",
            BindingSpec::Static {
                secret_ref: "env:X".into(),
            },
        )],
        &[("env:X", "real-secret")],
    );
    let open = |until| luoto_shared::policy::Open {
        until: Some(until),
        except: vec![luoto_shared::policy::Mute {
            host: "muted.test".into(),
            ..Default::default()
        }],
    };
    env.apply(Policy {
        open: Some(open(Utc::now() + TimeDelta::hours(1))),
        ..credentialed_policy()
    });

    assert_eq!(
        env.request("PUT", "http://open.test:8080/upload", &[], b"x")
            .status,
        200
    );
    // A host with a credential keeps to its rules; mutes and the self-test's name stay denied.
    let r = env.request("POST", "http://api.test/secret", &[], b"");
    assert!(
        r.status == 403 && r.denied("method_not_allowed"),
        "{}",
        r.head
    );
    for url in [
        "http://muted.test/",
        "http://selftest.luoto.invalid/",
        "http://x.selftest.luoto.invalid/",
    ] {
        let r = env.get(url);
        assert!(r.status == 403 && r.denied("no_rule"), "{url}: {}", r.head);
    }
    let r = env.get(&format!("http://127.0.0.1:{}/", at.port()));
    assert!(r.status == 403 && r.denied("private_address"), "{}", r.head);
    let r = send(
        env.gate_port,
        b"GET /_sandbox/status HTTP/1.1\r\nHost: gate\r\nConnection: close\r\n\r\n",
    );
    assert!(r.json()["open"]["until"].is_string(), "{}", r.body);

    // It closes at its time, with nothing to apply.
    env.apply(Policy {
        open: Some(open(Utc::now() + TimeDelta::seconds(1))),
        ..credentialed_policy()
    });
    std::thread::sleep(Duration::from_millis(1500));
    let r = env.get("http://open.test/");
    assert!(r.status == 403 && r.denied("no_rule"), "{}", r.head);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn paths_and_methods_are_canonical_for_rules_and_check_alike() {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let env = Env::start(&[("api.test", *upstream.address())]);
    env.apply(Policy {
        rules: vec![read("read", "api.test")],
        ..Default::default()
    });
    let check = |url: &str, method: &str| {
        let body = serde_json::json!({ "url": url, "method": method }).to_string();
        let r = env.request(
            "POST",
            "http://gate/_sandbox/check",
            &[("content-type", "application/json")],
            body.as_bytes(),
        );
        assert_eq!(r.status, 200, "{}", r.body);
        r.json()["allowed"].as_bool().unwrap()
    };

    // Paths servers resolve differently never reach a rule, and `sandbox check` agrees.
    for path in ["/x/../ok", "/x/%2e%2e/ok", "//ok", "/x%5c..%5cok"] {
        let url = format!("http://api.test{path}");
        let r = env.get(&url);
        assert!(r.status == 403 && r.denied("guard"), "{path}: {}", r.head);
        assert!(!check(&url, "GET"), "{path}");
    }
    // Methods are case-sensitive: a lower-case one is refused, not upper-cased.
    let r = env.request("get", "http://api.test/ok", &[], b"");
    assert!(r.status == 403 && r.denied("guard"), "{}", r.head);
    assert!(!check("http://api.test/ok", "get"));
    // A percent-encoded letter is the same path, matched and forwarded decoded.
    assert_eq!(env.get("http://api.test/%6fk").status, 200);
    assert!(check("http://api.test/%6fk", "GET"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn the_destination_and_framing_are_unambiguous() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&upstream)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let env = Env::start(&[
        ("api.test", *upstream.address()),
        ("other.test", *upstream.address()),
    ]);
    env.apply(Policy {
        rules: vec![
            rule("write", "api.test", Access::Level(AccessLevel::Write), &[]),
            read("other", "other.test"),
        ],
        ..Default::default()
    });

    let other = [("Host", "other.test")];
    let r = env.request("GET", "http://api.test/ok", &other, b"");
    assert!(r.status == 421 && r.denied("invalid_host"), "{}", r.head);
    let both = [("Host", "api.test"), ("Host", "other.test")];
    let r = env.request("GET", "http://api.test/ok", &both, b"");
    assert!(r.status == 421 && r.denied("invalid_host"), "{}", r.head);

    // Content-Length beside Transfer-Encoding: the gate reads the body as chunked and closes
    // the connection after it, so what follows the body never becomes a request of its own.
    let smuggled = "GET /smuggled HTTP/1.1\r\nHost: api.test\r\n\r\n";
    let raw = format!(
        "POST http://api.test/upload HTTP/1.1\r\nHost: api.test\r\nContent-Length: 4\r\n\
         Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n{smuggled}"
    );
    send(env.gate_port, raw.as_bytes());
    let seen = upstream.received_requests().await.unwrap();
    let upload = seen.iter().find(|r| r.url.path() == "/upload").unwrap();
    assert_eq!(upload.body, b"hello");
    assert!(seen.iter().all(|r| r.url.path() != "/smuggled"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn the_ssh_key_signs_in_the_vault_and_is_never_handed_out() {
    let env = Env::start(&[]);
    env.credentials(
        &[(
            "ssh",
            BindingSpec::SshAgent {
                key_ref: "env:K".into(),
                host_keys: vec![],
            },
        )],
        &[("env:K", include_str!("../../vault/tests/keys/user_ed25519"))],
    );

    // The gate passes a message on and the vault answers with the key's identity (base64 of
    // `12, 0 0 0 1, …`).
    let r = env.request(
        "POST",
        "http://gate/_sandbox/ssh-agent",
        &[("content-type", "application/json")],
        br#"{"conn":"c1","message":"Cw=="}"#,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let message = r.json()["message"].as_str().unwrap().to_string();
    assert!(message.starts_with("DAAAAAE"), "{message}");

    let r = env.credential("ssh");
    assert_eq!(
        r.status, 404,
        "an SSH key is not a credential the vault hands out"
    );
}

const ZERO: &str = "0000000000000000000000000000000000000000";
const ONE: &str = "1111111111111111111111111111111111111111";

fn pkt(line: &str) -> Vec<u8> {
    format!("{:04x}{line}", line.len() + 4).into_bytes()
}

/// A receive-pack request body: `updates` (`old new ref`), a flush and a pack.
fn push(updates: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    for (i, u) in updates.iter().enumerate() {
        let caps = if i == 0 { "\0report-status" } else { "" };
        body.extend(pkt(&format!("{u}{caps}\n")));
    }
    body.extend_from_slice(b"0000PACK\0\0\0\x02");
    body.extend((0..=255u8).cycle().take(4096));
    body
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn pushes_go_only_to_granted_repos_and_unprotected_branches() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex("/git-receive-pack$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let env = Env::start(&[("github.com", *upstream.address())]);
    env.apply(Policy {
        rules: vec![rule(
            "git",
            "github.com",
            Access::Methods(vec!["GET".into(), "POST".into()]),
            &[],
        )],
        github: Some(GithubGuard {
            repos: vec!["o/r".into()],
            protected_branches: vec!["main".into()],
            ..Default::default()
        }),
        ..Default::default()
    });
    let receive = |path: &str, headers: &[(&str, &str)], body: &[u8]| {
        env.request("POST", &format!("http://github.com{path}"), headers, body)
    };
    let refused = |r: &Reply, why: &str| {
        assert!(r.status == 403 && r.denied("guard"), "{}", r.head);
        assert!(r.body.contains(why), "{why}: {}", r.body);
    };

    // A feature branch of a granted repo, and the push arrives byte for byte.
    let feature = push(&[&format!("{ZERO} {ONE} refs/heads/feature")]);
    let r = receive("/o/r.git/git-receive-pack", &[], &feature);
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = upstream.received_requests().await.unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body, feature);

    let r = receive("/other/r.git/git-receive-pack", &[], &feature);
    refused(&r, "granted repositories");
    let main = push(&[&format!("{ONE} {ONE} refs/heads/main")]);
    refused(
        &receive("/o/r.git/git-receive-pack", &[], &main),
        "protected",
    );
    // Git hosts read paths without case, and so does the guard.
    refused(
        &receive("/O/R.git/GIT-RECEIVE-PACK", &[], &main),
        "protected",
    );
    let both = push(&[
        &format!("{ZERO} {ONE} refs/heads/feature"),
        &format!("{ONE} {ONE} refs/heads/main"),
    ]);
    refused(
        &receive("/o/r.git/git-receive-pack", &[], &both),
        "protected",
    );
    let tag = push(&[&format!("{ZERO} {ONE} refs/tags/v1")]);
    refused(&receive("/o/r.git/git-receive-pack", &[], &tag), "tag");
    let delete = push(&[&format!("{ONE} {ZERO} refs/heads/feature")]);
    refused(
        &receive("/o/r.git/git-receive-pack", &[], &delete),
        "deleting",
    );
    let gzip = [("content-encoding", "gzip")];
    refused(
        &receive("/o/r.git/git-receive-pack", &gzip, &feature),
        "compressed",
    );

    // A command list without its end: past 1 MiB the guard refuses. One byte past, so the gate
    // has read all of it when it answers; unread bytes would reset the connection first.
    let filler = format!("{ZERO} {ONE} refs/heads/{}\n", "a".repeat(65_400));
    let mut endless = Vec::new();
    while endless.len() + filler.len() + 4 <= 1 << 20 {
        endless.extend(pkt(&filler));
    }
    let rest = (1 << 20) + 1 - endless.len() - 4;
    endless.extend(pkt(&format!("a b {}\n", "c".repeat(rest - 5))));
    assert_eq!(endless.len(), (1 << 20) + 1);
    refused(
        &receive("/o/r.git/git-receive-pack", &[], &endless),
        "too large",
    );

    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        1,
        "no refused push reached upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn graphql_mutations_pass_only_from_the_allowlist() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let env = Env::start(&[("api.github.com", *upstream.address())]);
    env.apply(Policy {
        rules: vec![rule(
            "api",
            "api.github.com",
            Access::Methods(vec!["POST".into()]),
            &[],
        )],
        github: Some(GithubGuard {
            graphql_mutations: vec!["createPullRequest".into()],
            ..Default::default()
        }),
        ..Default::default()
    });
    let graphql = |path: &str, query: &str| {
        let body = serde_json::json!({ "query": query }).to_string();
        let url = format!("http://api.github.com{path}");
        (env.request("POST", &url, &[], body.as_bytes()), body)
    };

    let (r, body) = graphql("/graphql", "query { viewer { login } }");
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = upstream.received_requests().await.unwrap();
    assert_eq!(seen[0].body, body.as_bytes());
    let (r, _) = graphql(
        "/graphql",
        "mutation { createPullRequest(input: {}) { clientMutationId } }",
    );
    assert_eq!(r.status, 200, "{}", r.head);

    let unlisted = "mutation { mergePullRequest(input: {}) { clientMutationId } }";
    for path in ["/graphql", "/GraphQL"] {
        let (r, _) = graphql(path, unlisted);
        assert!(r.status == 403 && r.denied("guard"), "{path}: {}", r.head);
        assert!(r.body.contains("mergePullRequest"), "{}", r.body);
    }
    assert_eq!(upstream.received_requests().await.unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn model_apis_get_no_request_that_has_them_reach_the_network() {
    let upstream = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&upstream)
        .await;
    let env = Env::start(&[("api.model.test", *upstream.address())]);
    env.apply(Policy {
        rules: vec![rule(
            "api",
            "api.model.test",
            Access::Level(AccessLevel::Write),
            &[],
        )],
        body_denies: vec![
            BodyDeny {
                host: "api.model.test".into(),
                paths: vec!["/v1/messages".into()],
                keys: vec!["mcp_servers".into()],
                tool_types: vec!["web_fetch".into()],
                reason: "server tools are off".into(),
                ..Default::default()
            },
            BodyDeny {
                host: "api.model.test".into(),
                paths: vec!["/prs/*".into()],
                methods: vec!["PATCH".into()],
                ignore_case: true,
                only_keys: vec!["title".into()],
                reason: "completing stays with people".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    });
    let post = |path: &str, headers: &[(&str, &str)], body: &str| {
        let url = format!("http://api.model.test{path}");
        env.request("POST", &url, headers, body.as_bytes())
    };

    let plain = r#"{"model":"m","tools":[{"type":"web_search_20250305"}]}"#;
    let r = post("/v1/messages", &[], plain);
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(
        upstream.received_requests().await.unwrap()[0].body,
        plain.as_bytes()
    );

    let refused = [
        (
            &[][..],
            r#"{"tools":[{"type":"web_fetch_20260209"}]}"#,
            "server tools",
        ),
        (
            &[][..],
            r#"{"mcp_servers":[{"type":"url","url":"https://x"}]}"#,
            "server tools",
        ),
        (
            &[][..],
            r#"{"tools":[],"tools":[{"type":"web_fetch"}]}"#,
            "JSON object",
        ),
        (&[("content-encoding", "gzip")][..], plain, "compressed"),
    ];
    for (headers, body, why) in refused {
        let r = post("/v1/messages", headers, body);
        assert!(r.status == 403 && r.denied("guard"), "{body}: {}", r.head);
        assert!(r.body.contains(why), "{}", r.body);
    }
    // Other paths aren't read.
    let r = post("/v1/messages/count_tokens", &[], r#"{"mcp_servers":[]}"#);
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 2);

    // Other methods' bodies, when a deny names them; matched in any case, keys allowlisted.
    let patch = |path: &str, body: &str| {
        let url = format!("http://api.model.test{path}");
        env.request("PATCH", &url, &[], body.as_bytes())
    };
    let r = patch("/PRS/1", r#"{"status":"completed"}"#);
    assert!(r.status == 403 && r.body.contains("people"), "{}", r.head);
    let r = patch("/prs/1", r#"{"title":"t"}"#);
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 3);
}

/// A TCP server that echoes what it reads, one thread per connection.
fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn a_tunnel_closes_once_its_rule_is_revoked() {
    let env = Env::start(&[("tunnel.test", echo_server())]);
    let mut tunnel = read("tunnel", "tunnel.test");
    tunnel.rule.access = Access::Level(AccessLevel::Write);
    tunnel.rule.mode = Mode::Tunnel;
    env.apply(Policy {
        rules: vec![tunnel],
        ..Default::default()
    });

    let mut s = open_tunnel(&env);
    env.apply(Policy::default());
    let revoked = Instant::now();
    assert!(closed(&mut s), "the tunnel stayed open");
    assert!(
        revoked.elapsed() < Duration::from_secs(7),
        "closed after {:?}",
        revoked.elapsed()
    );
}

/// A tunnel to `tunnel.test:443` through the proxy, checked to echo.
fn open_tunnel(env: &Env) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", env.gate_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n")
        .unwrap();
    let head = read_head(&mut s).unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    s.write_all(b"ping").unwrap();
    let mut echo = [0u8; 4];
    s.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"ping");
    s
}

/// Whether the gate closed `s` (within its 10 s read timeout).
fn closed(s: &mut TcpStream) -> bool {
    let mut buf = [0u8; 16];
    match s.read(&mut buf) {
        Ok(n) => n == 0,
        Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn a_quiet_tunnel_is_closed() {
    let env = Env::start_limited(&[("tunnel.test", echo_server())], "tunnel_idle_ms=500");
    let mut tunnel_rule = read("tunnel", "tunnel.test");
    tunnel_rule.rule.access = Access::Level(AccessLevel::Write);
    tunnel_rule.rule.mode = Mode::Tunnel;
    env.apply(Policy {
        rules: vec![tunnel_rule],
        ..Default::default()
    });

    let mut s = open_tunnel(&env);
    let quiet = Instant::now();
    assert!(closed(&mut s), "the tunnel stayed open");
    let after = quiet.elapsed();
    assert!(
        after >= Duration::from_millis(400),
        "closed after {after:?}"
    );
    assert!(after < Duration::from_secs(5), "closed after {after:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn connections_past_the_cap_are_refused_and_reported() {
    let env = Env::start_limited(&[], "conns=2");
    let held: Vec<TcpStream> = (0..2)
        .map(|_| TcpStream::connect(("127.0.0.1", env.gate_port)).unwrap())
        .collect();
    // Accepted in order, so this one finds both places taken. It sends nothing: the gate
    // answers without reading, and unread bytes would turn its close into a reset.
    let mut third = TcpStream::connect(("127.0.0.1", env.gate_port)).unwrap();
    third
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut reply = String::new();
    third.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    assert!(reply.contains("too many open connections"), "{reply}");

    drop(held);
    // Time for the gate to see them close, so the next request finds a place.
    std::thread::sleep(Duration::from_millis(200));
    let deadline = Instant::now() + Duration::from_secs(10);
    let denial = loop {
        let r = send(
            env.gate_port,
            b"GET /_sandbox/status HTTP/1.1\r\nHost: gate\r\nConnection: close\r\n\r\n",
        );
        let found = (r.status == 200)
            .then(|| r.json()["recent_denials"].as_array().cloned())
            .flatten()
            .and_then(|ds| ds.into_iter().find(|d| d["reason"] == "conn_limit"));
        if let Some(d) = found {
            break d;
        }
        assert!(Instant::now() < deadline, "no refusal reported: {}", r.body);
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(denial["intake"], "proxy");
    let message = denial["message"].as_str().unwrap();
    assert!(message.contains("2 connections were open"), "{message}");
}

/// An HTTP server that answers by path: `/silent` never, `/stall` with a head and part of
/// the body it announces, anything else ten bytes, one every 100 ms.
fn timing_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 2 {
                    line.clear();
                }
                let mut s = stream;
                match first.split_whitespace().nth(1).unwrap_or("") {
                    "/silent" => std::thread::sleep(Duration::from_secs(30)),
                    "/late" => {
                        std::thread::sleep(Duration::from_millis(1500));
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nlate");
                    }
                    "/pause" => {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na");
                        std::thread::sleep(Duration::from_millis(1500));
                        let _ = s.write_all(b"b");
                    }
                    "/stall" => {
                        let _ =
                            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial");
                        std::thread::sleep(Duration::from_secs(30));
                    }
                    _ => {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n");
                        for _ in 0..10 {
                            std::thread::sleep(Duration::from_millis(100));
                            let _ = s.write_all(b"x");
                        }
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn a_stalled_exchange_is_cut_but_a_slow_one_is_not() {
    let env = Env::start_limited(
        &[("timing.test", timing_server())],
        "response_head_ms=500,idle_ms=500",
    );
    env.apply(Policy {
        rules: vec![read("timing", "timing.test")],
        ..Default::default()
    });

    let started = Instant::now();
    let r = env.get("http://timing.test/silent");
    assert_eq!(r.status, 504, "{}", r.head);
    assert!(r.body.contains("no response within 500 ms"), "{}", r.body);
    assert!(started.elapsed() < Duration::from_secs(5));

    let started = Instant::now();
    let r = env.get("http://timing.test/stall");
    assert_eq!((r.status, r.body.as_str()), (200, "partial"));
    assert!(started.elapsed() < Duration::from_secs(5));

    // Twice the idle limit in all, but never idle for it.
    let r = env.get("http://timing.test/slow");
    assert_eq!((r.status, r.body.as_str()), (200, "xxxxxxxxxx"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn a_rules_idle_lets_its_host_stay_silent_longer() {
    let env = Env::start_limited(
        &[("timing.test", timing_server())],
        "response_head_ms=500,idle_ms=500",
    );
    env.apply(Policy {
        rules: vec![read("timing", "timing.test")],
        ..Default::default()
    });
    assert_eq!(env.get("http://timing.test/late").status, 504);
    assert_eq!(env.get("http://timing.test/pause").body, "a");

    let mut patient = read("patient", "timing.test");
    patient.rule.idle = Some("3s".into());
    env.apply(Policy {
        rules: vec![patient],
        ..Default::default()
    });
    let r = env.get("http://timing.test/late");
    assert_eq!((r.status, r.body.as_str()), (200, "late"), "{}", r.head);
    let r = env.get("http://timing.test/pause");
    assert_eq!((r.status, r.body.as_str()), (200, "ab"));
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A CA made as `luoto` makes an env's (`cli/src/ca.rs`).
struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    cert: CertificateDer<'static>,
    cert_pem: String,
    key_pem: String,
}

impl TestCa {
    fn new(name: &str) -> TestCa {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            cert: cert.der().clone(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            issuer: Issuer::new(params, key),
        }
    }

    /// A server certificate for `name`, and its key.
    fn leaf(&self, name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        (
            cert.der().clone(),
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
    }

    /// Make this the CA the gate intercepts TLS with.
    fn install(&self, env: &Env) {
        env.gate(&GateCtl::InstallCa {
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
        });
    }
}

/// `LUOTO_UPSTREAM_CAS`: each host's own upstream CA.
fn upstream_cas(cas: &[(&str, &TestCa)]) -> String {
    let map: BTreeMap<&str, &str> = cas
        .iter()
        .map(|(h, ca)| (*h, ca.cert_pem.as_str()))
        .collect();
    serde_json::to_string(&map).unwrap()
}

#[derive(Clone)]
struct Seen {
    sni: Option<String>,
    /// The request head.
    head: String,
}

/// An HTTPS server presenting a certificate for `name` that `ca` signed: it keeps what each
/// request it reads came with and answers it `200 ok`.
struct Https {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Https {
    fn start(ca: &TestCa, name: &str) -> Https {
        let (cert, key) = ca.leaf(name);
        let cfg = Arc::new(
            ServerConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let (cfg, log) = (cfg.clone(), log.clone());
                std::thread::spawn(move || {
                    let mut tls = StreamOwned::new(ServerConnection::new(cfg).unwrap(), tcp);
                    let Ok(head) = read_head(&mut tls) else {
                        return;
                    };
                    let sni = tls.conn.server_name().map(str::to_string);
                    log.lock().unwrap().push(Seen { sni, head });
                    let _ = tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        Https { addr, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// Through the gate's proxy: CONNECT to `authority`, then TLS in the tunnel as `sni`, trusting
/// only `ca`.
fn connect_tls(
    gate_port: u16,
    authority: &str,
    sni: &str,
    ca: &TestCa,
) -> std::io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let mut tcp = TcpStream::connect(("127.0.0.1", gate_port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())?;
    let head = read_head(&mut tcp)?;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert.clone()).unwrap();
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(sni.to_string()).unwrap();
    let mut conn = ClientConnection::new(Arc::new(cfg), name).unwrap();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)?;
    }
    Ok(StreamOwned::new(conn, tcp))
}

/// What the client found wrong with the certificate, when that ended its handshake.
fn certificate_error(e: &std::io::Error) -> Option<&rustls::CertificateError> {
    match e.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::InvalidCertificate(c) => Some(c),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn intercepted_tls_shows_a_leaf_for_the_destination_signed_by_the_env_ca() {
    let env_ca = TestCa::new("luoto sandbox CA (it)");
    let forge_ca = TestCa::new("forge CA");
    let forge = Https::start(&forge_ca, "forge.test");
    let cas = upstream_cas(&[("forge.test", &forge_ca)]);
    let env = Env::start_with(
        &[("forge.test", forge.addr)],
        &[("LUOTO_UPSTREAM_CAS", &cas)],
    );
    env_ca.install(&env);
    env.apply(Policy {
        rules: vec![read("read", "forge.test")],
        ..Default::default()
    });

    // Trusting only the env CA, the client verifies the chain and the name it asked for.
    let r = env.https(&env_ca, "forge.test", "/ok", &[]);
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(r.body, "ok");
    let seen = forge.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].sni.as_deref(), Some("forge.test"));
    assert!(
        seen[0].head.starts_with("GET /ok HTTP/1.1\r\n"),
        "{}",
        seen[0].head
    );

    // The gate's own leaf, not the upstream's passed through.
    let Err(e) = connect_tls(env.gate_port, "forge.test:443", "forge.test", &forge_ca) else {
        panic!("the forge's CA verified the gate's certificate");
    };
    assert_eq!(
        certificate_error(&e),
        Some(&rustls::CertificateError::UnknownIssuer),
        "{e}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn a_renewed_env_ca_signs_every_leaf_from_its_install_on() {
    // A renewal keeps the CA's name and changes its key, as `luoto up` does.
    let old = TestCa::new("luoto sandbox CA (it)");
    let new = TestCa::new("luoto sandbox CA (it)");
    let forge_ca = TestCa::new("forge CA");
    let forge = Https::start(&forge_ca, "forge.test");
    let cas = upstream_cas(&[("forge.test", &forge_ca)]);
    let env = Env::start_with(
        &[("forge.test", forge.addr)],
        &[("LUOTO_UPSTREAM_CAS", &cas)],
    );
    let reported = |env: &Env| env.gate(&GateCtl::Status)["data"]["ca_pem_sha256"].clone();
    let sha = |ca: &TestCa| hex::encode(Sha256::digest(ca.cert_pem.as_bytes()));
    assert_eq!(reported(&env), serde_json::Value::Null);
    old.install(&env);
    env.apply(Policy {
        rules: vec![read("read", "forge.test")],
        ..Default::default()
    });
    assert_eq!(env.https(&old, "forge.test", "/ok", &[]).status, 200);
    assert_eq!(reported(&env), sha(&old));

    // The leaf cached for the host a moment ago went with the old CA.
    new.install(&env);
    assert_eq!(reported(&env), sha(&new));
    let r = env.https(&new, "forge.test", "/ok", &[]);
    assert_eq!(r.status, 200, "{}", r.head);
    let Err(e) = connect_tls(env.gate_port, "forge.test:443", "forge.test", &old) else {
        panic!("a client trusting only the old CA verified the gate's certificate");
    };
    assert!(certificate_error(&e).is_some(), "{e}");
    // Kept for a restarted gate.
    let kept = std::fs::read_to_string(env._dir.path().join("gate/ca.crt")).unwrap();
    assert_eq!(kept, new.cert_pem);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn sni_and_host_must_name_the_connect_destination() {
    let env_ca = TestCa::new("luoto sandbox CA (it)");
    let api_ca = TestCa::new("api CA");
    let api = Https::start(&api_ca, "api.test");
    let cas = upstream_cas(&[("api.test", &api_ca)]);
    let env = Env::start_with(
        &[("api.test", api.addr), ("other.test", api.addr)],
        &[("LUOTO_UPSTREAM_CAS", &cas)],
    );
    env_ca.install(&env);
    env.apply(Policy {
        rules: vec![read("api", "api.test"), read("other", "other.test")],
        ..Default::default()
    });

    // Domain fronting: the gate ends the handshake instead of choosing either name.
    let fronted = connect_tls(env.gate_port, "api.test:443", "other.test", &env_ca);
    let Err(e) = fronted else {
        panic!("a handshake for another name than the CONNECT's completed");
    };
    assert_eq!(e.kind(), ErrorKind::UnexpectedEof, "{e}");
    let r = env.https(&env_ca, "api.test", "/ok", &[("Host", "other.test")]);
    assert!(r.status == 421 && r.denied("invalid_host"), "{}", r.head);
    assert!(api.seen().is_empty());

    assert_eq!(env.https(&env_ca, "api.test", "/ok", &[]).status, 200);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn credentials_go_only_over_tls_in_place_of_the_clients_own() {
    let env_ca = TestCa::new("luoto sandbox CA (it)");
    let api_ca = TestCa::new("api CA");
    let api = Https::start(&api_ca, "api.test");
    let cas = upstream_cas(&[("api.test", &api_ca)]);
    let env = Env::start_with(&[("api.test", api.addr)], &[("LUOTO_UPSTREAM_CAS", &cas)]);
    env_ca.install(&env);
    env.credentials(
        &[(
            "t.key",
            BindingSpec::Static {
                secret_ref: "env:X".into(),
            },
        )],
        &[("env:X", "real-secret")],
    );
    let mut policy = credentialed_policy();
    policy.rules.push(read("plain", "plain.test"));
    policy.injections.push(Injection {
        binding: "t.key".into(),
        host: "plain.test".into(),
        paths: vec![],
        methods: Vec::new(),
        ignore_case: false,
        place: Placement::Header {
            name: "x-api-key".into(),
            format: "{secret}".into(),
        },
    });
    env.apply(policy);

    let attacker = [
        ("x-api-key", "attacker"),
        ("Authorization", "Bearer attacker"),
        ("Cookie", "session=attacker"),
    ];
    let r = env.https(&env_ca, "api.test", "/secret", &attacker);
    assert_eq!(r.status, 200, "{}", r.head);
    let sent = api.seen()[0].head.to_ascii_lowercase();
    assert!(sent.contains("\r\nx-api-key: real-secret\r\n"), "{sent}");
    for absent in ["attacker", "authorization", "cookie"] {
        assert!(!sent.contains(absent), "{absent}: {sent}");
    }

    // Plain HTTP would carry it readable: refused before the gate resolves the name.
    let r = env.get("http://plain.test/secret");
    assert!(r.status == 403 && r.denied("guard"), "{}", r.head);
    assert!(r.body.contains("only over HTTPS"), "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn upstream_certificates_verify_only_for_the_host_their_ca_is_trusted_for() {
    let env_ca = TestCa::new("luoto sandbox CA (it)");
    let forge_ca = TestCa::new("forge CA");
    let forge = Https::start(&forge_ca, "forge.test");
    // The forge's CA, signing for a host it isn't trusted for.
    let other = Https::start(&forge_ca, "other.test");
    // Trusted for `alias.test`, but its certificate names another host.
    let alias = Https::start(&forge_ca, "forge.test");
    let cas = upstream_cas(&[("forge.test", &forge_ca), ("alias.test", &forge_ca)]);
    let env = Env::start_with(
        &[
            ("forge.test", forge.addr),
            ("other.test", other.addr),
            ("alias.test", alias.addr),
        ],
        &[("LUOTO_UPSTREAM_CAS", &cas)],
    );
    env_ca.install(&env);
    env.apply(Policy {
        rules: vec![
            read("forge", "forge.test"),
            read("other", "other.test"),
            read("alias", "alias.test"),
        ],
        ..Default::default()
    });

    assert_eq!(env.https(&env_ca, "forge.test", "/", &[]).status, 200);
    for host in ["other.test", "alias.test"] {
        let r = env.https(&env_ca, host, "/", &[]);
        assert_eq!(r.status, 502, "{host}: {}", r.head);
        assert!(
            r.body
                .contains(&format!("TLS handshake with {host} failed")),
            "{}",
            r.body
        );
    }
    assert!(other.seen().is_empty() && alias.seen().is_empty());
}

const APP_KEY: &str = include_str!("keys/app_rsa");
const APP_PUB: &str = include_str!("keys/app_rsa.pub");
const ROTATED_KEY: &str = include_str!("keys/app_rsa_rotated");
const ROTATED_PUB: &str = include_str!("keys/app_rsa_rotated.pub");

/// GitHub's access-token endpoint: a new token on each call (`ghs_1`, `ghs_2`, …), valid for
/// `ttl`.
struct Mint {
    minted: AtomicUsize,
    ttl: TimeDelta,
}

impl Respond for Mint {
    fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
        let n = self.minted.fetch_add(1, Ordering::SeqCst) + 1;
        ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "token": format!("ghs_{n}"),
            "expires_at": Utc::now() + self.ttl,
        }))
    }
}

fn access_tokens(installation: u64) -> String {
    format!("/app/installations/{installation}/access_tokens")
}

/// GitHub minting tokens for `installation`, each valid for `ttl`.
async fn github_mints(api: &MockServer, installation: u64, ttl: TimeDelta) {
    Mock::given(method("POST"))
        .and(path(access_tokens(installation)))
        .respond_with(Mint {
            minted: AtomicUsize::new(0),
            ttl,
        })
        .mount(api)
        .await;
}

/// A binding to tokens from `installation` of App 123 (key `env:APP`) for `repos`.
fn app(api: &MockServer, installation: u64, repos: &[&str], perms: &[(&str, &str)]) -> BindingSpec {
    BindingSpec::GithubApp {
        app_id: "123".into(),
        installation_id: installation,
        key_ref: "env:APP".into(),
        repos: repos.iter().map(|r| r.to_string()).collect(),
        permissions: perms
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        api_base: api.uri(),
    }
}

#[derive(serde::Deserialize)]
struct AppClaims {
    iat: i64,
    exp: i64,
}

/// The claims of the App JWT `req` bore, if `public_pem` verifies it as RS256 from App 123.
fn app_jwt(req: &wiremock::Request, public_pem: &str) -> jsonwebtoken::errors::Result<AppClaims> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    let auth = req.headers.get("authorization").unwrap().to_str().unwrap();
    let jwt = auth.strip_prefix("Bearer ").unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["123"]);
    validation.set_required_spec_claims(&["iat", "exp", "iss"]);
    let key = DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();
    decode::<AppClaims>(jwt, &key, &validation).map(|t| t.claims)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn app_tokens_are_minted_with_the_app_keys_jwt_for_each_bindings_repos_and_permissions() {
    let api = MockServer::start().await;
    github_mints(&api, 42, TimeDelta::hours(1)).await;
    let env = Env::start(&[]);
    let write = [
        ("contents", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ];
    let read = [
        ("contents", "read"),
        ("metadata", "read"),
        ("pull_requests", "read"),
    ];
    env.credentials(
        &[
            ("github", app(&api, 42, &["web"], &write)),
            ("github-read", app(&api, 42, &["lib"], &read)),
            ("unknown", app(&api, 7, &["web"], &write)),
        ],
        &[("env:APP", APP_KEY)],
    );

    let before = Utc::now().timestamp();
    let r = env.credential("github");
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["value"], "ghs_1");
    assert_eq!(env.credential("github-read").json()["value"], "ghs_2");
    let after = Utc::now().timestamp();

    let seen = api.received_requests().await.unwrap();
    assert_eq!(seen.len(), 2);
    for (req, repos, perms) in [(&seen[0], "web", write), (&seen[1], "lib", read)] {
        assert_eq!(req.url.path(), access_tokens(42));
        let claims = app_jwt(req, APP_PUB).unwrap();
        // Backdated a minute for clock drift, and GitHub's ten-minute maximum.
        assert!(
            (before - 60..=after - 60).contains(&claims.iat),
            "iat {} between {before} and {after}",
            claims.iat
        );
        assert_eq!(claims.exp - claims.iat, 600);
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        let perms: BTreeMap<&str, &str> = perms.into_iter().collect();
        assert_eq!(
            body,
            serde_json::json!({ "repositories": [repos], "permissions": perms })
        );
    }

    let r = env.credential("unknown");
    assert_eq!(r.status, 502, "{}", r.body);
    assert!(
        r.body.contains("GitHub refused the token request (404)"),
        "{}",
        r.body
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn an_app_token_is_reused_until_ten_minutes_before_it_expires() {
    let api = MockServer::start().await;
    github_mints(&api, 42, TimeDelta::minutes(11)).await;
    github_mints(&api, 43, TimeDelta::minutes(9)).await;
    let env = Env::start(&[]);
    let perms = [("contents", "read")];
    env.credentials(
        &[
            ("eleven", app(&api, 42, &["web"], &perms)),
            ("nine", app(&api, 43, &["web"], &perms)),
        ],
        &[("env:APP", APP_KEY)],
    );
    let value = |binding| {
        let r = env.credential(binding);
        assert_eq!(r.status, 200, "{}", r.body);
        r.json()["value"].as_str().unwrap().to_string()
    };

    assert_eq!(value("eleven"), value("eleven"));
    assert_ne!(value("nine"), value("nine"));
    let seen = api.received_requests().await.unwrap();
    let mints = |installation| {
        seen.iter()
            .filter(|r| r.url.path() == access_tokens(installation))
            .count()
    };
    assert_eq!((mints(42), mints(43)), (1, 2));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn a_new_app_key_retires_the_minted_token_and_signs_the_next() {
    let api = MockServer::start().await;
    github_mints(&api, 42, TimeDelta::hours(1)).await;
    let env = Env::start(&[]);
    env.credentials(
        &[("github", app(&api, 42, &["web"], &[("contents", "write")]))],
        &[("env:APP", APP_KEY)],
    );
    let value = || env.credential("github").json()["value"].clone();
    let load = |key: &str| {
        let secrets = BTreeMap::from([("env:APP".to_string(), key.to_string())]);
        env.vault(&VaultCtl::Load {
            secrets,
            held_only: false,
        });
    };

    assert_eq!(value(), "ghs_1");
    load(APP_KEY);
    assert_eq!(value(), "ghs_1", "the same key again keeps the token");
    load(ROTATED_KEY);
    assert_eq!(value(), "ghs_2");

    let seen = api.received_requests().await.unwrap();
    assert_eq!(seen.len(), 2);
    assert!(app_jwt(&seen[0], APP_PUB).is_ok());
    assert!(app_jwt(&seen[1], ROTATED_PUB).is_ok());
    assert!(app_jwt(&seen[1], APP_PUB).is_err());
}

const SUB: &str = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0";
const ARM: &str = "https://management.azure.com/";

/// A signed JWT as Microsoft Entra ID issues one for `aud`, numbered `n`.
fn entra_token(aud: &str, n: usize) -> String {
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "aud": aud,
        "oid": "aaaaaaaa-0000-0000-0000-000000000001",
        "tid": "bbbbbbbb-0000-0000-0000-000000000002",
        "appid": "cccccccc-0000-0000-0000-000000000003",
        "nbf": now - 300,
        "exp": now + 3600,
        "upn": "someone@contoso.example",
        "ipaddr": "203.0.113.7",
        "n": n,
    });
    let key = jsonwebtoken::EncodingKey::from_secret(b"entra");
    jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &key).unwrap()
}

/// Resource Manager readable under the test subscription, with the `azure-arm` token on
/// reads there and from IMDS.
fn azure_policy() -> Policy {
    let paths = [format!("/subscriptions/{SUB}/**")];
    let mut arm = rule(
        "azure-arm",
        "management.azure.com",
        Access::Level(AccessLevel::Read),
        &[],
    );
    arm.rule.paths = paths.to_vec();
    arm.rule.ignore_case = true;
    Policy {
        rules: vec![arm],
        injections: vec![Injection {
            binding: "azure-arm".into(),
            host: "management.azure.com".into(),
            paths: paths.to_vec(),
            methods: ["GET", "HEAD", "OPTIONS"].map(String::from).to_vec(),
            ignore_case: true,
            place: Placement::Header {
                name: "authorization".into(),
                format: "Bearer {secret}".into(),
            },
        }],
        azure: Some(AzureIdentity {
            audiences: BTreeMap::from([(Audience::Arm, "azure-arm".to_string())]),
        }),
        ..Default::default()
    }
}

fn imds_path(resource: &str) -> String {
    format!("/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}")
}

impl Env {
    /// IMDS's answer for `resource` through the proxy, as a client asks with `Metadata: true`.
    fn imds(&self, resource: &str) -> Reply {
        let url = format!("http://169.254.169.254{}", imds_path(resource));
        self.request("GET", &url, &[("Metadata", "true")], b"")
    }
}

/// `placeholder` is `real`'s header and the claims tools read, with a signature that can't
/// verify.
fn assert_placeholder(placeholder: &str, real: &str) {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts = |t: &str| -> Vec<String> { t.split('.').map(str::to_string).collect() };
    let (p, r) = (parts(placeholder), parts(real));
    assert_eq!(p[0], r[0], "the header is the real token's");
    let claims = |payload: &str| -> serde_json::Value {
        serde_json::from_slice(&b64.decode(payload).unwrap()).unwrap()
    };
    let (kept, all) = (claims(&p[1]), claims(&r[1]));
    for k in ["aud", "oid", "tid", "appid", "nbf", "exp"] {
        assert_eq!(kept[k], all[k], "{k}");
    }
    for k in ["upn", "ipaddr", "n"] {
        assert!(all.get(k).is_some() && kept.get(k).is_none(), "{k}");
    }
    assert_ne!(p[2], r[2]);
    assert_eq!(
        b64.decode(&p[2]).unwrap(),
        b"luoto: the gate adds the real token"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn imds_answers_with_a_placeholder_through_both_intakes() {
    let transparent = free_port();
    let redirect = format!("127.0.0.1:{transparent}=169.254.169.254:80");
    let env = Env::start_with(&[], &[("LUOTO_TEST_TRANSPARENT", &redirect)]);
    let real = entra_token(ARM, 1);
    let real_sig = real.rsplit_once('.').unwrap().1;
    env.credentials(
        &[(
            "azure-arm",
            BindingSpec::Static {
                secret_ref: "env:ARM".into(),
            },
        )],
        &[("env:ARM", &real)],
    );
    env.apply(azure_policy());

    let encoded = "https%3A%2F%2Fmanagement.azure.com%2F";
    let raw = format!(
        "GET {} HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata: true\r\nConnection: close\r\n\r\n",
        imds_path(encoded)
    );
    for r in [env.imds(encoded), send(transparent, raw.as_bytes())] {
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(!r.body.contains(real_sig), "{}", r.body);
        let j = r.json();
        assert_placeholder(j["access_token"].as_str().unwrap(), &real);
        assert_eq!(j["resource"], ARM);
        assert_eq!(j["token_type"], "Bearer");
        assert_eq!(j["client_id"], "cccccccc-0000-0000-0000-000000000003");
        let expires_in: i64 = j["expires_in"].as_str().unwrap().parse().unwrap();
        assert!((3500..=3600).contains(&expires_in), "{expires_in}");
        let expires_on: i64 = j["expires_on"].as_str().unwrap().parse().unwrap();
        assert!(expires_on > Utc::now().timestamp() + 3500);
    }
    // The spellings the Azure CLI and the SDKs use.
    for resource in [
        "https://management.core.windows.net/",
        "https://management.azure.com",
    ] {
        assert_eq!(env.imds(resource).status, 200, "{resource}");
    }
    let r = env.request(
        "GET",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&scope=https://management.azure.com/.default",
        &[("Metadata", "true")],
        b"",
    );
    assert_eq!(r.status, 200, "{}", r.body);

    // Clients probe for IMDS without the header.
    let r = env.get(&format!("http://169.254.169.254{}", imds_path(encoded)));
    assert_eq!(r.status, 400);
    assert_eq!(r.json()["error"], "invalid_request");
    assert_eq!(
        r.json()["error_description"],
        "Required metadata header not specified"
    );
    // An audience the env isn't granted.
    let r = env.imds("https://vault.azure.net");
    assert_eq!(r.status, 400);
    assert_eq!(r.json()["error"], "invalid_resource");
    assert!(
        r.json()["error_description"]
            .as_str()
            .unwrap()
            .contains("https://vault.azure.net"),
        "{}",
        r.body
    );
    // Anything else under /metadata is answered too; elsewhere the address is never dialed.
    let r = env.request(
        "GET",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        &[("Metadata", "true")],
        b"",
    );
    assert_eq!(r.status, 404, "{}", r.body);
    let r = env.get("http://169.254.169.254/latest/meta-data/");
    assert!(r.status == 403 && r.denied("no_rule"), "{}", r.head);

    env.vault(&VaultCtl::Lock);
    env.gate(&GateCtl::FlushCredentials);
    let r = env.imds(encoded);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("luoto vault unlock"), "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn resource_manager_gets_the_real_token_in_place_of_the_placeholder() {
    let arm = MockServer::start().await;
    let real = entra_token(ARM, 1);
    Mock::given(header_exists("x-ms-authorization-auxiliary"))
        .respond_with(ResponseTemplate::new(418))
        .mount(&arm)
        .await;
    Mock::given(method("GET"))
        .and(header("authorization", format!("Bearer {real}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})))
        .mount(&arm)
        .await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(401))
        .mount(&arm)
        .await;
    let env = Env::start(&[("management.azure.com", *arm.address())]);
    env.credentials(
        &[(
            "azure-arm",
            BindingSpec::Static {
                secret_ref: "env:ARM".into(),
            },
        )],
        &[("env:ARM", &real)],
    );
    env.apply(azure_policy());

    let placeholder = env.imds(ARM).json()["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let bearer = format!("Bearer {placeholder}");
    let groups = format!("/subscriptions/{SUB}/resourceGroups?api-version=2021-04-01");
    for path in [groups.clone(), groups.to_uppercase()] {
        let r = env.request(
            "GET",
            &format!("http://management.azure.com{path}"),
            &[
                ("Authorization", &bearer),
                ("x-ms-authorization-auxiliary", "Bearer someone-elses"),
            ],
            b"",
        );
        assert_eq!(r.status, 200, "{path}: {}", r.head);
    }
    // Another subscription is not the env's.
    let r = env.request(
        "GET",
        "http://management.azure.com/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups",
        &[("Authorization", &bearer)],
        b"",
    );
    assert!(
        r.status == 403 && r.denied("path_not_allowed"),
        "{}",
        r.head
    );

    // A write another rule allows (an approved request) goes without the token, and without
    // the client's own.
    let mut policy = azure_policy();
    policy.rules.push(rule(
        "approved",
        "management.azure.com",
        Access::Level(AccessLevel::Write),
        &[],
    ));
    env.apply(policy);
    let keys = format!(
        "/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a/listKeys"
    );
    let r = env.request(
        "POST",
        &format!("http://management.azure.com{keys}"),
        &[("Authorization", "Bearer from-the-sandbox")],
        b"",
    );
    assert_eq!(r.status, 401, "{}", r.head);

    let seen = arm.received_requests().await.unwrap();
    assert_eq!(seen.len(), 3);
    for req in &seen[..2] {
        assert_eq!(
            req.headers["authorization"],
            format!("Bearer {real}").as_str()
        );
        assert!(!req.headers.contains_key("x-ms-authorization-auxiliary"));
    }
    assert_eq!(seen[2].method.as_str(), "POST");
    assert!(!seen[2].headers.contains_key("authorization"));
}

/// Entra ID's token endpoint: a new token for the scope's audience on each call, for client
/// secrets `good-1` and `good-2`; any other is refused as Entra refuses one.
struct EntraMint {
    minted: AtomicUsize,
    /// How long each answer takes.
    delay: Duration,
}

impl Respond for EntraMint {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        let body = String::from_utf8_lossy(&req.body);
        if !["client_secret=good-1", "client_secret=good-2"]
            .iter()
            .any(|s| body.split('&').any(|kv| kv == *s))
        {
            return ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client",
                "error_description": "AADSTS7000215: Invalid client secret provided.",
            }));
        }
        let n = self.minted.fetch_add(1, Ordering::SeqCst) + 1;
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "token_type": "Bearer",
                "expires_in": 3599,
                "ext_expires_in": 3599,
                "access_token": entra_token(ARM, n),
            }))
            .set_delay(self.delay)
    }
}

/// An env whose `azure-arm` binding is minted by `login` for a service principal with secret
/// `secret`.
async fn service_principal(login: &MockServer, delay: Duration, secret: &str) -> Env {
    Mock::given(method("POST"))
        .and(path("/contoso.onmicrosoft.com/oauth2/v2.0/token"))
        .respond_with(EntraMint {
            minted: AtomicUsize::new(0),
            delay,
        })
        .mount(login)
        .await;
    let env = Env::start_both(&[], &[], &[("LUOTO_TEST_AZURE_LOGIN", &login.uri())]);
    env.credentials(
        &[(
            "azure-arm",
            BindingSpec::AzureServicePrincipal {
                tenant: "contoso.onmicrosoft.com".into(),
                client_id: "11111111-2222-3333-4444-555555555555".into(),
                secret_ref: "env:SP".into(),
                audience: ARM.into(),
            },
        )],
        &[("env:SP", secret)],
    );
    env
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn requests_meanwhile_share_one_mint_and_a_refusal_is_not_asked_again_at_once() {
    let login = MockServer::start().await;
    let env = service_principal(&login, Duration::from_millis(500), "good-1").await;
    let tokens: Vec<String> = std::thread::scope(|s| {
        let asks: Vec<_> = (0..6)
            .map(|_| s.spawn(|| env.credential("azure-arm")))
            .collect();
        asks.into_iter()
            .map(|a| {
                let r = a.join().unwrap();
                assert_eq!(r.status, 200, "{}", r.body);
                r.json()["value"].as_str().unwrap().to_string()
            })
            .collect()
    });
    assert!(tokens.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(login.received_requests().await.unwrap().len(), 1);

    let refused = MockServer::start().await;
    let env = service_principal(&refused, Duration::ZERO, "revoked").await;
    let first = env.credential("azure-arm");
    assert_eq!(first.status, 502, "{}", first.body);
    for _ in 0..5 {
        let again = env.credential("azure-arm");
        assert_eq!((again.status, &again.body), (502, &first.body));
    }
    assert_eq!(refused.received_requests().await.unwrap().len(), 1);
    // A new secret is tried at once.
    env.vault(&VaultCtl::Load {
        secrets: BTreeMap::from([("env:SP".to_string(), "good-1".to_string())]),
        held_only: false,
    });
    assert_eq!(env.credential("azure-arm").status, 200);
    assert_eq!(refused.received_requests().await.unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn a_service_principal_token_is_minted_in_the_vault_reused_and_retired_with_its_secret() {
    let login = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/contoso.onmicrosoft.com/oauth2/v2.0/token"))
        .respond_with(EntraMint {
            minted: AtomicUsize::new(0),
            delay: Duration::ZERO,
        })
        .mount(&login)
        .await;
    let env = Env::start_both(&[], &[], &[("LUOTO_TEST_AZURE_LOGIN", &login.uri())]);
    let client = "11111111-2222-3333-4444-555555555555";
    env.credentials(
        &[(
            "azure-arm",
            BindingSpec::AzureServicePrincipal {
                tenant: "contoso.onmicrosoft.com".into(),
                client_id: client.into(),
                secret_ref: "env:SP".into(),
                audience: ARM.into(),
            },
        )],
        &[("env:SP", "good-1")],
    );
    let value = || {
        let r = env.credential("azure-arm");
        assert_eq!(r.status, 200, "{}", r.body);
        r.json()
    };
    let load = |secret: &str| {
        let secrets = BTreeMap::from([("env:SP".to_string(), secret.to_string())]);
        env.vault(&VaultCtl::Load {
            secrets,
            held_only: false,
        });
    };

    let first = value();
    let token = first["value"].as_str().unwrap().to_string();
    let expires: chrono::DateTime<Utc> =
        serde_json::from_value(first["expires_at"].clone()).unwrap();
    assert!((expires - Utc::now()).num_seconds() > 3500);
    assert_eq!(value()["value"], token.as_str(), "reused until near expiry");
    load("good-1");
    assert_eq!(
        value()["value"],
        token.as_str(),
        "the same secret keeps the token"
    );

    // The gate's IMDS hands out its placeholder.
    env.apply(azure_policy());
    assert_placeholder(
        env.imds(ARM).json()["access_token"].as_str().unwrap(),
        &token,
    );

    load("good-2");
    let rotated = value()["value"].as_str().unwrap().to_string();
    assert_ne!(rotated, token);

    load("not-the-secret");
    let r = env.credential("azure-arm");
    assert_eq!(r.status, 502, "{}", r.body);
    assert!(r.body.contains("invalid_client") && r.body.contains("AADSTS7000215"));
    assert!(!r.body.contains("not-the-secret"));
    assert_eq!(
        env.credential("azure-arm").body,
        r.body,
        "answered again, not asked"
    );

    let seen = login.received_requests().await.unwrap();
    assert_eq!(seen.len(), 3);
    for (req, secret) in seen.iter().zip(["good-1", "good-2", "not-the-secret"]) {
        assert_eq!(
            req.headers["content-type"],
            "application/x-www-form-urlencoded"
        );
        let mut form: Vec<&str> = std::str::from_utf8(&req.body).unwrap().split('&').collect();
        form.sort();
        let secret = format!("client_secret={secret}");
        let id = format!("client_id={client}");
        let mut want = vec![
            secret.as_str(),
            id.as_str(),
            "grant_type=client_credentials",
            "scope=https%3A%2F%2Fmanagement.azure.com%2F%2F.default",
        ];
        want.sort();
        assert_eq!(form, want);
    }
}
