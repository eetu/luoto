//! The real gate and vault binaries, spawned locally, in front of a wiremock upstream.
//! `#[ignore]`d because they build and spawn binaries: `just it`.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use luoto_shared::creds::{BindingSpec, Injection, Placement};
use luoto_shared::ctl::{GateCtl, VaultCtl};
use luoto_shared::policy::{Access, AccessLevel, CompiledRule, Policy, Rule};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build() {
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
            "luoto-gate/test-hooks",
        ])
        .status()
        .unwrap()
        .success();
    assert!(ok, "building gate/vault failed");
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
    head: String,
}

/// One absolute-form request through the proxy.
fn proxy(port: u16, method: &str, url: &str, extra: &[(&str, &str)]) -> Reply {
    let host = url.trim_start_matches("http://").split('/').next().unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!(
        "{method} {url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: 0\r\n"
    );
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let head = text
        .split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    Reply { status, head }
}

/// One POST of a JSON body; the status and the body.
fn post(port: u16, target: &str, headers: &str, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let req = format!(
        "POST {target} HTTP/1.1\r\n{headers}Connection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    let status = buf
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = buf
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string();
    (status, body)
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

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns binaries; run with `just it`"]
async fn gate_enforces_policy_and_injects_credentials() {
    build();
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

    let dir = tempfile::tempdir().unwrap();
    let vault_sock = dir.path().join("v.sock");
    let gate_sock = dir.path().join("g.sock");
    let vault_port = free_port();
    let gate_port = free_port();
    let bin = root().join("target/debug");

    let _vault = Proc(
        Command::new(bin.join("luoto-vault"))
            .env("LUOTO_VAULT_ADDR", format!("127.0.0.1:{vault_port}"))
            .env("LUOTO_CTL_SOCKET", &vault_sock)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let _gate = Proc(
        Command::new(bin.join("luoto-gate"))
            .env("LUOTO_ENV", "it")
            .env("LUOTO_GATE_IP", "10.255.255.1")
            .env("LUOTO_PROXY_ADDR", format!("127.0.0.1:{gate_port}"))
            .env("LUOTO_STATE_DIR", dir.path().join("gate"))
            .env("LUOTO_CTL_SOCKET", &gate_sock)
            .env(
                "LUOTO_TEST_RESOLVE",
                format!("api.test={}", upstream.address()),
            )
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(&vault_sock);
    wait_for(&gate_sock);

    let token = "test-env-token";
    let mut bindings = BTreeMap::new();
    bindings.insert(
        "t.key".to_string(),
        BindingSpec::Static {
            secret_ref: "env:X".into(),
        },
    );
    bindings.insert(
        "ssh".to_string(),
        BindingSpec::SshAgent {
            key_ref: "env:K".into(),
            host_keys: vec![],
        },
    );
    ctl(
        &vault_sock,
        &VaultCtl::Bind {
            env: "it".into(),
            token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
            bindings,
        },
    );
    let mut secrets = BTreeMap::new();
    secrets.insert("env:X".to_string(), "real-secret".to_string());
    secrets.insert(
        "env:K".to_string(),
        include_str!("../../vault/tests/keys/user_ed25519").to_string(),
    );
    ctl(&vault_sock, &VaultCtl::Load { secrets });
    ctl(
        &gate_sock,
        &GateCtl::SetVault {
            url: format!("http://127.0.0.1:{vault_port}"),
            token: token.into(),
        },
    );
    ctl(
        &gate_sock,
        &GateCtl::ApplyPolicy {
            policy: Box::new(Policy {
                env: "it".into(),
                rules: vec![
                    rule("read", "api.test", Access::Level(AccessLevel::Read), &[]),
                    rule(
                        "post",
                        "api.test",
                        Access::Methods(vec!["POST".into()]),
                        &["/ok"],
                    ),
                    rule(
                        "loopback",
                        "127.0.0.1",
                        Access::Level(AccessLevel::Read),
                        &[],
                    ),
                ],
                injections: vec![
                    Injection {
                        binding: "t.key".into(),
                        host: "api.test".into(),
                        paths: vec!["/secret".into()],
                        ignore_case: false,
                        place: Placement::Header {
                            name: "x-api-key".into(),
                            format: "{secret}".into(),
                        },
                    },
                    Injection {
                        binding: "t.key".into(),
                        host: "api.test".into(),
                        paths: vec!["/qsecret".into()],
                        ignore_case: false,
                        place: Placement::Query {
                            param: "key".into(),
                        },
                    },
                ],
                ..Default::default()
            }),
        },
    );

    let p = gate_port;
    assert_eq!(proxy(p, "GET", "http://api.test/ok", &[]).status, 200);
    assert_eq!(proxy(p, "POST", "http://api.test/ok", &[]).status, 201);

    let r = proxy(p, "DELETE", "http://api.test/ok", &[]);
    assert_eq!(r.status, 403);
    assert!(
        r.head.contains("x-luoto-denied: method_not_allowed"),
        "{}",
        r.head
    );

    let r = proxy(p, "GET", "http://unknown.test/", &[]);
    assert_eq!(r.status, 403);
    assert!(r.head.contains("x-luoto-denied: no_rule"));

    // Even with a rule, a private address is never dialed.
    let r = proxy(
        p,
        "GET",
        &format!("http://127.0.0.1:{}/ok", upstream.address().port()),
        &[],
    );
    assert_eq!(r.status, 403, "{}", r.head);

    // The attacker's header is stripped and the vault's credential injected.
    let r = proxy(
        p,
        "GET",
        "http://api.test/secret",
        &[
            ("x-api-key", "attacker"),
            ("authorization", "Bearer attacker"),
        ],
    );
    assert_eq!(r.status, 200, "{}", r.head);
    // Listing the credential's header in `Connection` doesn't strip the injected one.
    let r = proxy(
        p,
        "GET",
        "http://api.test/secret",
        &[("connection", "x-api-key")],
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let r = proxy(
        p,
        "GET",
        "http://api.test/qsecret?key=attacker&alt=json",
        &[],
    );
    assert_eq!(r.status, 200, "{}", r.head);

    // A mismatching Host header is refused.
    let r = proxy(p, "GET", "http://api.test/ok", &[("Host", "other.test")]);
    assert_ne!(r.status, 200);

    // Paths servers resolve differently, and lower-case methods, never reach a rule.
    for path in [
        "/x/../secret",
        "/x/%2e%2e/secret",
        "//secret",
        "/x%5c..%5csecret",
    ] {
        let r = proxy(p, "GET", &format!("http://api.test{path}"), &[]);
        assert_eq!(r.status, 403, "{path}: {}", r.head);
    }
    assert_eq!(proxy(p, "get", "http://api.test/ok", &[]).status, 403);
    // A percent-encoded letter is the same path, matched and forwarded decoded.
    assert_eq!(proxy(p, "GET", "http://api.test/%6fk", &[]).status, 200);

    // The env's ssh-agent: the gate passes a message on, the vault answers with the key's
    // identity (base64 of `12, 0 0 0 1, …`), and the key itself is never handed out.
    let (status, body) = post(
        p,
        "http://gate/_sandbox/ssh-agent",
        "Host: gate\r\n",
        r#"{"conn":"c1","message":"Cw=="}"#,
    );
    assert_eq!(status, 200, "{body}");
    let reply: serde_json::Value =
        serde_json::from_str(&body[body.find('{').unwrap()..=body.rfind('}').unwrap()]).unwrap();
    assert!(
        reply["message"].as_str().unwrap().starts_with("DAAAAAE"),
        "{reply}"
    );
    let (status, _) = post(
        vault_port,
        "/v1/credential",
        &format!("Host: vault\r\nAuthorization: Bearer {token}\r\n"),
        r#"{"binding":"ssh"}"#,
    );
    assert_eq!(
        status, 404,
        "an SSH key is not a credential the vault hands out"
    );

    // Lock: secrets wiped, caches flushed → credentialed paths fail closed.
    ctl(&vault_sock, &VaultCtl::Lock);
    ctl(&gate_sock, &GateCtl::FlushCredentials);
    let r = proxy(p, "GET", "http://api.test/secret", &[]);
    assert_eq!(r.status, 403);
    assert!(r.head.contains("x-luoto-denied: locked"), "{}", r.head);
    // Non-credentialed egress keeps working while locked.
    assert_eq!(proxy(p, "GET", "http://api.test/ok", &[]).status, 200);
}
