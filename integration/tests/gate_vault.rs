//! The real gate and vault binaries, spawned locally, in front of wiremock and plain TCP
//! upstreams. `#[ignore]`d because they build and spawn binaries: `just it`.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Once;
use std::time::{Duration, Instant};

use luoto_shared::creds::{BindingSpec, Injection, Placement};
use luoto_shared::ctl::{GateCtl, VaultCtl};
use luoto_shared::policy::{Access, AccessLevel, CompiledRule, GithubGuard, Mode, Policy, Rule};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
                "luoto-gate/test-hooks",
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
        self.vault(&VaultCtl::Load { secrets });
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

    let body = r#"{"binding":"ssh"}"#;
    let raw = format!(
        "POST /v1/credential HTTP/1.1\r\nHost: vault\r\nAuthorization: Bearer {TOKEN}\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let r = send(env.vault_port, raw.as_bytes());
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

    let mut s = TcpStream::connect(("127.0.0.1", env.gate_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n")
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    s.write_all(b"ping").unwrap();
    let mut echo = [0u8; 4];
    s.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"ping");

    env.apply(Policy::default());
    let revoked = Instant::now();
    let closed = match s.read(&mut echo) {
        Ok(n) => n == 0,
        Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    };
    assert!(closed, "the tunnel stayed open");
    assert!(
        revoked.elapsed() < Duration::from_secs(7),
        "closed after {:?}",
        revoked.elapsed()
    );
}
