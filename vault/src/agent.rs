//! An ssh-agent for one env's SSH key, which never leaves the vault. `sandbox ssh-agent`
//! passes each message on through the gate; the vault answers the few the OpenSSH client
//! needs and refuses the rest:
//!
//! - identities: the one key;
//! - `session-bind@openssh.com`: the client shows the server's host key, the session id and
//!   the server's signature over that id. The vault verifies it and remembers the session for
//!   that agent connection only when the host key is one the env's credential pins, and the
//!   session is not one forwarded further.
//! - sign: only a public-key login (`SSH_MSG_USERAUTH_REQUEST`) for a session bound that way,
//!   so the key logs in to the pinned hosts and signs nothing else.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rsa::signature::{SignatureEncoding, Signer, Verifier};
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
const USERAUTH_REQUEST: u8 = 50;
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// How long a connection's bound sessions are kept without use.
const IDLE: Duration = Duration::from_secs(3600);
/// Connections with bound sessions kept per env; the least recently used gives way.
const CONNS_PER_ENV: usize = 32;
/// Sessions one connection may bind (an OpenSSH client binds one per server connection).
const SESSIONS_PER_CONN: usize = 4;
/// The longest connection id: `sandbox ssh-agent` sends 16 random bytes as hex.
const CONN_ID_MAX: usize = 32;

/// A connection id as `sandbox ssh-agent` makes them: short lowercase hex.
pub fn conn_id_ok(conn: &str) -> bool {
    (1..=CONN_ID_MAX).contains(&conn.len())
        && conn.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The env's key, parsed once per secret.
pub struct Key {
    private: PrivateKey,
    blob: Vec<u8>,
}

impl Key {
    pub fn from_openssh(pem: &str) -> Result<Self, String> {
        let private =
            PrivateKey::from_openssh(pem.trim()).map_err(|e| format!("not an OpenSSH key: {e}"))?;
        if private.is_encrypted() {
            return Err("the key has a passphrase; give luoto one without".into());
        }
        let blob = private
            .public_key()
            .to_bytes()
            .map_err(|e| format!("encode public key: {e}"))?;
        Ok(Key { private, blob })
    }

    fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
        let sig = match self.private.key_data() {
            KeypairData::Rsa(keypair) => {
                let key = rsa_private(keypair)?;
                let (hash, bytes) = if flags & RSA_SHA2_512 != 0 {
                    let k = rsa::pkcs1v15::SigningKey::<ssh_key::sha2::Sha512>::new(key);
                    (HashAlg::Sha512, k.sign(data).to_vec())
                } else if flags & RSA_SHA2_256 != 0 {
                    let k = rsa::pkcs1v15::SigningKey::<ssh_key::sha2::Sha256>::new(key);
                    (HashAlg::Sha256, k.sign(data).to_vec())
                } else {
                    return Err("ssh-rsa (SHA-1) signatures are not made".into());
                };
                Signature::new(Algorithm::Rsa { hash: Some(hash) }, bytes)
                    .map_err(|e| e.to_string())?
            }
            _ => self.private.try_sign(data).map_err(|e| e.to_string())?,
        };
        Vec::<u8>::try_from(sig).map_err(|e| e.to_string())
    }
}

/// The `rsa` crate's key, built from the components: ssh-key 0.6's own conversion (and so its
/// RSA signing) passes the prime `p` twice instead of `p` and `q`, and every key fails it.
fn rsa_private(k: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey, String> {
    let int = |m: &ssh_key::Mpint| {
        m.as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(|| "malformed RSA key".to_string())
    };
    rsa::RsaPrivateKey::from_components(
        int(&k.public.n)?,
        int(&k.public.e)?,
        int(&k.private.d)?,
        vec![int(&k.private.p)?, int(&k.private.q)?],
    )
    .map_err(|e| format!("RSA key: {e}"))
}

/// Host keys a session may be bound to, from the binding's `host algorithm base64` lines.
pub fn host_keys(lines: &[String]) -> Vec<(String, PublicKey)> {
    lines
        .iter()
        .filter_map(|l| {
            let (host, key) = l.trim().split_once(' ')?;
            Some((host.to_string(), PublicKey::from_openssh(key.trim()).ok()?))
        })
        .collect()
}

/// A session bound on an agent connection.
pub struct Session {
    id: Vec<u8>,
    host: String,
    /// The host key that signed the session id, as its wire-format blob.
    host_key: Vec<u8>,
}

/// The sessions bound on one agent connection.
pub type Bound = Vec<Session>;

struct Conn {
    used: Instant,
    /// Order of last use, for choosing which connection gives way.
    turn: u64,
    bound: Bound,
}

/// Sessions bound on each agent connection, by env. A connection is kept only once a session
/// binds on it, so ids the sandbox makes up cost nothing.
#[derive(Default)]
pub struct Sessions {
    conns: HashMap<(String, String), Conn>,
    turns: u64,
}

impl Sessions {
    /// Run `f` on the sessions bound on `env`'s connection `conn`.
    pub fn with_conn<T>(&mut self, env: &str, conn: &str, f: impl FnOnce(&mut Bound) -> T) -> T {
        let now = Instant::now();
        self.conns.retain(|_, c| now.duration_since(c.used) < IDLE);
        let key = (env.to_string(), conn.to_string());
        let mut bound = self.conns.remove(&key).map(|c| c.bound).unwrap_or_default();
        let out = f(&mut bound);
        if bound.is_empty() {
            return out;
        }
        let same_env = self.conns.iter().filter(|((e, _), _)| e == env);
        if same_env.clone().count() >= CONNS_PER_ENV
            && let Some(oldest) = same_env.min_by_key(|(_, c)| c.turn).map(|(k, _)| k.clone())
        {
            self.conns.remove(&oldest);
        }
        self.turns += 1;
        self.conns.insert(
            key,
            Conn {
                used: now,
                turn: self.turns,
                bound,
            },
        );
        out
    }
}

/// What a message did, for the vault's event.
#[derive(Debug, PartialEq)]
pub enum Note {
    Listed,
    /// A session bound to this host.
    Bound(String),
    /// A login to this host signed.
    Signed(String),
    Refused(String),
}

/// Answer one agent message. `bound` is the connection's sessions.
pub fn handle(
    key: &Key,
    hosts: &[(String, PublicKey)],
    bound: &mut Bound,
    msg: &[u8],
) -> (Vec<u8>, Note) {
    let refuse = |why: &str| (vec![FAILURE], Note::Refused(why.to_string()));
    let mut r = Reader(msg);
    match r.byte() {
        Some(REQUEST_IDENTITIES) => {
            let mut out = vec![IDENTITIES_ANSWER];
            out.extend_from_slice(&1u32.to_be_bytes());
            put_string(&mut out, &key.blob);
            put_string(&mut out, b"luoto vault");
            (out, Note::Listed)
        }
        Some(EXTENSION) => {
            if r.string() != Some(SESSION_BIND) {
                return refuse("agent extension not supported");
            }
            let (Some(host_blob), Some(session), Some(sig), Some(forwarding)) =
                (r.string(), r.string(), r.string(), r.bool())
            else {
                return refuse("malformed session-bind");
            };
            if forwarding {
                return refuse("sessions forwarded beyond the env are not signed for");
            }
            let Ok(host_key) = PublicKey::from_bytes(host_blob) else {
                return refuse("unreadable host key in session-bind");
            };
            let Some((host, _)) = hosts
                .iter()
                .find(|(_, k)| k.key_data() == host_key.key_data())
            else {
                return refuse("the server's host key is not one the env's credential pins");
            };
            let verified = Signature::try_from(sig)
                .ok()
                .is_some_and(|s| Verifier::verify(&host_key, session, &s).is_ok());
            if !verified {
                return refuse("the server's session-bind signature does not verify");
            }
            let rebind = bound.iter().any(|s| s.id == session);
            if !rebind && bound.len() >= SESSIONS_PER_CONN {
                return refuse("too many sessions bound on this agent connection");
            }
            bound.retain(|s| s.id != session);
            bound.push(Session {
                id: session.to_vec(),
                host: host.clone(),
                host_key: host_blob.to_vec(),
            });
            (vec![SUCCESS], Note::Bound(host.clone()))
        }
        Some(SIGN_REQUEST) => {
            let (Some(blob), Some(data), Some(flags)) = (r.string(), r.string(), r.u32()) else {
                return refuse("malformed sign request");
            };
            if blob != key.blob.as_slice() {
                return refuse("unknown key");
            }
            let Some((session, host_key)) = login_session(data, &key.blob) else {
                return refuse("only SSH logins are signed");
            };
            let Some(s) = bound.iter().find(|s| s.id == session) else {
                return refuse("the login's session was not bound to a pinned host");
            };
            if host_key.is_some_and(|k| k != s.host_key) {
                return refuse("the login names another host key than its session's");
            }
            match key.sign(data, flags) {
                Ok(sig) => {
                    let mut out = vec![SIGN_RESPONSE];
                    put_string(&mut out, &sig);
                    (out, Note::Signed(s.host.clone()))
                }
                Err(e) => refuse(&e),
            }
        }
        _ => refuse("agent request not supported"),
    }
}

/// The session id of an `SSH_MSG_USERAUTH_REQUEST` for public-key login with `blob`, and the
/// server's host key when the login is host-bound: OpenSSH uses
/// `publickey-hostbound-v00@openssh.com`, which appends it, with every server that advertises
/// `publickey-hostbound@openssh.com` (GitHub does).
fn login_session<'a>(data: &'a [u8], blob: &[u8]) -> Option<(&'a [u8], Option<&'a [u8]>)> {
    let mut r = Reader(data);
    let session = r.string()?;
    if r.byte()? != USERAUTH_REQUEST {
        return None;
    }
    let (_user, _service) = (r.string()?, r.string()?);
    let hostbound = match r.string()? {
        b"publickey" => false,
        b"publickey-hostbound-v00@openssh.com" => true,
        _ => return None,
    };
    if !r.bool()? {
        return None;
    }
    let _alg = r.string()?;
    if r.string()? != blob {
        return None;
    }
    let host_key = if hostbound { Some(r.string()?) } else { None };
    r.0.is_empty().then_some((session, host_key))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn bool(&mut self) -> Option<bool> {
        self.byte().map(|b| b != 0)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test keys, made for these tests with ssh-keygen; they guard nothing.
    const USER_ED25519: &str = include_str!("../tests/keys/user_ed25519");
    const USER_RSA: &str = include_str!("../tests/keys/user_rsa");
    const HOST_ED25519: &str = include_str!("../tests/keys/host_ed25519");
    const OTHER_HOST: &str = include_str!("../tests/keys/other_host_ed25519");

    fn bind_msg(host: &PrivateKey, session: &[u8], forwarding: bool) -> Vec<u8> {
        let sig = Vec::<u8>::try_from(host.try_sign(session).unwrap()).unwrap();
        let mut m = vec![EXTENSION];
        put_string(&mut m, SESSION_BIND);
        put_string(&mut m, &host.public_key().to_bytes().unwrap());
        put_string(&mut m, session);
        put_string(&mut m, &sig);
        m.push(forwarding as u8);
        m
    }

    fn login(session: &[u8], key: &Key, alg: &str) -> Vec<u8> {
        let mut d = Vec::new();
        put_string(&mut d, session);
        d.push(USERAUTH_REQUEST);
        put_string(&mut d, b"git");
        put_string(&mut d, b"ssh-connection");
        put_string(&mut d, b"publickey");
        d.push(1);
        put_string(&mut d, alg.as_bytes());
        put_string(&mut d, &key.blob);
        d
    }

    fn sign_msg(key: &Key, data: &[u8], flags: u32) -> Vec<u8> {
        let mut m = vec![SIGN_REQUEST];
        put_string(&mut m, &key.blob);
        put_string(&mut m, data);
        m.extend_from_slice(&flags.to_be_bytes());
        m
    }

    fn signature_of(reply: &[u8]) -> Signature {
        assert_eq!(reply[0], SIGN_RESPONSE);
        let mut r = Reader(&reply[1..]);
        Signature::try_from(r.string().unwrap()).unwrap()
    }

    fn pinned(host: &PrivateKey) -> Vec<(String, PublicKey)> {
        host_keys(&[format!(
            "github.com {}",
            host.public_key().to_openssh().unwrap()
        )])
    }

    #[test]
    fn a_login_is_signed_only_for_a_session_a_pinned_host_bound() {
        let key = Key::from_openssh(USER_ED25519).unwrap();
        let host = PrivateKey::from_openssh(HOST_ED25519).unwrap();
        let other = PrivateKey::from_openssh(OTHER_HOST).unwrap();
        let hosts = pinned(&host);
        let mut bound = Vec::new();

        let (ids, note) = handle(&key, &hosts, &mut bound, &[REQUEST_IDENTITIES]);
        assert_eq!((ids[0], note), (IDENTITIES_ANSWER, Note::Listed));

        let data = login(b"session-1", &key, "ssh-ed25519");
        let (r, note) = handle(&key, &hosts, &mut bound, &sign_msg(&key, &data, 0));
        assert_eq!(r, [FAILURE], "{note:?}");

        let (r, _) = handle(
            &key,
            &hosts,
            &mut bound,
            &bind_msg(&other, b"session-1", false),
        );
        assert_eq!(r, [FAILURE], "a host key the env does not pin");
        let (r, _) = handle(
            &key,
            &hosts,
            &mut bound,
            &bind_msg(&host, b"session-1", true),
        );
        assert_eq!(r, [FAILURE], "a forwarded session");

        let (r, note) = handle(
            &key,
            &hosts,
            &mut bound,
            &bind_msg(&host, b"session-1", false),
        );
        assert_eq!((r, note), (vec![SUCCESS], Note::Bound("github.com".into())));
        let (r, note) = handle(&key, &hosts, &mut bound, &sign_msg(&key, &data, 0));
        assert_eq!(note, Note::Signed("github.com".into()));
        Verifier::verify(key.private.public_key(), &data, &signature_of(&r)).unwrap();

        let other_session = login(b"session-2", &key, "ssh-ed25519");
        let (r, _) = handle(&key, &hosts, &mut bound, &sign_msg(&key, &other_session, 0));
        assert_eq!(r, [FAILURE], "another session");
        let (r, _) = handle(
            &key,
            &hosts,
            &mut bound,
            &sign_msg(&key, b"anything else", 0),
        );
        assert_eq!(r, [FAILURE], "data that is no login");

        let mut forged = bind_msg(&host, b"session-1", false);
        let n = forged.len();
        forged[n - 2] ^= 1;
        let (r, _) = handle(&key, &hosts, &mut Vec::new(), &forged);
        assert_eq!(r, [FAILURE], "a signature that does not verify");
    }

    #[test]
    fn a_host_bound_login_is_signed_for_its_sessions_host_key() {
        let key = Key::from_openssh(USER_ED25519).unwrap();
        let host = PrivateKey::from_openssh(HOST_ED25519).unwrap();
        let other = PrivateKey::from_openssh(OTHER_HOST).unwrap();
        let hosts = pinned(&host);
        let mut bound = Vec::new();
        handle(&key, &hosts, &mut bound, &bind_msg(&host, b"s", false));
        let hostbound = |server: &PrivateKey| {
            let mut d = Vec::new();
            put_string(&mut d, b"s");
            d.push(USERAUTH_REQUEST);
            put_string(&mut d, b"git");
            put_string(&mut d, b"ssh-connection");
            put_string(&mut d, b"publickey-hostbound-v00@openssh.com");
            d.push(1);
            put_string(&mut d, b"ssh-ed25519");
            put_string(&mut d, &key.blob);
            put_string(&mut d, &server.public_key().to_bytes().unwrap());
            d
        };
        let data = hostbound(&host);
        let (r, note) = handle(&key, &hosts, &mut bound, &sign_msg(&key, &data, 0));
        assert_eq!(note, Note::Signed("github.com".into()));
        Verifier::verify(key.private.public_key(), &data, &signature_of(&r)).unwrap();
        let (r, _) = handle(
            &key,
            &hosts,
            &mut bound,
            &sign_msg(&key, &hostbound(&other), 0),
        );
        assert_eq!(r, [FAILURE], "another host key than the session's");
    }

    #[test]
    fn rsa_keys_sign_with_the_hash_the_client_asks_for() {
        let key = Key::from_openssh(USER_RSA).unwrap();
        let host = PrivateKey::from_openssh(HOST_ED25519).unwrap();
        let hosts = pinned(&host);
        let mut bound = Vec::new();
        handle(&key, &hosts, &mut bound, &bind_msg(&host, b"s", false));
        for (flags, alg) in [
            (RSA_SHA2_256, "rsa-sha2-256"),
            (RSA_SHA2_512, "rsa-sha2-512"),
        ] {
            let data = login(b"s", &key, alg);
            let (r, note) = handle(&key, &hosts, &mut bound, &sign_msg(&key, &data, flags));
            assert_eq!(note, Note::Signed("github.com".into()));
            let sig = signature_of(&r);
            assert_eq!(sig.algorithm().as_str(), alg);
            Verifier::verify(key.private.public_key(), &data, &sig).unwrap();
        }
        let data = login(b"s", &key, "ssh-rsa");
        let (r, _) = handle(&key, &hosts, &mut bound, &sign_msg(&key, &data, 0));
        assert_eq!(r, [FAILURE], "SHA-1");
    }

    #[test]
    fn an_rsa_host_key_binds_as_azure_devops_signs() {
        let host = PrivateKey::from_openssh(USER_RSA).unwrap();
        let KeypairData::Rsa(pair) = host.key_data() else {
            unreachable!()
        };
        let signer =
            rsa::pkcs1v15::SigningKey::<ssh_key::sha2::Sha256>::new(rsa_private(pair).unwrap());
        let sig = Signature::new(
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            signer.sign(b"s").to_vec(),
        )
        .unwrap();
        let mut m = vec![EXTENSION];
        put_string(&mut m, SESSION_BIND);
        put_string(&mut m, &host.public_key().to_bytes().unwrap());
        put_string(&mut m, b"s");
        put_string(&mut m, &Vec::<u8>::try_from(sig).unwrap());
        m.push(0);
        let key = Key::from_openssh(USER_ED25519).unwrap();
        let hosts = host_keys(&[format!(
            "ssh.dev.azure.com {}",
            host.public_key().to_openssh().unwrap()
        )]);
        let (r, note) = handle(&key, &hosts, &mut Vec::new(), &m);
        assert_eq!(
            (r, note),
            (vec![SUCCESS], Note::Bound("ssh.dev.azure.com".into()))
        );
    }

    fn session(id: &[u8]) -> Session {
        Session {
            id: id.to_vec(),
            host: "github.com".into(),
            host_key: Vec::new(),
        }
    }

    #[test]
    fn sessions_are_per_connection() {
        let mut s = Sessions::default();
        s.with_conn("e", "a", |b| b.push(session(b"x")));
        assert!(s.with_conn("e", "b", |b| b.is_empty()));
        assert!(s.with_conn("other", "a", |b| b.is_empty()));
        assert_eq!(s.with_conn("e", "a", |b| b.len()), 1);
    }

    #[test]
    fn a_connection_is_kept_only_once_a_session_binds() {
        let mut s = Sessions::default();
        for i in 0..100 {
            s.with_conn("e", &format!("{i:x}"), |b| b.len());
        }
        assert!(s.conns.is_empty());
    }

    #[test]
    fn an_env_keeps_its_most_recently_used_connections() {
        let mut s = Sessions::default();
        for i in 0..CONNS_PER_ENV {
            s.with_conn("e", &format!("{i:x}"), |b| b.push(session(b"x")));
        }
        s.with_conn("other", "0", |b| b.push(session(b"x")));
        s.with_conn("e", "0", |b| b.len());
        s.with_conn("e", "ff", |b| b.push(session(b"x")));
        let kept = |s: &mut Sessions, env: &str, c: &str| s.with_conn(env, c, |b| !b.is_empty());
        assert_eq!(
            s.conns.keys().filter(|(e, _)| e == "e").count(),
            CONNS_PER_ENV
        );
        assert!(!kept(&mut s, "e", "1"), "the least recently used gave way");
        assert!(kept(&mut s, "e", "0"));
        assert!(kept(&mut s, "e", "ff"));
        assert!(kept(&mut s, "other", "0"), "other envs are not counted");
    }

    #[test]
    fn a_connection_binds_few_sessions_and_each_once() {
        let key = Key::from_openssh(USER_ED25519).unwrap();
        let host = PrivateKey::from_openssh(HOST_ED25519).unwrap();
        let hosts = pinned(&host);
        let mut bound = Vec::new();
        for _ in 0..3 {
            let (r, _) = handle(&key, &hosts, &mut bound, &bind_msg(&host, b"s0", false));
            assert_eq!(r, [SUCCESS]);
        }
        assert_eq!(bound.len(), 1, "a replayed bind");
        for i in 1..SESSIONS_PER_CONN {
            let id = format!("s{i}");
            handle(
                &key,
                &hosts,
                &mut bound,
                &bind_msg(&host, id.as_bytes(), false),
            );
        }
        assert_eq!(bound.len(), SESSIONS_PER_CONN);
        let (r, note) = handle(&key, &hosts, &mut bound, &bind_msg(&host, b"more", false));
        assert_eq!(r, [FAILURE], "{note:?}");
        let (r, _) = handle(&key, &hosts, &mut bound, &bind_msg(&host, b"s0", false));
        assert_eq!(r, [SUCCESS], "a session already bound binds again");
        assert_eq!(bound.len(), SESSIONS_PER_CONN);
    }

    #[test]
    fn connection_ids_are_short_hex() {
        assert!(conn_id_ok(&"0f".repeat(16)));
        assert!(conn_id_ok("a"));
        for bad in ["", &"0".repeat(33), "0G", "AB", "a/b", "ä"] {
            assert!(!conn_id_ok(bad), "{bad:?}");
        }
    }
}
