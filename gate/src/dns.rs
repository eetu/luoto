//! The sandbox's only resolver. Env-internal names get real answers; every other name gets
//! a fake address from 198.18.0.0/15 that maps back to the name on the transparent path.
//! No query is ever forwarded, so DNS is not a channel out — and every lookup is visible.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use lru::LruCache;
use luoto_shared::events::{Event, EventKind, Intake};
use luoto_shared::host::normalize_host;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::state::{State, lock};

const BASE: u32 = u32::from_be_bytes([198, 18, 0, 16]);
const POOL: u32 = (1 << 17) - 32;
const TTL: u32 = 30;

pub struct FakeIps {
    next: u32,
    by_name: LruCache<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
}

impl Default for FakeIps {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeIps {
    pub fn new() -> Self {
        FakeIps {
            next: 0,
            by_name: LruCache::new(NonZeroUsize::new(65_536).expect("nonzero")),
            by_ip: HashMap::new(),
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn is_fake(ip: Ipv4Addr) -> bool {
        let o = ip.octets();
        o[0] == 198 && (o[1] & 0xfe) == 18
    }

    /// Returns the address for `name` and whether it was newly allocated.
    pub fn ip_for(&mut self, name: &str) -> (Ipv4Addr, bool) {
        if let Some(ip) = self.by_name.get(name) {
            return (*ip, false);
        }
        let ip = Ipv4Addr::from(BASE + (self.next % POOL));
        self.next = self.next.wrapping_add(1);
        if let Some(old) = self.by_ip.insert(ip, name.to_string()) {
            self.by_name.pop(&old);
        }
        if let Some((evicted, eip)) = self.by_name.push(name.to_string(), ip)
            && evicted != name
        {
            self.by_ip.remove(&eip);
        }
        (ip, true)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn name_for(&self, ip: Ipv4Addr) -> Option<String> {
        self.by_ip.get(&ip).cloned()
    }
}

fn answer(state: &State, query: &[u8]) -> Option<Vec<u8>> {
    let msg = Message::from_vec(query).ok()?;
    if msg.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut resp = Message::response(msg.metadata.id, msg.metadata.op_code);
    resp.metadata.recursion_desired = msg.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    let policy = state.policy();
    for q in &msg.queries {
        resp.add_query(q.clone());
        let raw = q.name().to_ascii();
        let Ok(name) = normalize_host(raw.trim_end_matches('.')) else {
            resp.metadata.response_code = ResponseCode::NXDomain;
            continue;
        };
        let gate_v4 = match state.cfg.gate_ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        };
        let internal = policy
            .internal_names
            .iter()
            .find(|n| n.name == name)
            .map(|n| n.ip)
            .or(if name == luoto_shared::GATE_HOST {
                gate_v4
            } else {
                None
            });
        if q.query_type() != RecordType::A {
            // AAAA, HTTPS, SVCB, TXT, …: empty NOERROR so clients fall back to A.
            continue;
        }
        let ip = match internal {
            Some(ip) => ip,
            None => {
                let (ip, fresh) = lock(&state.fake_ips).ip_for(&name);
                if fresh {
                    state.events.emit(Event {
                        kind: Some(EventKind::Dns),
                        intake: Some(Intake::Dns),
                        host: Some(name.clone()),
                        message: Some("resolved locally; nothing was sent upstream".into()),
                        ..Default::default()
                    });
                }
                ip
            }
        };
        resp.add_answer(Record::from_rdata(q.name().clone(), TTL, RData::A(A(ip))));
    }
    resp.to_vec().ok()
}

pub async fn serve_udp(state: Arc<State>, socket: UdpSocket) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        if let Some(reply) = answer(&state, &buf[..n]) {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}

pub async fn serve_tcp(state: Arc<State>, listener: TcpListener) {
    loop {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                if stream.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let Some(reply) = answer(&state, &buf) else {
                    return;
                };
                let mut out = (reply.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&reply);
                if stream.write_all(&out).await.is_err() {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ips_are_stable_and_reversible() {
        let mut f = FakeIps::new();
        let (a, fresh) = f.ip_for("example.com");
        assert!(fresh && FakeIps::is_fake(a));
        assert_eq!(f.ip_for("example.com"), (a, false));
        assert_eq!(f.name_for(a).as_deref(), Some("example.com"));
        let (b, _) = f.ip_for("other.test");
        assert_ne!(a, b);
    }
}
