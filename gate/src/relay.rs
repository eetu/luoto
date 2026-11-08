//! Dev-server port relays: the host reaches `127.0.0.1:<port>` (published on the gate),
//! the gate relays to the dev container. Inbound only; connections from the sandbox side
//! are refused so the relay is never a path back out.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ipnet::IpNet;
use tokio::net::{TcpListener, TcpStream};

use crate::state::State;

pub async fn serve(state: Arc<State>, listener: TcpListener, port: u16) {
    let Some(dev_ip) = state.cfg.dev_ip else {
        return;
    };
    let internal: Option<IpNet> = state
        .cfg
        .internal_subnet
        .as_deref()
        .and_then(|s| s.parse().ok());
    loop {
        let (mut inbound, peer) = crate::limits::accept(&listener).await;
        // Only podman's forwarder: not the env's own network, nor the vault network that
        // the vault and other envs' gates share (10.212.0.0/16).
        let vault_net = match peer.ip() {
            IpAddr::V4(v4) => v4.octets()[..2] == [10, 212],
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .is_some_and(|v4| v4.octets()[..2] == [10, 212]),
        };
        if internal.is_some_and(|net| net.contains(&peer.ip())) || peer.ip() == dev_ip || vault_net
        {
            continue;
        }
        tokio::spawn(async move {
            if let Ok(mut outbound) = TcpStream::connect(SocketAddr::new(dev_ip, port)).await {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            }
        });
    }
}
