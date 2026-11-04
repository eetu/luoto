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
        let Ok((mut inbound, peer)) = listener.accept().await else {
            continue;
        };
        if internal.is_some_and(|net| net.contains(&peer.ip())) || is_dev(peer.ip(), dev_ip) {
            continue;
        }
        tokio::spawn(async move {
            if let Ok(mut outbound) = TcpStream::connect(SocketAddr::new(dev_ip, port)).await {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            }
        });
    }
}

fn is_dev(peer: IpAddr, dev: IpAddr) -> bool {
    peer == dev
}
