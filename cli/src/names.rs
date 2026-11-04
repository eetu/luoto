//! Runtime object names and addresses. One place, so every command agrees.

use std::net::Ipv4Addr;

pub const VAULT: &str = "luoto-vault";
pub const VAULT_NET: &str = "luoto-vault";
pub const VAULT_OUT_NET: &str = "luoto-vault-out";
pub const VAULT_SUBNET: &str = "10.212.0.0/24";
pub const VAULT_GW: &str = "10.212.0.1";
pub const VAULT_IP: Ipv4Addr = Ipv4Addr::new(10, 212, 0, 2);

pub const LABEL_ENV: &str = "luoto.env";
pub const LABEL_ROLE: &str = "luoto.role";
pub const LABEL_SPEC: &str = "luoto.spec";

pub fn dev(env: &str) -> String {
    format!("luoto-{env}")
}

pub fn gate(env: &str) -> String {
    format!("luoto-{env}-gate")
}

pub fn internal_net(env: &str) -> String {
    format!("luoto-{env}")
}

pub fn egress_net(env: &str) -> String {
    format!("luoto-{env}-out")
}

pub fn volume(env: &str, what: &str) -> String {
    format!("luoto-{env}-{what}")
}

/// Addresses inside an env's /24.
pub struct Addrs {
    pub subnet: String,
    pub gateway: Ipv4Addr,
    pub gate: Ipv4Addr,
    pub dev: Ipv4Addr,
}

pub fn addrs(octet: u8) -> Addrs {
    Addrs {
        subnet: format!("10.213.{octet}.0/24"),
        gateway: Ipv4Addr::new(10, 213, octet, 1),
        gate: Ipv4Addr::new(10, 213, octet, 2),
        dev: Ipv4Addr::new(10, 213, octet, 3),
    }
}

pub fn image(component: &str, tag: &str) -> String {
    format!("localhost/luoto-{component}:{tag}")
}
