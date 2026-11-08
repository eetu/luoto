//! Runtime object names and addresses. One place, so every command agrees.
//!
//! A release binary is the `luoto` instance. A source build (no release image pins) is
//! `luoto-dev`: its own config dirs, vault, container names, keychain entries, ssh hosts and UI
//! port, in the same VM (podman on macOS runs one machine at a time), so a checkout runs beside
//! an installed release without touching its envs.

use std::net::Ipv4Addr;

pub fn instance() -> &'static str {
    if crate::release::pinned() {
        "luoto"
    } else {
        "luoto-dev"
    }
}

/// The instance that shares this one's VM.
pub fn other_instance() -> &'static str {
    if instance() == "luoto" {
        "luoto-dev"
    } else {
        "luoto"
    }
}

/// The `luoto ui` port, outside the ports envs forward (1024-32767).
pub fn ui_port() -> u16 {
    if crate::release::pinned() {
        47878
    } else {
        47879
    }
}

pub fn vault() -> String {
    format!("{}-vault", instance())
}

pub fn vault_net() -> String {
    vault()
}

pub fn vault_out_net() -> String {
    format!("{}-vault-out", instance())
}

/// The vault network's third octet: each instance's vault has its own /24.
fn vault_octet() -> u8 {
    if crate::release::pinned() { 0 } else { 1 }
}

pub fn vault_subnet() -> String {
    format!("10.212.{}.0/24", vault_octet())
}

pub fn vault_gw() -> String {
    format!("10.212.{}.1", vault_octet())
}

pub fn vault_ip() -> Ipv4Addr {
    Ipv4Addr::new(10, 212, vault_octet(), 2)
}

pub const LABEL_ENV: &str = "luoto.env";
pub const LABEL_ROLE: &str = "luoto.role";
pub const LABEL_SPEC: &str = "luoto.spec";

/// The env's dev container, and its ssh host alias.
pub fn dev(env: &str) -> String {
    format!("{}-{env}", instance())
}

pub fn gate(env: &str) -> String {
    format!("{}-{env}-gate", instance())
}

pub fn internal_net(env: &str) -> String {
    format!("{}-{env}", instance())
}

pub fn egress_net(env: &str) -> String {
    format!("{}-{env}-out", instance())
}

pub fn volume(env: &str, what: &str) -> String {
    format!("{}-{env}-{what}", instance())
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

/// Whether a container, network or volume labelled with `env` and `role` has the name
/// instance `inst` gives such an object. Both instances label alike in one VM, so the name
/// says whose it is.
pub fn named_by(inst: &str, name: &str, env: &str, role: &str) -> bool {
    let base = format!("{inst}-{env}");
    match role {
        "vault" => {
            env.is_empty()
                && (name == format!("{inst}-vault") || name == format!("{inst}-vault-out"))
        }
        _ if env.is_empty() => false,
        "dev" => name == base,
        "net" => name == base || name == format!("{base}-out"),
        // The gate container, and the tools, gate, work and home volumes.
        _ => name == format!("{base}-{role}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_say_which_instance_made_an_object() {
        for (name, env, role) in [
            (dev("web"), "web", "dev"),
            (gate("web"), "web", "gate"),
            (internal_net("web"), "web", "net"),
            (egress_net("web"), "web", "net"),
            (volume("web", "work"), "web", "work"),
            (volume("web", "gate"), "web", "gate"),
            (vault(), "", "vault"),
            (vault_out_net(), "", "vault"),
        ] {
            assert!(named_by(instance(), &name, env, role), "{name}");
            assert!(!named_by(other_instance(), &name, env, role), "{name}");
        }
        // A release's env `dev-web` (older than the rule against such names) and a source
        // build's env `web` share a container name; the env label tells them apart.
        assert!(named_by("luoto", "luoto-dev-web", "dev-web", "dev"));
        assert!(!named_by("luoto", "luoto-dev-web", "web", "dev"));
        assert!(named_by("luoto-dev", "luoto-dev-web", "web", "dev"));
        assert!(!named_by("luoto", "luoto-web", "", "dev"));
        assert!(!named_by("luoto", "luoto-vault", "web", "vault"));
    }
}
