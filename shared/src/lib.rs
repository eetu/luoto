//! Shared types and the policy engine for luoto. No I/O: the CLI, gate, vault and sandbox
//! helper all depend on this crate, so it stays dependency-light and fully unit-tested.

pub mod api;
pub mod creds;
pub mod ctl;
pub mod events;
pub mod forges;
pub mod glob;
pub mod host;
pub mod policy;
pub mod presets;
pub mod profiles;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Port the gate's explicit proxy and in-sandbox API listen on.
pub const PROXY_PORT: u16 = 3128;
/// Port the gate's transparent catch-all listens on (iptables REDIRECT target).
pub const TRANSPARENT_PORT: u16 = 15001;
/// Port the vault listens on (vault network only).
pub const VAULT_PORT: u16 = 8200;
/// Hostname the sandbox uses for the gate.
pub const GATE_HOST: &str = "gate";
