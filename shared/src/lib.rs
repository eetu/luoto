//! Shared types and the policy engine for luoto. No I/O: the CLI, gate, vault and sandbox
//! helper all depend on this crate, so it stays dependency-light and fully unit-tested.

pub mod api;
pub mod azure_identity;
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

/// `(name, text)` of each built-in TOML file `<dir>/<name>.toml`.
macro_rules! embed {
    ($dir:literal; $($name:literal),* $(,)?) => {
        &[$(($name, include_str!(concat!("../", $dir, "/", $name, ".toml")))),*]
    };
}
pub(crate) use embed;

/// The built-in file `name` among `files`, parsed, with `name_of` set to its name. The tests
/// parse every one, so a built-in file that doesn't is a bug caught before release.
pub(crate) fn load<T: serde::de::DeserializeOwned>(
    files: &[(&str, &str)],
    name: &str,
    name_of: fn(&mut T) -> &mut String,
) -> Option<T> {
    let (n, src) = files.iter().find(|(n, _)| *n == name)?;
    let mut item: T =
        toml::from_str(src).unwrap_or_else(|e| panic!("built-in `{n}.toml` does not parse: {e}"));
    *name_of(&mut item) = (*n).to_string();
    Some(item)
}
