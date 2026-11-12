//! Shared types and the policy engine for luoto. No I/O: the CLI, gate, vault and sandbox
//! helper all depend on this crate, so it stays dependency-light and fully unit-tested. The
//! one exception is `tun`, behind its feature, for the gate and the sandbox helper.

pub mod api;
pub mod azure_identity;
pub mod creds;
pub mod ctl;
pub mod events;
pub mod forges;
pub mod frame;
pub mod glob;
pub mod host;
pub mod policy;
pub mod presets;
pub mod profiles;
#[cfg(all(target_os = "linux", feature = "tun"))]
pub mod tun;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Port the gate's explicit proxy and in-sandbox API listen on.
pub const PROXY_PORT: u16 = 3128;
/// Port the gate's transparent catch-all listens on (iptables REDIRECT target).
pub const TRANSPARENT_PORT: u16 = 15001;
/// Where a gate reaches the vault: a unix socket that is its env's alone (the env's folder of
/// the vault's socket volume, or on Apple the gate's broker, `gate/src/uplink.rs`).
pub const VAULT_SOCKET: &str = "/run/luoto/vault/vault.sock";
/// Hostname the sandbox uses for the gate.
pub const GATE_HOST: &str = "gate";

/// The variables every dev container gets pointing at the gate's proxy.
pub const PROXY_VARS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"];
/// The variables every dev container gets naming what bypasses the proxy.
pub const NO_PROXY_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
/// The variables every dev container gets pointing at the CA bundle with the gate's CA.
pub const CA_VARS: [&str; 8] = [
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "PIP_CERT",
    "CARGO_HTTP_CAINFO",
    "GIT_SSL_CAINFO",
    "DENO_CERT",
];

/// Whether luoto sets variable `name` in every dev container itself (its proxy, CA bundle and
/// `LUOTO_` names), so a value of the env's own would break it.
pub fn luoto_sets(name: &str) -> bool {
    name.starts_with("LUOTO_")
        || name == "NODE_USE_ENV_PROXY"
        || PROXY_VARS
            .iter()
            .chain(&NO_PROXY_VARS)
            .chain(&CA_VARS)
            .any(|v| *v == name)
}

/// Variables a shell owns: setting one breaks it (zsh stops reading the file that exports
/// `UID`, bash refuses its read-only ones, fish its `status`).
const SHELL_OWNS: [&str; 22] = [
    "UID",
    "EUID",
    "GID",
    "EGID",
    "PPID",
    "USERNAME",
    "USER",
    "LOGNAME",
    "HOME",
    "SHELL",
    "PATH",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "IFS",
    "HOSTNAME",
    "TERM",
    "status",
    "pipestatus",
    "argv",
    "fish_pid",
    "version",
];

/// Why the env's own variable can't be named `name`, if it can't.
pub fn variable_refused(name: &str) -> Option<String> {
    if !variable_name(name) {
        Some(format!(
            "`{name}` is not a variable name (letters, digits and `_`, not starting with a digit)"
        ))
    } else if luoto_sets(name) {
        Some(format!(
            "luoto sets `{name}` in every env itself (its proxy, CA bundle or own names)"
        ))
    } else if SHELL_OWNS.contains(&name) {
        Some(format!("`{name}` is the shell's own"))
    } else {
        None
    }
}

/// A variable name every shell exports: letters, digits and `_`, not starting with a digit.
pub fn variable_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

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
