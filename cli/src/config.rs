//! Host-side configuration: the global `config.toml` and one `envs/<name>.toml` per env.
//! Env files are meant to be read and edited by hand; CLI edits go through toml_edit so
//! comments and ordering survive.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use luoto_shared::policy::{AccessLevel, Deny, Mute, Rule};
use serde::{Deserialize, Serialize};
use toml_edit::DocumentMut;

use crate::paths::Paths;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    /// The config format (`format.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// `podman`, `docker` or `container` (Apple's), or a path to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Podman connection / Docker context to use (e.g. the dedicated `luoto` machine).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    /// Stop an env after this long with nothing running in it (`30m`, `2h`, `off`); default
    /// 30 minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_stop: Option<String>,
    /// Forward each port an env listens on to localhost here (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_forward: Option<bool>,
    /// Desktop notifications for access requests and the first denial at each host (default
    /// true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<bool>,
    /// gVisor's `runsc` inside the runtime, which dev containers run on; set by `luoto setup`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gvisor: Option<String>,
    /// Run locally built images with this tag (`dev`) instead of the ones this release pins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<String>,
    /// Login shell of the dev user in every env (`fish`, `zsh`, `bash`, …); default: the
    /// host's own login shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// Editor `luoto open` launches (`zed`, `code`, `cursor`, `ssh`); default: the first one
    /// installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,
    /// Default toolchains for every env (mise `[tools]` syntax); an env's `[tools]` and the
    /// project's own version files take precedence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, toml::Value>,
    /// Installed in every env on `up`, before the env's own `[deps]`.
    #[serde(default, skip_serializing_if = "is_default")]
    pub deps: Deps,
    /// Default options for agents (`[agents.claude] model = "opus"`), wherever an env has
    /// the agent; its luoto.toml and its own config take precedence. Adds no agent to an env.
    #[serde(default, skip_serializing_if = "Agents::is_empty")]
    pub agents: Agents,
    /// Denies for every env, under each env's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Deny>,
    /// Mutes for every env, beside each env's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mute: Vec<Mute>,
    /// Refused, with where credentials go instead ([`env_only`]).
    #[serde(
        rename = "credentials",
        default,
        skip_serializing,
        deserialize_with = "env_only"
    )]
    _credentials: (),
    /// Refused: egress opens per env ([`open_per_env`]).
    #[serde(
        rename = "egress",
        default,
        skip_serializing,
        deserialize_with = "open_per_env"
    )]
    _egress: (),
    #[serde(default)]
    pub sources: Sources,
}

/// `[credentials.*]` in config.toml. Each env names its own, so none reaches an account it
/// doesn't name.
fn env_only<'de, D: serde::Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "credentials go in each env's own file (envs/<env>.toml, `luoto edit -e <env>`), not \
         in config.toml",
    ))
}

/// `[egress]` in config.toml: open egress is one env's, for a while.
fn open_per_env<'de, D: serde::Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "egress opens for one env at a time (`luoto egress open -e <env>`), not in config.toml",
    ))
}

impl GlobalConfig {
    /// The mutes an env with config `cfg` has: these and its own (a luoto.toml has none).
    pub fn mutes_for(&self, cfg: &EnvConfig) -> Vec<Mute> {
        self.mute.iter().chain(&cfg.mute).cloned().collect()
    }

    /// Put these denies and mutes under an env's, each deny noting where it came from.
    pub fn layer_under(&self, cfg: &mut EnvConfig) {
        let mut deny: Vec<Deny> = self
            .deny
            .iter()
            .map(|d| Deny {
                note: Some(match &d.note {
                    Some(n) => format!("config.toml: {n}"),
                    None => "config.toml".into(),
                }),
                ..d.clone()
            })
            .collect();
        deny.append(&mut cfg.deny);
        cfg.deny = deny;
        cfg.mute = self.mutes_for(cfg);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    #[serde(default)]
    pub op: OpSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OpSource {
    /// `desktop` (biometric unlock through the 1Password app) or `service-account`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Ref to the service account token, e.g. `keyring:luoto/op-sa`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSource {
    pub addr: String,
    /// Ref to a token, e.g. `keyring:luoto/vault` or `env:VAULT_TOKEN`.
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// Extra software for the dev container, installed inside the sandbox on `up`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Deps {
    /// Packages for the image's package manager (apt, apk or dnf).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system: Vec<String>,
    /// Shell commands run as the dev user in their home after packages and toolchains;
    /// rerun when `[deps]` changes, so keep them safe to repeat.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub run: Vec<String>,
    /// Extra hosts readable only while deps and toolchains install.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    /// The project's host folder (absolute), copied into the env's workspace volume on the
    /// first `up`; `luoto pull` writes back to it. An env has this or `url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// A remote cloned into `/workspace` inside the env, through the gate, on the first `up`
    /// (`repos::clone_workspace`): the env has nothing on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The branch that clone checks out (default: the remote's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Repositories beside the folder, each at `/workspace/<name>` (`repos.rs`), over the
    /// accepted luoto.toml's of the same name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub repos: BTreeMap<String, Repo>,
}

/// A repository in the workspace: a host folder copied in, or a remote cloned in the env.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Repo {
    /// A host folder (absolute), copied in on the env's next `up`; `luoto pull` writes back
    /// to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    /// A remote cloned inside the env, through the gate, on its next `up`: `owner/repo` on
    /// GitHub, an `https://` or `ssh://` URL, or `user@host:path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The branch a clone checks out (default: the remote's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    /// OCI runtime for the dev container (e.g. `runsc` for gVisor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci_runtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GithubCred {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<u64>,
    /// Ref to the App private key (PEM), e.g. `op://Dev/luoto-gh-app/private key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Ref to a fine-grained PAT, instead of an App.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// `owner/repo` the env may read and write: push (protected branches refused) and pull
    /// requests.
    #[serde(default)]
    pub repos: Vec<String>,
    /// `owner/repo` the env may only fetch and read (a private one needs it here).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_repos: Vec<String>,
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
    #[serde(default = "default_protected")]
    pub protected_branches: Vec<String>,
    #[serde(default = "default_mutations")]
    pub graphql_mutations: Vec<String>,
    #[serde(default)]
    pub allow_tags: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,
}

fn default_protected() -> Vec<String> {
    vec!["main".into(), "master".into()]
}

fn default_mutations() -> Vec<String> {
    vec!["createPullRequest".into(), "updatePullRequest".into()]
}

/// Git over SSH: the private key the vault signs logins with, as the env's ssh-agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SshCred {
    /// Ref to the private key in OpenSSH format (`op://…/private key?ssh-format=openssh`).
    pub key: String,
    /// Hosts it logs in to, on port 22: `github.com`, `ssh.dev.azure.com` (keys pinned), or
    /// others with their `host_keys`.
    pub hosts: Vec<String>,
    /// Host keys for other hosts, as `known_hosts` lines (`host algorithm base64`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_keys: Vec<String>,
    /// 443: GitHub's SSH goes to `ssh.github.com:443`, for networks that block port 22.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_port: Option<u16>,
}

/// Azure DevOps git repositories over HTTPS, with a PAT the gate adds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AzureDevopsCred {
    /// Ref to a PAT with Code (Read & write) in the repos' organization.
    pub token: String,
    /// `org/project/repo` (or a clone URL) the env may fetch and push.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Repos the env may only fetch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_repos: Vec<String>,
    #[serde(default = "default_protected")]
    pub protected_branches: Vec<String>,
    #[serde(default)]
    pub allow_tags: bool,
}

/// Azure Resource Manager and the data planes listed, as a managed identity: the gate answers
/// IMDS in the env with placeholder tokens and adds the real ones on these hosts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AzureCred {
    /// Subscription IDs whose Resource Manager paths the env may reach.
    pub subscriptions: Vec<String>,
    /// `read` (GET, HEAD, OPTIONS) or `write` (every method), on Resource Manager and the
    /// data planes.
    #[serde(default = "read_access")]
    pub access: AccessLevel,
    /// Tenant ID or domain: required with a service principal; else `az`'s current tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Key vault names whose data plane (`<name>.vault.azure.net`) the env may reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_vaults: Vec<String>,
    /// Storage account names whose blob, queue, table, file and dfs hosts the env may reach.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_accounts: Vec<String>,
    /// Microsoft Graph, read-only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub graph: bool,
    /// Under `access = "write"`, also what gives someone access: role assignments and
    /// definitions, PIM requests and policies, federated identity credentials, Lighthouse
    /// delegations, key vault access policies and `elevateAccess`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub role_assignments: bool,
    /// Under `access = "write"`, also template deployments, deployment scripts and deployment
    /// stacks, which act with all of the identity's roles, beyond `subscriptions` too.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deployments: bool,
    /// A service principal's application ID, as the token source in place of `az` on this
    /// machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Ref to its client secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

fn read_access() -> AccessLevel {
    AccessLevel::Read
}

/// Git over HTTPS on any other host (GitLab, Forgejo, Gitea, Bitbucket, GitHub Enterprise
/// Server): a token the gate adds to the listed repos' git requests as basic auth, and the
/// push guard on them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct GitCred {
    /// `git.example.com`, or `git.example.com:3000` for another port.
    pub host: String,
    /// Ref to the token; none for public repos it only fetches (`read_repos`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The user name sent with the token (GitLab takes `oauth2`; Forgejo and Gitea, the
    /// token's owner).
    #[serde(default = "default_git_user")]
    pub username: String,
    /// Repository paths as their URLs write them (`group/sub/repo`) the env may fetch and push.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<String>,
    /// Repository paths the env may only fetch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_repos: Vec<String>,
    #[serde(default = "default_protected")]
    pub protected_branches: Vec<String>,
    #[serde(default)]
    pub allow_tags: bool,
    /// The host is on a private network (its addresses are private), as self-hosted ones are.
    #[serde(default)]
    pub private: bool,
    /// A CA certificate (PEM file on this machine) the host's TLS certificate is signed by,
    /// for a host with an internal CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
}

fn default_git_user() -> String {
    "oauth2".into()
}

/// A custom header credential for any API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CustomCred {
    pub host: String,
    pub secret: String,
    #[serde(default = "default_header")]
    pub header: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub write: bool,
    /// Env vars set in the sandbox with placeholder values (`NAME = "placeholder"`).
    #[serde(default)]
    pub placeholder_env: BTreeMap<String, String>,
}

fn default_header() -> String {
    "authorization".into()
}

fn default_format() -> String {
    "Bearer {secret}".into()
}

/// `[credentials.github]`, or `[[credentials.github]]` once per account: a token or an App
/// installation reaches one owner's repos.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GithubCreds(pub Vec<GithubCred>);

impl GithubCreds {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether one of them lists `owner/repo`, to write (`write`) or at all.
    pub fn covers(&self, repo: &str, write: bool) -> bool {
        self.0.iter().any(|c| {
            c.repos
                .iter()
                .chain(c.read_repos.iter().filter(|_| !write))
                .any(|r| r.eq_ignore_ascii_case(repo))
        })
    }
}

impl Serialize for GithubCreds {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [one] => one.serialize(s),
            many => many.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for GithubCreds {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::value::{MapAccessDeserializer, SeqAccessDeserializer};
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = GithubCreds;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a [credentials.github] table, or [[credentials.github]] tables")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                m: A,
            ) -> Result<GithubCreds, A::Error> {
                Ok(GithubCreds(vec![GithubCred::deserialize(
                    MapAccessDeserializer::new(m),
                )?]))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                s: A,
            ) -> Result<GithubCreds, A::Error> {
                Ok(GithubCreds(Vec::deserialize(SeqAccessDeserializer::new(
                    s,
                ))?))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Credentials {
    #[serde(default, skip_serializing_if = "GithubCreds::is_empty")]
    pub github: GithubCreds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_devops: Option<AzureDevopsCred>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure: Option<AzureCred>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshCred>,
    /// `[[credentials.git]]`, one per host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git: Vec<GitCred>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, CustomCred>,
    /// Provider credentials (`anthropic`, `openai`, …): auth kind → secret ref, or
    /// `login_inside = true`.
    #[serde(flatten)]
    pub providers: BTreeMap<String, BTreeMap<String, ProviderValue>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ProviderValue {
    Ref(String),
    Flag(bool),
}

/// The keys of `[credentials.<provider>]` that say how it authenticates, one at a time: its
/// auth kinds and `login_inside`.
fn auth_keys(provider: &str) -> Result<Vec<String>> {
    let p = luoto_shared::profiles::provider(provider)
        .with_context(|| format!("unknown provider `{provider}`"))?;
    Ok(p.auth
        .into_keys()
        .chain(std::iter::once("login_inside".to_string()))
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvConfig {
    /// The config format (`format.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Login shell for this env; overrides `shell` in config.toml.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub workspace: Workspace,
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default, skip_serializing_if = "Agents::is_empty")]
    pub agents: Agents,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub resources: Resources,
    /// What separates the dev container from the VM's kernel (default: gVisor when set up).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<Isolation>,
    /// Overrides `idle_stop` in config.toml for this env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_stop: Option<String>,
    /// Overrides `auto_forward` in config.toml for this env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_forward: Option<bool>,
    #[serde(default, rename = "allow", skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Rule>,
    /// Open egress (`luoto egress open`); only this file sets it.
    #[serde(default, skip_serializing_if = "is_default")]
    pub egress: Egress,
    /// Requests refused whatever allows them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Deny>,
    /// Denials left out of `luoto egress` and the UI.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mute: Vec<Mute>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub credentials: Credentials,
    /// Model servers agents can use beside their providers (`model_servers.rs`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub model_servers: BTreeMap<String, ModelServer>,
    /// Secrets deliberately exposed to code in the sandbox as env vars.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sandbox_secrets: BTreeMap<String, String>,
    /// Plain env vars for the dev container.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Folders of this machine the env reads at `/shares/<name>`, never writes (`luoto share`,
    /// `shares.rs`). Only the env's own file names them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shares: BTreeMap<String, String>,
    /// Transparent catch-all for tools that ignore the proxy settings (default on).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparent: Option<bool>,
    /// This env's toolchains (mise `[tools]` syntax), over config.toml's; the project's own
    /// version files (`.tool-versions`, `.node-version`, `mise.toml`, …) take precedence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tools: BTreeMap<String, toml::Value>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub deps: Deps,
}

/// `[egress]`: what the env reaches beyond its rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    /// Any HTTP(S) host no rule allows, until `luoto egress close`: written by hand only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open: bool,
    /// The same until then (`luoto egress open --for 1h`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl Egress {
    /// Open at `now`: `Some(None)` with no end, `Some(Some(t))` until `t`.
    pub fn open_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<Option<chrono::DateTime<chrono::Utc>>>> {
        match (self.open, self.open_until) {
            (true, Some(_)) => bail!(
                "[egress]: `open = true` keeps it open with no end and `open_until` until a \
                 time; keep one (`luoto egress open --for 1h` writes `open_until`)"
            ),
            (true, None) => Ok(Some(None)),
            (false, Some(t)) if t > now => Ok(Some(Some(t))),
            _ => Ok(None),
        }
    }
}

/// What can be chosen for an agent (its profile's `settings` say where each goes in its own
/// config): the default for its sessions, which a session can still change.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// The `[model_servers]` entry it starts on, `model` naming the model there; without it,
    /// its provider. Each developer's own: a luoto.toml can't set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_server: Option<String>,
    /// Arguments for every start through luoto (`agent run`, `luoto run`), after its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Arguments for `luoto run` only, after `args`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headless_args: Vec<String>,
}

impl AgentOpts {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The options set, by name.
    pub fn values(&self) -> Vec<(&'static str, &str)> {
        [("model", &self.model), ("effort", &self.effort)]
            .into_iter()
            .filter_map(|(k, v)| Some((k, v.as_deref()?)))
            .collect()
    }

    fn fill_from(&mut self, lower: &AgentOpts) {
        // On a model server, `model` names one of its models, which no team or default knows.
        if self.model.is_none() && self.model_server.is_none() {
            self.model = lower.model.clone();
        }
        if self.effort.is_none() {
            self.effort = lower.effort.clone();
        }
        if self.args.is_empty() {
            self.args = lower.args.clone();
        }
        if self.headless_args.is_empty() {
            self.headless_args = lower.headless_args.clone();
        }
    }
}

/// `[model_servers.<name>]`: a server with an OpenAI- and/or Anthropic-compatible API, on this
/// machine, your network or the internet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelServer {
    /// As this machine reaches it: `http://localhost:11434`, `https://models.example.com`.
    pub url: String,
    /// What it serves: `anthropic`, `openai`.
    pub api: Vec<String>,
    /// The model agents use there unless their own `model` names another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The context window of the model agents use there, in tokens, for agents that can't
    /// tell it from the model's name (Claude Code assumes 200k).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<u64>,
    /// Its token, a secret reference; none for a server that takes none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The header the token goes in: `authorization` (as `Bearer`, the default), or another
    /// as it is (`x-api-key`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Its host name is on a private network, as a self-hosted one is (an address of one
    /// says so itself).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub private: bool,
}

/// The agents of an env: `agents = ["claude"]`, or `[agents.claude]` tables with options
/// (`model`, `effort`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Agents(pub Vec<(String, AgentOpts)>);

impl Agents {
    pub fn from_names(names: impl IntoIterator<Item = String>) -> Self {
        let mut out = Agents::default();
        for n in names {
            out.push(&n);
        }
        out
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(n, _)| n)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|(n, _)| n == name)
    }

    pub fn get(&self, name: &str) -> Option<&AgentOpts> {
        self.0.iter().find(|(n, _)| n == name).map(|(_, o)| o)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, name: &str) {
        if !self.contains(name) {
            self.0.push((name.to_string(), AgentOpts::default()));
        }
    }

    /// Lay `lower` (the accepted luoto.toml) under these: its agents join, and its options fill
    /// what these leave unset.
    pub fn layer_under(&mut self, lower: &Agents) {
        for (name, opts) in &lower.0 {
            match self.0.iter_mut().find(|(n, _)| n == name) {
                Some((_, own)) => own.fill_from(opts),
                None => self.0.push((name.clone(), opts.clone())),
            }
        }
    }
}

impl Agents {
    /// Options from `defaults` (config.toml's) for the agents these have, where unset; it
    /// adds no agent.
    pub fn fill_options(&mut self, defaults: &Agents) {
        for (name, own) in &mut self.0 {
            if let Some(d) = defaults.get(name) {
                own.fill_from(d);
            }
        }
    }
}

impl Serialize for Agents {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        if self.0.iter().all(|(_, o)| o.is_empty()) {
            return s.collect_seq(self.names());
        }
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (n, o) in &self.0 {
            m.serialize_entry(n, o)?;
        }
        m.end()
    }
}

impl<'de> Deserialize<'de> for Agents {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Agents;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a list of agents, or [agents.<name>] tables")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut s: A) -> Result<Agents, A::Error> {
                let mut out = Agents::default();
                while let Some(n) = s.next_element::<String>()? {
                    out.push(&n);
                }
                Ok(out)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Agents, A::Error> {
                let mut out = Agents::default();
                while let Some((n, o)) = m.next_entry::<String, AgentOpts>()? {
                    out.0.push((n, o));
                }
                Ok(out)
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Isolation {
    /// gVisor's user-space kernel: a kernel exploit in the env doesn't reach the VM.
    Gvisor,
    /// A plain container on the VM's kernel: builds about 1.6× faster, weaker.
    Container,
}

impl EnvConfig {
    /// The env's isolation: its own choice, else gVisor when `luoto setup` installed it.
    pub fn isolation(&self, global: &GlobalConfig) -> Isolation {
        self.isolation.unwrap_or(if global.gvisor.is_some() {
            Isolation::Gvisor
        } else {
            Isolation::Container
        })
    }
}

pub(crate) fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 40
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !ok {
        bail!("env names are 1-40 chars of a-z, 0-9 and '-' (got `{name}`)");
    }
    if name == "vault" {
        bail!("`vault` is reserved");
    }
    // A source build names env x's containers `luoto-dev-x` in the same VM (names.rs).
    if name == "dev" || name.starts_with("dev-") {
        bail!(
            "env names can't be `dev` or start with `dev-` (luoto's dev build names its envs so)"
        );
    }
    // `luoto-x-gate` is env x's gate and `luoto-x-out` its egress network (see names.rs).
    if let Some(suffix) = ["-gate", "-out"].iter().find(|s| name.ends_with(*s)) {
        bail!("env names can't end in `{suffix}` (luoto names another env's containers so)");
    }
    Ok(())
}

pub fn load_global(paths: &Paths) -> Result<GlobalConfig> {
    let p = paths.global_config();
    match std::fs::read_to_string(&p) {
        Ok(s) => parse_global(&crate::format::upgrade(&p, &s)?.text)
            .with_context(|| format!("parse {}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(GlobalConfig::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
    }
}

/// config.toml's text, its source tokens checked: an `azcli:` ref is a token for all of your
/// Azure, which only `[credentials.azure]` hands out, to the hosts it names.
pub fn parse_global(text: &str) -> Result<GlobalConfig> {
    let cfg: GlobalConfig = toml::from_str(text)?;
    let tokens = [
        (
            "sources.op.service_account_token",
            cfg.sources.op.service_account_token.as_deref(),
        ),
        (
            "sources.vault.token",
            cfg.sources.vault.as_ref().map(|v| v.token.as_str()),
        ),
    ];
    for (key, r) in tokens {
        if r.is_some_and(|r| r.starts_with(crate::azure_identity::AZCLI)) {
            bail!("{key}: an `azcli:` ref is only for [credentials.azure], which writes its own");
        }
    }
    // Model servers are each env's own, and so is which one an agent starts on.
    if let Some((name, _)) = cfg.agents.0.iter().find(|(_, o)| o.model_server.is_some()) {
        bail!(
            "agents.{name}.model_server: an agent's model server is set in each env's file \
             (`luoto agent auth`), not config.toml"
        );
    }
    Ok(cfg)
}

pub fn save_global(paths: &Paths, cfg: &GlobalConfig) -> Result<()> {
    let p = paths.global_config();
    std::fs::create_dir_all(p.parent().unwrap_or(Path::new(".")))?;
    let cfg = GlobalConfig {
        version: Some(crate::format::CURRENT),
        ..cfg.clone()
    };
    std::fs::write(&p, toml::to_string_pretty(&cfg)?)
        .with_context(|| format!("write {}", p.display()))
}

pub fn list_envs(paths: &Paths) -> Result<Vec<String>> {
    let dir = paths.envs_dir();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in rd {
        let p = entry?.path();
        if p.extension().is_some_and(|e| e == "toml")
            && let Some(stem) = p.file_stem().and_then(|s| s.to_str())
        {
            out.push(stem.to_string());
        }
    }
    out.sort();
    Ok(out)
}

pub struct EnvFile {
    pub path: PathBuf,
    pub doc: DocumentMut,
    pub cfg: EnvConfig,
    /// The format the file is in on disk; `save` keeps a copy of an older one.
    from: u32,
}

impl EnvFile {
    pub fn load(paths: &Paths, name: &str) -> Result<Self> {
        validate_name(name)?;
        let path = paths.env_config(name);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("no env `{name}` ({} not found)", path.display()))?;
        Self::parse(path, &text)
    }

    pub fn parse(path: PathBuf, text: &str) -> Result<Self> {
        let up = crate::format::upgrade(&path, text)?;
        let cfg: EnvConfig =
            toml::from_str(&up.text).with_context(|| format!("parse {}", path.display()))?;
        crate::shares::check_config(&cfg.shares).with_context(|| path.display().to_string())?;
        let doc: DocumentMut = up
            .text
            .parse()
            .with_context(|| format!("parse {}", path.display()))?;
        Ok(EnvFile {
            path,
            doc,
            cfg,
            from: up.from,
        })
    }

    pub fn create(paths: &Paths, name: &str, cfg: &EnvConfig) -> Result<Self> {
        validate_name(name)?;
        let path = paths.env_config(name);
        if path.exists() {
            bail!("env `{name}` already exists ({})", path.display());
        }
        let header = format!(
            "# luoto env `{name}`. Edit freely; apply with `luoto up -e {name}`.\n\
             # Reference: presets {:?}\n\n",
            luoto_shared::presets::names().collect::<Vec<_>>()
        );
        let cfg = EnvConfig {
            version: Some(crate::format::CURRENT),
            ..cfg.clone()
        };
        let text = format!("{header}{}", toml::to_string_pretty(&cfg)?);
        std::fs::create_dir_all(paths.envs_dir())?;
        std::fs::write(&path, &text)?;
        Self::parse(path, &text)
    }

    pub fn save(&mut self) -> Result<()> {
        let text = self.doc.to_string();
        // Re-validate what we are about to write.
        self.cfg = toml::from_str(&text).context("edited env config no longer parses")?;
        // Writing upgrades the file to the current format; the old one stays beside it.
        if self.from < crate::format::CURRENT {
            let old = self.path.with_extension(format!("toml.v{}", self.from));
            std::fs::copy(&self.path, &old)
                .with_context(|| format!("keep {} as {}", self.path.display(), old.display()))?;
            eprintln!(
                "{} is now config format {}; the old one is {}",
                self.path.display(),
                crate::format::CURRENT,
                old.display()
            );
            self.from = crate::format::CURRENT;
        }
        std::fs::write(&self.path, text).with_context(|| format!("write {}", self.path.display()))
    }

    /// `allow` as an array of tables, in the order of `cfg.allow`.
    fn allow_tables(&mut self) -> Result<&mut toml_edit::ArrayOfTables> {
        // `allow = [...]` written inline (e.g. by a serializer) becomes an array of tables.
        if let Some(inline) = self.doc.get("allow").and_then(|i| i.as_array()) {
            let mut tables = toml_edit::ArrayOfTables::new();
            for v in inline.iter() {
                if let Some(t) = v.as_inline_table() {
                    tables.push(t.clone().into_table());
                }
            }
            self.doc["allow"] = toml_edit::Item::ArrayOfTables(tables);
        }
        let path = self.path.display().to_string();
        self.doc
            .entry("allow")
            .or_insert_with(|| toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()))
            .as_array_of_tables_mut()
            .with_context(|| format!("`allow` in {path} is not an array of tables"))
    }

    pub fn add_rule(&mut self, rule: &Rule) -> Result<()> {
        self.add_rules(std::slice::from_ref(rule))
    }

    pub fn add_rules(&mut self, rules: &[Rule]) -> Result<()> {
        let tables = rules
            .iter()
            .map(|r| {
                Ok(toml_edit::ser::to_document(r)
                    .context("serialize rule")?
                    .as_table()
                    .clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let arr = self.allow_tables()?;
        for t in tables {
            arr.push(t);
        }
        self.save()
    }

    /// Keep the rules `keep` accepts. Returns how many were removed.
    pub fn retain_rules(&mut self, keep: impl Fn(&Rule) -> bool) -> Result<usize> {
        let kept: Vec<bool> = self.cfg.allow.iter().map(keep).collect();
        let removed = kept.iter().filter(|k| !**k).count();
        if removed == 0 {
            return Ok(0);
        }
        let arr = self.allow_tables()?;
        if arr.len() != kept.len() {
            bail!("`allow` changed while it was being edited");
        }
        let mut kept = kept.into_iter();
        arr.retain(|_| kept.next().unwrap_or(true));
        self.save()?;
        Ok(removed)
    }

    /// Set `key` (an auth kind of `provider`, or `login_inside`) under
    /// `[credentials.<provider>]`, in place of whichever of those it had. The table's other
    /// keys (`server_tools`, `write`) stay.
    pub fn set_provider_kind(
        &mut self,
        provider: &str,
        key: &str,
        value: &ProviderValue,
    ) -> Result<()> {
        let drop = auth_keys(provider)?;
        let path = self.path.display().to_string();
        let creds = self.doc.entry("credentials").or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        });
        let creds = creds
            .as_table_like_mut()
            .with_context(|| format!("`credentials` in {path} is not a table"))?;
        let table = creds
            .entry(provider)
            .or_insert_with(toml_edit::table)
            .as_table_like_mut()
            .with_context(|| format!("`credentials.{provider}` in {path} is not a table"))?;
        for k in drop.iter().filter(|k| *k != key) {
            table.remove(k);
        }
        table.insert(
            key,
            match value {
                ProviderValue::Ref(r) => toml_edit::value(r.as_str()),
                ProviderValue::Flag(b) => toml_edit::value(*b),
            },
        );
        self.save()
    }

    /// `[workspace.repos]`, created when missing.
    fn repos_table(&mut self) -> Result<&mut dyn toml_edit::TableLike> {
        let path = self.path.display().to_string();
        let ws = self
            .doc
            .entry("workspace")
            .or_insert_with(toml_edit::table)
            .as_table_like_mut()
            .with_context(|| format!("`workspace` in {path} is not a table"))?;
        ws.entry("repos")
            .or_insert_with(|| {
                let mut t = toml_edit::Table::new();
                t.set_implicit(true);
                toml_edit::Item::Table(t)
            })
            .as_table_like_mut()
            .with_context(|| format!("`workspace.repos` in {path} is not a table"))
    }

    /// Write `[workspace.repos.<name>]`, replacing any it had.
    pub fn set_repo(&mut self, name: &str, repo: &Repo) -> Result<()> {
        let table = toml_edit::ser::to_document(repo)
            .context("serialize repo")?
            .as_table()
            .clone();
        self.repos_table()?
            .insert(name, toml_edit::Item::Table(table));
        self.save()
    }

    pub fn remove_repo(&mut self, name: &str) -> Result<()> {
        let repos = self.repos_table()?;
        repos.remove(name);
        if repos.is_empty()
            && let Some(ws) = self
                .doc
                .get_mut("workspace")
                .and_then(|w| w.as_table_like_mut())
        {
            ws.remove("repos");
        }
        self.save()
    }

    /// `[credentials]`, created when missing.
    fn credentials_table(&mut self) -> Result<&mut dyn toml_edit::TableLike> {
        let path = self.path.display().to_string();
        self.doc
            .entry("credentials")
            .or_insert_with(|| {
                let mut t = toml_edit::Table::new();
                t.set_implicit(true);
                toml_edit::Item::Table(t)
            })
            .as_table_like_mut()
            .with_context(|| format!("`credentials` in {path} is not a table"))
    }

    /// Add `repos` (`owner/repo`) to the GitHub credential that lists a repo of `owner`
    /// already, whose token must then reach them, or that has `token` itself (one token for
    /// several owners), or else as a new credential with `token`: `[credentials.github]` for
    /// the first, `[[credentials.github]]` once there are more. `read` puts them in
    /// `read_repos`.
    pub fn add_github_repos(
        &mut self,
        owner: &str,
        token: Option<&str>,
        repos: &[String],
        read: bool,
    ) -> Result<()> {
        let key = if read { "read_repos" } else { "repos" };
        let has_owner = |t: &toml_edit::Table| {
            token.is_some() && t.get("token").and_then(|v| v.as_str()) == token
                || ["repos", "read_repos"].iter().any(|k| {
                    t.get(k).and_then(|i| i.as_array()).is_some_and(|a| {
                        a.iter().filter_map(|v| v.as_str()).any(|r| {
                            r.split('/')
                                .next()
                                .is_some_and(|o| o.eq_ignore_ascii_case(owner))
                        })
                    })
                })
        };
        let new = |token: Option<&str>| -> Result<toml_edit::Table> {
            let token = token.context("a new GitHub credential needs its token")?;
            let mut t = toml_edit::Table::new();
            t["token"] = toml_edit::value(token);
            Ok(t)
        };
        let creds = self.credentials_table()?;
        let table: &mut toml_edit::Table = match creds.get_mut("github") {
            None => {
                creds.insert("github", toml_edit::Item::Table(new(token)?));
                creds
                    .get_mut("github")
                    .and_then(|i| i.as_table_mut())
                    .context("credentials.github")?
            }
            Some(toml_edit::Item::Table(t)) if has_owner(t) => t,
            Some(toml_edit::Item::Table(t)) => {
                let mut list = toml_edit::ArrayOfTables::new();
                list.push(t.clone());
                list.push(new(token)?);
                *creds.get_mut("github").context("credentials.github")? =
                    toml_edit::Item::ArrayOfTables(list);
                creds
                    .get_mut("github")
                    .and_then(|i| i.as_array_of_tables_mut())
                    .and_then(|a| a.iter_mut().last())
                    .context("credentials.github")?
            }
            Some(toml_edit::Item::ArrayOfTables(list)) => {
                let found = list.iter().position(has_owner);
                let at = match found {
                    Some(i) => i,
                    None => {
                        list.push(new(token)?);
                        list.len() - 1
                    }
                };
                list.get_mut(at).context("credentials.github")?
            }
            Some(_) => bail!(
                "`credentials.github` in {} is written inline; add the repos by hand",
                self.path.display()
            ),
        };
        push_unique(table, key, repos);
        self.save()
    }

    /// Add repository paths to the `[[credentials.git]]` of `new.host`, or add `new` (with
    /// them) when there is none. `read` puts them in `read_repos`.
    pub fn add_git_repos(&mut self, new: &GitCred, repos: &[String], read: bool) -> Result<()> {
        let key = if read { "read_repos" } else { "repos" };
        let path = self.path.display().to_string();
        let creds = self.credentials_table()?;
        if creds.get("git").is_none() {
            creds.insert(
                "git",
                toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
            );
        }
        let list = creds
            .get_mut("git")
            .and_then(|i| i.as_array_of_tables_mut())
            .with_context(|| {
                format!("`credentials.git` in {path} is not [[credentials.git]] tables")
            })?;
        let found = list.iter().position(|t| {
            t.get("host")
                .and_then(|h| h.as_str())
                .is_some_and(|h| h.eq_ignore_ascii_case(&new.host))
        });
        let at = match found {
            Some(i) => i,
            None => {
                let mut t = toml_edit::Table::new();
                t["host"] = toml_edit::value(new.host.as_str());
                if let Some(token) = &new.token {
                    t["token"] = toml_edit::value(token.as_str());
                    t["username"] = toml_edit::value(new.username.as_str());
                }
                if new.private {
                    t["private"] = toml_edit::value(true);
                }
                if let Some(ca) = &new.ca {
                    t["ca"] = toml_edit::value(ca.as_str());
                }
                list.push(t);
                list.len() - 1
            }
        };
        let table = list.get_mut(at).context("credentials.git")?;
        if found.is_some() && table.get("token").is_none() && new.token.is_some() {
            table["token"] = toml_edit::value(new.token.as_deref().unwrap_or_default());
            table["username"] = toml_edit::value(new.username.as_str());
            if new.private && table.get("private").is_none() {
                table["private"] = toml_edit::value(true);
            }
            if let Some(ca) = new.ca.as_deref().filter(|_| table.get("ca").is_none()) {
                table["ca"] = toml_edit::value(ca);
            }
        }
        push_unique(table, key, repos);
        self.save()
    }

    /// Add `repos` (`org/project/repo`) to `[credentials.azure_devops]`, created with `token`
    /// when missing. `read` puts them in `read_repos`.
    pub fn add_azure_repos(
        &mut self,
        token: Option<&str>,
        repos: &[String],
        read: bool,
    ) -> Result<()> {
        let key = if read { "read_repos" } else { "repos" };
        let path = self.path.display().to_string();
        let creds = self.credentials_table()?;
        if creds.get("azure_devops").is_none() {
            let token = token.context("a new Azure DevOps credential needs its token")?;
            let mut t = toml_edit::Table::new();
            t["token"] = toml_edit::value(token);
            creds.insert("azure_devops", toml_edit::Item::Table(t));
        }
        let table = creds
            .get_mut("azure_devops")
            .and_then(|i| i.as_table_mut())
            .with_context(|| {
                format!(
                    "`credentials.azure_devops` in {path} is written inline; add the repos by hand"
                )
            })?;
        push_unique(table, key, repos);
        self.save()
    }

    /// Move a repo within the `[credentials.<key>]` table (`github`, `azure_devops`, or `git`
    /// of `host`) that lists it, `same` telling its entries: into `repos` or `read_repos`, or
    /// out of both, and out of every other table of `key`. `token` replaces that table's. Its
    /// other keys stay; a table it leaves listing no repo, which no credential may, goes.
    pub fn relist_repo(
        &mut self,
        key: &str,
        host: Option<&str>,
        same: &dyn Fn(&str) -> bool,
        to: ListAs,
        token: Option<&str>,
    ) -> Result<Relisted> {
        let path = self.path.display().to_string();
        let Some(creds) = self
            .doc
            .get_mut("credentials")
            .and_then(|c| c.as_table_like_mut())
        else {
            return Ok(Relisted::No);
        };
        let Some(item) = creds.get_mut(key) else {
            return Ok(Relisted::No);
        };
        let tables: Vec<&mut toml_edit::Table> = match item {
            toml_edit::Item::Table(t) => vec![t],
            toml_edit::Item::ArrayOfTables(list) => list.iter_mut().collect(),
            _ => bail!("`credentials.{key}` in {path} is written inline; change it by hand"),
        };
        let mut found = false;
        let mut touched = Vec::new();
        for (i, t) in tables.into_iter().enumerate() {
            let of_host = host.is_none_or(|h| {
                t.get("host")
                    .and_then(|v| v.as_str())
                    .is_some_and(|x| x.eq_ignore_ascii_case(h))
            });
            if !of_host {
                continue;
            }
            let mut entry = None;
            for list in ["repos", "read_repos"] {
                let Some(arr) = t.get_mut(list).and_then(|i| i.as_array_mut()) else {
                    continue;
                };
                if let Some(v) = arr.iter().find_map(|v| v.as_str().filter(|s| same(s))) {
                    entry.get_or_insert_with(|| v.to_string());
                }
                arr.retain(|v| !v.as_str().is_some_and(same));
                if list == "read_repos" && arr.is_empty() {
                    t.remove(list);
                }
            }
            if entry.is_some() {
                touched.push(i);
            }
            let Some(entry) = entry.filter(|_| !found) else {
                continue;
            };
            found = true;
            match to {
                ListAs::Write => push_unique(t, "repos", &[entry]),
                ListAs::Read => push_unique(t, "read_repos", &[entry]),
                ListAs::Nowhere => {}
            }
            if let Some(token) = token {
                // The line's comment stays with the new value.
                match t.get_mut("token").and_then(|i| i.as_value_mut()) {
                    Some(v) => {
                        let decor = v.decor().clone();
                        *v = token.into();
                        *v.decor_mut() = decor;
                    }
                    None => t["token"] = toml_edit::value(token),
                }
            }
        }
        if !found {
            return Ok(Relisted::No);
        }
        let lists_none = |t: &toml_edit::Table| {
            ["repos", "read_repos"].iter().all(|k| {
                t.get(k)
                    .and_then(|i| i.as_array())
                    .is_none_or(|a| a.is_empty())
            })
        };
        let mut emptied = false;
        match creds.get_mut(key) {
            Some(toml_edit::Item::Table(t)) if lists_none(t) => {
                creds.remove(key);
                emptied = true;
            }
            Some(toml_edit::Item::ArrayOfTables(list)) => {
                for i in touched.into_iter().rev() {
                    if list.get(i).is_some_and(lists_none) {
                        list.remove(i);
                        emptied = true;
                    }
                }
                if list.is_empty() {
                    creds.remove(key);
                }
            }
            _ => {}
        }
        self.save()?;
        Ok(if emptied {
            Relisted::Emptied
        } else {
            Relisted::Moved
        })
    }

    /// Drop `name` from the env's agents, in whichever form the file writes them.
    pub fn remove_agent(&mut self, name: &str) -> Result<()> {
        if let Some(item) = self.doc.get_mut("agents") {
            if let Some(arr) = item.as_array_mut() {
                arr.retain(|v| v.as_str() != Some(name));
            } else if let Some(t) = item.as_table_like_mut() {
                t.remove(name);
            }
        }
        let empty = self.doc.get("agents").is_some_and(|i| {
            i.as_array().is_some_and(|a| a.is_empty())
                || i.as_table_like().is_some_and(|t| t.is_empty())
        });
        if empty {
            self.doc.remove("agents");
        }
        self.save()
    }

    /// Add `name` to the env's agents, in the form the file writes them.
    /// Set (or, for `None`, remove) options of agent `name` under `[agents.<name>]`, the
    /// agent listed if it wasn't; an `agents = [...]` list becomes tables for it.
    pub fn set_agent_opts(&mut self, name: &str, opts: &[(&str, Option<&str>)]) -> Result<()> {
        let path = self.path.display().to_string();
        let listed: Option<Vec<String>> =
            self.doc.get("agents").and_then(|i| i.as_array()).map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            });
        if let Some(names) = listed {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            for n in names {
                t.insert(&n, toml_edit::table());
            }
            self.doc["agents"] = toml_edit::Item::Table(t);
        }
        let agents = self
            .doc
            .entry("agents")
            .or_insert_with(|| {
                let mut t = toml_edit::Table::new();
                t.set_implicit(true);
                toml_edit::Item::Table(t)
            })
            .as_table_like_mut()
            .with_context(|| format!("`agents` in {path} is not a table"))?;
        let table = agents
            .entry(name)
            .or_insert_with(toml_edit::table)
            .as_table_like_mut()
            .with_context(|| format!("`agents.{name}` in {path} is not a table"))?;
        for (k, v) in opts {
            match v {
                Some(v) => {
                    table.insert(k, toml_edit::value(*v));
                }
                None => {
                    table.remove(k);
                }
            }
        }
        self.save()
    }

    /// `[model_servers.<name>]` as `server` has it, in place of what it had.
    pub fn set_model_server(&mut self, name: &str, server: &ModelServer) -> Result<()> {
        let path = self.path.display().to_string();
        let servers = self
            .doc
            .entry("model_servers")
            .or_insert_with(|| {
                let mut t = toml_edit::Table::new();
                t.set_implicit(true);
                toml_edit::Item::Table(t)
            })
            .as_table_like_mut()
            .with_context(|| format!("`model_servers` in {path} is not a table"))?;
        let mut t = toml_edit::Table::new();
        t.insert("url", toml_edit::value(server.url.as_str()));
        let mut api = toml_edit::Array::new();
        for a in &server.api {
            api.push(a.as_str());
        }
        t.insert("api", toml_edit::value(api));
        for (k, v) in [
            ("model", &server.model),
            ("token", &server.token),
            ("header", &server.header),
        ] {
            if let Some(v) = v {
                t.insert(k, toml_edit::value(v.as_str()));
            }
        }
        if let Some(c) = server.context.and_then(|c| i64::try_from(c).ok()) {
            t.insert("context", toml_edit::value(c));
        }
        if server.private {
            t.insert("private", toml_edit::value(true));
        }
        servers.insert(name, toml_edit::Item::Table(t));
        self.save()
    }

    pub fn add_agent(&mut self, name: &str) -> Result<()> {
        let path = self.path.display().to_string();
        match self.doc.get_mut("agents") {
            None => {
                let mut arr = toml_edit::Array::new();
                arr.push(name);
                self.doc["agents"] = toml_edit::value(arr);
            }
            Some(item) => {
                if let Some(arr) = item.as_array_mut() {
                    if !arr.iter().any(|v| v.as_str() == Some(name)) {
                        arr.push(name);
                    }
                } else if let Some(t) = item.as_table_like_mut() {
                    if t.get(name).is_none() {
                        t.insert(name, toml_edit::table());
                    }
                } else {
                    bail!("`agents` in {path} is neither a list nor tables");
                }
            }
        }
        self.save()
    }

    pub fn set_list(&mut self, key: &str, values: &[String]) -> Result<()> {
        let mut arr = toml_edit::Array::new();
        for v in values {
            arr.push(v.as_str());
        }
        self.doc[key] = toml_edit::value(arr);
        self.save()
    }

    /// Set `values` in the table at `path` (`["credentials", "custom", "stripe"]`), made where
    /// missing, its other keys kept.
    pub fn set_in_tables(
        &mut self,
        path: &[&str],
        values: Vec<(&str, toml_edit::Value)>,
    ) -> Result<()> {
        let file = self.path.display().to_string();
        let mut table: &mut dyn toml_edit::TableLike = self.doc.as_table_mut();
        for (i, k) in path.iter().enumerate() {
            let at = path[..=i].join(".");
            table = table
                .entry(k)
                .or_insert_with(|| {
                    let mut t = toml_edit::Table::new();
                    // A parent table shows only as its children's headings.
                    t.set_implicit(i + 1 < path.len());
                    toml_edit::Item::Table(t)
                })
                .as_table_like_mut()
                .with_context(|| format!("`{at}` in {file} is not a table"))?;
        }
        for (k, v) in values {
            table.insert(k, toml_edit::Item::Value(v));
        }
        self.save()
    }

    /// Set `key = value` in the top-level table `table`, creating the table if needed.
    pub fn set_in_table(&mut self, table: &str, key: &str, value: &str) -> Result<()> {
        if !self.doc.contains_key(table) {
            self.doc[table] = toml_edit::table();
        }
        self.doc[table]
            .as_table_like_mut()
            .with_context(|| format!("`{table}` is not a table"))?
            .insert(key, toml_edit::value(value));
        self.save()
    }

    /// Set variable `name` in `[env]` (a plain value) or `[sandbox_secrets]` (a ref), and drop
    /// it from the other: a name lives in one of the two.
    pub fn set_var(&mut self, secret: bool, name: &str, value: &str) -> Result<()> {
        let (to, from) = if secret {
            ("sandbox_secrets", "env")
        } else {
            ("env", "sandbox_secrets")
        };
        self.take_key(from, name)?;
        self.set_in_table(to, name, value)
    }

    /// Remove `key` from the top-level table `table`, and the table once empty; whether it had
    /// the key.
    pub fn remove_from_table(&mut self, table: &str, key: &str) -> Result<bool> {
        let had = self.take_key(table, key)?;
        if had {
            self.save()?;
        }
        Ok(had)
    }

    /// Remove variable `name` from `[env]` and `[sandbox_secrets]`; whether either had it.
    pub fn remove_var(&mut self, name: &str) -> Result<bool> {
        let had = self.take_key("env", name)? | self.take_key("sandbox_secrets", name)?;
        if had {
            self.save()?;
        }
        Ok(had)
    }

    /// Remove `key` from the top-level table `table`, and the table once empty; whether it had
    /// the key. Not saved.
    fn take_key(&mut self, table: &str, key: &str) -> Result<bool> {
        let Some(item) = self.doc.get_mut(table) else {
            return Ok(false);
        };
        let t = item
            .as_table_like_mut()
            .with_context(|| format!("`{table}` is not a table"))?;
        let had = t.remove(key).is_some();
        if had && t.is_empty() {
            self.doc.remove(table);
        }
        Ok(had)
    }

    /// Add a package to `[deps] system`.
    pub fn add_system_package(&mut self, name: &str) -> Result<()> {
        if !self.doc.contains_key("deps") {
            self.doc["deps"] = toml_edit::table();
        }
        let deps = self.doc["deps"]
            .as_table_like_mut()
            .context("`deps` is not a table")?;
        if deps.get("system").is_none() {
            deps.insert("system", toml_edit::value(toml_edit::Array::new()));
        }
        let arr = deps
            .get_mut("system")
            .and_then(|i| i.as_array_mut())
            .context("`deps.system` is not a list")?;
        if !arr.iter().any(|v| v.as_str() == Some(name)) {
            arr.push(name);
        }
        self.save()
    }

    /// Add hosts to `[deps] hosts` (readable only while installs run).
    pub fn add_install_hosts(&mut self, hosts: &[String]) -> Result<()> {
        if !self.doc.contains_key("deps") {
            self.doc["deps"] = toml_edit::table();
        }
        let deps = self.doc["deps"]
            .as_table_like_mut()
            .context("`deps` is not a table")?;
        if deps.get("hosts").is_none() {
            deps.insert("hosts", toml_edit::value(toml_edit::Array::new()));
        }
        let arr = deps
            .get_mut("hosts")
            .and_then(|i| i.as_array_mut())
            .context("`deps.hosts` is not an array")?;
        let mut all = self.cfg.deps.hosts.clone();
        let had = all.len();
        extend_unique(&mut all, hosts.iter().cloned());
        for h in &all[had..] {
            arr.push(h.as_str());
        }
        self.save()
    }

    /// Remove rules by id or by exact host. Returns how many were removed.
    pub fn remove_rules(&mut self, id_or_host: &str) -> Result<usize> {
        self.retain_rules(|r| r.id.as_deref() != Some(id_or_host) && r.host != id_or_host)
    }

    /// Drop expired rules (keeps the file from accumulating stale grants), and an
    /// `open_until` that has passed.
    pub fn prune_expired(&mut self) -> Result<usize> {
        let now = chrono::Utc::now();
        if self.cfg.egress.open_until.is_some_and(|t| t <= now) {
            self.set_open(None)?;
        }
        self.retain_rules(|r| !r.expired(now))
    }

    /// `[egress]`: open until `until`, or closed with `None` (`open = true` goes too). The
    /// table goes when nothing is left in it.
    pub fn set_open(&mut self, until: Option<chrono::DateTime<chrono::Utc>>) -> Result<()> {
        let path = self.path.display().to_string();
        if until.is_none() && self.doc.get("egress").is_none() {
            return Ok(());
        }
        let table = self
            .doc
            .entry("egress")
            .or_insert_with(toml_edit::table)
            .as_table_like_mut()
            .with_context(|| format!("`egress` in {path} is not a table"))?;
        table.remove("open");
        match until {
            Some(t) => {
                let t = t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                table.insert("open_until", toml_edit::value(t));
            }
            None => {
                table.remove("open_until");
            }
        }
        if table.is_empty() {
            self.doc.remove("egress");
        }
        self.save()
    }
}

/// Append `values` missing from the string array `key` of `table`, creating it.
/// Where [`EnvFile::relist_repo`] lists a repo in its credential.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ListAs {
    Write,
    Read,
    Nowhere,
}

/// What [`EnvFile::relist_repo`] did.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Relisted {
    /// No credential listed the repo.
    No,
    Moved,
    /// It was the last repo of its credential, which is gone.
    Emptied,
}

fn push_unique(table: &mut toml_edit::Table, key: &str, values: &[String]) {
    if table.get(key).and_then(|i| i.as_array()).is_none() {
        table[key] = toml_edit::value(toml_edit::Array::new());
    }
    if let Some(arr) = table.get_mut(key).and_then(|i| i.as_array_mut()) {
        for v in values {
            if !arr
                .iter()
                .any(|x| x.as_str().is_some_and(|x| x.eq_ignore_ascii_case(v)))
            {
                arr.push(v.as_str());
            }
        }
    }
}

pub fn new_rule_id() -> String {
    format!("r{}", hex::encode(rand::random::<[u8; 3]>()))
}

/// Append the items of `add` that `base` lacks, in order.
pub fn extend_unique<T: PartialEq>(base: &mut Vec<T>, add: impl IntoIterator<Item = T>) {
    for x in add {
        if !base.contains(&x) {
            base.push(x);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# my env
image = "localhost/luoto-base:dev"
presets = ["npm"]   # registries

[workspace]
dir = "/home/me/foo"

[[allow]]
id = "r1"
host = "docs.rs"

[credentials.github]
app_id = "123"
installation_id = 456
private_key = "op://Dev/app/key"
repos = ["octo/foo"]
permissions = { contents = "write" }

[credentials.anthropic]
oauth_token = "op://Private/claude/token"
"#;

    #[test]
    fn env_files_carry_their_format() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        let f = EnvFile::create(&paths, "web", &EnvConfig::default()).unwrap();
        assert_eq!(f.cfg.version, Some(crate::format::CURRENT));
        let newer = format!("version = {}\n", crate::format::CURRENT + 1);
        assert!(EnvFile::parse(f.path.clone(), &newer).is_err());
    }

    #[test]
    fn parses_and_edits_preserving_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, SAMPLE).unwrap();
        let mut f = EnvFile::parse(path.clone(), SAMPLE).unwrap();
        assert_eq!(
            f.cfg.credentials.github.0[0].protected_branches,
            vec!["main", "master"]
        );
        assert_eq!(
            f.cfg.credentials.providers["anthropic"]["oauth_token"],
            ProviderValue::Ref("op://Private/claude/token".into())
        );
        f.add_rule(&Rule {
            id: Some("r2".into()),
            ..Rule::read("example.com")
        })
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# registries") && text.contains("example.com"));
        assert_eq!(f.cfg.allow.len(), 2);
        assert_eq!(f.remove_rules("r1").unwrap(), 1);
        assert_eq!(f.cfg.allow.len(), 1);
    }

    #[test]
    fn a_credential_kind_replaces_only_the_providers_auth_keys() {
        let text = "[credentials.anthropic]\noauth_token = \"op://Private/claude/token\"\n\
                    # kept\nserver_tools = true\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, text).unwrap();
        let mut f = EnvFile::parse(path.clone(), text).unwrap();
        let entries = |f: &EnvFile| f.cfg.credentials.providers["anthropic"].clone();

        let key = ProviderValue::Ref("keyring:luoto/anthropic.api_key".into());
        f.set_provider_kind("anthropic", "api_key", &key).unwrap();
        assert_eq!(
            entries(&f),
            BTreeMap::from([
                ("api_key".to_string(), key.clone()),
                ("server_tools".to_string(), ProviderValue::Flag(true)),
            ])
        );
        f.set_provider_kind("anthropic", "login_inside", &ProviderValue::Flag(true))
            .unwrap();
        assert_eq!(
            entries(&f),
            BTreeMap::from([
                ("login_inside".to_string(), ProviderValue::Flag(true)),
                ("server_tools".to_string(), ProviderValue::Flag(true)),
            ])
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("# kept"), "{on_disk}");

        f.set_provider_kind("openai", "api_key", &key).unwrap();
        assert_eq!(f.cfg.credentials.providers["openai"]["api_key"], key);
        assert!(f.set_provider_kind("nobody", "api_key", &key).is_err());
    }

    #[test]
    fn a_need_writes_its_table_keeping_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        let text = "[workspace]\ndir = \"/w\"\n\n[credentials.custom.stripe]\nhost = \"old.example\"\nsecret = \"env:OLD\"\nheader = \"x-key\" # kept\n";
        std::fs::write(&path, text).unwrap();
        let mut f = EnvFile::parse(path.clone(), text).unwrap();
        f.set_in_tables(
            &["credentials", "custom", "stripe"],
            vec![
                ("host", "api.stripe.com".into()),
                ("secret", "env:S".into()),
            ],
        )
        .unwrap();
        let c = &f.cfg.credentials.custom["stripe"];
        assert_eq!(
            (c.host.as_str(), c.secret.as_str(), c.header.as_str()),
            ("api.stripe.com", "env:S", "x-key")
        );
        let mut subs = toml_edit::Array::new();
        subs.push("00000000-0000-0000-0000-000000000001");
        f.set_in_tables(
            &["credentials", "azure"],
            vec![("subscriptions", subs.into())],
        )
        .unwrap();
        assert_eq!(
            f.cfg
                .credentials
                .azure
                .as_ref()
                .unwrap()
                .subscriptions
                .len(),
            1
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        // A parent shows only as its children's headings.
        assert!(!on_disk.contains("[credentials]\n"), "{on_disk}");
        assert!(
            on_disk.contains("# kept") && on_disk.contains("[credentials.azure]"),
            "{on_disk}"
        );
    }

    #[test]
    fn a_repo_moves_within_its_credential_keeping_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.toml");
        let text = "presets = []\n\n\
                    [[credentials.github]]\n\
                    token = \"env:A\"   # acme's\n\
                    repos = [\"acme/web\"]\n\
                    read_repos = [\"Acme/API\"]\n\
                    protected_branches = [\"main\", \"release\"]\n\n\
                    [[credentials.github]]\n\
                    app_id = \"1\"\n\
                    installation_id = 2\n\
                    private_key = \"env:K\"\n\
                    repos = [\"other/x\"]\n\n\
                    [[credentials.git]]\n\
                    host = \"gitlab.com\"\n\
                    read_repos = [\"group/api\"]\n";
        std::fs::write(&path, text).unwrap();
        let mut f = EnvFile::parse(path.clone(), text).unwrap();
        let mut relist = |key: &str, host: Option<&str>, repo: &str, to, token| {
            let repo = repo.to_string();
            f.relist_repo(key, host, &|e| e.eq_ignore_ascii_case(&repo), to, token)
                .unwrap()
        };
        assert_eq!(
            relist("github", None, "acme/api", ListAs::Write, Some("env:B")),
            Relisted::Moved
        );
        assert_eq!(
            relist("github", None, "acme/new", ListAs::Read, None),
            Relisted::No
        );
        assert_eq!(
            relist("azure_devops", None, "acme/api", ListAs::Read, None),
            Relisted::No
        );
        // Another host's credential stays as it is.
        assert_eq!(
            relist(
                "git",
                Some("forge.example"),
                "group/api",
                ListAs::Write,
                None
            ),
            Relisted::No
        );
        assert_eq!(
            relist("git", Some("GitLab.com"), "group/api", ListAs::Write, None),
            Relisted::Moved
        );
        // The App's only repo out: a credential that lists none goes, the other stays.
        assert_eq!(
            relist("github", None, "other/x", ListAs::Nowhere, None),
            Relisted::Emptied
        );
        let gh = &f.cfg.credentials.github.0;
        assert_eq!(gh.len(), 1);
        assert_eq!(gh[0].repos, ["acme/web", "Acme/API"]);
        assert!(gh[0].read_repos.is_empty());
        assert_eq!(gh[0].token.as_deref(), Some("env:B"));
        assert_eq!(gh[0].protected_branches, ["main", "release"]);
        assert_eq!(f.cfg.credentials.git[0].repos, ["group/api"]);
        assert!(f.cfg.credentials.git[0].read_repos.is_empty());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("# acme's"), "{on_disk}");
        assert!(!on_disk.contains("app_id"), "{on_disk}");
    }

    #[test]
    fn denies_and_mutes_parse_and_layer_under_the_env() {
        let env = r#"
[[deny]]
host = "registry.npmjs.org"
paths = ["/-/npm/v1/security/**"]
methods = ["POST"]

[[mute]]
host = "telemetry.example"
"#;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = EnvFile::parse(dir.path().join("t.toml"), env).unwrap().cfg;
        assert_eq!(cfg.deny[0].methods, ["POST"]);
        for bad in [
            "[[deny]]\nhost = \"x.example\"\naccess = \"write\"",
            "[[mute]]\nhost = \"x.example\"\nmethods = [\"GET\"]",
        ] {
            assert!(
                EnvFile::parse(dir.path().join("t.toml"), bad).is_err(),
                "{bad}"
            );
        }

        let text = "[[deny]]\nhost = \"collector.example\"\n\n[[mute]]\nhost = \"stats.example\"\npaths = [\"/v1/**\"]\n";
        let global: GlobalConfig = toml::from_str(text).unwrap();
        // `luoto setup` writes config.toml back whole: the entries survive it.
        let again: GlobalConfig =
            toml::from_str(&toml::to_string_pretty(&global).unwrap()).unwrap();
        assert_eq!(
            (again.deny, again.mute),
            (global.deny.clone(), global.mute.clone())
        );
        global.layer_under(&mut cfg);
        let hosts: Vec<&str> = cfg.deny.iter().map(|d| d.host.as_str()).collect();
        assert_eq!(hosts, ["collector.example", "registry.npmjs.org"]);
        assert_eq!(cfg.deny[0].note.as_deref(), Some("config.toml"));
        let muted: Vec<&str> = cfg.mute.iter().map(|m| m.host.as_str()).collect();
        assert_eq!(muted, ["stats.example", "telemetry.example"]);
    }

    #[test]
    fn open_egress_is_written_as_a_window_and_closed_in_place() {
        let text = "# my env\npresets = []\n\n[egress]\nopen = true\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, text).unwrap();
        let mut f = EnvFile::parse(path.clone(), text).unwrap();
        let now = chrono::Utc::now();
        assert_eq!(f.cfg.egress.open_at(now).unwrap(), Some(None));
        let until: chrono::DateTime<chrono::Utc> = "2099-01-01T12:00:00Z".parse().unwrap();
        f.set_open(Some(until)).unwrap();
        assert_eq!(
            f.cfg.egress,
            Egress {
                open: false,
                open_until: Some(until)
            }
        );
        assert_eq!(f.cfg.egress.open_at(now).unwrap(), Some(Some(until)));
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(
            saved.contains("open_until = \"2099-01-01T12:00:00Z\"") && !saved.contains("open ="),
            "{saved}"
        );
        f.set_open(None).unwrap();
        assert_eq!(f.cfg.egress, Egress::default());
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(
            saved.starts_with("# my env") && !saved.contains("egress"),
            "{saved}"
        );

        // A window that has passed is closed, and `up` drops it from the file.
        let past = "[egress]\nopen_until = \"2000-01-01T00:00:00Z\"\n";
        std::fs::write(&path, past).unwrap();
        let mut f = EnvFile::parse(path.clone(), past).unwrap();
        assert_eq!(f.cfg.egress.open_at(now).unwrap(), None);
        f.prune_expired().unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("egress"));

        let both = "[egress]\nopen = true\nopen_until = \"2099-01-01T00:00:00Z\"\n";
        let f = EnvFile::parse(path.clone(), both).unwrap();
        assert!(f.cfg.egress.open_at(now).is_err());
        assert!(EnvFile::parse(path.clone(), "[egress]\nopen = \"yes\"\n").is_err());
        assert!(EnvFile::parse(path, "[egress]\nopen_for = \"1h\"\n").is_err());

        let e = parse_global("[egress]\nopen = true\n").unwrap_err();
        assert!(format!("{e:#}").contains("luoto egress open -e"), "{e:#}");
    }

    #[test]
    fn appends_rules_to_inline_empty_allow() {
        let text = "presets = [\"npm\"]\nallow = []\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, text).unwrap();
        let mut f = EnvFile::parse(path, text).unwrap();
        f.add_rule(&Rule::read("docs.rs")).unwrap();
        assert_eq!(f.cfg.allow.len(), 1);
    }

    #[test]
    fn rules_are_added_and_pruned_in_place() {
        let text = "# my env\npresets = []\n\n[[allow]]\nid = \"old\"\nhost = \"a.example\"\nexpires = \"2000-01-01T00:00:00Z\"\n\n[[allow]]\nid = \"keep\"\nhost = \"b.example\"\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, text).unwrap();
        let mut f = EnvFile::parse(path.clone(), text).unwrap();
        f.add_rules(&[Rule::read("c.example"), Rule::read("d.example")])
            .unwrap();
        assert_eq!(f.prune_expired().unwrap(), 1);
        assert_eq!(f.remove_rules("c.example").unwrap(), 1);
        let hosts: Vec<&str> = f.cfg.allow.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, ["b.example", "d.example"]);
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.starts_with("# my env") && !saved.contains("a.example"));
    }

    #[test]
    fn a_workspace_is_a_folder_or_a_remote_never_both() {
        let f = EnvFile::parse(
            "t.toml".into(),
            "[workspace]\nurl = \"acme/web\"\nbranch = \"develop\"\n",
        )
        .unwrap();
        assert_eq!(f.cfg.workspace.dir, None);
        assert_eq!(f.cfg.workspace.url.as_deref(), Some("acme/web"));
        assert_eq!(f.cfg.workspace.branch.as_deref(), Some("develop"));
        assert!(crate::compile::compile("web", &f.cfg, None, &[]).is_ok());
        let both = EnvFile::parse(
            "t.toml".into(),
            "[workspace]\ndir = \"/home/me/web\"\nurl = \"acme/web\"\n",
        )
        .unwrap();
        let Err(e) = crate::compile::compile("web", &both.cfg, None, &[]) else {
            panic!("a folder and a remote compiled");
        };
        assert!(format!("{e:#}").contains("not both"), "{e:#}");
    }

    #[test]
    fn repos_are_added_and_removed_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, SAMPLE).unwrap();
        let mut f = EnvFile::parse(path.clone(), SAMPLE).unwrap();
        let web = Repo {
            url: Some("acme/web".into()),
            branch: Some("dev".into()),
            ..Default::default()
        };
        f.set_repo("web", &web).unwrap();
        f.set_repo(
            "api",
            &Repo {
                dir: Some("/home/me/api".into()),
                ..Default::default()
            },
        )
        .unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("[workspace.repos.web]") && saved.contains("# my env"));
        assert_eq!(f.cfg.workspace.dir.as_deref(), Some("/home/me/foo"));
        assert_eq!(f.cfg.workspace.repos["web"], web);
        f.remove_repo("web").unwrap();
        f.remove_repo("api").unwrap();
        assert!(f.cfg.workspace.repos.is_empty());
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("workspace.repos")
        );
    }

    #[test]
    fn github_credentials_are_one_table_or_several() {
        let one: EnvConfig =
            toml::from_str("[credentials.github]\ntoken = \"env:T\"\nrepos = [\"o/r\"]\n").unwrap();
        assert_eq!(one.credentials.github.0.len(), 1);
        let two: EnvConfig = toml::from_str(
            "[[credentials.github]]\ntoken = \"env:A\"\nrepos = [\"a/r\"]\n[[credentials.github]]\ntoken = \"env:B\"\nread_repos = [\"b/r\"]\n",
        )
        .unwrap();
        assert!(two.credentials.github.covers("B/R", false));
        assert!(!two.credentials.github.covers("b/r", true));
        let typo = toml::from_str::<EnvConfig>(
            "[credentials.github]\ntoken = \"env:T\"\nrepo = [\"o/r\"]\n",
        );
        assert!(typo.unwrap_err().to_string().contains("repo"));
        // Written back in the form it was read.
        assert!(
            toml::to_string(&one)
                .unwrap()
                .contains("[credentials.github]")
        );
        assert!(
            toml::to_string(&two)
                .unwrap()
                .contains("[[credentials.github]]")
        );
    }

    #[test]
    fn git_credentials_are_written_per_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, SAMPLE).unwrap();
        let mut f = EnvFile::parse(path.clone(), SAMPLE).unwrap();
        // A repo of an owner the App covers joins it.
        f.add_github_repos("octo", None, &["octo/bar".into()], false)
            .unwrap();
        assert_eq!(f.cfg.credentials.github.0.len(), 1);
        assert!(f.cfg.credentials.github.covers("octo/bar", true));
        // Another owner's gets a credential of its own; the table becomes an array.
        f.add_github_repos(
            "acme",
            Some("op://v/acme/token"),
            &["acme/web".into()],
            true,
        )
        .unwrap();
        assert_eq!(f.cfg.credentials.github.0.len(), 2);
        assert!(f.cfg.credentials.github.covers("acme/web", false));
        assert!(!f.cfg.credentials.github.covers("acme/web", true));
        f.add_github_repos("acme", None, &["acme/api".into()], false)
            .unwrap();
        assert_eq!(f.cfg.credentials.github.0[1].repos, ["acme/api"]);
        // The same token for a third owner joins the credential that has it.
        f.add_github_repos(
            "acme-oss",
            Some("op://v/acme/token"),
            &["acme-oss/ds".into()],
            false,
        )
        .unwrap();
        assert_eq!(f.cfg.credentials.github.0.len(), 2);
        assert_eq!(
            f.cfg.credentials.github.0[1].repos,
            ["acme/api", "acme-oss/ds"]
        );
        assert!(
            f.add_github_repos("other", None, &["other/x".into()], false)
                .is_err()
        );
        f.add_azure_repos(Some("op://v/ado/pat"), &["org/P/r".into()], false)
            .unwrap();
        f.add_azure_repos(None, &["org/P/s".into()], true).unwrap();
        let ado = f.cfg.credentials.azure_devops.as_ref().unwrap();
        assert_eq!((ado.repos.len(), ado.read_repos.len()), (1, 1));
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("[[credentials.github]]") && saved.contains("# my env"));
    }

    #[test]
    fn agents_are_a_list_or_tables_with_options() {
        let list: EnvConfig = toml::from_str("agents = [\"claude\", \"codex\"]").unwrap();
        assert_eq!(list.agents.names().count(), 2);
        assert!(toml::to_string(&list).unwrap().contains("agents = ["));
        let tables: EnvConfig =
            toml::from_str("[agents.claude]\nmodel = \"opus\"\n\n[agents.codex]\n").unwrap();
        assert_eq!(
            tables.agents.get("claude").unwrap().model.as_deref(),
            Some("opus")
        );
        assert!(tables.agents.contains("codex"));
        assert!(
            toml::to_string(&tables)
                .unwrap()
                .contains("[agents.claude]")
        );
        assert!(toml::from_str::<EnvConfig>("[agents.claude]\nmodle = \"x\"").is_err());

        // luoto.toml's agents join; config.toml's give options, never agents.
        let mut own = tables.agents.clone();
        own.layer_under(&Agents(vec![(
            "claude".into(),
            AgentOpts {
                model: Some("sonnet".into()),
                effort: Some("high".into()),
                ..Default::default()
            },
        )]));
        own.layer_under(&Agents::from_names(["opencode".to_string()]));
        let claude = own.get("claude").unwrap();
        assert_eq!(
            (claude.model.as_deref(), claude.effort.as_deref()),
            (Some("opus"), Some("high"))
        );
        assert!(own.contains("opencode"));
        let global: GlobalConfig =
            toml::from_str("[agents.codex]\neffort = \"low\"\n[agents.copilot]\nmodel = \"x\"")
                .unwrap();
        own.fill_options(&global.agents);
        assert_eq!(own.get("codex").unwrap().effort.as_deref(), Some("low"));
        assert!(!own.contains("copilot"));
    }

    #[test]
    fn agents_are_added_in_the_files_form() {
        let dir = tempfile::tempdir().unwrap();
        for (text, want) in [
            (
                "agents = [\"claude\"]\n",
                "agents = [\"claude\", \"codex\"]",
            ),
            ("[agents.claude]\nmodel = \"opus\"\n", "[agents.codex]"),
            ("presets = []\n", "agents = [\"codex\"]"),
        ] {
            let path = dir.path().join("t.toml");
            std::fs::write(&path, text).unwrap();
            let mut f = EnvFile::parse(path.clone(), text).unwrap();
            f.add_agent("codex").unwrap();
            assert!(
                std::fs::read_to_string(&path).unwrap().contains(want),
                "{text}"
            );
            assert!(f.cfg.agents.contains("codex"));
            f.remove_agent("codex").unwrap();
            assert!(!f.cfg.agents.contains("codex"));
            assert!(
                !std::fs::read_to_string(&path).unwrap().contains("codex"),
                "{text}"
            );
        }
    }

    #[test]
    fn names_are_restricted() {
        assert!(validate_name("my-env-2").is_ok());
        assert!(validate_name("My_Env").is_err());
        assert!(validate_name("../x").is_err());
        assert!(validate_name("vault").is_err());
        assert!(validate_name("dev").is_err());
        assert!(validate_name("dev-web").is_err());
        assert!(validate_name("devops").is_ok());
    }
}
