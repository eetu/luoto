//! Host-side configuration: the global `config.toml` and one `envs/<name>.toml` per env.
//! Env files are meant to be read and edited by hand; CLI edits go through toml_edit so
//! comments and ordering survive.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use luoto_shared::policy::Rule;
use serde::{Deserialize, Serialize};
use toml_edit::DocumentMut;

use crate::paths::Paths;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    /// `podman` or `docker` (or a path to either).
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
    #[serde(default)]
    pub sources: Sources,
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
    /// first `up`; `luoto pull` writes back to it. Every env has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
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
    /// `owner/repo` the env may write to.
    #[serde(default)]
    pub repos: Vec<String>,
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
    #[serde(default = "default_protected")]
    pub protected_branches: Vec<String>,
    #[serde(default)]
    pub allow_tags: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Credentials {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github: Option<GithubCred>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azure_devops: Option<AzureDevopsCred>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshCred>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Login shell for this env; overrides `shell` in config.toml.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub workspace: Workspace,
    #[serde(default)]
    pub presets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
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
    #[serde(default, skip_serializing_if = "is_default")]
    pub credentials: Credentials,
    /// Secrets deliberately exposed to code in the sandbox as env vars.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sandbox_secrets: BTreeMap<String, String>,
    /// Plain env vars for the dev container.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
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

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
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
    // `luoto-x-gate` is env x's gate and `luoto-x-out` its egress network (see names.rs).
    if let Some(suffix) = ["-gate", "-out"].iter().find(|s| name.ends_with(*s)) {
        bail!("env names can't end in `{suffix}` (luoto names another env's containers so)");
    }
    Ok(())
}

pub fn load_global(paths: &Paths) -> Result<GlobalConfig> {
    let p = paths.global_config();
    match std::fs::read_to_string(&p) {
        Ok(s) => toml::from_str(&s).with_context(|| format!("parse {}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(GlobalConfig::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
    }
}

pub fn save_global(paths: &Paths, cfg: &GlobalConfig) -> Result<()> {
    let p = paths.global_config();
    std::fs::create_dir_all(p.parent().unwrap_or(Path::new(".")))?;
    std::fs::write(&p, toml::to_string_pretty(cfg)?)
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
        let cfg: EnvConfig =
            toml::from_str(text).with_context(|| format!("parse {}", path.display()))?;
        let doc: DocumentMut = text
            .parse()
            .with_context(|| format!("parse {}", path.display()))?;
        Ok(EnvFile { path, doc, cfg })
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
        let text = format!("{header}{}", toml::to_string_pretty(cfg)?);
        std::fs::create_dir_all(paths.envs_dir())?;
        std::fs::write(&path, &text)?;
        Self::parse(path, &text)
    }

    pub fn save(&mut self) -> Result<()> {
        let text = self.doc.to_string();
        // Re-validate what we are about to write.
        self.cfg = toml::from_str(&text).context("edited env config no longer parses")?;
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

    /// Write `[credentials.<provider>]`, replacing any entries it had.
    pub fn set_provider_credential(
        &mut self,
        provider: &str,
        entries: &BTreeMap<String, ProviderValue>,
    ) -> Result<()> {
        let mut table = toml_edit::Table::new();
        for (k, v) in entries {
            table[k] = match v {
                ProviderValue::Ref(r) => toml_edit::value(r.as_str()),
                ProviderValue::Flag(b) => toml_edit::value(*b),
            };
        }
        let creds = self.doc.entry("credentials").or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        });
        let Some(creds) = creds.as_table_like_mut() else {
            bail!("`credentials` in {} is not a table", self.path.display());
        };
        creds.insert(provider, toml_edit::Item::Table(table));
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

    /// Drop expired rules (keeps the file from accumulating stale grants).
    pub fn prune_expired(&mut self) -> Result<usize> {
        let now = chrono::Utc::now();
        self.retain_rules(|r| !r.expired(now))
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
repos = ["eetu/foo"]
permissions = { contents = "write" }

[credentials.anthropic]
oauth_token = "op://Private/claude/token"
"#;

    #[test]
    fn parses_and_edits_preserving_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        std::fs::write(&path, SAMPLE).unwrap();
        let mut f = EnvFile::parse(path.clone(), SAMPLE).unwrap();
        assert_eq!(
            f.cfg
                .credentials
                .github
                .as_ref()
                .unwrap()
                .protected_branches,
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
    fn names_are_restricted() {
        assert!(validate_name("my-env-2").is_ok());
        assert!(validate_name("My_Env").is_err());
        assert!(validate_name("../x").is_err());
        assert!(validate_name("vault").is_err());
    }
}
