//! Agent, model-provider and editor profiles, shipped as TOML data: supporting another coding
//! agent, model API or editor is a new file, not code.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::policy::Rule;
use crate::{embed, load};

/// How a model API credential is injected by the gate.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    #[serde(skip)]
    pub name: String,
    pub description: String,
    pub host: String,
    /// Paths the credential may be used on (empty = every path not denied).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Extra hosts needed only when the user logs in inside the sandbox.
    #[serde(default)]
    pub login_hosts: Vec<String>,
    /// How to log in inside the sandbox, and what that leaves there.
    #[serde(default)]
    pub login_how: Option<String>,
    #[serde(default)]
    pub deny: Vec<ProviderDeny>,
    /// Credential kinds (`api_key`, `oauth_token`) → how each is placed. Empty for a provider
    /// whose only way in is a login inside the sandbox (`login_hosts`).
    #[serde(default)]
    pub auth: BTreeMap<String, ProviderAuth>,
    /// The kind most users have, suggested first.
    #[serde(default)]
    pub suggested: Option<String>,
    /// WebSocket upgrades on the API host (clients that stream over `wss://`).
    #[serde(default)]
    pub ws: bool,
    /// More hosts the same credential goes to, each with its own paths.
    #[serde(default)]
    pub also: Vec<ProviderHost>,
    /// Request fields that have the provider reach the network for the request. The gate
    /// refuses requests that carry them, and the WebSocket API (whose messages it can't read),
    /// unless the env sets `server_tools = true` for the provider.
    #[serde(default, rename = "server_tool")]
    pub server_tools: Vec<ServerTool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTool {
    /// What it is, as a refusal names it ("web fetch").
    pub what: String,
    /// POST paths on the provider's `host` whose JSON bodies are read.
    pub paths: Vec<String>,
    /// Top-level keys that ask for it (`mcp_servers`).
    #[serde(default)]
    pub keys: Vec<String>,
    /// `tools[].type` values that ask for it, each also with a version suffix.
    #[serde(default)]
    pub tool_types: Vec<String>,
    /// Keys of a `tools[]` entry that ask for it (`url_context`).
    #[serde(default)]
    pub tool_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHost {
    pub host: String,
    /// Paths the credential may be used on (empty = every path).
    #[serde(default)]
    pub paths: Vec<String>,
    /// What the env may do there (default: write, as on `host`).
    #[serde(default)]
    pub access: Option<crate::policy::AccessLevel>,
}

impl Provider {
    /// Every host the credential goes to, with its paths and access: `host` first, then
    /// `also`.
    pub fn hosts(&self) -> Vec<(&str, &[String], crate::policy::AccessLevel)> {
        use crate::policy::AccessLevel::Write;
        std::iter::once((self.host.as_str(), self.paths.as_slice(), Write))
            .chain(self.also.iter().map(|h| {
                (
                    h.host.as_str(),
                    h.paths.as_slice(),
                    h.access.unwrap_or(Write),
                )
            }))
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDeny {
    pub paths: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAuth {
    /// What the credential is, as the user knows it ("Claude subscription token").
    pub label: String,
    /// Where to get one, in a sentence or two.
    pub how: String,
    pub header: String,
    pub format: String,
    /// Also replace this query parameter (clients that pass keys in the URL).
    #[serde(default)]
    pub query: Option<String>,
    /// Format-valid placeholders exported in the sandbox so clients start up.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    #[serde(skip)]
    pub name: String,
    pub description: String,
    pub command: String,
    /// Arguments that turn off the agent's own permission prompts (the sandbox is the
    /// boundary instead).
    #[serde(default)]
    pub yolo: Vec<String>,
    /// Providers this agent can use; suggested when adding the agent.
    #[serde(default)]
    pub providers: Vec<String>,
    /// Shell steps run inside the sandbox as the user to install the agent.
    #[serde(default)]
    pub install: Vec<String>,
    /// Hosts granted read access only while installing.
    #[serde(default)]
    pub install_hosts: Vec<String>,
    /// mise tools the agent runs on (`node = "lts"`); installed with the env's toolchains,
    /// and overridden by the project's own versions.
    #[serde(default)]
    pub tools: BTreeMap<String, String>,
    /// What the agent reaches at runtime besides its provider, as preset-style rules.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// User-level instruction files linked to the luoto briefing.
    #[serde(default)]
    pub briefing: Vec<String>,
    /// How to register the sandbox MCP server (`claude`, `opencode`, `codex`, `copilot`, `agy`).
    #[serde(default)]
    pub mcp: Option<String>,
    /// Answers to what the agent asks on its first start, set in its JSON config: in a
    /// sandbox, its trust questions guard nothing the sandbox doesn't.
    #[serde(default, rename = "first_run")]
    pub first_run: Vec<JsonSet>,
    /// Where each option an env can give the agent (`model`, `effort`) goes in its own
    /// config: written at `up`, under anything the user chooses in a session.
    #[serde(default)]
    pub settings: BTreeMap<String, AgentSetting>,
}

/// Where one agent option goes: a key path in a config file of the home (JSON, or TOML for a
/// `.toml` file), and the values it takes when the agent limits them.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentSetting {
    pub file: String,
    pub path: Vec<String>,
    #[serde(default)]
    pub values: Vec<String>,
}

/// One value set in a config file (JSON, or TOML for a `.toml` file), at a path of keys,
/// keeping everything else there.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct JsonSet {
    /// `~/…` for the dev user's home.
    pub file: String,
    pub path: Vec<String>,
    pub value: serde_json::Value,
}

/// An editor `luoto open` connects to an env. Every editor reaches the env over SSH through
/// luoto's `ProxyCommand`, so all of them get the same server-side restrictions.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Editor {
    #[serde(skip)]
    pub name: String,
    pub description: String,
    /// Program and arguments; `{host}` (the SSH host alias), `{user}` and `{path}` are filled
    /// in. Empty: `luoto open` prints how to connect instead.
    #[serde(default)]
    pub launch: Vec<String>,
    /// The program's name on Windows when it differs (`code.cmd`).
    #[serde(default)]
    pub windows_program: Option<String>,
    /// One line shown when opening.
    #[serde(default)]
    pub hint: Option<String>,
    /// A one-time setting the editor needs, shown until its settings file has it.
    #[serde(default)]
    pub setting: Option<EditorSetting>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditorSetting {
    /// Settings file: `{home}` and `{config}` (the platform's config directory) are filled in.
    pub file: String,
    #[serde(default)]
    pub windows_file: Option<String>,
    /// Text whose presence in the file means the setting is there.
    pub contains: String,
    pub why: String,
    pub snippet: String,
}

const PROVIDERS: &[(&str, &str)] = embed!("providers"; "anthropic", "openai", "openrouter", "gemini", "mistral", "groq", "copilot", "antigravity");
const AGENTS: &[(&str, &str)] = embed!("agents"; "claude", "opencode", "codex", "copilot", "agy");
const EDITORS: &[(&str, &str)] = embed!("editors"; "zed", "code", "cursor", "ssh");

/// Editors in the order `luoto open` tries them when none is configured.
pub fn editor_names() -> impl Iterator<Item = &'static str> {
    EDITORS.iter().map(|(n, _)| *n)
}

pub fn editor(name: &str) -> Option<Editor> {
    load(EDITORS, name, |e: &mut Editor| &mut e.name)
}

pub fn provider_names() -> impl Iterator<Item = &'static str> {
    PROVIDERS.iter().map(|(n, _)| *n)
}

pub fn agent_names() -> impl Iterator<Item = &'static str> {
    AGENTS.iter().map(|(n, _)| *n)
}

pub fn provider(name: &str) -> Option<Provider> {
    load(PROVIDERS, name, |p: &mut Provider| &mut p.name)
}

pub fn agent(name: &str) -> Option<Agent> {
    load(AGENTS, name, |a: &mut Agent| &mut a.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{WildcardRisk, normalize_host, wildcard_risk};

    #[test]
    fn editors_parse_and_use_known_placeholders() {
        for name in editor_names() {
            let e = editor(name).unwrap();
            for a in &e.launch {
                let rest = a
                    .replace("{host}", "")
                    .replace("{user}", "")
                    .replace("{path}", "");
                assert!(!rest.contains('{'), "{name}: unknown placeholder in {a}");
            }
        }
        assert!(editor("ssh").unwrap().launch.is_empty());
    }

    #[test]
    fn profiles_parse_and_reference_known_providers() {
        for name in provider_names() {
            let p = provider(name).unwrap();
            for (h, _, _) in p.hosts() {
                assert!(normalize_host(h).is_ok(), "{name}: {h}");
                assert_eq!(wildcard_risk(h), WildcardRisk::None, "{name}: {h}");
            }
            assert!(
                !p.auth.is_empty() || !p.login_hosts.is_empty(),
                "{name} has auth kinds or a login"
            );
            for a in p.auth.values() {
                assert!(a.format.contains("{secret}"), "{name}");
            }
        }
        for name in agent_names() {
            let a = agent(name).unwrap();
            for p in &a.providers {
                assert!(
                    provider(p).is_some(),
                    "agent {name} references unknown provider {p}"
                );
            }
            for h in a.rules.iter().map(|r| &r.host).chain(&a.install_hosts) {
                assert_eq!(wildcard_risk(h), WildcardRisk::None, "{name}: {h}");
            }
        }
    }
}
