//! An env's credentials as people see them: each vault binding with what it is for, where its
//! secret is kept (the ref as `luoto` shows refs, never the value), the hosts the gate adds it
//! on, whether the vault holds it, and the command that changes it. The UI's vault view and an
//! env's credentials section read these rows; `ui/api.rs` only passes them on.

use std::collections::BTreeSet;

use luoto_shared::creds::SSH_BINDING;
use luoto_shared::ctl::VaultStatus;
use serde::Serialize;

use crate::compile::Compiled;
use crate::config::EnvConfig;

#[derive(Debug, Clone, Serialize)]
pub struct Credential {
    pub env: String,
    pub binding: String,
    /// What it is for, for people: `GitHub token for acme/api`, `anthropic oauth_token, for claude`.
    pub what: String,
    /// Where its secret is kept, as `luoto` shows refs.
    pub kept: String,
    /// Where the gate adds it; an SSH key's, the hosts it logs in to.
    pub hosts: Vec<String>,
    pub state: CredState,
    /// The command that changes it; none: the env's own file does (`luoto edit`).
    pub change: Option<String>,
    #[serde(skip)]
    secret_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredState {
    /// The vault holds its secret.
    Loaded,
    /// The vault runs unlocked but lacks it: `luoto vault unlock` reads it.
    Missing,
    /// The vault is locked (after a restart): `luoto vault unlock`.
    Locked,
    /// The env isn't registered with the vault yet: `luoto up`.
    NotUp,
}

/// The credentials of `env`, from its compiled config and what the vault holds (none: the
/// vault isn't running).
pub fn of(
    env: &str,
    cfg: &EnvConfig,
    compiled: &Compiled,
    vault: Option<&VaultStatus>,
) -> Vec<Credential> {
    let registered = vault.and_then(|v| v.envs.iter().find(|e| e.env == env));
    compiled
        .bindings
        .iter()
        .map(|(binding, spec)| {
            let secret_ref = spec.secret_ref().to_string();
            let state = match (vault, registered) {
                (Some(v), _) if v.locked => CredState::Locked,
                (Some(_), Some(e)) if e.missing.contains(&secret_ref) => CredState::Missing,
                (Some(_), Some(_)) => CredState::Loaded,
                _ => CredState::NotUp,
            };
            let mut hosts: Vec<String> = if binding == SSH_BINDING {
                cfg.credentials
                    .ssh
                    .as_ref()
                    .map(|s| s.hosts.clone())
                    .unwrap_or_default()
            } else {
                compiled
                    .policy
                    .injections
                    .iter()
                    .filter(|i| &i.binding == binding)
                    .map(|i| i.host.clone())
                    .collect()
            };
            hosts.sort();
            hosts.dedup();
            let (what, change) = describe(env, cfg, binding);
            Credential {
                env: env.to_string(),
                binding: binding.clone(),
                what,
                kept: crate::secrets::shown_ref(&secret_ref),
                hosts,
                state,
                change,
                secret_ref,
            }
        })
        .collect()
}

/// The refs the vault holds that none of `credentials` uses, as `luoto` shows refs: left from
/// a credential since removed or changed.
pub fn unused(vault: &VaultStatus, credentials: &[Credential]) -> Vec<String> {
    let used: BTreeSet<&str> = credentials.iter().map(|c| c.secret_ref.as_str()).collect();
    vault
        .loaded_refs
        .iter()
        .filter(|r| !used.contains(r.as_str()))
        .map(|r| crate::secrets::shown_ref(r))
        .collect()
}

/// What `binding` is for, and the command that changes it, from the config that made it.
fn describe(env: &str, cfg: &EnvConfig, binding: &str) -> (String, Option<String>) {
    let repo_auth = |repo: Option<&String>| {
        repo.map(|r| format!("luoto repo auth -e {env} {}", crate::text::display(r)))
    };
    let creds = &cfg.credentials;
    // `github`, `github-read`, `github-2`, `github-2-read`: the GitHub credential's index.
    if let Some(rest) = binding.strip_prefix("github") {
        let rest = rest.strip_suffix("-read").unwrap_or(rest);
        let i = match rest.strip_prefix('-') {
            None if rest.is_empty() => Some(0),
            Some(n) => n.parse::<usize>().ok().map(|n| n - 1),
            None => None,
        };
        if let Some(gh) = i.and_then(|i| creds.github.0.get(i)) {
            let repos: Vec<&String> = gh.repos.iter().chain(&gh.read_repos).collect();
            let kind = if gh.app_id.is_some() { "App" } else { "token" };
            return (
                format!("GitHub {kind} for {}", list(&repos)),
                repo_auth(repos.first().copied()),
            );
        }
    }
    if let Some(n) = binding.strip_prefix("git-")
        && let Some(g) = n.parse::<usize>().ok().and_then(|n| creds.git.get(n - 1))
    {
        let repos: Vec<&String> = g.repos.iter().chain(&g.read_repos).collect();
        return (
            format!("git token for {} ({})", g.host, list(&repos)),
            repo_auth(repos.first().copied()),
        );
    }
    if binding == "azure_devops"
        && let Some(a) = &creds.azure_devops
    {
        let repos: Vec<&String> = a.repos.iter().chain(&a.read_repos).collect();
        return (
            format!("Azure DevOps token for {}", list(&repos)),
            repo_auth(repos.first().copied()),
        );
    }
    if binding == SSH_BINDING {
        return ("SSH key, signed with in the vault".into(), None);
    }
    if let Some(aud) = binding.strip_prefix("azure-") {
        return (format!("Azure identity ({aud})"), None);
    }
    if let Some(name) = binding.strip_prefix("custom.") {
        return (format!("custom credential {name}"), None);
    }
    if let Some(name) = binding.strip_prefix("model_server.") {
        return (format!("model server {name}'s token"), None);
    }
    if let Some((provider, kind)) = binding.split_once('.') {
        // An agent's provider: `luoto agent auth` asks again.
        let agent = cfg.agents.names().find(|a| {
            luoto_shared::profiles::agent(a)
                .is_some_and(|p| p.providers.iter().any(|x| x == provider))
        });
        return match agent {
            Some(a) => (
                format!("{provider} {kind}, for {a}"),
                Some(format!("luoto agent auth -e {env} {a}")),
            ),
            None => (format!("{provider} {kind}"), None),
        };
    }
    (binding.to_string(), None)
}

fn list(items: &[&String]) -> String {
    match items {
        [] => "no repos".into(),
        [one] => crate::text::display(one),
        [first, rest @ ..] => format!("{} and {} more", crate::text::display(first), rest.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use luoto_shared::ctl::VaultEnvSummary;

    #[test]
    fn each_credential_says_what_it_is_for_where_it_goes_and_how_to_change_it() {
        let cfg: EnvConfig = toml::from_str(
            r#"
agents = ["claude"]
[credentials.anthropic]
oauth_token = "op://p/claude/token"
[[credentials.github]]
token = "keyring:luoto/gh"
repos = ["acme/api"]
[[credentials.github]]
token = "keyring:luoto/gh2"
read_repos = ["other/docs"]
[credentials.custom.billing]
host = "api.example.com"
secret = "op://Dev/billing/key"
"#,
        )
        .unwrap();
        let c = crate::compile::compile("web", &cfg, None, &[]).unwrap();
        let vault = VaultStatus {
            version: "x".into(),
            started: chrono::Utc::now(),
            locked: false,
            loaded_refs: vec!["op://p/claude/token".into(), "op://Old/gone".into()],
            envs: vec![VaultEnvSummary {
                env: "web".into(),
                bindings: vec![],
                missing: vec!["keyring:luoto/gh".into()],
            }],
        };
        let rows = of("web", &cfg, &c, Some(&vault));
        let row = |b: &str| rows.iter().find(|r| r.binding == b).unwrap();

        let claude = row("anthropic.oauth_token");
        assert_eq!(claude.what, "anthropic oauth_token, for claude");
        assert_eq!(
            claude.change.as_deref(),
            Some("luoto agent auth -e web claude")
        );
        assert_eq!(claude.state, CredState::Loaded);
        assert!(claude.hosts.contains(&"api.anthropic.com".to_string()));

        let gh = row("github");
        assert_eq!(gh.what, "GitHub token for acme/api");
        assert_eq!(
            gh.change.as_deref(),
            Some("luoto repo auth -e web acme/api")
        );
        assert_eq!(gh.state, CredState::Missing);
        assert_eq!(row("github-2").what, "GitHub token for other/docs");

        let custom = row("custom.billing");
        assert_eq!(custom.what, "custom credential billing");
        assert_eq!(custom.change, None);
        assert_eq!(custom.hosts, ["api.example.com"]);

        // What the vault holds that no env uses: left from a credential since changed.
        assert_eq!(unused(&vault, &rows), ["op://Old/gone"]);
        // A locked vault, or an env the vault doesn't know yet.
        let locked = VaultStatus {
            locked: true,
            ..vault.clone()
        };
        let all = |v: Option<&VaultStatus>, s: CredState| {
            of("web", &cfg, &c, v).iter().all(|r| r.state == s)
        };
        assert!(all(Some(&locked), CredState::Locked));
        assert!(all(None, CredState::NotUp));
    }
}
