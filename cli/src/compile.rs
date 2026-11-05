//! Env config → what the gate enforces (policy), what the vault serves (bindings), which
//! secret refs must be resolved, and the placeholder environment for the sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use luoto_shared::creds::{
    BindingSpec, FORBIDDEN_GITHUB_PERMISSIONS, Injection, Placement, SSH_BINDING,
    default_github_api,
};
use luoto_shared::policy::{
    Access, AccessLevel, AzureGuard, BodyDeny, CompiledRule, DenyRule, GithubGuard, InternalName,
    Mode, Policy, Rule, RuleOrigin, rule_error,
};
use luoto_shared::{forges, presets, profiles};

use crate::azure;
use crate::config::{
    AzureDevopsCred, CustomCred, EnvConfig, GithubCred, ProviderValue, SshCred, extend_unique,
};

pub struct Compiled {
    pub policy: Policy,
    pub bindings: BTreeMap<String, BindingSpec>,
    /// Refs exposed to the sandbox as env vars (`sandbox_secrets`), resolved at `up`.
    pub sandbox_refs: BTreeMap<String, String>,
    /// Placeholder and agent env vars for processes in the sandbox.
    pub dev_env: BTreeMap<String, String>,
    /// The env's git remote rewrites (`/run/luoto/gitconfig`, which its system config
    /// includes).
    pub git_config: String,
    /// Pinned host keys of the hosts git over SSH may log in to (`/run/luoto/ssh_known_hosts`).
    pub known_hosts: String,
    pub warnings: Vec<String>,
}

impl Compiled {
    /// Refs the vault needs for the bindings, resolved at unlock.
    pub fn vault_refs(&self) -> BTreeSet<String> {
        self.bindings
            .values()
            .map(|b| b.secret_ref().to_string())
            .collect()
    }
}

const GH_PLACEHOLDER: &str = "ghs_luotoPlaceholder0000000000000000000";

#[derive(Default)]
struct Builder {
    rules: Vec<CompiledRule>,
    denies: Vec<DenyRule>,
    body_denies: Vec<BodyDeny>,
    injections: Vec<Injection>,
    bindings: BTreeMap<String, BindingSpec>,
    dev_env: BTreeMap<String, String>,
    warnings: Vec<String>,
    /// `url.<base>.insteadOf` pairs, as (base, prefix it replaces).
    rewrites: Vec<(String, String)>,
}

impl Builder {
    fn rule(&mut self, id: String, origin: &str, mut rule: Rule) {
        rule.id = None;
        self.rules.push(CompiledRule {
            id,
            origin: origin.to_string(),
            rule,
        });
    }

    fn has_read(&self, host: &str) -> bool {
        self.rules
            .iter()
            .any(|r| r.rule.host == host && r.rule.paths.is_empty() && r.rule.access.allows("GET"))
    }
}

/// `gate_ip` is the env's gate once `up` has given the env its addresses; `aliases` are the SSH
/// host aliases its folder's remotes use for Azure DevOps ([`azure::aliases`]).
pub fn compile(
    env: &str,
    cfg: &EnvConfig,
    gate_ip: Option<Ipv4Addr>,
    aliases: &[(String, String)],
) -> Result<Compiled> {
    let mut b = Builder::default();

    for name in &cfg.presets {
        let Some(p) = presets::get(name) else {
            bail!(
                "unknown preset `{name}` (known: {})",
                presets::names().collect::<Vec<_>>().join(", ")
            );
        };
        for (i, r) in p.rules.into_iter().enumerate() {
            b.rule(format!("{name}-{i}"), &format!("preset:{name}"), r);
        }
    }

    for name in &cfg.agents {
        let Some(a) = profiles::agent(name) else {
            bail!(
                "unknown agent `{name}` (known: {})",
                profiles::agent_names().collect::<Vec<_>>().join(", ")
            );
        };
        for (i, r) in a.rules.into_iter().enumerate() {
            b.rule(format!("agent-{name}-{i}"), &format!("agent:{name}"), r);
        }
        b.dev_env.extend(a.env.clone());
    }

    for (pname, entries) in &cfg.credentials.providers {
        compile_provider(&mut b, pname, entries)?;
    }
    for (cname, c) in &cfg.credentials.custom {
        compile_custom(&mut b, cname, c)?;
    }
    let github = cfg
        .credentials
        .github
        .as_ref()
        .map(|gh| compile_github(&mut b, gh))
        .transpose()?;

    let (ssh_hosts, known_hosts) = compile_ssh(&mut b, cfg.credentials.ssh.as_ref())?;
    let over_ssh = |h: &str| ssh_hosts.iter().any(|s| s == h);
    // Only HTTP(S) leaves the env, so SSH remotes go to HTTPS unless the vault's key logs in
    // to their host.
    if !over_ssh(forges::GITHUB) {
        for from in ["git@github.com:", "ssh://git@github.com/"] {
            b.rewrites
                .push(("https://github.com/".to_string(), from.to_string()));
        }
    }
    let (azure_devops, azure_repos) = match &cfg.credentials.azure_devops {
        Some(c) => {
            let (guard, repos) = compile_azure(&mut b, c)?;
            (Some(guard), repos)
        }
        None => (None, Vec::new()),
    };
    b.rewrites.extend(azure::rewrites(
        &azure_repos,
        aliases,
        over_ssh(azure::SSH_HOST),
    ));

    for (i, r) in cfg.allow.iter().enumerate() {
        if let Some(e) = rule_error(r, RuleOrigin::Host) {
            bail!("rule for `{}`: {}", r.host, e.message);
        }
        if r.expired(Utc::now()) {
            continue;
        }
        let id = r.id.clone().unwrap_or_else(|| format!("user-{i}"));
        // Rules from the accepted luoto.toml (see project::layer) say where they came from.
        let origin = if id.starts_with("project-") {
            "project"
        } else {
            "user"
        };
        b.rule(id, origin, r.clone());
    }
    b.dev_env.extend(cfg.env.clone());

    let policy = Policy {
        env: env.to_string(),
        rules: b.rules,
        denies: b.denies,
        body_denies: b.body_denies,
        injections: b.injections,
        github,
        azure_devops,
        internal_names: gate_ip
            .map(|ip| InternalName {
                name: luoto_shared::GATE_HOST.into(),
                ip,
            })
            .into_iter()
            .collect(),
    };
    // A tunnel passes bytes unread: one you or a repository wrote can't cover a host whose
    // credentials, forge guards or denies the gate applies (`luoto allow` refuses it too).
    for r in &policy.rules {
        if matches!(r.origin.as_str(), "user" | "project")
            && r.rule.mode == Mode::Tunnel
            && let Some(why) = policy.tunnel_bypass(&r.rule.host)
        {
            bail!("rule `{}`: {why}", r.id);
        }
    }

    Ok(Compiled {
        policy,
        bindings: b.bindings,
        sandbox_refs: cfg.sandbox_secrets.clone(),
        dev_env: b.dev_env,
        git_config: git_config(&b.rewrites),
        known_hosts,
        warnings: b.warnings,
    })
}

/// A model provider: `[credentials.<provider>] <auth_kind> = "<ref>"` or `login_inside = true`,
/// and `server_tools = true` to let it reach the network for the sandbox's requests.
fn compile_provider(
    b: &mut Builder,
    pname: &str,
    entries: &BTreeMap<String, ProviderValue>,
) -> Result<()> {
    let Some(p) = profiles::provider(pname) else {
        bail!(
            "unknown credential section `{pname}` (providers: {}; or use [credentials.custom.<name>])",
            profiles::provider_names().collect::<Vec<_>>().join(", ")
        );
    };
    if let Some(k) = entries.iter().find_map(|(k, v)| {
        (matches!(v, ProviderValue::Flag(_)) && k != "login_inside" && k != "server_tools")
            .then_some(k)
    }) {
        bail!("credentials.{pname}: `{k}` is not a setting (login_inside, server_tools)");
    }
    let login_inside = entries.get("login_inside") == Some(&ProviderValue::Flag(true));
    let server_tools = entries.get("server_tools") == Some(&ProviderValue::Flag(true));
    if login_inside
        && let Some(kind) = entries
            .iter()
            .find_map(|(k, v)| matches!(v, ProviderValue::Ref(_)).then_some(k))
    {
        bail!(
            "credentials.{pname}: `login_inside` and `{kind}` are both set; keep one (the \
             login keeps its session in the env, `{kind}` stays outside it)"
        );
    }
    let origin = format!("provider:{pname}");
    for (i, (host, paths, access)) in p.hosts().into_iter().enumerate() {
        b.rule(
            match i {
                0 => format!("provider-{pname}"),
                i => format!("provider-{pname}-{i}"),
            },
            &origin,
            Rule {
                host: host.to_string(),
                access: Access::Level(access),
                paths: paths.to_vec(),
                // The gate can't read WebSocket messages for server tools.
                ws: p.ws && (server_tools || p.server_tools.is_empty()),
                ..Default::default()
            },
        );
    }
    for d in &p.deny {
        b.denies.push(DenyRule {
            host: p.host.clone(),
            paths: d.paths.clone(),
            methods: vec![],
            reason: d.reason.clone(),
        });
    }
    if server_tools && !p.server_tools.is_empty() {
        b.warnings.push(format!(
            "{pname}: server_tools lets {pname} fetch URLs and call MCP servers for the sandbox"
        ));
    } else if !server_tools {
        for t in &p.server_tools {
            b.body_denies.push(BodyDeny {
                host: p.host.clone(),
                paths: t.paths.clone(),
                keys: t.keys.clone(),
                tool_types: t.tool_types.clone(),
                tool_keys: t.tool_keys.clone(),
                reason: format!(
                    "{} has {pname} reach the network for the request; the env allows it with \
                     `server_tools = true` under [credentials.{pname}]",
                    t.what
                ),
            });
        }
    }
    if login_inside {
        for (i, h) in p.login_hosts.iter().enumerate() {
            b.rule(
                format!("provider-{pname}-login-{i}"),
                &origin,
                Rule {
                    host: h.clone(),
                    access: Access::Level(AccessLevel::Write),
                    ..Default::default()
                },
            );
        }
        b.warnings.push(format!(
            "{pname}: login_inside keeps the {pname} credential inside the sandbox (reduced assurance)"
        ));
        return Ok(());
    }
    let mut configured = 0;
    for (kind, value) in entries {
        let ProviderValue::Ref(secret_ref) = value else {
            continue;
        };
        let Some(auth) = p.auth.get(kind) else {
            bail!(
                "credentials.{pname}: unknown kind `{kind}` (known: {})",
                p.auth.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        };
        let binding = format!("{pname}.{kind}");
        b.bindings.insert(
            binding.clone(),
            BindingSpec::Static {
                secret_ref: secret_ref.clone(),
            },
        );
        for (host, paths, _) in p.hosts() {
            b.injections.push(Injection {
                binding: binding.clone(),
                host: host.to_string(),
                paths: paths.to_vec(),
                place: Placement::Header {
                    name: auth.header.clone(),
                    format: auth.format.clone(),
                },
                ignore_case: false,
            });
            if let Some(q) = &auth.query {
                b.injections.push(Injection {
                    binding: binding.clone(),
                    host: host.to_string(),
                    paths: paths.to_vec(),
                    place: Placement::Query { param: q.clone() },
                    ignore_case: false,
                });
            }
        }
        b.dev_env.extend(auth.env.clone());
        configured += 1;
    }
    if configured > 1 {
        bail!("credentials.{pname}: configure one credential kind, not {configured}");
    }
    Ok(())
}

/// `[credentials.custom.<name>]`: a header credential for one exact host.
fn compile_custom(b: &mut Builder, cname: &str, c: &CustomCred) -> Result<()> {
    // A credential goes to one exact host: a wildcard would hand it to every tenant there.
    let host = luoto_shared::host::normalize_host(&c.host)
        .ok()
        .filter(|_| !c.host.contains(['*', '/']))
        .with_context(|| {
            format!(
                "credentials.custom.{cname}: host `{}` must be one exact host name",
                c.host
            )
        })?;
    let binding = format!("custom.{cname}");
    b.bindings.insert(
        binding.clone(),
        BindingSpec::Static {
            secret_ref: c.secret.clone(),
        },
    );
    b.injections.push(Injection {
        binding,
        host: host.clone(),
        paths: c.paths.clone(),
        place: Placement::Header {
            name: c.header.to_ascii_lowercase(),
            format: c.format.clone(),
        },
        ignore_case: false,
    });
    b.rule(
        format!("custom-{cname}"),
        &format!("credential:{cname}"),
        Rule {
            host,
            access: if c.write {
                Access::Level(AccessLevel::Write)
            } else {
                Access::Level(AccessLevel::Read)
            },
            paths: c.paths.clone(),
            ..Default::default()
        },
    );
    b.dev_env.extend(c.placeholder_env.clone());
    Ok(())
}

/// `url.<base>.insteadOf` pairs as a git config file, grouped by base.
fn git_config(pairs: &[(String, String)]) -> String {
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::from("# Written by luoto at `up`: where this env's git remotes go.\n");
    let mut bases: Vec<&str> = Vec::new();
    extend_unique(&mut bases, pairs.iter().map(|(b, _)| b.as_str()));
    for base in bases {
        out.push_str(&format!("[url \"{}\"]\n", quote(base)));
        for (_, from) in pairs.iter().filter(|(b, _)| b == base) {
            out.push_str(&format!("\tinsteadOf = \"{}\"\n", quote(from)));
        }
    }
    out
}

/// Git over SSH: the key as a vault binding the env's agent signs with, a tunnel rule on
/// port 22 for each host, and the hosts' pinned keys. The hosts, and their `known_hosts`.
fn compile_ssh(b: &mut Builder, c: Option<&SshCred>) -> Result<(Vec<String>, String)> {
    let Some(c) = c else {
        return Ok((Vec::new(), String::new()));
    };
    if c.hosts.is_empty() {
        bail!("credentials.ssh: list the hosts the key logs in to (`hosts = [\"github.com\"]`)");
    }
    let normalized: Vec<String> = c
        .hosts
        .iter()
        .map(|h| {
            luoto_shared::host::normalize_host(h)
                .map_err(|e| anyhow::anyhow!("credentials.ssh: host `{h}`: {e}"))
        })
        .collect::<Result<_>>()?;
    let mut hosts = Vec::new();
    extend_unique(&mut hosts, normalized);
    for line in &c.host_keys {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            bail!(
                "credentials.ssh: host_keys are known_hosts lines (`host algorithm base64`), not `{line}`"
            );
        }
        if !hosts.iter().any(|h| h.eq_ignore_ascii_case(fields[0])) {
            bail!(
                "credentials.ssh: host_keys names `{}`, which is not in hosts",
                fields[0]
            );
        }
    }
    let mut lines = Vec::new();
    for host in &hosts {
        let before = lines.len();
        lines.extend(luoto_shared::forges::host_keys(host).map(|k| format!("{host} {k}")));
        lines.extend(
            c.host_keys
                .iter()
                .filter(|l| {
                    l.split_whitespace()
                        .next()
                        .is_some_and(|h| h.eq_ignore_ascii_case(host))
                })
                .map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" ")),
        );
        if lines.len() == before {
            bail!(
                "credentials.ssh: luoto pins no host key for `{host}`; add its known_hosts line to host_keys"
            );
        }
        b.rule(
            format!("ssh-{host}"),
            "ssh",
            Rule {
                host: host.clone(),
                port: Some(22),
                mode: Mode::Tunnel,
                access: Access::Level(AccessLevel::Write),
                note: Some("git over SSH; the vault signs the login".into()),
                ..Default::default()
            },
        );
    }
    b.bindings.insert(
        SSH_BINDING.into(),
        BindingSpec::SshAgent {
            key_ref: c.key.clone(),
            host_keys: lines.clone(),
        },
    );
    Ok((hosts, lines.join("\n") + "\n"))
}

fn split_repo(full: &str) -> Result<(String, String)> {
    let full = full
        .trim()
        .trim_start_matches("https://github.com/")
        .trim_end_matches(".git");
    match full.split_once('/') {
        Some((o, r)) if !o.is_empty() && !r.is_empty() && !r.contains('/') => {
            Ok((o.to_ascii_lowercase(), r.to_ascii_lowercase()))
        }
        _ => bail!("GitHub repos are `owner/repo` (got `{full}`)"),
    }
}

fn compile_github(b: &mut Builder, gh: &GithubCred) -> Result<GithubGuard> {
    if gh.repos.is_empty() {
        bail!(
            "credentials.github: list the repos the env may write to (`repos = [\"owner/repo\"]`)"
        );
    }
    for p in gh.permissions.keys() {
        if FORBIDDEN_GITHUB_PERMISSIONS.contains(&p.as_str()) {
            bail!(
                "credentials.github: permission `{p}` is refused — it would let the sandbox reach CI secrets or account settings"
            );
        }
    }
    let repos: Vec<(String, String)> = gh
        .repos
        .iter()
        .map(|r| split_repo(r))
        .collect::<Result<_>>()?;
    let spec = match (&gh.app_id, &gh.private_key, &gh.token) {
        (Some(app_id), Some(key), None) => {
            let Some(installation_id) = gh.installation_id else {
                bail!("credentials.github: installation_id is required with app_id");
            };
            let mut permissions = gh.permissions.clone();
            if permissions.is_empty() {
                permissions.insert("contents".into(), "write".into());
                permissions.insert("pull_requests".into(), "write".into());
            }
            permissions
                .entry("metadata".into())
                .or_insert_with(|| "read".into());
            BindingSpec::GithubApp {
                app_id: app_id.clone(),
                installation_id,
                key_ref: key.clone(),
                repos: repos.iter().map(|(_, r)| r.clone()).collect(),
                permissions,
                api_base: gh.api_base.clone().unwrap_or_else(default_github_api),
            }
        }
        (None, None, Some(token)) => BindingSpec::Static {
            secret_ref: token.clone(),
        },
        _ => {
            bail!("credentials.github: set either app_id + installation_id + private_key, or token")
        }
    };
    b.bindings.insert("github".into(), spec);

    let mut git_paths = Vec::new();
    let mut api_paths = vec!["/graphql".to_string()];
    for (o, r) in &repos {
        for base in [format!("/{o}/{r}"), format!("/{o}/{r}.git")] {
            git_paths.push(format!("{base}/info/refs"));
            git_paths.push(format!("{base}/git-upload-pack"));
            git_paths.push(format!("{base}/git-receive-pack"));
            git_paths.push(format!("{base}/info/lfs/**"));
        }
        api_paths.push(format!("/repos/{o}/{r}"));
        api_paths.push(format!("/repos/{o}/{r}/**"));
    }
    // GitHub reads owner and repo in any case, and a remote keeps the case it was cloned with.
    b.injections.push(Injection {
        binding: "github".into(),
        host: forges::GITHUB.into(),
        paths: git_paths.clone(),
        place: Placement::Basic {
            username: "x-access-token".into(),
        },
        ignore_case: true,
    });
    b.injections.push(Injection {
        binding: "github".into(),
        host: forges::GITHUB_API.into(),
        paths: api_paths,
        place: Placement::Header {
            name: "authorization".into(),
            format: "Bearer {secret}".into(),
        },
        ignore_case: true,
    });
    if !b.has_read(forges::GITHUB) {
        b.rule("github-read".into(), "github", Rule::read(forges::GITHUB));
    }
    if !b.has_read(forges::GITHUB_API) {
        b.rule(
            "github-api-read".into(),
            "github",
            Rule::read(forges::GITHUB_API),
        );
    }
    b.rule(
        "github-git".into(),
        "github",
        Rule {
            host: forges::GITHUB.into(),
            access: Access::Methods(vec!["GET".into(), "POST".into()]),
            paths: git_paths,
            ignore_case: true,
            ..Default::default()
        },
    );
    // REST writes are an allowlist: pull requests, reviews and issues. Branch content goes
    // through git-receive-pack, where the push guard checks every ref; the contents, git-data,
    // merge, ref, release and settings endpoints would bypass it.
    let mut write_paths = vec!["/graphql".to_string()];
    for (o, r) in &repos {
        for path in [
            "pulls",
            "pulls/*",
            "pulls/*/comments",
            "pulls/*/comments/*/replies",
            "pulls/*/reviews",
            "pulls/*/requested_reviewers",
            "pulls/comments/*",
            "issues",
            "issues/*",
            "issues/*/comments",
            "issues/*/labels",
            "issues/comments/*",
        ] {
            write_paths.push(format!("/repos/{o}/{r}/{path}"));
        }
    }
    b.rule(
        "github-api-write".into(),
        "github",
        Rule {
            host: forges::GITHUB_API.into(),
            access: Access::Methods(vec!["POST".into(), "PATCH".into()]),
            paths: write_paths,
            ignore_case: true,
            ..Default::default()
        },
    );
    let write = vec!["POST".into(), "PUT".into(), "PATCH".into(), "DELETE".into()];
    for (paths, reason) in [
        (
            vec![
                "/repos/*/*/actions",
                "/repos/*/*/actions/**",
                "/repos/*/*/dispatches",
            ],
            "GitHub Actions cannot be triggered or configured from the sandbox",
        ),
        (
            vec!["/repos/*/*/environments/**", "/repos/*/*/deployments/**"],
            "deployments and environments are off-limits",
        ),
        (
            vec![
                "/repos/*/*/hooks/**",
                "/repos/*/*/keys/**",
                "/repos/*/*/collaborators/**",
                "/repos/*/*/invitations/**",
            ],
            "repository administration is off-limits",
        ),
        (
            vec!["/repos/*/*/contents/.github/**"],
            "workflow and repository settings files cannot be changed from the sandbox",
        ),
        (
            vec![
                "/repos/*/*/git/refs/tags/**",
                "/repos/*/*/releases",
                "/repos/*/*/releases/**",
            ],
            "tags and releases are made by humans",
        ),
    ] {
        b.denies.push(DenyRule {
            host: forges::GITHUB_API.into(),
            paths: paths.into_iter().map(str::to_string).collect(),
            methods: write.clone(),
            reason: reason.into(),
        });
    }
    b.dev_env.insert("GH_TOKEN".into(), GH_PLACEHOLDER.into());
    b.dev_env
        .insert("GITHUB_TOKEN".into(), GH_PLACEHOLDER.into());
    b.dev_env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());

    Ok(GithubGuard {
        repos: repos.iter().map(|(o, r)| format!("{o}/{r}")).collect(),
        protected_branches: gh.protected_branches.clone(),
        graphql_mutations: gh.graphql_mutations.clone(),
        allow_tags: gh.allow_tags,
    })
}

/// Azure DevOps: the PAT added as basic auth on the repos' git paths, those paths allowed
/// (case-insensitively, as Azure DevOps reads them) and the push guard. The guard, and the
/// repos for the remote rewrites ([`azure::rewrites`]).
fn compile_azure(b: &mut Builder, c: &AzureDevopsCred) -> Result<(AzureGuard, Vec<azure::Repo>)> {
    if c.repos.is_empty() {
        bail!(
            "credentials.azure_devops: list the repos the env may use (`repos = [\"org/project/repo\"]`)"
        );
    }
    let repos: Vec<azure::Repo> = c
        .repos
        .iter()
        .map(|r| azure::parse_repo(r))
        .collect::<Result<_>>()?;
    b.bindings.insert(
        "azure_devops".into(),
        BindingSpec::Static {
            secret_ref: c.token.clone(),
        },
    );
    let paths: Vec<String> = repos.iter().flat_map(azure::Repo::git_paths).collect();
    b.injections.push(Injection {
        binding: "azure_devops".into(),
        host: azure::HOST.into(),
        paths: paths.clone(),
        place: Placement::Basic {
            username: String::new(),
        },
        ignore_case: true,
    });
    b.rule(
        "azure-git".into(),
        "azure_devops",
        Rule {
            host: azure::HOST.into(),
            access: Access::Methods(vec!["GET".into(), "POST".into()]),
            paths,
            ignore_case: true,
            ..Default::default()
        },
    );
    b.dev_env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    let guard = AzureGuard {
        repos: repos.iter().map(azure::Repo::key).collect(),
        protected_branches: c.protected_branches.clone(),
        allow_tags: c.allow_tags,
    };
    Ok((guard, repos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use luoto_shared::policy::{Decision, DenyReason, RequestInfo};

    const GATE: Option<Ipv4Addr> = Some(Ipv4Addr::new(10, 0, 0, 2));

    fn cfg(text: &str) -> EnvConfig {
        toml::from_str(text).unwrap()
    }

    /// The folder's remote `git@azure-invinite:v3/invinite/AppServices/pseudo-registry`.
    fn alias() -> [(String, String); 1] {
        [("invinite".into(), "azure-invinite".into())]
    }

    fn decide(p: &Policy, host: &str, method: &str, path: &str) -> Decision {
        p.decide(
            &RequestInfo {
                host,
                port: 443,
                method,
                path,
                websocket: false,
                content_length: Some(10),
            },
            Utc::now(),
        )
    }

    #[test]
    fn azure_devops_scopes_git_to_its_repos_in_any_case() {
        let text = r#"
[credentials.azure_devops]
token = "op://v/ado/pat"
repos = [
  "invinite/AppServices/pseudo-registry",
  "invinite/Data Platform/dbt-core",
  "https://other@dev.azure.com/other/Web/_git/site",
]
"#;
        let c = compile("t", &cfg(text), GATE, &alias()).unwrap();
        let p = &c.policy;
        for (method, path) in [
            (
                "POST",
                "/invinite/AppServices/_git/pseudo-registry/git-receive-pack",
            ),
            (
                "GET",
                "/Invinite/appservices/_git/Pseudo-Registry/info/refs",
            ),
            (
                "POST",
                "/invinite/Data%20Platform/_git/dbt-core/git-upload-pack",
            ),
            ("POST", "/other/Web/_git/site/git-receive-pack"),
        ] {
            assert!(
                matches!(
                    decide(p, "dev.azure.com", method, path),
                    Decision::Allow { .. }
                ),
                "{method} {path}"
            );
        }
        for path in [
            "/invinite/AppServices/_git/other/git-receive-pack",
            "/invinite/Web/_git/site/git-receive-pack",
            "/invinite/_apis/git/repositories",
        ] {
            assert!(
                !matches!(
                    decide(p, "dev.azure.com", "POST", path),
                    Decision::Allow { .. }
                ),
                "{path}"
            );
        }
        let inj = p.injections_for(
            "dev.azure.com",
            "/INVINITE/AppServices/_git/pseudo-registry/info/refs",
        );
        assert_eq!(inj.len(), 1);
        assert_eq!(inj[0].binding, "azure_devops");
        assert_eq!(
            inj[0].place,
            Placement::Basic {
                username: String::new()
            }
        );
        assert_eq!(
            p.injections_for("dev.azure.com", "/other/Web/_git/site/info/refs")
                .len(),
            1,
            "another organization's repo, with the same PAT"
        );
        assert!(c.vault_refs().contains("op://v/ado/pat"));
        let guard = p.azure_devops.as_ref().unwrap();
        assert!(
            guard
                .repos
                .contains(&"invinite/data%20platform/dbt-core".to_string())
        );
        assert_eq!(guard.protected_branches, ["main", "master"]);
        let section = c
            .git_config
            .split("[url ")
            .find(|s| s.starts_with("\"https://dev.azure.com/invinite/AppServices/_git/\""))
            .unwrap_or_default();
        assert!(
            section.contains("\tinsteadOf = \"git@azure-invinite:v3/invinite/AppServices/\"\n"),
            "the folder's SSH alias goes to HTTPS:\n{}",
            c.git_config
        );
        assert!(c.git_config.contains("\tinsteadOf = \"git@github.com:\"\n"));
        assert!(
            compile(
                "t",
                &cfg("[credentials.azure_devops]\ntoken = \"op://v/p\"\n"),
                GATE,
                &[]
            )
            .is_err(),
            "repos are required"
        );
    }

    #[test]
    fn an_ssh_key_logs_in_to_its_hosts_and_their_remotes_stay_ssh() {
        let text = r#"
[credentials.ssh]
key = "op://v/ssh/private key?ssh-format=openssh"
hosts = ["github.com", "ssh.dev.azure.com", "git.example.com"]
host_keys = ["git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x"]
"#;
        let c = compile("t", &cfg(text), GATE, &alias()).unwrap();
        let p = &c.policy;
        assert_eq!(
            p.tunnel_rule("github.com", 22, Utc::now())
                .map(|r| r.id.as_str()),
            Some("ssh-github.com")
        );
        assert!(p.tunnel_rule("github.com", 443, Utc::now()).is_none());
        assert!(p.tunnel_rule("gitlab.com", 22, Utc::now()).is_none());
        let BindingSpec::SshAgent { key_ref, host_keys } = &c.bindings["ssh"] else {
            panic!("ssh binding")
        };
        assert_eq!(key_ref, "op://v/ssh/private key?ssh-format=openssh");
        assert_eq!(
            host_keys.len(),
            5,
            "three GitHub keys, Azure DevOps' and the extra one"
        );
        assert!(c.known_hosts.contains("ssh.dev.azure.com ssh-rsa AAAA"));
        assert!(
            c.known_hosts
                .lines()
                .any(|l| l.starts_with("git.example.com ssh-ed25519 ") && !l.ends_with(" x"))
        );
        assert!(
            !c.git_config.contains("git@github.com:"),
            "GitHub remotes stay SSH"
        );
        assert!(c.git_config.contains(
            "[url \"git@ssh.dev.azure.com:v3/invinite/\"]\n\tinsteadOf = \"invinite@vs-ssh.visualstudio.com:v3/invinite/\"\n"
        ));
        assert!(
            c.git_config
                .contains("\tinsteadOf = \"git@azure-invinite:v3/invinite/\"\n")
        );
        for bad in [
            "[credentials.ssh]\nkey = \"op://k\"\nhosts = []\n",
            "[credentials.ssh]\nkey = \"op://k\"\nhosts = [\"gitlab.com\"]\n",
            "[credentials.ssh]\nkey = \"op://k\"\nhosts = [\"github.com\"]\nhost_keys = [\"other.example ssh-ed25519 AAAA\"]\n",
        ] {
            assert!(compile("t", &cfg(bad), GATE, &[]).is_err(), "{bad}");
        }
    }

    #[test]
    fn github_app_scopes_writes_to_granted_repos() {
        let c = compile(
            "t",
            &cfg(r#"
presets = ["github"]
[credentials.github]
app_id = "1"
installation_id = 2
private_key = "op://v/app/key"
repos = ["Eetu/Foo"]
"#),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        assert!(matches!(
            decide(p, "github.com", "POST", "/eetu/foo.git/git-receive-pack"),
            Decision::Allow { .. }
        ));
        assert!(
            matches!(
                decide(p, "github.com", "POST", "/Eetu/Foo.git/git-receive-pack"),
                Decision::Allow { .. }
            ),
            "a remote in the case it was cloned with"
        );
        assert_eq!(
            p.injections_for("github.com", "/Eetu/Foo.git/info/refs")
                .len(),
            1
        );
        assert!(!matches!(
            decide(p, "github.com", "POST", "/other/repo.git/git-receive-pack"),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            decide(p, "api.github.com", "POST", "/repos/eetu/foo/pulls"),
            Decision::Allow { .. }
        ));
        assert!(!matches!(
            decide(p, "api.github.com", "POST", "/repos/other/repo/pulls"),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            decide(
                p,
                "api.github.com",
                "POST",
                "/repos/eetu/foo/actions/workflows/x/dispatches"
            ),
            Decision::Deny(DenyReason::Explicit { .. })
        ));
        for (method, path) in [
            ("PATCH", "/repos/eetu/foo/pulls/7"),
            ("POST", "/repos/eetu/foo/pulls/7/reviews"),
            ("POST", "/repos/eetu/foo/issues/3/comments"),
            ("POST", "/graphql"),
        ] {
            assert!(
                matches!(
                    decide(p, "api.github.com", method, path),
                    Decision::Allow { .. }
                ),
                "{method} {path} should be allowed"
            );
        }
        // REST routes around the push guard stay closed.
        for (method, path) in [
            ("PUT", "/repos/eetu/foo/contents/src/main.rs"),
            ("PATCH", "/repos/eetu/foo/git/refs/heads/main"),
            ("POST", "/repos/eetu/foo/git/refs"),
            ("DELETE", "/repos/eetu/foo/git/refs/heads/feature"),
            ("PUT", "/repos/eetu/foo/pulls/7/merge"),
            ("POST", "/repos/eetu/foo/merges"),
            ("PATCH", "/repos/eetu/foo"),
            ("DELETE", "/repos/eetu/foo/issues/comments/1"),
        ] {
            assert!(
                !matches!(
                    decide(p, "api.github.com", method, path),
                    Decision::Allow { .. }
                ),
                "{method} {path} must not be allowed"
            );
        }
        assert_eq!(
            p.injections_for("github.com", "/eetu/foo.git/info/refs")
                .len(),
            1
        );
        assert!(
            p.injections_for("github.com", "/other/repo.git/info/refs")
                .is_empty()
        );
        assert!(c.vault_refs().contains("op://v/app/key"));
        assert!(c.dev_env["GH_TOKEN"].starts_with("ghs_"));
    }

    #[test]
    fn refuses_dangerous_github_permissions() {
        let err = compile(
            "t",
            &cfg(r#"
[credentials.github]
token = "op://v/pat/token"
repos = ["a/b"]
permissions = { workflows = "write" }
"#),
            GATE,
            &[],
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("workflows"));
    }

    #[test]
    fn provider_injection_and_denies() {
        let c = compile(
            "t",
            &cfg(r#"
agents = ["claude"]
[credentials.anthropic]
oauth_token = "op://p/claude/token"
"#),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        assert!(matches!(
            decide(p, "api.anthropic.com", "POST", "/v1/messages"),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            decide(p, "api.anthropic.com", "POST", "/v1/files"),
            Decision::Deny(DenyReason::Explicit { .. })
        ));
        assert!(p.is_credentialed_host("api.anthropic.com"));
        assert_eq!(c.dev_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1");
        assert!(c.dev_env.contains_key("CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(c.bindings.contains_key("anthropic.oauth_token"));
        let fetch = r#"{"tools":[{"type":"web_fetch_20260209"}]}"#;
        let json = luoto_shared::policy::JsonBody::parse(fetch.as_bytes()).unwrap();
        assert!(
            p.body_denies
                .iter()
                .any(|d| d.applies("api.anthropic.com", "/v1/messages") && d.asks(&json))
        );
    }

    #[test]
    fn server_tools_and_the_websocket_api_wait_for_the_opt_in() {
        let openai = |extra: &str| {
            let text = format!("[credentials.openai]\napi_key = \"op://p/oai/key\"\n{extra}");
            compile("t", &cfg(&text), GATE, &[]).unwrap()
        };
        let ws = |c: &Compiled| c.policy.rules.iter().any(|r| r.rule.ws);
        let off = openai("");
        assert!(!off.policy.body_denies.is_empty() && !ws(&off));
        let on = openai("server_tools = true");
        assert!(on.policy.body_denies.is_empty() && ws(&on));
        assert!(on.warnings.iter().any(|w| w.contains("server_tools")));
        let err = compile(
            "t",
            &cfg("[credentials.openai]\nservertools = true"),
            GATE,
            &[],
        );
        assert!(err.err().unwrap().to_string().contains("not a setting"));
    }

    #[test]
    fn a_provider_credential_goes_to_each_of_its_hosts_and_paths() {
        let c = compile(
            "t",
            &cfg(r#"
agents = ["copilot"]
[credentials.copilot]
token = "op://p/copilot/token"
[credentials.github]
token = "op://p/gh/token"
repos = ["o/r"]
"#),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        let copilot = |host, path| {
            p.injections_for(host, path)
                .iter()
                .any(|i| i.binding == "copilot.token")
        };
        assert!(copilot("api.githubcopilot.com", "/chat/completions"));
        assert!(copilot(
            "api.business.githubcopilot.com",
            "/chat/completions"
        ));
        assert!(copilot("api.github.com", "/copilot_internal/user"));
        assert!(
            !copilot("api.github.com", "/repos/o/r"),
            "the GitHub credential's paths"
        );
        assert!(matches!(
            decide(
                p,
                "api.individual.githubcopilot.com",
                "POST",
                "/chat/completions"
            ),
            Decision::Allow { .. }
        ));
        assert!(c.dev_env.contains_key("COPILOT_GITHUB_TOKEN"));
        assert_eq!(c.dev_env["COPILOT_AUTO_UPDATE"], "false");
    }

    #[test]
    fn a_written_tunnel_cannot_cover_a_credentialed_host() {
        let c = cfg(r#"
[credentials.anthropic]
api_key = "env:K"

[[allow]]
host = "api.anthropic.com"
mode = "tunnel"
"#);
        let err = compile("t", &c, GATE, &[]).err().expect("refused");
        assert!(err.to_string().contains("tunnel"), "{err}");
        // A tunnel to a host the gate enforces nothing on stays possible.
        let ok = cfg("[[allow]]\nhost = \"grpc.example.com\"\nmode = \"tunnel\"");
        assert!(compile("t", &ok, GATE, &[]).is_ok());
    }

    #[test]
    fn a_custom_credential_goes_to_one_exact_host() {
        for host in ["*.github.io", "*", "10.0.0.0/8"] {
            let c = cfg(&format!(
                "[credentials.custom.x]\nhost = \"{host}\"\nheader = \"authorization\"\nsecret = \"env:X\""
            ));
            assert!(compile("t", &c, GATE, &[]).is_err(), "{host}");
        }
    }

    #[test]
    fn copilot_reads_but_never_writes_the_github_user() {
        let c = compile(
            "t",
            &cfg("agents = [\"copilot\"]\n[credentials.copilot]\ntoken = \"env:T\""),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        assert!(matches!(
            decide(p, "api.github.com", "GET", "/user"),
            Decision::Allow { .. }
        ));
        assert!(!matches!(
            decide(p, "api.github.com", "PATCH", "/user"),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn a_login_inside_excludes_a_credential_of_the_same_provider() {
        let both = cfg(r#"
agents = ["opencode"]
[credentials.gemini]
api_key = "op://p/gemini/key"
login_inside = true
"#);
        let err = compile("t", &both, GATE, &[]).err().expect("refused");
        assert!(err.to_string().contains("keep one"), "{err}");
    }

    #[test]
    fn user_rules_are_validated() {
        let bad = cfg("[[allow]]\nhost = \"*.github.io\"\n");
        assert!(compile("t", &bad, GATE, &[]).is_err());
    }
}
