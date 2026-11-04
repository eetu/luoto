//! Env config → what the gate enforces (policy), what the vault serves (bindings), which
//! secret refs must be resolved, and the placeholder environment for the sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use luoto_shared::creds::{
    BindingSpec, FORBIDDEN_GITHUB_PERMISSIONS, Injection, Placement, default_github_api,
};
use luoto_shared::policy::{
    Access, AccessLevel, AzureGuard, CompiledRule, DenyRule, GithubGuard, InternalName, Mode,
    Policy, Rule, RuleOrigin, Severity, validate_rule,
};
use luoto_shared::{presets, profiles};

use crate::azure;
use crate::config::{AzureDevopsCred, EnvConfig, GithubCred, ProviderValue, SshCred};

pub struct Compiled {
    pub policy: Policy,
    pub bindings: BTreeMap<String, BindingSpec>,
    /// Refs the vault needs (bindings) — resolved at unlock.
    pub vault_refs: BTreeSet<String>,
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

const GH_PLACEHOLDER: &str = "ghs_luotoPlaceholder0000000000000000000";

struct Builder {
    rules: Vec<CompiledRule>,
    denies: Vec<DenyRule>,
    injections: Vec<Injection>,
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

pub fn compile(env: &str, cfg: &EnvConfig, gate_ip: Ipv4Addr) -> Result<Compiled> {
    let mut b = Builder {
        rules: Vec::new(),
        denies: Vec::new(),
        injections: Vec::new(),
    };
    let mut bindings = BTreeMap::new();
    let mut vault_refs = BTreeSet::new();
    let mut dev_env = BTreeMap::new();
    let mut warnings = Vec::new();

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
        dev_env.extend(a.env.clone());
    }

    // Model providers: `[credentials.<provider>] <auth_kind> = "<ref>"` or `login_inside = "true"`.
    for (pname, entries) in &cfg.credentials.providers {
        let Some(p) = profiles::provider(pname) else {
            bail!(
                "unknown credential section `{pname}` (providers: {}; or use [credentials.custom.<name>])",
                profiles::provider_names().collect::<Vec<_>>().join(", ")
            );
        };
        let login_inside = entries.get("login_inside") == Some(&ProviderValue::Flag(true));
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
                    ws: p.ws,
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
            warnings.push(format!(
                "{pname}: login_inside keeps the {pname} credential inside the sandbox (reduced assurance)"
            ));
            continue;
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
            bindings.insert(
                binding.clone(),
                BindingSpec::Static {
                    secret_ref: secret_ref.clone(),
                },
            );
            vault_refs.insert(secret_ref.clone());
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
            dev_env.extend(auth.env.clone());
            configured += 1;
        }
        if configured > 1 {
            bail!("credentials.{pname}: configure one credential kind, not {configured}");
        }
    }

    for (cname, c) in &cfg.credentials.custom {
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
        bindings.insert(
            binding.clone(),
            BindingSpec::Static {
                secret_ref: c.secret.clone(),
            },
        );
        vault_refs.insert(c.secret.clone());
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
        dev_env.extend(c.placeholder_env.clone());
    }

    let github = match &cfg.credentials.github {
        Some(gh) => Some(compile_github(
            gh,
            &mut b,
            &mut bindings,
            &mut vault_refs,
            &mut dev_env,
        )?),
        None => None,
    };

    let (ssh_hosts, known_hosts) = compile_ssh(
        cfg.credentials.ssh.as_ref(),
        &mut b,
        &mut bindings,
        &mut vault_refs,
    )?;
    let over_ssh = |h: &str| ssh_hosts.iter().any(|s| s == h);
    // Only HTTP(S) leaves the env, so SSH remotes go to HTTPS unless the vault's key logs in
    // to their host.
    let mut rewrites = Vec::new();
    if !over_ssh("github.com") {
        for from in ["git@github.com:", "ssh://git@github.com/"] {
            rewrites.push(("https://github.com/".to_string(), from.to_string()));
        }
    }
    let aliases = azure::aliases(&cfg.workspace);
    let azure_ssh = over_ssh(azure::SSH_HOST);
    let azure_devops = compile_azure(
        cfg.credentials.azure_devops.as_ref(),
        &aliases,
        azure_ssh,
        &mut b,
        &mut bindings,
        &mut vault_refs,
        &mut dev_env,
        &mut rewrites,
    )?;
    if azure_ssh {
        let mut orgs: Vec<String> = aliases.iter().map(|(o, _)| o.clone()).collect();
        if let Some(c) = &cfg.credentials.azure_devops {
            orgs.extend(
                c.repos
                    .iter()
                    .filter_map(|r| azure::parse_repo(r).ok())
                    .map(|r| r.org),
            );
        }
        orgs.sort_by_key(|o| o.to_ascii_lowercase());
        orgs.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        for org in &orgs {
            rewrites.extend(azure::ssh_to_ssh(org, &aliases));
        }
    }

    for (i, r) in cfg.allow.iter().enumerate() {
        if let Some(e) = validate_rule(r, RuleOrigin::Host)
            .into_iter()
            .find(|i| i.severity == Severity::Error)
        {
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

    let mut sandbox_refs = BTreeMap::new();
    for (k, v) in &cfg.sandbox_secrets {
        sandbox_refs.insert(k.clone(), v.clone());
    }
    for (k, v) in &cfg.env {
        dev_env.insert(k.clone(), v.clone());
    }

    let policy = Policy {
        env: env.to_string(),
        generated_at: Some(Utc::now()),
        rules: b.rules,
        denies: b.denies,
        injections: b.injections,
        github,
        azure_devops,
        internal_names: vec![InternalName {
            name: luoto_shared::GATE_HOST.into(),
            ip: gate_ip,
        }],
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
        bindings,
        vault_refs,
        sandbox_refs,
        dev_env,
        git_config: git_config(&rewrites),
        known_hosts,
        warnings,
    })
}

/// `url.<base>.insteadOf` pairs as a git config file, grouped by base.
fn git_config(pairs: &[(String, String)]) -> String {
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::from("# Written by luoto at `up`: where this env's git remotes go.\n");
    let mut bases: Vec<&str> = Vec::new();
    for (base, _) in pairs {
        if !bases.contains(&base.as_str()) {
            bases.push(base);
        }
    }
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
fn compile_ssh(
    c: Option<&SshCred>,
    b: &mut Builder,
    bindings: &mut BTreeMap<String, BindingSpec>,
    vault_refs: &mut BTreeSet<String>,
) -> Result<(Vec<String>, String)> {
    let Some(c) = c else {
        return Ok((Vec::new(), String::new()));
    };
    if c.hosts.is_empty() {
        bail!("credentials.ssh: list the hosts the key logs in to (`hosts = [\"github.com\"]`)");
    }
    let mut hosts = Vec::new();
    for h in &c.hosts {
        let host = luoto_shared::host::normalize_host(h)
            .map_err(|e| anyhow::anyhow!("credentials.ssh: host `{h}`: {e}"))?;
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
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
    bindings.insert(
        "ssh".into(),
        BindingSpec::SshAgent {
            key_ref: c.key.clone(),
            host_keys: lines.clone(),
        },
    );
    vault_refs.insert(c.key.clone());
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

fn compile_github(
    gh: &GithubCred,
    b: &mut Builder,
    bindings: &mut BTreeMap<String, BindingSpec>,
    vault_refs: &mut BTreeSet<String>,
    dev_env: &mut BTreeMap<String, String>,
) -> Result<GithubGuard> {
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
            vault_refs.insert(key.clone());
            BindingSpec::GithubApp {
                app_id: app_id.clone(),
                installation_id,
                key_ref: key.clone(),
                repos: repos.iter().map(|(_, r)| r.clone()).collect(),
                permissions,
                api_base: gh.api_base.clone().unwrap_or_else(default_github_api),
            }
        }
        (None, None, Some(token)) => {
            vault_refs.insert(token.clone());
            BindingSpec::Static {
                secret_ref: token.clone(),
            }
        }
        _ => {
            bail!("credentials.github: set either app_id + installation_id + private_key, or token")
        }
    };
    bindings.insert("github".into(), spec);

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
        host: "github.com".into(),
        paths: git_paths.clone(),
        place: Placement::Basic {
            username: "x-access-token".into(),
        },
        ignore_case: true,
    });
    b.injections.push(Injection {
        binding: "github".into(),
        host: "api.github.com".into(),
        paths: api_paths.clone(),
        place: Placement::Header {
            name: "authorization".into(),
            format: "Bearer {secret}".into(),
        },
        ignore_case: true,
    });

    if !b.has_read("github.com") {
        b.rule("github-read".into(), "github", Rule::read("github.com"));
    }
    if !b.has_read("api.github.com") {
        b.rule(
            "github-api-read".into(),
            "github",
            Rule::read("api.github.com"),
        );
    }
    b.rule(
        "github-git".into(),
        "github",
        Rule {
            host: "github.com".into(),
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
            host: "api.github.com".into(),
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
            host: "api.github.com".into(),
            paths: paths.into_iter().map(str::to_string).collect(),
            methods: write.clone(),
            reason: reason.into(),
        });
    }
    dev_env.insert("GH_TOKEN".into(), GH_PLACEHOLDER.into());
    dev_env.insert("GITHUB_TOKEN".into(), GH_PLACEHOLDER.into());
    dev_env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());

    Ok(GithubGuard {
        repos: repos.iter().map(|(o, r)| format!("{o}/{r}")).collect(),
        protected_branches: gh.protected_branches.clone(),
        graphql_mutations: gh.graphql_mutations.clone(),
        allow_tags: gh.allow_tags,
        allow_branch_delete: false,
    })
}

/// Azure DevOps: the PAT added as basic auth on the repos' git paths, those paths allowed
/// (case-insensitively, as Azure DevOps reads them), the push guard, and the rewrites that send
/// each organization's legacy URLs, and unless the vault's key logs in over SSH (`over_ssh`)
/// its SSH remotes, `aliases` among them, to HTTPS.
#[allow(clippy::too_many_arguments)]
fn compile_azure(
    c: Option<&AzureDevopsCred>,
    aliases: &[(String, String)],
    over_ssh: bool,
    b: &mut Builder,
    bindings: &mut BTreeMap<String, BindingSpec>,
    vault_refs: &mut BTreeSet<String>,
    dev_env: &mut BTreeMap<String, String>,
    rewrites: &mut Vec<(String, String)>,
) -> Result<Option<AzureGuard>> {
    let Some(c) = c else {
        return Ok(None);
    };
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
    bindings.insert(
        "azure_devops".into(),
        BindingSpec::Static {
            secret_ref: c.token.clone(),
        },
    );
    vault_refs.insert(c.token.clone());
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
    // Organizations as their repos write them, each with its projects.
    let mut orgs: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for r in &repos {
        let (_, projects) = orgs
            .entry(r.org.to_ascii_lowercase())
            .or_insert_with(|| (r.org.clone(), Vec::new()));
        if !projects.contains(&r.project) {
            projects.push(r.project.clone());
        }
    }
    for (org, projects) in orgs.values() {
        rewrites.extend(azure::https_rewrites(org));
        if !over_ssh {
            rewrites.extend(azure::ssh_to_https(org, projects, aliases));
        }
    }
    dev_env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    Ok(Some(AzureGuard {
        repos: repos.iter().map(azure::Repo::key).collect(),
        protected_branches: c.protected_branches.clone(),
        allow_tags: c.allow_tags,
        allow_branch_delete: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use luoto_shared::policy::{Decision, DenyReason, RequestInfo};

    fn cfg(text: &str) -> EnvConfig {
        toml::from_str(text).unwrap()
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
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "[remote \"origin\"]\n\turl = git@azure-invinite:v3/invinite/AppServices/pseudo-registry\n",
        )
        .unwrap();
        let text = format!(
            r#"
[workspace]
dir = '{}'
[credentials.azure_devops]
token = "op://v/ado/pat"
repos = [
  "invinite/AppServices/pseudo-registry",
  "invinite/Data Platform/dbt-core",
  "https://other@dev.azure.com/other/Web/_git/site",
]
"#,
            dir.path().display()
        );
        let c = compile("t", &cfg(&text), Ipv4Addr::new(10, 0, 0, 2)).unwrap();
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
        assert!(c.vault_refs.contains("op://v/ado/pat"));
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
                Ipv4Addr::new(10, 0, 0, 2)
            )
            .is_err(),
            "repos are required"
        );
    }

    #[test]
    fn an_ssh_key_logs_in_to_its_hosts_and_their_remotes_stay_ssh() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "[remote \"origin\"]\n\turl = git@azure-invinite:v3/invinite/AppServices/pseudo-registry\n",
        )
        .unwrap();
        let text = format!(
            r#"
[workspace]
dir = '{}'
[credentials.ssh]
key = "op://v/ssh/private key?ssh-format=openssh"
hosts = ["github.com", "ssh.dev.azure.com", "git.example.com"]
host_keys = ["git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x"]
"#,
            dir.path().display()
        );
        let c = compile("t", &cfg(&text), Ipv4Addr::new(10, 0, 0, 2)).unwrap();
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
            assert!(
                compile("t", &cfg(bad), Ipv4Addr::new(10, 0, 0, 2)).is_err(),
                "{bad}"
            );
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
            Ipv4Addr::new(10, 0, 0, 2),
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
        assert!(c.vault_refs.contains("op://v/app/key"));
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
            Ipv4Addr::new(10, 0, 0, 2),
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
            Ipv4Addr::new(10, 0, 0, 2),
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
            Ipv4Addr::new(10, 0, 0, 2),
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
        let err = compile("t", &c, Ipv4Addr::new(10, 0, 0, 2))
            .err()
            .expect("refused");
        assert!(err.to_string().contains("tunnel"), "{err}");
        // A tunnel to a host the gate enforces nothing on stays possible.
        let ok = cfg("[[allow]]\nhost = \"grpc.example.com\"\nmode = \"tunnel\"");
        assert!(compile("t", &ok, Ipv4Addr::new(10, 0, 0, 2)).is_ok());
    }

    #[test]
    fn a_custom_credential_goes_to_one_exact_host() {
        for host in ["*.github.io", "*", "10.0.0.0/8"] {
            let c = cfg(&format!(
                "[credentials.custom.x]\nhost = \"{host}\"\nheader = \"authorization\"\nsecret = \"env:X\""
            ));
            assert!(
                compile("t", &c, Ipv4Addr::new(10, 0, 0, 2)).is_err(),
                "{host}"
            );
        }
    }

    #[test]
    fn copilot_reads_but_never_writes_the_github_user() {
        let c = compile(
            "t",
            &cfg("agents = [\"copilot\"]\n[credentials.copilot]\ntoken = \"env:T\""),
            Ipv4Addr::new(10, 0, 0, 2),
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
        let err = compile("t", &both, Ipv4Addr::new(10, 0, 0, 2))
            .err()
            .expect("refused");
        assert!(err.to_string().contains("keep one"), "{err}");
    }

    #[test]
    fn user_rules_are_validated() {
        let bad = cfg("[[allow]]\nhost = \"*.github.io\"\n");
        assert!(compile("t", &bad, Ipv4Addr::new(10, 0, 0, 2)).is_err());
    }
}
