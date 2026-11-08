//! Env config → what the gate enforces (policy), what the vault serves (bindings), which
//! secret refs must be resolved, and the placeholder environment for the sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use luoto_shared::creds::{
    BindingSpec, FORBIDDEN_GITHUB_PERMISSIONS, Injection, Placement, SSH_BINDING,
    default_github_api,
};
use luoto_shared::policy::{
    Access, AccessLevel, AzureGuard, BodyDeny, CompiledRule, DenyRule, GitGuard, GithubGuard,
    InternalName, Mode, Policy, Rule, RuleOrigin, rule_error,
};
use luoto_shared::{forges, presets, profiles};

use crate::azure;
use crate::config::{
    AzureDevopsCred, CustomCred, EnvConfig, GitCred, GithubCred, ProviderValue, SshCred,
    extend_unique,
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
    /// CA certificates (PEM) the gate trusts upstream besides the public roots, each for its
    /// own host only: those of self-hosted git hosts.
    pub upstream_cas: BTreeMap<String, String>,
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
    crate::repos::check(&cfg.workspace)?;

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
        b.dev_env.extend(p.env);
    }

    for (name, opts) in &cfg.agents.0 {
        let Some(a) = profiles::agent(name) else {
            bail!(
                "unknown agent `{name}` (known: {})",
                profiles::agent_names().collect::<Vec<_>>().join(", ")
            );
        };
        check_agent_opts(&a, name, opts)?;
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
    let github = compile_github(&mut b, &cfg.credentials.github.0)?;

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
    let (git, upstream_cas) = compile_git(&mut b, &cfg.credentials.git)?;
    for c in &cfg.credentials.git {
        let host = c.host.split(':').next().unwrap_or_default();
        if !over_ssh(host) {
            for from in [format!("git@{host}:"), format!("ssh://git@{host}/")] {
                b.rewrites.push((format!("https://{}/", c.host), from));
            }
        }
    }

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
    for d in &cfg.deny {
        let rule = d
            .rule()
            .map_err(|e| anyhow!("deny for `{}`: {e}", crate::text::display(&d.host)))?;
        b.denies.push(rule);
    }
    // Mutes only filter what egress views show; checked here so a bad one is reported.
    for m in &cfg.mute {
        if let Err(e) = m.checked() {
            bail!("mute for `{}`: {e}", crate::text::display(&m.host));
        }
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
        git,
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
        upstream_cas,
        warnings: b.warnings,
    })
}

/// An agent's options are ones its profile takes, with values it accepts.
pub fn check_agent_opts(
    a: &profiles::Agent,
    name: &str,
    opts: &crate::config::AgentOpts,
) -> Result<()> {
    for (key, value) in opts.values() {
        let Some(s) = a.settings.get(key) else {
            let takes: Vec<&str> = a.settings.keys().map(String::as_str).collect();
            bail!(
                "agents.{name}: {} has no `{key}` option{}",
                a.description,
                if takes.is_empty() {
                    String::new()
                } else {
                    format!(" (it takes {})", takes.join(", "))
                }
            );
        };
        let plain = !value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-:/@[]".contains(&b));
        if !plain || (!s.values.is_empty() && !s.values.iter().any(|v| v == value)) {
            bail!(
                "agents.{name}.{key}: `{}` is not {}",
                crate::text::display(value),
                if s.values.is_empty() {
                    "a name".to_string()
                } else {
                    format!("one of {}", s.values.join(", "))
                }
            );
        }
    }
    Ok(())
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
                ..Default::default()
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

/// Git paths of `owner/repo` on github.com, both URL forms; `write` adds pushes.
fn github_git_paths(o: &str, r: &str, write: bool) -> Vec<String> {
    [format!("/{o}/{r}"), format!("/{o}/{r}.git")]
        .iter()
        .flat_map(|base| smart_http_paths(base, write))
        .collect()
}

/// A repository's smart-HTTP paths under `base` (`/owner/repo`, `/owner/repo.git`): fetches,
/// pushes when `write`, and of Git LFS the batch API, object downloads from the same host and
/// the lock check a push makes. Exact paths, no `**`: a server that normalises a path its own
/// way (`..;` on Java servers) can't be led from them to a push.
pub fn smart_http_paths(base: &str, write: bool) -> Vec<String> {
    let mut out = vec![
        format!("{base}/info/refs"),
        format!("{base}/git-upload-pack"),
        format!("{base}/info/lfs/objects/batch"),
        format!("{base}/info/lfs/objects/*"),
    ];
    if write {
        out.push(format!("{base}/git-receive-pack"));
        out.push(format!("{base}/info/lfs/locks/verify"));
    }
    out
}

/// Every `[[credentials.github]]` (one per account, as an org's token reaches only that org).
/// Each repo's git and REST paths get the credential that lists it; `/graphql`, which names no
/// repo, gets the first one that may write. One push guard covers them all, as strict as the
/// strictest.
fn compile_github(b: &mut Builder, creds: &[GithubCred]) -> Result<Option<GithubGuard>> {
    if creds.is_empty() {
        return Ok(None);
    }
    // GraphQL names no repo in its path, so it goes out with one credential: the first that
    // may write, else the first; a read-only one mutates nothing.
    let graphql = creds.iter().position(|c| !c.repos.is_empty()).unwrap_or(0);
    let mut guard = GithubGuard {
        graphql_mutations: if creds[graphql].repos.is_empty() {
            Vec::new()
        } else {
            creds[graphql].graphql_mutations.clone()
        },
        allow_tags: creds.iter().all(|c| c.allow_tags),
        ..Default::default()
    };
    let mut tokens: BTreeSet<&str> = BTreeSet::new();
    for t in creds.iter().filter_map(|c| c.token.as_deref()) {
        if !tokens.insert(t) {
            b.warnings.push(format!(
                "credentials.github: two credentials use {t}; one listing all their repos lets \
                 GraphQL (`gh pr create`) reach every one of them"
            ));
        }
    }
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    for (i, gh) in creds.iter().enumerate() {
        let name = if i == 0 {
            "github".to_string()
        } else {
            format!("github-{}", i + 1)
        };
        let write = compile_github_one(b, gh, &name, i == graphql)?;
        for (o, r) in gh
            .repos
            .iter()
            .chain(&gh.read_repos)
            .map(|r| split_repo(r))
            .collect::<Result<Vec<_>>>()?
        {
            if !seen.insert((o.clone(), r.clone())) {
                bail!("credentials.github: {o}/{r} is listed twice");
            }
        }
        guard.repos.extend(write);
        extend_unique(
            &mut guard.protected_branches,
            gh.protected_branches.iter().cloned(),
        );
    }
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
    Ok(Some(guard))
}

/// One GitHub credential as binding `name`: its `repos` read and written (pushes, pull
/// requests, issues), its `read_repos` fetched and read only. An App mints a separate
/// read-only token for those, so not even GraphQL can write there. Returns the written
/// repos, `owner/repo` lowercase.
fn compile_github_one(
    b: &mut Builder,
    gh: &GithubCred,
    name: &str,
    graphql: bool,
) -> Result<Vec<String>> {
    if gh.repos.is_empty() && gh.read_repos.is_empty() {
        bail!(
            "credentials.github: list the repos the env may write to (`repos = [\"owner/repo\"]`) \
             or only read (`read_repos`)"
        );
    }
    for p in gh.permissions.keys() {
        if FORBIDDEN_GITHUB_PERMISSIONS.contains(&p.as_str()) {
            bail!(
                "credentials.github: permission `{p}` is refused — it would let the sandbox reach CI secrets or account settings"
            );
        }
    }
    let parse = |list: &[String]| -> Result<Vec<(String, String)>> {
        list.iter().map(|r| split_repo(r)).collect()
    };
    let (repos, read_repos) = (parse(&gh.repos)?, parse(&gh.read_repos)?);
    let read_name = if repos.is_empty() {
        name.to_string()
    } else {
        format!("{name}-read")
    };
    match (&gh.app_id, &gh.private_key, &gh.token) {
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
            let app = |repos: &[(String, String)], permissions| BindingSpec::GithubApp {
                app_id: app_id.clone(),
                installation_id,
                key_ref: key.clone(),
                repos: repos.iter().map(|(_, r)| r.clone()).collect(),
                permissions,
                api_base: gh.api_base.clone().unwrap_or_else(default_github_api),
            };
            if !repos.is_empty() {
                b.bindings
                    .insert(name.into(), app(&repos, permissions.clone()));
            }
            if !read_repos.is_empty() {
                let read = permissions
                    .keys()
                    .map(|k| (k.clone(), "read".to_string()))
                    .collect();
                b.bindings.insert(read_name.clone(), app(&read_repos, read));
            }
        }
        (None, None, Some(token)) => {
            // One token: its scope at GitHub decides what GraphQL can write; the gate keeps
            // git and REST writes to `repos`.
            b.bindings.insert(
                name.into(),
                BindingSpec::Static {
                    secret_ref: token.clone(),
                },
            );
        }
        _ => {
            bail!("credentials.github: set either app_id + installation_id + private_key, or token")
        }
    }
    let read_binding = if gh.token.is_some() {
        name.to_string()
    } else {
        read_name
    };
    let mut git_paths = Vec::new();
    for (list, binding, write) in [
        (&repos, name.to_string(), true),
        (&read_repos, read_binding, false),
    ] {
        if list.is_empty() {
            continue;
        }
        let paths: Vec<String> = list
            .iter()
            .flat_map(|(o, r)| github_git_paths(o, r, write))
            .collect();
        let mut api_paths: Vec<String> = list
            .iter()
            .flat_map(|(o, r)| [format!("/repos/{o}/{r}"), format!("/repos/{o}/{r}/**")])
            .collect();
        if graphql && (write || repos.is_empty()) {
            api_paths.insert(0, "/graphql".to_string());
        }
        // GitHub reads owner and repo in any case, and a remote keeps the case it was cloned
        // with.
        b.injections.push(Injection {
            binding: binding.clone(),
            host: forges::GITHUB.into(),
            paths: paths.clone(),
            place: Placement::Basic {
                username: "x-access-token".into(),
            },
            ignore_case: true,
        });
        b.injections.push(Injection {
            binding,
            host: forges::GITHUB_API.into(),
            paths: api_paths,
            place: Placement::Header {
                name: "authorization".into(),
                format: "Bearer {secret}".into(),
            },
            ignore_case: true,
        });
        git_paths.extend(paths);
    }
    b.rule(
        format!("{name}-git"),
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
    // GraphQL reads are POSTs too; the guard decides which mutations pass.
    let mut write_paths = if graphql {
        vec!["/graphql".to_string()]
    } else {
        Vec::new()
    };
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
    if !write_paths.is_empty() {
        b.rule(
            format!("{name}-api-write"),
            "github",
            Rule {
                host: forges::GITHUB_API.into(),
                access: Access::Methods(vec!["POST".into(), "PATCH".into()]),
                paths: write_paths,
                ignore_case: true,
                ..Default::default()
            },
        );
    }
    Ok(repos.iter().map(|(o, r)| format!("{o}/{r}")).collect())
}

/// `[[credentials.git]]`, git over HTTPS on any other host: its token as basic auth on the
/// listed repos' smart-HTTP paths, those paths allowed (fetches; pushes for `repos`, under
/// the push guard), private addresses for a host on a private network. The guards, and the
/// hosts' CA certificates for the gate's upstream TLS.
fn compile_git(
    b: &mut Builder,
    creds: &[GitCred],
) -> Result<(Vec<GitGuard>, BTreeMap<String, String>)> {
    let mut guards = Vec::new();
    let mut cas = BTreeMap::new();
    let mut hosts = BTreeSet::new();
    for (i, c) in creds.iter().enumerate() {
        let (host, port) =
            match c.host.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_ascii_lowercase(),
                    Some(p.parse::<u16>().with_context(|| {
                        format!("credentials.git: `{}` has no valid port", c.host)
                    })?),
                ),
                None => (c.host.to_ascii_lowercase(), None),
            };
        let plain = !host.is_empty()
            && !host.starts_with(['-', '.'])
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b));
        if !plain {
            bail!("credentials.git: `{}` is not a host name", c.host);
        }
        if host == forges::GITHUB || host == forges::AZURE_DEVOPS {
            bail!(
                "credentials.git: {host} has a credential of its own, [credentials.{}]",
                if host == forges::GITHUB {
                    "github"
                } else {
                    "azure_devops"
                }
            );
        }
        if !hosts.insert(host.clone()) {
            bail!("credentials.git: {host} is listed twice; one credential per host");
        }
        if c.repos.is_empty() && c.read_repos.is_empty() {
            bail!(
                "credentials.git ({host}): list the repos the env may push to (`repos`) or only \
                 fetch (`read_repos`)"
            );
        }
        if !c.repos.is_empty() && c.token.is_none() {
            bail!("credentials.git ({host}): pushing to `repos` takes a `token`");
        }
        let parse = |list: &[String]| -> Result<Vec<String>> {
            list.iter()
                .map(|r| {
                    let r = r.trim_matches('/');
                    let r = r.strip_suffix(".git").unwrap_or(r);
                    let ok = !r.is_empty()
                        && r.split('/').all(|s| {
                            !s.is_empty()
                                && s != "."
                                && s != ".."
                                && s.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"._~%+-".contains(&b))
                        });
                    if !ok {
                        bail!("credentials.git ({host}): `{r}` is not a repository path");
                    }
                    Ok(r.to_string())
                })
                .collect()
        };
        let (repos, read_repos) = (parse(&c.repos)?, parse(&c.read_repos)?);
        let git_paths = |r: &str, write: bool| {
            let mut out = Vec::new();
            for base in [format!("/{r}"), format!("/{r}.git")] {
                out.extend(smart_http_paths(&base, write));
            }
            // GitLab serves LFS objects here.
            out.push(format!("/{r}.git/gitlab-lfs/objects/*"));
            out
        };
        let paths: Vec<String> = repos
            .iter()
            .flat_map(|r| git_paths(r, true))
            .chain(read_repos.iter().flat_map(|r| git_paths(r, false)))
            .collect();
        let id = format!("git-{}", i + 1);
        if let Some(token) = &c.token {
            b.bindings.insert(
                id.clone(),
                BindingSpec::Static {
                    secret_ref: token.clone(),
                },
            );
            // Forges read repository paths in any case.
            b.injections.push(Injection {
                binding: id.clone(),
                host: host.clone(),
                paths: paths.clone(),
                place: Placement::Basic {
                    username: c.username.clone(),
                },
                ignore_case: true,
            });
        }
        b.rule(
            id,
            "git",
            Rule {
                host: host.clone(),
                port,
                access: Access::Methods(vec!["GET".into(), "POST".into()]),
                paths,
                ignore_case: true,
                allow_private: c.private,
                ..Default::default()
            },
        );
        if !repos.is_empty() {
            guards.push(GitGuard {
                host: host.clone(),
                repos: repos.iter().map(|r| r.to_ascii_lowercase()).collect(),
                protected_branches: c.protected_branches.clone(),
                allow_tags: c.allow_tags,
            });
        }
        if let Some(ca) = &c.ca {
            let path = crate::workspace::expand(ca);
            let text = std::fs::read_to_string(&path).with_context(|| {
                format!("credentials.git ({host}): read its CA {}", path.display())
            })?;
            // Only the certificates: a file that also holds a key keeps it here.
            let certs: String = text
                .split_inclusive("-----END CERTIFICATE-----")
                .filter_map(|c| {
                    let start = c.find("-----BEGIN CERTIFICATE-----")?;
                    c.ends_with("-----END CERTIFICATE-----")
                        .then(|| format!("{}\n", &c[start..]))
                })
                .collect();
            if certs.is_empty() {
                bail!(
                    "credentials.git ({host}): {} holds no PEM certificate",
                    path.display()
                );
            }
            cas.insert(host.clone(), certs);
        }
        b.dev_env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    }
    Ok((guards, cas))
}

/// Azure DevOps: the PAT added as basic auth on the repos' git paths, those paths allowed
/// (case-insensitively, as Azure DevOps reads them) and the push guard. The guard, and the
/// repos for the remote rewrites ([`azure::rewrites`]).
fn compile_azure(b: &mut Builder, c: &AzureDevopsCred) -> Result<(AzureGuard, Vec<azure::Repo>)> {
    if c.repos.is_empty() && c.read_repos.is_empty() {
        bail!(
            "credentials.azure_devops: list the repos the env may use (`repos = [\"org/project/repo\"]`, or `read_repos` for fetch only)"
        );
    }
    let parse = |list: &[String]| -> Result<Vec<azure::Repo>> {
        list.iter().map(|r| azure::parse_repo(r)).collect()
    };
    let (writable, readable) = (parse(&c.repos)?, parse(&c.read_repos)?);
    let repos: Vec<azure::Repo> = writable.iter().chain(&readable).cloned().collect();
    b.bindings.insert(
        "azure_devops".into(),
        BindingSpec::Static {
            secret_ref: c.token.clone(),
        },
    );
    let paths: Vec<String> = writable
        .iter()
        .flat_map(|r| r.git_paths(true))
        .chain(readable.iter().flat_map(|r| r.git_paths(false)))
        .collect();
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
    // Pull requests over REST, for the repos the env may write: read, open, comment, and
    // change a title, description, draft state or target. The bodies are an allowlist, so
    // completing one (a merge), auto-complete and votes stay with people, as a merge does on
    // GitHub; branch content goes only through the push guard.
    let mut reads = Vec::new();
    let mut posts = Vec::new();
    let mut patches = Vec::new();
    for r in &writable {
        let base = r.api_base();
        reads.extend([
            base.clone(),
            format!("{base}/pullrequests"),
            format!("{base}/pullrequests/**"),
        ]);
        posts.extend([
            format!("{base}/pullrequests"),
            format!("{base}/pullrequests/*/threads"),
            format!("{base}/pullrequests/*/threads/*/comments"),
        ]);
        patches.push(format!("{base}/pullrequests/*"));
    }
    if !writable.is_empty() {
        b.injections.push(Injection {
            binding: "azure_devops".into(),
            host: azure::HOST.into(),
            paths: reads.iter().chain(&posts).cloned().collect(),
            place: Placement::Basic {
                username: String::new(),
            },
            ignore_case: true,
        });
        for (id, methods, paths) in [
            ("azure-api-read", vec!["GET"], &reads),
            ("azure-api-post", vec!["POST"], &posts),
            ("azure-api-patch", vec!["PATCH"], &patches),
        ] {
            b.rule(
                id.into(),
                "azure_devops",
                Rule {
                    host: azure::HOST.into(),
                    access: Access::Methods(methods.iter().map(|m| m.to_string()).collect()),
                    paths: paths.clone(),
                    ignore_case: true,
                    ..Default::default()
                },
            );
        }
        b.denies.push(DenyRule {
            host: azure::HOST.into(),
            paths: vec![
                "/*/*/_apis/git/repositories/*/pullrequests/*/reviewers".into(),
                "/*/*/_apis/git/repositories/*/pullrequests/*/reviewers/**".into(),
            ],
            methods: vec!["POST".into(), "PUT".into(), "PATCH".into(), "DELETE".into()],
            reason: "votes on pull requests are cast by people".into(),
        });
        let keys = |k: &[&str]| k.iter().map(|k| k.to_string()).collect::<Vec<_>>();
        let pr_paths: Vec<String> = writable
            .iter()
            .map(|r| format!("{}/pullrequests", r.api_base()))
            .collect();
        b.body_denies.push(BodyDeny {
            host: azure::HOST.into(),
            paths: pr_paths,
            ignore_case: true,
            only_keys: keys(&[
                "sourceRefName",
                "targetRefName",
                "title",
                "description",
                "isDraft",
                "reviewers",
                "workItemRefs",
                "labels",
            ]),
            reason: "a pull request opened from the sandbox takes a title, description, \
                     branches, draft state, reviewers, work items and labels; completing it \
                     stays with you"
                .into(),
            ..Default::default()
        });
        b.body_denies.push(BodyDeny {
            host: azure::HOST.into(),
            paths: patches.clone(),
            methods: vec!["PATCH".into()],
            ignore_case: true,
            only_keys: keys(&["title", "description", "isDraft", "targetRefName"]),
            reason: "the sandbox may change a pull request's title, description, draft state \
                     and target; completing it (or auto-complete) stays with you"
                .into(),
            ..Default::default()
        });
    }
    b.dev_env.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
    let guard = AzureGuard {
        repos: writable.iter().map(azure::Repo::key).collect(),
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
    fn azure_devops_pull_requests_go_through_rest_but_are_completed_by_people() {
        use luoto_shared::policy::JsonBody;
        let text = r#"
[credentials.azure_devops]
token = "op://v/ado/pat"
repos = ["invinite/InviniteInfra/azure-devops-agent"]
read_repos = ["invinite/InviniteInfra/lib"]
"#;
        let c = compile("t", &cfg(text), GATE, &alias()).unwrap();
        let p = &c.policy;
        let base = "/invinite/InviniteInfra/_apis/git/repositories/azure-devops-agent";
        let allowed = |method: &str, path: &str| {
            matches!(
                decide(p, "dev.azure.com", method, path),
                Decision::Allow { .. }
            )
        };
        for (method, path) in [
            ("POST", format!("{base}/pullrequests")),
            ("POST", format!("{base}/pullRequests")),
            ("GET", format!("{base}/pullrequests/12")),
            ("PATCH", format!("{base}/pullRequests/12")),
            ("POST", format!("{base}/pullrequests/12/threads")),
            ("POST", format!("{base}/pullrequests/12/threads/3/comments")),
        ] {
            assert!(allowed(method, &path), "{method} {path}");
            assert_eq!(p.injections_for("dev.azure.com", &path).len(), 1, "{path}");
        }
        for (method, path) in [
            ("PUT", format!("{base}/pullrequests/12/reviewers/me")),
            ("POST", format!("{base}/pushes")),
            (
                "POST",
                "/invinite/InviniteInfra/_apis/git/repositories/lib/pullrequests".into(),
            ),
            ("POST", "/invinite/_apis/projects".into()),
        ] {
            assert!(!allowed(method, &path), "{method} {path}");
        }
        assert!(
            p.injections_for(
                "dev.azure.com",
                "/invinite/InviniteInfra/_apis/git/repositories/lib/pullrequests"
            )
            .is_empty()
        );
        let refused = |method: &str, path: &str, body: &str| {
            let json = JsonBody::parse(body.as_bytes()).unwrap();
            p.body_denies
                .iter()
                .any(|d| d.applies("dev.azure.com", method, path) && d.asks(&json))
        };
        let create = format!("{base}/PullRequests");
        let one = format!("{base}/pullrequests/12");
        assert!(!refused(
            "POST",
            &create,
            r#"{"sourceRefName":"refs/heads/f","targetRefName":"refs/heads/main","title":"t"}"#
        ));
        assert!(refused(
            "POST",
            &create,
            r#"{"title":"t","completionOptions":{}}"#
        ));
        assert!(!refused("PATCH", &one, r#"{"description":"d"}"#));
        assert!(refused("PATCH", &one, r#"{"status":"completed"}"#));
        assert!(refused(
            "PATCH",
            &one.to_uppercase(),
            r#"{"autoCompleteSetBy":{"id":"x"}}"#
        ));
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
    fn read_repos_are_fetched_never_written() {
        let c = compile(
            "t",
            &cfg(r#"
[credentials.github]
app_id = "1"
installation_id = 2
private_key = "op://v/app/key"
repos = ["acme/web"]
read_repos = ["acme/lib"]

[credentials.azure_devops]
token = "op://v/ado/pat"
read_repos = ["org/Infra/agent"]
"#),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        let allowed =
            |host, method, path| matches!(decide(p, host, method, path), Decision::Allow { .. });
        assert!(allowed(
            "github.com",
            "POST",
            "/acme/lib.git/git-upload-pack"
        ));
        assert!(!allowed(
            "github.com",
            "POST",
            "/acme/lib.git/git-receive-pack"
        ));
        assert!(allowed(
            "github.com",
            "POST",
            "/acme/web.git/git-receive-pack"
        ));
        assert!(!allowed("api.github.com", "POST", "/repos/acme/lib/pulls"));
        assert!(allowed("api.github.com", "POST", "/repos/acme/web/pulls"));
        let binding = |path| p.injections_for("github.com", path)[0].binding.clone();
        assert_eq!(binding("/acme/web.git/info/refs"), "github");
        assert_eq!(binding("/acme/lib.git/info/refs"), "github-read");
        let BindingSpec::GithubApp {
            permissions, repos, ..
        } = &c.bindings["github-read"]
        else {
            panic!("an App token for the read repos");
        };
        assert_eq!(repos, &["lib"]);
        assert!(permissions.values().all(|v| v == "read"));
        assert_eq!(p.github.as_ref().unwrap().repos, ["acme/web"]);
        assert!(allowed(
            "dev.azure.com",
            "POST",
            "/org/Infra/_git/agent/git-upload-pack"
        ));
        assert!(!allowed(
            "dev.azure.com",
            "POST",
            "/org/Infra/_git/agent/git-receive-pack"
        ));
        assert!(p.azure_devops.as_ref().unwrap().repos.is_empty());
    }

    #[test]
    fn each_github_owner_gets_its_own_credential() {
        let c = compile(
            "t",
            &cfg(r#"
[[credentials.github]]
token = "op://v/fi/token"
repos = ["invinite-fi/upcloud-dev"]
protected_branches = ["main"]

[[credentials.github]]
token = "op://v/open/token"
repos = ["inviniteopen/upcloud-web"]
protected_branches = ["prod"]
"#),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        let binding = |host, path| {
            p.injections_for(host, path)
                .iter()
                .map(|i| i.binding.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            binding("github.com", "/invinite-fi/upcloud-dev/info/refs"),
            ["github"]
        );
        assert_eq!(
            binding("github.com", "/inviniteopen/upcloud-web/info/refs"),
            ["github-2"]
        );
        assert_eq!(
            binding("api.github.com", "/repos/inviniteopen/upcloud-web/pulls"),
            ["github-2"]
        );
        assert_eq!(binding("api.github.com", "/graphql"), ["github"]);
        for path in [
            "/repos/invinite-fi/upcloud-dev/pulls",
            "/repos/inviniteopen/upcloud-web/pulls",
        ] {
            assert!(matches!(
                decide(p, "api.github.com", "POST", path),
                Decision::Allow { .. }
            ));
        }
        let guard = p.github.as_ref().unwrap();
        assert_eq!(guard.repos.len(), 2);
        assert_eq!(guard.protected_branches, ["main", "prod"]);
        let twice = cfg(
            "[[credentials.github]]\ntoken = \"env:A\"\nrepos = [\"a/x\"]\n[[credentials.github]]\ntoken = \"env:B\"\nread_repos = [\"A/X\"]\n",
        );
        assert!(compile("t", &twice, GATE, &[]).is_err());
    }

    #[test]
    fn any_git_host_gets_its_token_on_its_repos_only() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(
            &ca,
            "-----BEGIN PRIVATE KEY-----\nKKKK\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let text = format!(
            r#"
[[credentials.git]]
host = "forge.internal:3000"
token = "op://v/forge/token"
username = "dev"
repos = ["Infra/Platform/api"]
read_repos = ["infra/lib"]
private = true
ca = '{}'
"#,
            ca.display()
        );
        let c = compile("t", &cfg(&text), GATE, &[]).unwrap();
        let p = &c.policy;
        let allowed = |method, path| {
            matches!(
                p.decide(
                    &RequestInfo {
                        host: "forge.internal",
                        port: 3000,
                        method,
                        path,
                        websocket: false,
                        content_length: Some(10),
                    },
                    Utc::now(),
                ),
                Decision::Allow { .. }
            )
        };
        assert!(allowed("POST", "/infra/platform/api.git/git-receive-pack"));
        assert!(allowed("GET", "/infra/lib.git/info/refs"));
        assert!(!allowed("POST", "/infra/lib.git/git-receive-pack"));
        assert!(!allowed("GET", "/other/repo.git/info/refs"));
        let inj = p.injections_for("forge.internal", "/Infra/Platform/api/info/refs");
        assert!(matches!(&inj[0].place, Placement::Basic { username } if username == "dev"));
        assert!(
            p.injections_for("forge.internal", "/other/repo/info/refs")
                .is_empty()
        );
        assert_eq!(p.git[0].repos, ["infra/platform/api"]);
        assert!(c.upstream_cas["forge.internal"].contains("BEGIN CERTIFICATE"));
        assert!(!c.upstream_cas["forge.internal"].contains("KEY"));
        assert!(c.git_config.contains("insteadOf = \"git@forge.internal:\""));
        assert!(c.git_config.contains("https://forge.internal:3000/"));
        assert!(
            p.rules
                .iter()
                .any(|r| r.rule.allow_private && r.rule.port == Some(3000))
        );
        for bad in [
            "[[credentials.git]]\nhost = \"github.com\"\ntoken = \"env:T\"\nrepos = [\"a/b\"]",
            "[[credentials.git]]\nhost = \"x.example\"\nrepos = [\"a/b\"]",
            "[[credentials.git]]\nhost = \"x.example\"\ntoken = \"env:T\"\nrepos = [\"a/../b\"]",
        ] {
            assert!(compile("t", &cfg(bad), GATE, &[]).is_err(), "{bad}");
        }
        // Public repos: fetched, no credential.
        let public = cfg("[[credentials.git]]\nhost = \"codeberg.org\"\nread_repos = [\"o/r\"]");
        let c = compile("t", &public, GATE, &[]).unwrap();
        assert!(c.policy.injections.is_empty() && c.policy.git.is_empty());
    }

    #[test]
    fn graphql_goes_with_the_first_credential_that_writes() {
        let c = compile(
            "t",
            &cfg("[[credentials.github]]\ntoken = \"env:R\"\nread_repos = [\"a/x\"]\n[[credentials.github]]\ntoken = \"env:W\"\nrepos = [\"b/y\"]\n"),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        let graphql: Vec<&str> = p
            .injections_for("api.github.com", "/graphql")
            .iter()
            .map(|i| i.binding.as_str())
            .collect();
        assert_eq!(graphql, ["github-2"]);
        assert!(!p.github.as_ref().unwrap().graphql_mutations.is_empty());
    }

    #[test]
    fn a_token_shared_by_two_credentials_is_pointed_out() {
        let c = compile(
            "t",
            &cfg("[[credentials.github]]\ntoken = \"env:T\"\nrepos = [\"a/x\"]\n[[credentials.github]]\ntoken = \"env:T\"\nrepos = [\"b/y\"]\n"),
            GATE,
            &[],
        )
        .unwrap();
        assert!(
            c.warnings
                .iter()
                .any(|w| w.contains("two credentials use env:T"))
        );
    }

    #[test]
    fn agent_options_are_the_profiles() {
        assert!(
            compile(
                "t",
                &cfg("[agents.claude]\nmodel = \"opus\"\neffort = \"medium\""),
                GATE,
                &[]
            )
            .is_ok()
        );
        assert!(
            compile(
                "t",
                &cfg("[agents.claude]\nmodel = \"sonnet[1m]\""),
                GATE,
                &[]
            )
            .is_ok()
        );
        for bad in [
            "[agents.claude]\neffort = \"max\"",
            "[agents.claude]\nmodel = \"x; rm\"",
            "[agents.opencode]\neffort = \"high\"",
        ] {
            assert!(compile("t", &cfg(bad), GATE, &[]).is_err(), "{bad}");
        }
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
        assert!(p.body_denies.iter().any(|d| d.applies(
            "api.anthropic.com",
            "POST",
            "/v1/messages"
        ) && d.asks(&json)));
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

    #[test]
    fn your_deny_beats_a_preset_and_a_rule() {
        let c = compile(
            "t",
            &cfg(r#"
presets = ["npm"]

[[allow]]
host = "registry.npmjs.org"
access = "write"

[[deny]]
host = "Registry.npmjs.org"
paths = ["/-/npm/v1/security/**"]
note = "no audits"
"#),
            GATE,
            &[],
        )
        .unwrap();
        let p = &c.policy;
        for method in ["POST", "GET"] {
            assert_eq!(
                decide(
                    p,
                    "registry.npmjs.org",
                    method,
                    "/-/npm/v1/Security/audits/quick"
                ),
                Decision::Deny(DenyReason::Explicit {
                    reason: "denied by a [[deny]] rule: no audits".into()
                }),
                "{method}"
            );
        }
        assert!(matches!(
            decide(p, "registry.npmjs.org", "GET", "/react"),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn denies_and_mutes_are_validated_and_tunnels_cannot_skip_a_deny() {
        for bad in [
            "[[deny]]\nhost = \"not a host\"",
            "[[deny]]\nhost = \"x.example\"\npaths = [\"v1/**\"]",
            "[[deny]]\nhost = \"x.example\"\nmethods = [\"GET,POST\"]",
            "[[mute]]\nhost = \"*\"",
            "[[mute]]\nhost = \"x.example\"\npaths = [\"v1\"]",
        ] {
            assert!(compile("t", &cfg(bad), GATE, &[]).is_err(), "{bad}");
        }
        let tunnel = cfg(r#"
[[allow]]
host = "grpc.example.com"
mode = "tunnel"
access = "write"

[[deny]]
host = "*.example.com"
methods = ["DELETE"]
"#);
        let err = compile("t", &tunnel, GATE, &[]).err().expect("refused");
        assert!(err.to_string().contains("[[deny]]"), "{err}");
        let muted = cfg("[[mute]]\nhost = \"telemetry.example\"\npaths = [\"/v1/**\"]");
        let c = compile("t", &muted, GATE, &[]).unwrap();
        assert!(c.policy.denies.is_empty());
    }
}
