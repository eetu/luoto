//! A project's own `luoto.toml`: what the team says the project needs — registries and APIs
//! to reach, ports, system packages, agents, and the credentials each developer fills in.
//!
//! Whoever can write the repository writes this file, code in the sandbox included (it writes
//! the env's copy, and a `git pull` there brings any commit). So it only proposes: the user
//! reviews it, luoto keeps the exact accepted text in the env's state, and a changed file
//! applies only after the user accepts the difference. It cannot hold credentials or secret
//! refs, and its rules pass the same checks as the sandbox's access requests. Its denies only
//! tighten; it can't mute, which would hide denials from the user.
//! Layering: config.toml < the accepted luoto.toml < the env's own config.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use luoto_shared::policy::{Access, AccessLevel, Deny, Mode, Policy, Rule, RuleOrigin, rule_error};
use luoto_shared::{presets, profiles};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Deps, EnvConfig, EnvFile, Repo, extend_unique};
use crate::env::{Ctx, UpOptions};
use crate::paths::write_private;
use crate::runtime::exec;
use crate::text::display;
use crate::workspace::{self, Oversize};
use crate::{deps, names, sync};

pub const FILE: &str = "luoto.toml";
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presets: Vec<String>,
    #[serde(default, rename = "allow", skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Deny>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "crate::config::Agents::is_empty")]
    pub agents: crate::config::Agents,
    #[serde(default, skip_serializing_if = "crate::config::is_default")]
    pub deps: Deps,
    #[serde(default, skip_serializing_if = "crate::config::is_default")]
    pub needs: crate::needs::Needs,
    /// Repositories cloned beside the project in the env, each at `/workspace/<name>`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub repos: BTreeMap<String, ProjectRepo>,
}

/// A remote the env clones (`repos.rs`); never a host folder, which is each developer's own.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectRepo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

pub fn parse(text: &str) -> Result<ProjectConfig> {
    let up = crate::format::upgrade(std::path::Path::new(FILE), text)
        .context("luoto.toml is not valid TOML")?;
    let mut table: toml::Table = up.text.parse().context("luoto.toml is not valid TOML")?;
    table.remove("version");
    for k in ["credentials", "sandbox_secrets"] {
        if table.contains_key(k) {
            bail!(
                "luoto.toml can't hold `{k}`: secrets stay in each developer's own env config; \
                 list what the project needs under [needs]"
            );
        }
    }
    if table.contains_key("shares") {
        bail!(
            "luoto.toml can't hold `shares`: which folders of a machine an env reads is each \
             developer's own (`luoto share add`)"
        );
    }
    if table.contains_key("mute") {
        bail!(
            "luoto.toml can't hold `mute`: muted denials are hidden from you, so only your own \
             config mutes"
        );
    }
    if table.contains_key("egress") {
        bail!(
            "luoto.toml can't hold `egress`: only you open an env's egress, for a while \
             (`luoto egress open`)"
        );
    }
    if table.contains_key("tools") {
        bail!("luoto.toml doesn't take [tools]: pin toolchains in mise.toml or .tool-versions");
    }
    if let Some(repos) = table.get("repos").and_then(|r| r.as_table())
        && let Some(name) = repos
            .iter()
            .find(|(_, r)| r.as_table().is_some_and(|t| t.contains_key("dir")))
            .map(|(n, _)| n)
    {
        bail!(
            "luoto.toml: repos.{}: a repository can't name your folders; give its `url`, or \
             add your own copy with `luoto repo add <folder>`",
            display(name)
        );
    }
    let p: ProjectConfig = toml::Value::Table(table).try_into().context("luoto.toml")?;
    validate(&p)?;
    Ok(p)
}

fn validate(p: &ProjectConfig) -> Result<()> {
    for n in &p.presets {
        if presets::get(n).is_none() {
            bail!("luoto.toml: unknown preset `{}`", display(n));
        }
    }
    for (name, opts) in &p.agents.0 {
        let Some(a) = profiles::agent(name) else {
            bail!("luoto.toml: unknown agent `{}`", display(name));
        };
        if opts.model_server.is_some() {
            bail!(
                "luoto.toml: agents.{}: `model_server` is each developer's own choice, in their \
                 env's file",
                display(name)
            );
        }
        // The agent's own prompts are each developer's to turn off (`--yolo`) or loosen.
        let loosens = |x: &str| {
            a.yolo.iter().chain(&a.prompt_flags).any(|f| {
                x == f
                    || x.starts_with(&format!("{f}="))
                    // `-anever`: a one-letter flag takes its value joined.
                    || (f.len() == 2 && !f.starts_with("--") && x.starts_with(f.as_str()))
            })
        };
        if let Some(y) = opts
            .args
            .iter()
            .chain(&opts.headless_args)
            .find(|x| loosens(x))
        {
            bail!(
                "luoto.toml: agents.{}: `{}` turns off or loosens the agent's own prompts, \
                 which only you do (`luoto agent run --yolo`, your env's own `args`)",
                display(name),
                display(y)
            );
        }
        crate::compile::check_agent_opts(&a, name, opts).context("luoto.toml")?;
    }
    for r in &p.allow {
        if let Some(i) = rule_error(r, RuleOrigin::Sandbox) {
            bail!("luoto.toml: allow {}: {}", display(&r.host), i.message);
        }
    }
    for d in &p.deny {
        if let Err(e) = d.rule() {
            bail!("luoto.toml: deny {}: {}", display(&d.host), display(&e));
        }
    }
    deps::check(&p.deps, RuleOrigin::Sandbox).context("luoto.toml")?;
    crate::needs::check(&p.needs)?;
    if let Some(i) = &p.image
        && !i
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./:_@-".contains(&b))
    {
        bail!("luoto.toml: `{}` is not an image reference", display(i));
    }
    let mut folded = std::collections::BTreeSet::new();
    for (name, r) in &p.repos {
        crate::repos::check_name(name).context("luoto.toml: repos")?;
        if !folded.insert(name.to_lowercase()) {
            bail!(
                "luoto.toml: repos: `{}` differs from another only by case",
                display(name)
            );
        }
        crate::repos::check_project_url(&r.url)
            .with_context(|| format!("luoto.toml: repos.{name}"))?;
        if let Some(b) = &r.branch {
            crate::repos::check_branch(b).with_context(|| format!("luoto.toml: repos.{name}"))?;
        }
    }
    Ok(())
}

/// Hex sha256 of a luoto.toml text: what the UI shows and later sends back to accept it.
pub fn sha(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// The project folder's file, read on the host: a regular file (never a link that could
/// point at your own files), size-capped.
pub fn read_host(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(FILE);
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return Ok(None);
    };
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() as usize > MAX_BYTES {
        bail!("{} is larger than {MAX_BYTES} bytes", path.display());
    }
    Ok(Some(std::fs::read_to_string(&path)?))
}

/// Write `text` as the project folder's luoto.toml, replacing a regular file there: a new file
/// renamed into place, so a failed write leaves the old one and no link is written through.
pub fn write_host(dir: &Path, text: &str) -> Result<()> {
    let path = dir.join(FILE);
    if let Ok(meta) = std::fs::symlink_metadata(&path)
        && !meta.is_file()
    {
        bail!("{} is not a regular file", path.display());
    }
    let tmp = dir.join(format!(
        ".{FILE}.{}",
        hex::encode(rand::random::<[u8; 4]>())
    ));
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()))
        .and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("write {}", path.display()));
    }
    Ok(())
}

/// Write `text` as the running env's `/workspace/luoto.toml`, as the dev user: a new file
/// moved into place, replacing whatever is there.
pub fn write_env(ctx: &Ctx, env: &str, text: &str) -> Result<()> {
    let dev = names::dev(env);
    ctx.rt
        .run_stdin(
            exec(&dev).stdin().user(crate::env::UID).sh(
                r#"t=$(mktemp /workspace/.luoto.toml.XXXXXX) && cat >"$t" && chmod 644 "$t" && mv -f "$t" /workspace/luoto.toml || { rm -f "$t"; exit 1; }"#,
            ),
            text.as_bytes(),
        )
        .with_context(|| format!("write /workspace/{FILE} in env `{env}`"))?;
    Ok(())
}

/// The file as the env's workspace has it now (a `git pull` inside may have changed it):
/// the whole text or an error, never a part of it.
pub fn read_env(ctx: &Ctx, env: &str) -> Result<Option<String>> {
    let rel = [FILE.to_string()];
    match workspace::read_files(ctx, env, &rel, MAX_BYTES, Oversize::Refuse)?.remove(FILE) {
        Some(b) => Ok(Some(
            String::from_utf8(b).context("luoto.toml is not UTF-8")?,
        )),
        None => Ok(None),
    }
}

/// The accepted text.
pub fn snapshot_path(ctx: &Ctx, env: &str) -> PathBuf {
    ctx.paths.env_state(env).join("project.toml")
}

/// `sha` of a text the user declined, so it isn't offered again.
pub fn declined_path(ctx: &Ctx, env: &str) -> PathBuf {
    ctx.paths.env_state(env).join("project.declined")
}

/// The accepted text and its settings, if the user accepted one.
pub fn accepted(ctx: &Ctx, env: &str) -> Option<(String, ProjectConfig)> {
    let text = std::fs::read_to_string(snapshot_path(ctx, env)).ok()?;
    match parse(&text) {
        Ok(p) => Some((text, p)),
        Err(e) => {
            eprintln!("warning: the accepted luoto.toml no longer parses ({e:#}); ignoring it");
            None
        }
    }
}

pub fn accept(ctx: &Ctx, env: &str, text: &str) -> Result<()> {
    parse(text)?;
    write_private(&snapshot_path(ctx, env), text.as_bytes())?;
    set_declined(ctx, env, None)
}

/// Stop applying the project's settings; this exact text isn't offered again.
pub fn forget(ctx: &Ctx, env: &str, current: Option<&str>) -> Result<()> {
    remove(&snapshot_path(ctx, env))?;
    set_declined(ctx, env, current.map(sha))
}

fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn set_declined(ctx: &Ctx, env: &str, hash: Option<String>) -> Result<()> {
    match hash {
        Some(h) => write_private(&declined_path(ctx, env), h.as_bytes()),
        None => remove(&declined_path(ctx, env)),
    }
}

fn declined(ctx: &Ctx, env: &str, text: &str) -> bool {
    std::fs::read_to_string(declined_path(ctx, env)).is_ok_and(|h| h.trim() == sha(text))
}

/// Put the project's settings under the env's own: lists merge, the env's scalars win.
pub fn layer(cfg: &mut EnvConfig, p: &ProjectConfig) {
    extend_unique(&mut cfg.presets, p.presets.iter().cloned());
    cfg.agents.layer_under(&p.agents);
    extend_unique(&mut cfg.ports, p.ports.iter().copied());
    if cfg.image.is_none() {
        cfg.image = p.image.clone();
    }
    let mut rules: Vec<Rule> = p
        .allow
        .iter()
        .enumerate()
        .map(|(i, r)| Rule {
            id: Some(format!("project-{}", i + 1)),
            note: Some(match &r.note {
                Some(n) => format!("luoto.toml: {}", display(n)),
                None => "luoto.toml".into(),
            }),
            ..r.clone()
        })
        .collect();
    rules.append(&mut cfg.allow);
    cfg.allow = rules;
    let mut denies: Vec<Deny> = p
        .deny
        .iter()
        .map(|d| Deny {
            note: Some(match &d.note {
                Some(n) => format!("luoto.toml: {}", display(n)),
                None => "luoto.toml".into(),
            }),
            ..d.clone()
        })
        .collect();
    denies.append(&mut cfg.deny);
    cfg.deny = denies;
    cfg.deps = deps::merged(&p.deps, &cfg.deps);
    for (name, r) in &p.repos {
        // The env's own repo of a name (a folder of yours, say) replaces the project's, also
        // when the two differ only by case.
        if !cfg
            .workspace
            .repos
            .keys()
            .any(|n| n.eq_ignore_ascii_case(name))
        {
            cfg.workspace.repos.insert(
                name.clone(),
                Repo {
                    url: Some(r.url.clone()),
                    branch: r.branch.clone(),
                    ..Default::default()
                },
            );
        }
    }
}

/// A luoto.toml for the team from what an env has: `luoto project suggest`.
#[derive(Debug)]
pub struct Suggestion {
    pub config: ProjectConfig,
    /// The file: a header comment, then `config`.
    pub text: String,
    /// What the env has that the file leaves out, and why, one item each.
    pub left_out: Vec<String>,
}

/// The settings `env` works with that a team can share: the accepted luoto.toml's, with the
/// env's own file (`own`) on top. Rules luoto adds itself (a preset's, an agent's, a
/// credential's) compile from the config and aren't in it, so none is copied as a rule.
/// Nothing personal or secret goes in, and the text passes `parse`.
pub fn suggest(env: &str, own: &EnvConfig, accepted: Option<&ProjectConfig>) -> Result<Suggestion> {
    let mut p = accepted.cloned().unwrap_or_default();
    let mut left_out = Vec::new();
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    extend_unique(&mut p.presets, own.presets.iter().cloned());
    let mut agents = own.agents.clone();
    agents.layer_under(&p.agents);
    p.agents = agents;
    extend_unique(&mut p.ports, own.ports.iter().copied());

    let mut expiring = 0;
    for r in &own.allow {
        if r.expires.is_some() {
            expiring += 1;
        } else if let Some(i) = rule_error(r, RuleOrigin::Sandbox) {
            left_out.push(format!("rule {}: {}", display(&r.host), i.message));
        } else {
            extend_unique(
                &mut p.allow,
                [Rule {
                    id: None,
                    ..r.clone()
                }],
            );
        }
    }
    if expiring > 0 {
        left_out.push(format!(
            "{expiring} expiring rule{} (grants for a while, not for the team)",
            plural(expiring)
        ));
    }
    extend_unique(&mut p.deny, own.deny.iter().cloned());

    extend_unique(&mut p.deps.system, own.deps.system.iter().cloned());
    extend_unique(&mut p.deps.run, own.deps.run.iter().cloned());
    for h in &own.deps.hosts {
        match rule_error(&Rule::read(h), RuleOrigin::Sandbox) {
            Some(i) => left_out.push(format!("install host {}: {}", display(h), i.message)),
            None => extend_unique(&mut p.deps.hosts, [h.clone()]),
        }
    }

    let mut folders = Vec::new();
    for (name, r) in &own.workspace.repos {
        let Some(url) = r.url.as_ref().filter(|_| r.dir.is_none()) else {
            if !p.repos.keys().any(|n| n.eq_ignore_ascii_case(name)) {
                folders.push(display(name));
            }
            continue;
        };
        if let Err(e) = crate::repos::check_project_url(url) {
            left_out.push(format!("repo {}: {e:#}", display(name)));
            continue;
        }
        // The env's own repo of a name replaces the project's, as in `layer`.
        p.repos.retain(|n, _| !n.eq_ignore_ascii_case(name));
        p.repos.insert(
            name.clone(),
            ProjectRepo {
                url: url.clone(),
                branch: r.branch.clone(),
            },
        );
    }
    if !folders.is_empty() {
        left_out.push(format!(
            "repo{} {}: your folder{} (a luoto.toml names remotes)",
            plural(folders.len()),
            folders.join(", "),
            plural(folders.len())
        ));
    }

    if let Some(i) = own.image.as_ref().filter(|i| p.image.as_ref() != Some(*i)) {
        left_out.push(format!(
            "image {}: your env's (`image = …` gives the team one)",
            display(i)
        ));
    }
    if !own.tools.is_empty() {
        let tools: Vec<String> = own
            .tools
            .iter()
            .map(|(k, v)| display(&format!("{k} = {v}")))
            .collect();
        left_out.push(format!(
            "toolchain defaults ({}): the project pins toolchains in mise.toml",
            tools.join(", ")
        ));
    }
    let c = &own.credentials;
    let mut creds: Vec<String> = Vec::new();
    if !c.github.is_empty() {
        creds.push("github".into());
    }
    if c.azure_devops.is_some() {
        creds.push("azure_devops".into());
    }
    if c.azure.is_some() {
        creds.push("azure".into());
    }
    if c.ssh.is_some() {
        creds.push("ssh".into());
    }
    creds.extend(c.git.iter().map(|g| format!("git {}", display(&g.host))));
    creds.extend(c.providers.keys().map(|k| display(k)));
    creds.extend(c.custom.keys().map(|k| format!("custom.{}", display(k))));
    if !creds.is_empty() {
        left_out.push(format!(
            "credentials ({}): each developer's own; [needs] can list what the project expects",
            creds.join(", ")
        ));
    }
    if !own.sandbox_secrets.is_empty() {
        let names: Vec<String> = own.sandbox_secrets.keys().map(|k| display(k)).collect();
        left_out.push(format!(
            "sandbox secrets ({}): each developer's own; [needs] can list them",
            names.join(", ")
        ));
    }
    if !own.mute.is_empty() {
        left_out.push(format!(
            "{} mute{} (only your own config mutes)",
            own.mute.len(),
            plural(own.mute.len())
        ));
    }
    if own.egress != crate::config::Egress::default() {
        left_out.push("open egress (only you open an env's)".into());
    }

    let text = format!(
        "# Suggested by `luoto project suggest` from env `{env}`: the settings it works with that a\n\
         # team can share. Review it before you commit it: everyone who accepts it allows this.\n\n{}",
        toml::to_string(&p).context("write the suggested luoto.toml")?
    );
    parse(&text).context("the suggested luoto.toml doesn't pass luoto's checks")?;
    Ok(Suggestion {
        config: p,
        text,
        left_out,
    })
}

/// Every setting of a rule, so no change to it can pass the review unseen.
pub fn rule_line(r: &Rule) -> String {
    let mut parts = vec![match &r.access {
        Access::Level(AccessLevel::Read) => "read".to_string(),
        Access::Level(AccessLevel::Write) => "WRITE".to_string(),
        Access::Methods(m) => display(&m.join(",").to_uppercase()),
    }];
    if !r.paths.is_empty() {
        parts.push(display(&r.paths.join(" ")));
    }
    if let Some(port) = r.port {
        parts.push(format!("port {port}"));
    }
    if r.mode == Mode::Tunnel {
        parts.push("TUNNEL: not inspected".into());
    }
    if r.ws {
        parts.push("websockets".into());
    }
    if let Some(m) = r.max_body {
        parts.push(format!("bodies up to {m} bytes"));
    }
    if let Some(i) = &r.idle {
        parts.push(format!("silent up to {}", display(i)));
    }
    if let Some(e) = r.expires {
        parts.push(format!("until {}", e.to_rfc3339()));
    }
    if r.allow_private {
        parts.push("PRIVATE addresses".into());
    }
    if let Some(n) = &r.note {
        parts.push(format!("note: {}", display(n)));
    }
    format!("{} ({})", display(&r.host), parts.join(", "))
}

/// Every setting of a deny: what it refuses, and its note.
pub fn deny_line(d: &Deny) -> String {
    let mut parts = vec![if d.methods.is_empty() {
        "every method".to_string()
    } else {
        display(&d.methods.join(",").to_uppercase())
    }];
    if !d.paths.is_empty() {
        parts.push(display(&d.paths.join(" ")));
    }
    if let Some(n) = &d.note {
        parts.push(format!("note: {}", display(n)));
    }
    format!("{} ({})", display(&d.host), parts.join(", "))
}

/// Everything accepting `p` sets, as `(label, item)` pairs, egress first.
fn items(p: &ProjectConfig) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let mut add = |label: &'static str, items: Vec<String>| {
        out.extend(items.into_iter().map(|i| (label, i)));
    };
    add("presets", p.presets.iter().map(|s| display(s)).collect());
    add("allow", p.allow.iter().map(rule_line).collect());
    add("deny", p.deny.iter().map(deny_line).collect());
    add(
        "install",
        p.deps
            .hosts
            .iter()
            .map(|h| format!("{} (read)", display(h)))
            .collect(),
    );
    add(
        "agents",
        p.agents
            .0
            .iter()
            .map(|(n, o)| {
                let quoted = |args: &[String]| {
                    args.iter()
                        .map(|x| format!("`{}`", display(x)))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                let mut opts: Vec<String> = o
                    .values()
                    .iter()
                    .map(|(k, v)| format!("{k} {}", display(v)))
                    .collect();
                if !o.args.is_empty() {
                    opts.push(format!("started with {}", quoted(&o.args)));
                }
                if !o.headless_args.is_empty() {
                    opts.push(format!("headless with {}", quoted(&o.headless_args)));
                }
                if opts.is_empty() {
                    display(n)
                } else {
                    format!("{} ({})", display(n), opts.join(", "))
                }
            })
            .collect(),
    );
    add("system", p.deps.system.iter().map(|s| display(s)).collect());
    add(
        "run",
        p.deps
            .run
            .iter()
            .map(|s| format!("`{}` (a command the env runs on `up`)", display(s)))
            .collect(),
    );
    add(
        "ports",
        p.ports
            .iter()
            .map(|p| format!("{p} (published on 127.0.0.1 on this machine)"))
            .collect(),
    );
    add(
        "image",
        p.image
            .iter()
            .map(|s| format!("{} (pulled outside the gate; the env runs it)", display(s)))
            .collect(),
    );
    add(
        "repos",
        p.repos
            .iter()
            .map(|(n, r)| {
                format!(
                    "{} cloned from {}{}",
                    display(n),
                    display(&r.url),
                    r.branch
                        .as_deref()
                        .map(|b| format!(" ({})", display(b)))
                        .unwrap_or_default()
                )
            })
            .collect(),
    );
    add("needs", crate::needs::review(&p.needs));
    out
}

/// What accepting `p` grants: one entry per kind, egress first, its items one per line.
pub fn summary(p: &ProjectConfig) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (label, item) in items(p) {
        match out.last_mut() {
            Some((l, v)) if l == label => {
                v.push('\n');
                v.push_str(&item);
            }
            _ => out.push((label.to_string(), item)),
        }
    }
    out
}

/// Settings added (`+`) and removed (`-`) between two versions; a changed setting shows as
/// both. Complete: two configs with the same lines here are equal.
pub fn diff(old: &ProjectConfig, new: &ProjectConfig) -> Vec<String> {
    let (a, b) = (items(old), items(new));
    let mut out: Vec<String> = b
        .iter()
        .filter(|x| !a.contains(x))
        .map(|(l, v)| format!("+ {l:<8} {v}"))
        .collect();
    out.extend(
        a.iter()
            .filter(|x| !b.contains(x))
            .map(|(l, v)| format!("- {l:<8} {v}")),
    );
    out
}

/// The credentials of yours that the rules `new` adds over `old` would carry (`policy` is the
/// env's), one line each below the diff.
fn credentials_reached(policy: &Policy, old: &ProjectConfig, new: &ProjectConfig) -> Vec<String> {
    let mut out = Vec::new();
    for r in new.allow.iter().filter(|r| !old.allow.contains(r)) {
        for why in policy.credentials_reached(r) {
            out.push(format!("! {:<8} {}: {why}", "allow", display(&r.host)));
        }
    }
    out
}

/// `label  value` lines, a multi-line value's later lines aligned under its first.
pub fn print_entries(entries: &[(String, String)], indent: &str) {
    for (label, value) in entries {
        let mut lines = value.lines();
        println!("{indent}{label:<8} {}", lines.next().unwrap_or_default());
        for l in lines {
            println!("{indent}{:<8} {l}", "");
        }
    }
}

/// Where an env stands with its project's luoto.toml.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// The project has no luoto.toml.
    None,
    Accepted,
    /// It differs from the accepted one.
    Changed,
    /// Never accepted.
    New,
    /// This version was ignored.
    Declined,
    /// It can't be read or parsed.
    Invalid,
    /// The file is gone; the accepted settings still apply.
    Removed,
    /// The env is stopped and its workspace exists only in the env (a clone), so the file
    /// can't be read; the accepted settings still apply.
    Unread,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub state: State,
    pub accepted: Vec<(String, String)>,
    pub current: Vec<(String, String)>,
    /// What applying the current text adds (`+`) and removes (`-`).
    pub diff: Vec<String>,
    pub error: Option<String>,
    /// Config snippets for credentials the project needs and the env lacks.
    pub needs: Vec<String>,
    /// `sha` of the current text; accepting it in the UI must name this.
    pub sha: Option<String>,
    #[serde(skip)]
    pub text: Option<String>,
}

impl Status {
    /// A text the user can apply: changed, new, or ignored before.
    pub fn pending(&self) -> bool {
        matches!(self.state, State::Changed | State::New | State::Declined)
    }
}

/// Where the project's luoto.toml is read now.
#[derive(Debug, PartialEq)]
enum Source {
    /// The running env's workspace, where the work happens.
    Env,
    /// The env's host folder.
    Host(PathBuf),
    /// Nowhere until the env runs: its workspace is a clone that exists only in the env.
    Unread,
    /// Nowhere: the env is stopped and its folder is gone.
    Nothing,
}

fn source(running: bool, ws: &crate::config::Workspace) -> Source {
    if running {
        return Source::Env;
    }
    match (ws.dir.as_deref().map(crate::workspace::canonical), &ws.url) {
        (Some(Ok(d)), _) => Source::Host(d),
        (None, Some(_)) => Source::Unread,
        _ => Source::Nothing,
    }
}

pub fn status(ctx: &Ctx, env: &str) -> Result<Status> {
    let cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    let public = crate::repos::declined(ctx, env);
    let missing = |p: &ProjectConfig| crate::needs::snippets(&p.needs, &cfg, &public);
    let old = accepted(ctx, env);
    let mut s = Status {
        state: State::None,
        accepted: old.as_ref().map(|(_, p)| summary(p)).unwrap_or_default(),
        current: Vec::new(),
        diff: Vec::new(),
        error: None,
        needs: Vec::new(),
        sha: None,
        text: None,
    };
    let running = ctx.rt.container_state(&names::dev(env)).as_deref() == Some("running");
    let text = match source(running, &cfg.workspace) {
        Source::Env => read_env(ctx, env),
        Source::Host(d) => read_host(&d),
        Source::Unread => {
            s.state = State::Unread;
            if let Some((_, p)) = &old {
                s.needs = missing(p);
            }
            return Ok(s);
        }
        Source::Nothing => Ok(None),
    };
    let new = text.and_then(|t| t.map(|t| parse(&t).map(|p| (t, p))).transpose());
    let (text, new) = match new {
        Ok(Some(found)) => found,
        Ok(None) => {
            if let Some((_, p)) = &old {
                s.state = State::Removed;
                s.needs = missing(p);
            }
            return Ok(s);
        }
        Err(e) => {
            s.state = State::Invalid;
            s.error = Some(crate::text::lines(&format!("{e:#}")));
            return Ok(s);
        }
    };
    s.current = summary(&new);
    s.needs = missing(&new);
    let none = ProjectConfig::default();
    let changed_from = match &old {
        Some((t, p)) if *t == text || *p == new => None,
        Some((_, p)) => Some(p),
        None => Some(&none),
    };
    if let Some(before) = changed_from {
        s.diff = diff(before, &new);
        if let Ok(plan) = crate::env::plan(ctx, env) {
            s.diff
                .extend(credentials_reached(&plan.compiled.policy, before, &new));
        }
    }
    s.state = match &old {
        Some((t, p)) if *t == text || *p == new => State::Accepted,
        Some(_) => State::Changed,
        None => State::New,
    };
    if s.state != State::Accepted && declined(ctx, env, &text) {
        s.state = State::Declined;
    }
    s.sha = Some(sha(&text));
    s.text = Some(text);
    Ok(s)
}

/// On `up`: let the user decide on a luoto.toml the workspace changed. Never applies anything
/// without a yes on a terminal. Whether the user applied a change.
pub fn review(ctx: &Ctx, env: &str) -> Result<bool> {
    let st = status(ctx, env)?;
    let text = st.text.as_deref().unwrap_or_default();
    match st.state {
        State::Invalid => eprintln!(
            "warning: the project's luoto.toml is not applied: {}",
            st.error.as_deref().unwrap_or_default()
        ),
        State::Removed => println!(
            "note: the project no longer has luoto.toml; its accepted settings still apply \
             (`luoto project ignore -e {env}` drops them)"
        ),
        // Only formatting or comments changed, or the file sets nothing: nothing is granted.
        State::Accepted if accepted(ctx, env).is_some_and(|(t, _)| t != text) => {
            accept(ctx, env, text)?;
        }
        State::New if parse(text).is_ok_and(|p| p == ProjectConfig::default()) => {
            accept(ctx, env, text)?;
        }
        State::New => {
            println!(
                "\nthe project's luoto.toml, not applied (written in the repository, so review it):"
            );
            print_entries(&st.current, "  ");
            if crate::prompt::confirm("Apply these settings to this env?") {
                accept(ctx, env, text)?;
                println!("applied");
                return Ok(true);
            }
            if crate::prompt::interactive() {
                set_declined(ctx, env, Some(sha(text)))?;
                println!("not applied (`luoto project apply -e {env}` applies it later)");
            } else {
                println!("not applied: run `luoto project apply -e {env}` to review and apply");
            }
        }
        State::Changed => {
            println!("the project's luoto.toml changed (written in the repository, so review it):");
            if st.diff.is_empty() {
                println!("  settings changed in a way this summary can't show; read luoto.toml");
            }
            for l in &st.diff {
                println!("  {l}");
            }
            if crate::prompt::confirm("Apply these settings to this env?") {
                accept(ctx, env, text)?;
                println!("applied");
                return Ok(true);
            }
            if crate::prompt::interactive() {
                set_declined(ctx, env, Some(sha(text)))?;
                println!(
                    "kept the previous settings (`luoto project apply -e {env}` applies it later)"
                );
            } else {
                println!("not applied: run `luoto project apply -e {env}` to review and apply");
            }
        }
        State::Accepted | State::None | State::Declined | State::Unread => {}
    }
    Ok(false)
}

/// Accept `reviewed`, the luoto.toml text the user reviewed, and apply it to the env if it
/// runs. Whether it applied now; otherwise the next `up` applies it.
pub fn apply(ctx: &Ctx, env: &str, reviewed: &str) -> Result<bool> {
    accept(ctx, env, reviewed)?;
    if ctx.rt.container_state(&names::dev(env)).as_deref() != Some("running") {
        return Ok(false);
    }
    crate::env::up(
        ctx,
        env,
        &UpOptions {
            quiet: true,
            ..Default::default()
        },
    )?;
    Ok(true)
}

/// Stop applying the project's luoto.toml; its current text isn't offered again.
pub fn ignore(ctx: &Ctx, env: &str) -> Result<()> {
    let st = status(ctx, env)?;
    forget(ctx, env, st.text.as_deref())?;
    sync::reapply(ctx, env)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_projects_rule_over_your_credentials_host_says_so() {
        let cfg: EnvConfig = toml::from_str(
            "[credentials.azure]\nsubscriptions = [\"0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0\"]\n\
             graph = true\n",
        )
        .unwrap();
        let policy = crate::compile::compile("t", &cfg, None, &[])
            .unwrap()
            .policy;
        let old = parse("[[allow]]\nhost = \"docs.rs\"").unwrap();
        let new = parse("[[allow]]\nhost = \"docs.rs\"\n[[allow]]\nhost = \"graph.microsoft.com\"")
            .unwrap();
        assert_eq!(
            credentials_reached(&policy, &old, &new),
            [
                "! allow    graph.microsoft.com: requests it allows to graph.microsoft.com carry \
              your `azure-graph` credential"
            ]
        );
        assert!(credentials_reached(&policy, &new, &new).is_empty());
    }

    #[test]
    fn refuses_secrets_tools_and_risky_rules() {
        assert!(parse("[credentials.github]\ntoken = \"op://x\"").is_err());
        assert!(parse("[credentials.azure]\nsubscriptions = [\"x\"]").is_err());
        assert!(parse("[sandbox_secrets]\nX = \"op://x\"").is_err());
        assert!(parse("[tools]\nnode = \"22\"").is_err());
        assert!(parse("[[allow]]\nhost = \"*\"").is_err());
        assert!(parse("[[allow]]\nhost = \"10.0.0.0/8\"").is_err());
        assert!(parse("[[allow]]\nhost = \"db.internal\"\nallow_private = true").is_err());
        assert!(parse("presets = [\"nope\"]").is_err());
        assert!(parse("image = \"x; rm\"").is_err());
        assert!(parse("[needs]\ngithub = [\"no-slash\"]").is_err());
        // Which server an agent uses is each developer's own.
        assert!(
            parse("[model_servers.x]\nurl = \"http://localhost:1\"\napi = [\"openai\"]").is_err()
        );
        let err = parse("[agents.claude]\nmodel_server = \"x\"").unwrap_err();
        assert!(
            format!("{err:#}").contains("each developer's own"),
            "{err:#}"
        );
        // A team may set arguments, not the ones that turn the agent's prompts off.
        assert!(parse("[agents.claude]\nheadless_args = [\"--bare\"]").is_ok());
        let err =
            parse("[agents.claude]\nargs = [\"--dangerously-skip-permissions\"]").unwrap_err();
        assert!(format!("{err:#}").contains("--yolo"), "{err:#}");
        for loose in [
            "[agents.claude]\nargs = [\"--permission-mode\", \"bypassPermissions\"]",
            "[agents.claude]\nheadless_args = [\"--settings=x.json\"]",
            "[agents.codex]\nargs = [\"-anever\"]",
            "[agents.codex]\nargs = [\"--config\", \"approval_policy=never\"]",
            "[agents.copilot]\nargs = [\"--allow-all-tools\"]",
        ] {
            assert!(parse(loose).is_err(), "{loose}");
        }
        assert!(parse("[agents.codex]\nargs = [\"--search\"]").is_ok());
        assert!(parse("[agents.claude]\nargs = [\"a\\u0007b\"]").is_err());
    }

    #[test]
    fn denies_only_tighten_but_mutes_would_hide() {
        let err = parse("[[mute]]\nhost = \"telemetry.example\"").unwrap_err();
        assert!(format!("{err:#}").contains("can't hold `mute`"), "{err:#}");
        for open in [
            "[egress]\nopen = true",
            "[egress]\nopen_until = \"2099-01-01T00:00:00Z\"",
        ] {
            let err = parse(open).unwrap_err();
            assert!(
                format!("{err:#}").contains("can't hold `egress`"),
                "{err:#}"
            );
        }
        assert!(parse("[[deny]]\nhost = \"x.example\"\npaths = [\"v1\"]").is_err());
        let p = parse(
            "[[deny]]\nhost = \"registry.npmjs.org\"\nmethods = [\"POST\"]\nnote = \"no audits\"",
        )
        .unwrap();
        let mut cfg = EnvConfig {
            deny: vec![Deny {
                host: "mine.example".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        layer(&mut cfg, &p);
        assert_eq!(cfg.deny.len(), 2);
        assert_eq!(cfg.deny[0].note.as_deref(), Some("luoto.toml: no audits"));
        assert_eq!(cfg.deny[1].host, "mine.example");
        assert_eq!(
            diff(&ProjectConfig::default(), &p),
            ["+ deny     registry.npmjs.org (POST, note: no audits)"]
        );
    }

    #[test]
    fn the_format_is_not_project_content() {
        assert_eq!(parse("version = 1\n").unwrap(), ProjectConfig::default());
        assert!(parse("version = 99\n").is_err());
    }

    #[test]
    fn layers_under_the_env_and_marks_its_rules() {
        let p = parse(
            r#"presets = ["npm"]
ports = [5173]
[[allow]]
host = "api.stripe.com"
[deps]
system = ["libpq-dev"]
[needs]
github = ["acme/web"]
credentials = ["anthropic"]
"#,
        )
        .unwrap();
        let mut cfg = EnvConfig {
            presets: vec!["debian".into()],
            ports: vec![5173, 3000],
            ..Default::default()
        };
        layer(&mut cfg, &p);
        assert_eq!(cfg.presets, ["debian", "npm"]);
        assert_eq!(cfg.ports, [5173, 3000]);
        assert_eq!(cfg.allow[0].id.as_deref(), Some("project-1"));
        assert_eq!(cfg.deps.system, ["libpq-dev"]);
        let needs = crate::needs::snippets(&p.needs, &cfg, &Default::default());
        assert_eq!(needs.len(), 2);
        assert!(needs[0].contains("repos = [\"acme/web\"]"));
    }

    #[test]
    fn repos_are_remotes_under_the_envs_own() {
        assert!(parse("[repos.api]\ndir = \"/home/me/.ssh\"").is_err());
        assert!(parse("[repos.api]\nurl = \"file:///etc\"").is_err());
        assert!(parse("[repos.\".git\"]\nurl = \"acme/api\"").is_err());
        assert!(parse("[repos.api]\nurl = \"acme/api\"\nbranch = \"--x\"").is_err());
        assert!(parse("[repos.api]\nurl = \"a/b\"\n[repos.API]\nurl = \"a/c\"").is_err());
        let p = parse(
            "[repos.api]\nurl = \"acme/api\"\n\n[repos.web]\nurl = \"git@github.com:acme/web.git\"\nbranch = \"dev\"\n",
        )
        .unwrap();
        let mut cfg = EnvConfig::default();
        cfg.workspace.repos.insert(
            "API".into(),
            Repo {
                dir: Some("/home/me/api".into()),
                ..Default::default()
            },
        );
        layer(&mut cfg, &p);
        let names: Vec<&str> = cfg.workspace.repos.keys().map(String::as_str).collect();
        assert_eq!(names, ["API", "web"]);
        assert_eq!(cfg.workspace.repos["web"].branch.as_deref(), Some("dev"));
        assert!(
            summary(&p)
                .iter()
                .any(|(l, v)| l == "repos" && v.contains("web cloned from git@github.com"))
        );
    }

    #[test]
    fn the_launchpad_example_parses() {
        let p = parse(include_str!("../../docs/examples/launchpad/luoto.toml")).unwrap();
        assert_eq!(p.repos.len(), 4);
    }

    #[test]
    fn diff_shows_every_rule_setting() {
        let a = parse("[[allow]]\nhost = \"api.example\"").unwrap();
        for extra in [
            "port = 8443",
            "ws = true",
            "max_body = 99",
            "expires = 2030-01-01T00:00:00Z",
            "mode = \"tunnel\"",
            "paths = [\"/v1/**\"]",
            "note = \"x\"",
        ] {
            let b = parse(&format!("[[allow]]\nhost = \"api.example\"\n{extra}")).unwrap();
            assert_ne!(a, b);
            assert_eq!(diff(&a, &b).len(), 2, "{extra} must show in the diff");
        }
        let a = parse("[[deny]]\nhost = \"api.example\"").unwrap();
        for extra in [
            "paths = [\"/v1/**\"]",
            "methods = [\"GET\"]",
            "note = \"x\"",
        ] {
            let b = parse(&format!("[[deny]]\nhost = \"api.example\"\n{extra}")).unwrap();
            assert_ne!(a, b);
            assert_eq!(diff(&a, &b).len(), 2, "{extra} must show in the diff");
        }
        let image = parse("image = \"x\"").unwrap();
        assert_eq!(
            diff(&ProjectConfig::default(), &image),
            ["+ image    x (pulled outside the gate; the env runs it)"]
        );
    }

    #[test]
    fn the_review_says_what_reaches_past_the_gate() {
        let p = parse(
            "image = \"ghcr.io/acme/dev:1\"\nports = [5173]\n[deps]\nrun = [\"make setup\"]\n\
             [repos.api]\nurl = \"acme/api\"\n",
        )
        .unwrap();
        let s = summary(&p);
        let line = |l: &str| s.iter().find(|(k, _)| k == l).unwrap().1.clone();
        assert!(line("image").contains("pulled outside the gate"));
        assert!(line("ports").contains("published on 127.0.0.1"));
        assert!(line("run").contains("`make setup` (a command the env runs"));
        assert_eq!(line("repos"), "api cloned from acme/api");
    }

    #[test]
    fn a_stopped_env_without_a_folder_has_its_luoto_toml_unread() {
        let remote = crate::config::Workspace {
            url: Some("acme/web".into()),
            ..Default::default()
        };
        assert_eq!(source(false, &remote), Source::Unread);
        assert_eq!(source(true, &remote), Source::Env);
        let dir = tempfile::tempdir().unwrap();
        let folder = crate::config::Workspace {
            dir: Some(dir.path().display().to_string()),
            ..Default::default()
        };
        assert_eq!(
            source(false, &folder),
            Source::Host(dir.path().canonicalize().unwrap())
        );
        let gone = crate::config::Workspace {
            dir: Some("/nonexistent/luoto-test".into()),
            ..Default::default()
        };
        assert_eq!(source(false, &gone), Source::Nothing);
    }

    const FULL_ENV: &str = r#"
image = "localhost/mine:dev"
presets = ["debian", "npm"]
ports = [5173]
idle_stop = "2h"

[egress]
open = true

[agents.claude]
model = "opus"

[tools]
node = "lts"

[workspace]
dir = "/home/me/web"

[workspace.repos.api]
url = "acme/api"
branch = "dev"

[workspace.repos.lib]
dir = "/home/me/lib"

[workspace.repos.lan]
url = "https://10.0.0.5/acme/lan.git"

[[allow]]
id = "r1a2b3"
host = "api.stripe.com"
note = "payments test API"

[[allow]]
id = "r4"
host = "docs.example"
paths = ["/v2/**"]
note = "approved request #3"

[[allow]]
host = "grpc.example"
access = "write"
mode = "tunnel"
port = 8443

[[allow]]
host = "docs.rs"
expires = "2030-01-01T00:00:00Z"

[[allow]]
host = "db.example"
allow_private = true

[[allow]]
host = "*.workers.dev"

[[allow]]
host = "10.0.0.0/8"

[[deny]]
host = "registry.npmjs.org"
methods = ["POST"]

[[mute]]
host = "telemetry.example"

[credentials.github]
token = "op://Dev/gh/token"
repos = ["acme/web"]

[credentials.azure_devops]
token = "op://Dev/ado/pat"
repos = ["acme/Platform/infra"]

[credentials.anthropic]
oauth_token = "op://Private/claude/token"

[credentials.custom.stripe]
host = "api.stripe.com"
secret = "op://Dev/stripe/key"

[sandbox_secrets]
DATABASE_URL = "op://Dev/db/url"

[env]
RUST_LOG = "debug"

[deps]
system = ["libpq-dev"]
run = ["git config --global pull.rebase true"]
hosts = ["dl.k8s.io", "*"]
"#;

    #[test]
    fn a_suggestion_parses_as_a_luoto_toml_and_keeps_nothing_personal() {
        let own: EnvConfig = toml::from_str(FULL_ENV).unwrap();
        let s = suggest("web", &own, None).unwrap();
        assert_eq!(parse(&s.text).unwrap(), s.config);
        assert!(
            s.text
                .starts_with("# Suggested by `luoto project suggest` from env `web`")
        );
        for secret in [
            "op://",
            "DATABASE_URL",
            "RUST_LOG",
            "telemetry",
            "/home/me",
            "10.0.",
        ] {
            assert!(!s.text.contains(secret), "{secret} in:\n{}", s.text);
        }
        let p = &s.config;
        assert_eq!(p.presets, ["debian", "npm"]);
        assert_eq!(p.ports, [5173]);
        assert_eq!(
            p.agents.get("claude").unwrap().model.as_deref(),
            Some("opus")
        );
        assert_eq!(p.image, None);
        // Only the rules written in the env; none a credential or preset compiles to.
        let hosts: Vec<&str> = p.allow.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, ["api.stripe.com", "docs.example", "grpc.example"]);
        assert!(p.allow.iter().all(|r| r.id.is_none()));
        assert_eq!(p.allow[1].note.as_deref(), Some("approved request #3"));
        assert_eq!(p.allow[2].mode, Mode::Tunnel);
        assert_eq!(p.deny.len(), 1);
        assert_eq!(p.deps.hosts, ["dl.k8s.io"]);
        assert_eq!(p.deps.run.len(), 1);
        assert_eq!(p.repos.keys().collect::<Vec<_>>(), ["api"]);
        assert_eq!(p.repos["api"].branch.as_deref(), Some("dev"));
        assert_eq!(p.needs, crate::needs::Needs::default());
        let out = s.left_out.join("\n");
        for said in [
            "1 expiring rule ",
            "rule db.example: allows dialing private",
            "rule *.workers.dev:",
            "rule 10.0.0.0/8:",
            "install host *:",
            "repo lib: your folder",
            "repo lan:",
            "image localhost/mine:dev",
            "toolchain defaults (node = \"lts\")",
            "credentials (github, azure_devops, anthropic, custom.stripe)",
            "sandbox secrets (DATABASE_URL)",
            "1 mute ",
            "open egress",
        ] {
            assert!(out.contains(said), "`{said}` not in:\n{out}");
        }
    }

    #[test]
    fn a_suggestion_keeps_the_accepted_luoto_toml_under_the_envs_own() {
        let accepted = parse(
            r#"presets = ["npm"]
image = "ghcr.io/acme/dev:1"
[[allow]]
host = "api.stripe.com"
note = "payments test API"
[agents.claude]
model = "sonnet"
effort = "high"
[deps]
run = ["make setup"]
[needs]
credentials = ["anthropic"]
[repos.api]
url = "acme/api"
[repos.web]
url = "acme/web"
"#,
        )
        .unwrap();
        let own: EnvConfig = toml::from_str(
            r#"presets = ["debian", "npm"]
[agents.claude]
model = "opus"
[[allow]]
id = "r1"
host = "api.stripe.com"
note = "payments test API"
[[allow]]
id = "r2"
host = "pypi.org"
[deps]
run = ["make setup"]
[workspace.repos.API]
dir = "/home/me/api"
[workspace.repos.WEB]
url = "acme/web"
branch = "next"
"#,
        )
        .unwrap();
        let s = suggest("web", &own, Some(&accepted)).unwrap();
        let p = &s.config;
        assert_eq!(p.presets, ["npm", "debian"]);
        assert_eq!(p.image.as_deref(), Some("ghcr.io/acme/dev:1"));
        let claude = p.agents.get("claude").unwrap();
        assert_eq!(claude.model.as_deref(), Some("opus"));
        assert_eq!(claude.effort.as_deref(), Some("high"));
        assert_eq!(p.allow.len(), 2);
        assert_eq!(p.deps.run, ["make setup"]);
        assert_eq!(p.needs.credentials, ["anthropic"]);
        assert_eq!(p.repos.keys().collect::<Vec<_>>(), ["WEB", "api"]);
        assert_eq!(p.repos["WEB"].branch.as_deref(), Some("next"));
        assert!(s.left_out.is_empty(), "{:?}", s.left_out);
        assert_eq!(
            diff(&accepted, p),
            [
                "+ presets  debian",
                "+ allow    pypi.org (read)",
                "+ agents   claude (model opus, effort high)",
                "+ repos    WEB cloned from acme/web (next)",
                "- agents   claude (model sonnet, effort high)",
                "- repos    web cloned from acme/web",
            ]
        );
        assert_eq!(
            suggest("web", &EnvConfig::default(), None).unwrap().config,
            ProjectConfig::default()
        );
    }

    #[test]
    fn a_suggestion_is_written_in_place_never_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        write_host(dir.path(), "presets = [\"npm\"]\n").unwrap();
        write_host(dir.path(), "ports = [5173]\n").unwrap();
        assert_eq!(read_host(dir.path()).unwrap().unwrap(), "ports = [5173]\n");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            let other = tempfile::tempdir().unwrap();
            std::fs::create_dir(other.path().join("target")).unwrap();
            std::os::unix::fs::symlink(other.path().join("target"), other.path().join(FILE))
                .unwrap();
            assert!(write_host(other.path(), "x = 1\n").is_err());
        }
    }

    #[test]
    fn diff_lists_what_changes() {
        let a = parse("presets = [\"npm\"]").unwrap();
        let b = parse("presets = [\"npm\"]\n[[allow]]\nhost = \"up.example\"\naccess = \"write\"")
            .unwrap();
        assert_eq!(diff(&a, &b), ["+ allow    up.example (WRITE)"]);
        assert_eq!(diff(&b, &a), ["- allow    up.example (WRITE)"]);
    }
}
