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
    if table.contains_key("workspace") || table.contains_key("dangerously_pull_on_stop") {
        bail!(
            "luoto.toml can't hold `workspace` or `dangerously_pull_on_stop`: whether an env's \
             files land in a folder of yours with nobody reviewing them is only yours to say \
             (`luoto pull --on-stop on`)"
        );
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

/// The text luoto last copied from the folder into the env: with the first `up`, or taken in
/// since. The env's copy being this text means the env didn't change it, accepted or not.
pub fn taken_path(ctx: &Ctx, env: &str) -> PathBuf {
    ctx.paths.env_state(env).join("project.taken")
}

/// Remember `text` as what the env's copy was made from.
pub fn set_taken(ctx: &Ctx, env: &str, text: &str) -> Result<()> {
    write_private(&taken_path(ctx, env), text.as_bytes())
}

fn taken(ctx: &Ctx, env: &str) -> Option<String> {
    std::fs::read_to_string(taken_path(ctx, env)).ok()
}

/// `sha` of a folder's text the user kept the env's copy over, so `up` doesn't ask about it
/// again.
fn kept_path(ctx: &Ctx, env: &str) -> PathBuf {
    ctx.paths.env_state(env).join("project.kept")
}

fn kept(ctx: &Ctx, env: &str, folder: &str) -> bool {
    std::fs::read_to_string(kept_path(ctx, env)).is_ok_and(|h| h.trim() == sha(folder))
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
            crate::progress::warn(&format!(
                "the accepted luoto.toml no longer parses ({e:#}); ignoring it"
            ));
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
        if r.ignore_case {
            parts.push("paths in any case".into());
        }
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
        parts.push(format!("until {}", crate::egress::at_text(e)));
    }
    if r.allow_private {
        parts.push("PRIVATE addresses".into());
    }
    if let Some(ca) = &r.ca {
        parts.push(format!("TRUSTS the CA in {}", display(ca)));
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
        let label = crate::style::out().dim(&format!("{label:<8}"));
        println!("{indent}{label} {}", lines.next().unwrap_or_default());
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
    // A workspace of repos has no luoto.toml of its own: one at /workspace is only what the
    // sandbox wrote there.
    if ws.dir.is_none() && ws.url.is_none() {
        return Source::Nothing;
    }
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
    let missing = |p: &ProjectConfig| crate::needs::snippets(env, &p.needs, &cfg, &public);
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
    let text = match text {
        Ok(Some(text)) => text,
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
    let new = match parse(&text) {
        Ok(new) => new,
        Err(e) => {
            s.state = State::Invalid;
            s.error = Some(crate::text::lines(&format!("{e:#}")));
            // Kept, not offered: whose text it is says where to fix it.
            s.text = Some(text);
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

/// The env's folder's luoto.toml against the env's copy, which is what luoto reads while the
/// env runs: the folder is copied in only on the first `up`.
#[derive(Debug, PartialEq)]
pub enum FolderCopy {
    /// The same, or nothing to compare.
    Same,
    /// Changed in the folder since the env took its copy, which the env left as it was: the
    /// accepted text, or the one luoto copied in.
    Newer(String),
    /// Changed in the folder and in the env: both texts.
    Both { folder: String, env: String },
}

/// Which copy to go on with when both changed, or to look first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyChoice {
    Env,
    Folder,
    Diff,
}

/// What `take_from_folder` may do without being told more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Take {
    /// `up`: asks before it takes anything.
    Asking,
    /// `luoto project apply`: takes a folder copy the env left alone.
    Newer,
    /// `luoto project apply --from-folder`: takes the folder's over the env's too.
    Folder,
}

/// What to do about a folder copy that differs from the env's.
#[derive(Debug, PartialEq, Eq)]
enum CopyStep {
    Take,
    /// `up`'s yes or no about a folder copy the env left alone.
    Confirm,
    /// Which copy to go on with.
    Ask,
    /// Keep the env's and say how to choose: nothing is overwritten unasked.
    Note,
    /// Without a terminal, a folder copy the env left alone waits for `project apply`.
    NoteNewer,
    /// Keep the env's without a word: the user chose it over this folder text before.
    Quiet,
}

/// `both`: the env changed its copy too. `kept`: the user kept the env's over this folder
/// text before, which holds once that copy is accepted and so no longer counts as changed.
/// Either way the env's copy stands against the folder's: only `--from-folder` or an answer
/// replaces it.
fn copy_step(take: Take, both: bool, kept: bool, interactive: bool) -> CopyStep {
    match take {
        Take::Folder => CopyStep::Take,
        Take::Asking if kept => CopyStep::Quiet,
        _ if both || kept => {
            if interactive {
                CopyStep::Ask
            } else {
                CopyStep::Note
            }
        }
        Take::Newer => CopyStep::Take,
        Take::Asking if interactive => CopyStep::Confirm,
        Take::Asking => CopyStep::NoteNewer,
    }
}

/// The menu's rows for [`CopyChoice`]: the env's first, which may hold work not pulled yet.
/// `committed`: whether the env's luoto.toml is committed in its repository, where known.
pub fn copy_rows(committed: Option<bool>, diff: bool) -> Vec<(CopyChoice, String, String)> {
    let env = match committed {
        Some(true) => "it may hold work not pulled yet; committed in the env",
        Some(false) => "it may hold work not pulled yet; not committed in the env",
        None => "it may hold work not pulled yet",
    };
    let mut rows = vec![
        (
            CopyChoice::Env,
            "Keep the env's (recommended)".to_string(),
            env.to_string(),
        ),
        (
            CopyChoice::Folder,
            "Take yours from the folder".to_string(),
            "overwrites the env's copy".to_string(),
        ),
    ];
    if diff {
        rows.push((
            CopyChoice::Diff,
            "Show the differences".to_string(),
            "the env's against yours, then this question again".to_string(),
        ));
    }
    rows
}

/// The most lines a comparison prints, and the most of each text it compares: a text is
/// capped in bytes, not lines, and the table below grows with their product.
const DIFF_LINES: usize = 200;
const DIFF_SIDE: usize = 1000;

/// The env's text against the folder's, line by line: `-` only in the env's, `+` only in the
/// folder's. Every line is escaped (the env's is the sandbox's), and the whole is capped.
pub fn copy_diff(env: &str, folder: &str) -> Vec<String> {
    let (a, b): (Vec<&str>, Vec<&str>) = (
        env.lines().take(DIFF_SIDE).collect(),
        folder.lines().take(DIFF_SIDE).collect(),
    );
    // Longest common subsequence, from the end: `lcs[i][j]` of `a[i..]` and `b[j..]`.
    let mut lcs = vec![vec![0u16; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = vec!["- the env's   + your folder's".to_string()];
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let line = if i < a.len() && j < b.len() && a[i] == b[j] {
            i += 1;
            j += 1;
            format!("  {}", display(a[i - 1]))
        } else if j == b.len() || (i < a.len() && lcs[i + 1][j] >= lcs[i][j + 1]) {
            i += 1;
            format!("- {}", display(a[i - 1]))
        } else {
            j += 1;
            format!("+ {}", display(b[j - 1]))
        };
        if out.len() > DIFF_LINES {
            out.push(format!(
                "… {} more lines",
                (a.len() - i).max(b.len() - j) + 1
            ));
            break;
        }
        out.push(line);
    }
    out
}

/// Whether the env's luoto.toml is committed in the env's repository; `None` where
/// /workspace is none, or the env doesn't say.
fn committed_in_env(ctx: &Ctx, env: &str) -> Option<bool> {
    let out = ctx
        .rt
        .run_limited(
            exec(&names::dev(env)).user(crate::env::UID).sh(COMMITTED),
            std::time::Duration::from_secs(5),
            64,
        )
        .ok()?;
    read_committed(&out)
}

/// Tracked and the same as in HEAD: an ignored or untracked file is not committed. The
/// repository is the sandbox's, so nothing of its own runs: no fsmonitor hook, no diff
/// driver or textconv.
const COMMITTED: &str = "cd /workspace && git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0; \
     g='git -c core.fsmonitor=false -c core.untrackedCache=false'; \
     if $g ls-files --error-unmatch -- luoto.toml >/dev/null 2>&1 \
        && $g diff --quiet --no-ext-diff --no-textconv HEAD -- luoto.toml >/dev/null 2>&1; \
     then echo committed; else echo uncommitted; fi";

/// Only its own two words are read of what the env printed.
fn read_committed(output: &str) -> Option<bool> {
    match output.trim() {
        "committed" => Some(true),
        "uncommitted" => Some(false),
        _ => None,
    }
}

pub fn folder_copy(ctx: &Ctx, env: &str) -> Result<FolderCopy> {
    let cfg = EnvFile::load(&ctx.paths, env)?.cfg;
    let Some(dir) = cfg.workspace.dir.as_deref() else {
        return Ok(FolderCopy::Same);
    };
    if !ctx.rt.is_running(&names::dev(env)) {
        return Ok(FolderCopy::Same);
    }
    let Some(host) = read_host(&workspace::canonical(dir)?)? else {
        return Ok(FolderCopy::Same);
    };
    let copy = read_env(ctx, env)?;
    Ok(compare_copies(
        &host,
        copy.as_deref(),
        // As it is on disk: one that no longer parses is still what was accepted.
        std::fs::read_to_string(snapshot_path(ctx, env))
            .ok()
            .as_deref(),
        taken(ctx, env).as_deref(),
    ))
}

/// `host` (the folder's text) against the env's `copy`. The env changed its copy only when
/// it is neither the `accepted` text nor the one luoto last copied in (`taken`): a copy luoto
/// wrote itself, which was never accepted because it didn't parse, is not the env's edit.
fn compare_copies(
    host: &str,
    copy: Option<&str>,
    accepted: Option<&str>,
    taken: Option<&str>,
) -> FolderCopy {
    if copy == Some(host) {
        FolderCopy::Same
    } else if copy.is_none() || copy == accepted || copy == taken {
        FolderCopy::Newer(host.to_string())
    } else {
        FolderCopy::Both {
            folder: host.to_string(),
            env: copy.unwrap_or_default().to_string(),
        }
    }
}

/// Take the folder's luoto.toml into the env when it changed there since the env took its copy:
/// on `up` after a yes, with `luoto project apply` at once. Where the env's copy stands
/// against it (the env changed it too, or the user kept it), a terminal is asked which to go
/// on with and nothing is overwritten without one. The text taken, if any; either way the
/// copy the env then has is reviewed as any other.
pub fn take_from_folder(ctx: &Ctx, env: &str, take: Take) -> Result<Option<String>> {
    let (folder, copy) = match folder_copy(ctx, env)? {
        FolderCopy::Same => return Ok(None),
        FolderCopy::Newer(folder) => (folder, None),
        FolderCopy::Both { folder, env } => (folder, Some(env)),
    };
    let took = |text: String| -> Result<Option<String>> {
        write_env(ctx, env, &text)?;
        set_taken(ctx, env, &text)?;
        remove(&kept_path(ctx, env))?;
        println!("took luoto.toml from your folder into the env");
        Ok(Some(text))
    };
    let step = copy_step(
        take,
        copy.is_some(),
        kept(ctx, env, &folder),
        crate::prompt::interactive(),
    );
    match step {
        CopyStep::Take => took(folder),
        CopyStep::Quiet => Ok(None),
        CopyStep::Confirm => {
            if crate::prompt::confirm(
                "luoto.toml in your folder changed since the env took its copy, which is \
                 the one luoto reads. Take yours into the env?",
            ) {
                took(folder)
            } else {
                Ok(None)
            }
        }
        CopyStep::NoteNewer => {
            out!(
                "note: luoto.toml in your folder changed since the env took its copy: \
                 `luoto project apply -e {env}` takes it in"
            );
            Ok(None)
        }
        CopyStep::Note => {
            out_text!("{}", both_note(env, false));
            Ok(None)
        }
        CopyStep::Ask => {
            let committed = committed_in_env(ctx, env);
            let mut choice = crate::wizard::pick_copy(copy_rows(committed, true))?;
            if choice == Some(CopyChoice::Diff) {
                // A kept copy is the accepted one by now: read it as it is.
                let copy = match copy {
                    Some(copy) => copy,
                    None => read_env(ctx, env)?.unwrap_or_default(),
                };
                for line in copy_diff(&copy, &folder) {
                    println!("  {line}");
                }
                choice = crate::wizard::pick_copy(copy_rows(committed, false))?;
            }
            match choice {
                Some(CopyChoice::Folder) => took(folder),
                Some(CopyChoice::Env) => {
                    write_private(&kept_path(ctx, env), sha(&folder).as_bytes())?;
                    out!("kept the env's luoto.toml (`luoto project apply -e {env}` asks again)");
                    Ok(None)
                }
                _ => {
                    out_text!("{}", both_note(env, true));
                    Ok(None)
                }
            }
        }
    }
}

/// What is said when both copies changed and neither was chosen: later on a terminal
/// (`asked`), or without one, where each choice has its command.
fn both_note(env: &str, asked: bool) -> String {
    let what = "note: luoto.toml changed in your folder and in the env; the env's copy is read";
    if asked {
        format!("{what} (`luoto project apply -e {env}` asks again)")
    } else {
        format!(
            "{what}\n  compare them:        `luoto pull -e {env}`\n  \
             take your folder's:  `luoto project apply -e {env} --from-folder`"
        )
    }
}

/// Where to fix a luoto.toml that doesn't parse: in the folder, when the env's copy is the
/// text luoto took from there.
fn invalid_hint(env: &str, text: Option<&str>, taken: Option<&str>) -> String {
    if text.is_some() && text == taken {
        format!("; fix it in your folder, and `luoto up -e {env}` offers to take it in")
    } else {
        String::new()
    }
}

/// The env still holds the text that was just taken from the folder: only that text was
/// meant to be reviewed and applied, and code in the env can write the file in between.
pub fn taken_intact(took: Option<&str>, read: Option<&str>) -> bool {
    took.is_none() || took == read
}

/// On `up`: let the user decide on a luoto.toml the workspace changed. Never applies anything
/// without a yes on a terminal. Whether the user applied a change.
pub fn review(ctx: &Ctx, env: &str) -> Result<bool> {
    take_from_folder(ctx, env, Take::Asking)?;
    let st = status(ctx, env)?;
    let text = st.text.as_deref().unwrap_or_default();
    match st.state {
        State::Invalid => crate::progress::warn(&format!(
            "the project's luoto.toml is not applied: {}{}",
            st.error.as_deref().unwrap_or_default(),
            invalid_hint(env, st.text.as_deref(), taken(ctx, env).as_deref())
        )),
        State::Removed => out!(
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
                head!("applied");
                return Ok(true);
            }
            if crate::prompt::interactive() {
                set_declined(ctx, env, Some(sha(text)))?;
                out!("not applied (`luoto project apply -e {env}` applies it later)");
            } else {
                out!("not applied: run `luoto project apply -e {env}` to review and apply");
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
                head!("applied");
                return Ok(true);
            }
            if crate::prompt::interactive() {
                set_declined(ctx, env, Some(sha(text)))?;
                out!(
                    "kept the previous settings (`luoto project apply -e {env}` applies it later)"
                );
            } else {
                out!("not applied: run `luoto project apply -e {env}` to review and apply");
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
    fn a_rules_line_shows_how_its_paths_match_and_a_ca_it_trusts() {
        let r = Rule {
            host: "git.corp.example".into(),
            paths: vec!["/a/b/**".into()],
            ignore_case: true,
            ca: Some("/certs/corp.pem".into()),
            ..Default::default()
        };
        let line = rule_line(&r);
        assert!(line.contains("paths in any case"), "{line}");
        assert!(line.contains("TRUSTS the CA in /certs/corp.pem"), "{line}");
        let plain = rule_line(&Rule {
            host: "docs.rs".into(),
            ..Default::default()
        });
        assert!(
            !plain.contains("any case") && !plain.contains("TRUSTS"),
            "{plain}"
        );
    }

    #[test]
    fn a_folder_copy_changed_only_on_this_machine_is_taken_in() {
        let (old, new) = ("presets = [\"npm\"]\n", "presets = [\"pypi\"]\n");
        assert_eq!(
            compare_copies(old, Some(old), Some(old), None),
            FolderCopy::Same
        );
        assert_eq!(
            compare_copies(new, Some(old), Some(old), None),
            FolderCopy::Newer(new.into())
        );
        assert_eq!(
            compare_copies(new, None, None, None),
            FolderCopy::Newer(new.into())
        );
        // Changed in the env too (a `git pull` there): neither wins.
        assert_eq!(
            compare_copies(new, Some("ports = [3000]\n"), Some(old), None),
            FolderCopy::Both {
                folder: new.into(),
                env: "ports = [3000]\n".into()
            }
        );
    }

    #[test]
    fn a_copy_that_stands_against_the_folders_is_asked_about_and_never_overwritten_unasked() {
        // Both changed. `up`:
        assert_eq!(copy_step(Take::Asking, true, false, true), CopyStep::Ask);
        assert_eq!(copy_step(Take::Asking, true, false, false), CopyStep::Note);
        // Kept over this folder text before: `up` doesn't ask again.
        assert_eq!(copy_step(Take::Asking, true, true, true), CopyStep::Quiet);
        assert_eq!(copy_step(Take::Asking, true, true, false), CopyStep::Quiet);
        // `luoto project apply` asks whatever was kept, and takes nothing without a terminal.
        assert_eq!(copy_step(Take::Newer, true, true, true), CopyStep::Ask);
        assert_eq!(copy_step(Take::Newer, true, false, false), CopyStep::Note);

        // The kept copy was accepted since, so only the folder's counts as changed: the
        // choice still holds. `up` is quiet, and `project apply` asks, not overwrites.
        assert_eq!(copy_step(Take::Asking, false, true, true), CopyStep::Quiet);
        assert_eq!(copy_step(Take::Asking, false, true, false), CopyStep::Quiet);
        assert_eq!(copy_step(Take::Newer, false, true, true), CopyStep::Ask);
        assert_eq!(copy_step(Take::Newer, false, true, false), CopyStep::Note);

        // A folder copy the env left alone, as ever.
        assert_eq!(
            copy_step(Take::Asking, false, false, true),
            CopyStep::Confirm
        );
        assert_eq!(
            copy_step(Take::Asking, false, false, false),
            CopyStep::NoteNewer
        );
        assert_eq!(copy_step(Take::Newer, false, false, false), CopyStep::Take);

        // Only `--from-folder` overwrites a copy that stands, unasked.
        for (both, kept) in [(true, false), (true, true), (false, true), (false, false)] {
            assert_eq!(copy_step(Take::Folder, both, kept, false), CopyStep::Take);
            assert_eq!(copy_step(Take::Folder, both, kept, true), CopyStep::Take);
        }
    }

    #[test]
    fn a_luoto_toml_that_doesnt_parse_is_fixed_where_it_came_from() {
        let broken = "repose = []\n";
        assert_eq!(
            invalid_hint("web", Some(broken), Some(broken)),
            "; fix it in your folder, and `luoto up -e web` offers to take it in"
        );
        // The env's own text (a `git pull` there, the sandbox), or nothing taken: no hint.
        assert_eq!(invalid_hint("web", Some(broken), Some("ports = [1]\n")), "");
        assert_eq!(invalid_hint("web", Some(broken), None), "");
        assert_eq!(invalid_hint("web", None, None), "");
    }

    #[test]
    fn only_the_text_taken_from_the_folder_is_applied_after_taking_it() {
        let taken = "presets = [\"npm\"]\n";
        assert!(taken_intact(Some(taken), Some(taken)));
        // Swapped in the env between the write and the read, or gone.
        assert!(!taken_intact(
            Some(taken),
            Some("presets = [\"npm\", \"pypi\"]\n")
        ));
        assert!(!taken_intact(Some(taken), None));
        // Nothing was taken: whatever is there is reviewed as usual.
        assert!(taken_intact(None, Some(taken)));
        assert!(taken_intact(None, None));
    }

    #[test]
    fn the_committed_check_runs_nothing_of_the_repositorys_and_reads_ignored_as_not() {
        for needs in [
            "core.fsmonitor=false",
            "ls-files --error-unmatch -- luoto.toml",
            "--no-ext-diff",
            "--no-textconv",
        ] {
            assert!(COMMITTED.contains(needs), "{needs}");
        }
        assert!(!COMMITTED.contains("git status"));
    }

    #[test]
    fn the_question_offers_the_envs_copy_first_and_says_whether_it_is_committed() {
        let rows = copy_rows(None, true);
        let choices: Vec<_> = rows.iter().map(|r| r.0).collect();
        assert_eq!(
            choices,
            [CopyChoice::Env, CopyChoice::Folder, CopyChoice::Diff]
        );
        assert_eq!(rows[0].1, "Keep the env's (recommended)");
        assert_eq!(rows[0].2, "it may hold work not pulled yet");
        assert_eq!(rows[1].2, "overwrites the env's copy");
        assert!(
            copy_rows(Some(true), true)[0]
                .2
                .ends_with("; committed in the env")
        );
        assert!(
            copy_rows(Some(false), true)[0]
                .2
                .ends_with("; not committed in the env")
        );
        // After the differences were shown they aren't offered again.
        assert_eq!(copy_rows(None, false).len(), 2);

        assert_eq!(read_committed("committed\n"), Some(true));
        assert_eq!(read_committed("uncommitted\n"), Some(false));
        assert_eq!(read_committed(""), None);
        assert_eq!(read_committed("committed\nuncommitted\n"), None);
    }

    #[test]
    fn the_comparison_marks_each_sides_lines_escapes_them_and_is_capped() {
        let env = "presets = [\"npm\"]\nports = [3000]\n";
        let folder = "presets = [\"npm\"]\nports = [8080]\n[repos.web]\n";
        assert_eq!(
            copy_diff(env, folder),
            [
                "- the env's   + your folder's",
                "  presets = [\"npm\"]",
                "- ports = [3000]",
                "+ ports = [8080]",
                "+ [repos.web]",
            ]
        );
        // What the sandbox wrote can't move the cursor or color the terminal.
        let shown = copy_diff("a = \"\x1b[31mred\"\n", "a = 1\n");
        assert!(shown.iter().all(|l| !l.contains('\x1b')), "{shown:?}");
        let long: String = (0..500).map(|i| format!("k{i} = 1\n")).collect();
        let capped = copy_diff(&long, "");
        assert_eq!(capped.len(), DIFF_LINES + 2);
        assert_eq!(capped.last().unwrap(), "… 300 more lines");
        // A text of nothing but line ends is within the byte cap: its lines are capped too.
        let blank = "\n".repeat(MAX_BYTES);
        assert_eq!(copy_diff(&blank, &blank).len(), DIFF_LINES + 2);
    }

    #[test]
    fn without_a_terminal_each_choice_has_its_command() {
        assert_eq!(
            both_note("web", false),
            "note: luoto.toml changed in your folder and in the env; the env's copy is read\n  \
             compare them:        `luoto pull -e web`\n  \
             take your folder's:  `luoto project apply -e web --from-folder`"
        );
        assert!(
            both_note("web", false)
                .lines()
                .all(|l| l.chars().count() <= 80)
        );
        assert!(both_note("web", true).ends_with("(`luoto project apply -e web` asks again)"));
    }

    #[test]
    fn a_copy_luoto_took_from_the_folder_is_not_the_envs_change() {
        let accepted = "presets = [\"npm\"]\n";
        // Taken in with a typo, so never accepted; then fixed in the folder.
        let broken = "presets = [\"npm\"]\nrepose = []\n";
        let fixed = "presets = [\"npm\"]\n[repos.web]\nurl = \"acme/web\"\n";
        assert!(parse(broken).is_err());
        assert_eq!(
            compare_copies(fixed, Some(broken), Some(accepted), Some(broken)),
            FolderCopy::Newer(fixed.into())
        );
        // The same from the first `up`, with nothing accepted yet.
        assert_eq!(
            compare_copies(fixed, Some(broken), None, Some(broken)),
            FolderCopy::Newer(fixed.into())
        );
        // Still the taken text in the folder: nothing to take.
        assert_eq!(
            compare_copies(broken, Some(broken), Some(accepted), Some(broken)),
            FolderCopy::Same
        );
        // The env changed its copy after that: neither wins, as before.
        let edited = "presets = [\"npm\", \"pypi\"]\n";
        assert!(matches!(
            compare_copies(fixed, Some(edited), Some(accepted), Some(broken)),
            FolderCopy::Both { .. }
        ));
        // Without a record of what was taken, an unaccepted copy is the env's.
        assert!(matches!(
            compare_copies(fixed, Some(broken), Some(accepted), None),
            FolderCopy::Both { .. }
        ));
    }

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
        let needs = crate::needs::snippets("web", &p.needs, &cfg, &Default::default());
        assert_eq!(needs.len(), 2);
        assert!(needs[0].contains("repos = [\"acme/web\"]"));
    }

    #[test]
    fn pulling_unreviewed_is_never_a_projects_to_set() {
        for text in [
            "[workspace]\ndangerously_pull_on_stop = true\n",
            "dangerously_pull_on_stop = true\n",
            "[workspace]\ndir = \"/home/me\"\n",
        ] {
            let e = parse(text).unwrap_err();
            assert!(
                format!("{e:#}").contains("luoto pull --on-stop on"),
                "{text}: {e:#}"
            );
        }
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
        // A workspace of repos has none, running or not: /workspace is the sandbox's.
        let repos = crate::config::Workspace {
            repos: [("api".to_string(), Default::default())].into(),
            ..Default::default()
        };
        assert_eq!(source(true, &repos), Source::Nothing);
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
