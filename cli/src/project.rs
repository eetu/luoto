//! A project's own `luoto.toml`: what the team says the project needs — registries and APIs
//! to reach, ports, system packages, agents, and the credentials each developer fills in.
//!
//! Whoever can write the repository writes this file, code in the sandbox included (it writes
//! the env's copy, and a `git pull` there brings any commit). So it only proposes: the user
//! reviews it, luoto keeps the exact accepted text in the env's state, and a changed file
//! applies only after the user accepts the difference. It cannot hold credentials or secret
//! refs, and its rules pass the same checks as the sandbox's access requests.
//! Layering: config.toml < the accepted luoto.toml < the env's own config.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use luoto_shared::policy::{Access, AccessLevel, Mode, Rule, RuleOrigin, rule_error};
use luoto_shared::{presets, profiles};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Deps, EnvConfig, EnvFile, Repo, extend_unique};
use crate::env::{Ctx, UpOptions};
use crate::paths::write_private;
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
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
    #[serde(default)]
    pub deps: Deps,
    #[serde(default)]
    pub needs: Needs,
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

/// Credentials the project expects; each developer fills in their own refs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Needs {
    /// `owner/repo` the env should be able to push to.
    #[serde(default)]
    pub github: Vec<String>,
    /// Provider profiles (`anthropic`, `openai`, …) or `custom.<name>`.
    #[serde(default)]
    pub credentials: Vec<String>,
    /// Names of `[sandbox_secrets]` the project's code reads.
    #[serde(default)]
    pub sandbox_secrets: Vec<String>,
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
    for a in &p.agents {
        if profiles::agent(a).is_none() {
            bail!("luoto.toml: unknown agent `{}`", display(a));
        }
    }
    for r in &p.allow {
        if let Some(i) = rule_error(r, RuleOrigin::Sandbox) {
            bail!("luoto.toml: allow {}: {}", display(&r.host), i.message);
        }
    }
    deps::check(&p.deps, RuleOrigin::Sandbox).context("luoto.toml")?;
    if let Some(i) = &p.image
        && !i
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./:_@-".contains(&b))
    {
        bail!("luoto.toml: `{}` is not an image reference", display(i));
    }
    let word = |s: &str, extra: &[u8]| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
    };
    for r in &p.needs.github {
        if r.split('/').count() != 2 || !word(r, b"/._-") {
            bail!(
                "luoto.toml: needs.github: `{}` is not owner/repo",
                display(r)
            );
        }
    }
    for c in &p.needs.credentials {
        if !word(c, b"._-") {
            bail!(
                "luoto.toml: needs.credentials: `{}` is not a name",
                display(c)
            );
        }
    }
    for s in &p.needs.sandbox_secrets {
        if !word(s, b"_") {
            bail!(
                "luoto.toml: needs.sandbox_secrets: `{}` is not a name",
                display(s)
            );
        }
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
        crate::repos::check_url(&r.url).with_context(|| format!("luoto.toml: repos.{name}"))?;
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

/// The file as the env's workspace has it now (a `git pull` inside may have changed it):
/// the whole text or an error, never a part of it.
fn read_env(ctx: &Ctx, env: &str) -> Result<Option<String>> {
    let rel = [FILE.to_string()];
    match workspace::read_files(ctx, env, &rel, MAX_BYTES, Oversize::Refuse)?.remove(FILE) {
        Some(b) => Ok(Some(
            String::from_utf8(b).context("luoto.toml is not UTF-8")?,
        )),
        None => Ok(None),
    }
}

/// The accepted text.
fn snapshot_path(ctx: &Ctx, env: &str) -> PathBuf {
    ctx.paths.env_state(env).join("project.toml")
}

/// `sha` of a text the user declined, so it isn't offered again.
fn declined_path(ctx: &Ctx, env: &str) -> PathBuf {
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
    extend_unique(&mut cfg.agents, p.agents.iter().cloned());
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

/// Every setting of a rule, so no change to it can pass the review unseen.
fn rule_line(r: &Rule) -> String {
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

/// Everything accepting `p` sets, as `(label, item)` pairs, egress first.
fn items(p: &ProjectConfig) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let mut add = |label: &'static str, items: Vec<String>| {
        out.extend(items.into_iter().map(|i| (label, i)));
    };
    add("presets", p.presets.iter().map(|s| display(s)).collect());
    add("allow", p.allow.iter().map(rule_line).collect());
    add(
        "install",
        p.deps
            .hosts
            .iter()
            .map(|h| format!("{} (read)", display(h)))
            .collect(),
    );
    add("agents", p.agents.iter().map(|s| display(s)).collect());
    add("system", p.deps.system.iter().map(|s| display(s)).collect());
    add(
        "run",
        p.deps
            .run
            .iter()
            .map(|s| format!("`{}`", display(s)))
            .collect(),
    );
    add("ports", p.ports.iter().map(u16::to_string).collect());
    add("image", p.image.iter().map(|s| display(s)).collect());
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
    let mut needs: Vec<String> = Vec::new();
    if !p.needs.github.is_empty() {
        needs.push(format!(
            "GitHub push to {}",
            display(&p.needs.github.join(", "))
        ));
    }
    needs.extend(
        p.needs
            .credentials
            .iter()
            .map(|c| format!("{} credential", display(c))),
    );
    needs.extend(
        p.needs
            .sandbox_secrets
            .iter()
            .map(|s| format!("secret {}", display(s))),
    );
    add("needs", needs);
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
fn diff(old: &ProjectConfig, new: &ProjectConfig) -> Vec<String> {
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

/// Config snippets for credentials the project needs and the env lacks.
pub fn missing_needs(p: &ProjectConfig, cfg: &EnvConfig) -> Vec<String> {
    let mut out = Vec::new();
    if !p.needs.github.is_empty() && cfg.credentials.github.is_none() {
        out.push(format!(
            "[credentials.github]\ntoken = \"op://<vault>/<item>/<field>\"   # or app_id + installation_id + private_key\nrepos = [{}]",
            p.needs
                .github
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for c in &p.needs.credentials {
        if let Some(name) = c.strip_prefix("custom.") {
            if !cfg.credentials.custom.contains_key(name) {
                out.push(format!(
                    "[credentials.custom.{name}]\nhost = \"<api host>\"\nsecret = \"op://<vault>/<item>/<field>\""
                ));
            }
        } else if !cfg.credentials.providers.contains_key(c) {
            let kind = profiles::provider(c)
                .and_then(|p| p.auth.keys().next().cloned())
                .unwrap_or_else(|| "api_key".into());
            out.push(format!(
                "[credentials.{c}]\n{kind} = \"op://<vault>/<item>/<field>\""
            ));
        }
    }
    let secrets: Vec<&String> = p
        .needs
        .sandbox_secrets
        .iter()
        .filter(|s| !cfg.sandbox_secrets.contains_key(*s))
        .collect();
    if !secrets.is_empty() {
        out.push(format!(
            "[sandbox_secrets]\n{}",
            secrets
                .iter()
                .map(|s| format!("{s} = \"op://<vault>/<item>/<field>\""))
                .collect::<Vec<_>>()
                .join("\n")
        ));
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

/// The project's luoto.toml now: from the running env's workspace, else the host folder.
fn current(ctx: &Ctx, env: &str, cfg: &EnvConfig) -> Result<Option<String>> {
    if ctx.rt.container_state(&names::dev(env)).as_deref() == Some("running") {
        return read_env(ctx, env);
    }
    match cfg
        .workspace
        .dir
        .as_deref()
        .map(crate::workspace::canonical)
    {
        Some(Ok(d)) => read_host(&d),
        _ => Ok(None),
    }
}

pub fn status(ctx: &Ctx, env: &str) -> Result<Status> {
    let cfg = EnvFile::load(&ctx.paths, env)?.cfg;
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
    let new =
        current(ctx, env, &cfg).and_then(|t| t.map(|t| parse(&t).map(|p| (t, p))).transpose());
    let (text, new) = match new {
        Ok(Some(found)) => found,
        Ok(None) => {
            if let Some((_, p)) = &old {
                s.state = State::Removed;
                s.needs = missing_needs(p, &cfg);
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
    s.needs = missing_needs(&new, &cfg);
    s.state = match &old {
        Some((t, p)) if *t == text || *p == new => State::Accepted,
        Some((_, p)) => {
            s.diff = diff(p, &new);
            State::Changed
        }
        None => {
            s.diff = diff(&ProjectConfig::default(), &new);
            State::New
        }
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
        State::Changed | State::New => {
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
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                set_declined(ctx, env, Some(sha(text)))?;
                println!(
                    "kept the previous settings (`luoto project apply -e {env}` applies it later)"
                );
            } else {
                println!("not applied: run `luoto project apply -e {env}` to review and apply");
            }
        }
        State::Accepted | State::None | State::Declined => {}
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
    fn refuses_secrets_tools_and_risky_rules() {
        assert!(parse("[credentials.github]\ntoken = \"op://x\"").is_err());
        assert!(parse("[sandbox_secrets]\nX = \"op://x\"").is_err());
        assert!(parse("[tools]\nnode = \"22\"").is_err());
        assert!(parse("[[allow]]\nhost = \"*\"").is_err());
        assert!(parse("[[allow]]\nhost = \"10.0.0.0/8\"").is_err());
        assert!(parse("[[allow]]\nhost = \"db.internal\"\nallow_private = true").is_err());
        assert!(parse("presets = [\"nope\"]").is_err());
        assert!(parse("image = \"x; rm\"").is_err());
        assert!(parse("[needs]\ngithub = [\"no-slash\"]").is_err());
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
        let needs = missing_needs(&p, &cfg);
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
        let image = parse("image = \"x\"").unwrap();
        assert_eq!(diff(&ProjectConfig::default(), &image), ["+ image    x"]);
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
