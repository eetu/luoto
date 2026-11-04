//! A project's own `luoto.toml`: what the team says the project needs — registries and APIs
//! to reach, ports, system packages, agents, and the credentials each developer fills in.
//!
//! Whoever can write the repository writes this file, code in the sandbox included (a mount
//! writes the host folder; a `git pull` in the env brings any commit). So it only proposes:
//! the user reviews it, luoto keeps the exact accepted text in the env's state, and a changed
//! file applies only after the user accepts the difference. It cannot hold credentials or
//! secret refs, and its rules pass the same checks as the sandbox's access requests.
//! Layering: config.toml < the accepted luoto.toml < the env's own config.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use luoto_shared::policy::{Access, AccessLevel, Mode, Rule, RuleOrigin, Severity, validate_rule};
use luoto_shared::{presets, profiles};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Deps, EnvConfig, EnvFile};
use crate::env::{Ctx, EnvState, UID};
use crate::paths::write_private;
use crate::{deps, names};

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
    let table: toml::Table = text.parse().context("luoto.toml is not valid TOML")?;
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
    let p: ProjectConfig = toml::Value::Table(table).try_into().context("luoto.toml")?;
    validate(&p)?;
    Ok(p)
}

fn validate(p: &ProjectConfig) -> Result<()> {
    for n in &p.presets {
        if presets::get(n).is_none() {
            bail!("luoto.toml: unknown preset `{}`", clean(n));
        }
    }
    for a in &p.agents {
        if profiles::agent(a).is_none() {
            bail!("luoto.toml: unknown agent `{}`", clean(a));
        }
    }
    for r in &p.allow {
        if let Some(i) = validate_rule(r, RuleOrigin::Sandbox)
            .into_iter()
            .find(|i| i.severity == Severity::Error)
        {
            bail!("luoto.toml: allow {}: {}", clean(&r.host), i.message);
        }
    }
    deps::check(&p.deps, RuleOrigin::Sandbox).context("luoto.toml")?;
    if let Some(i) = &p.image
        && !i
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"./:_@-".contains(&b))
    {
        bail!("luoto.toml: `{}` is not an image reference", clean(i));
    }
    let word = |s: &str, extra: &[u8]| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
    };
    for r in &p.needs.github {
        if r.split('/').count() != 2 || !word(r, b"/._-") {
            bail!("luoto.toml: needs.github: `{}` is not owner/repo", clean(r));
        }
    }
    for c in &p.needs.credentials {
        if !word(c, b"._-") {
            bail!(
                "luoto.toml: needs.credentials: `{}` is not a name",
                clean(c)
            );
        }
    }
    for s in &p.needs.sandbox_secrets {
        if !word(s, b"_") {
            bail!(
                "luoto.toml: needs.sandbox_secrets: `{}` is not a name",
                clean(s)
            );
        }
    }
    Ok(())
}

/// Text from the file, safe to print in full (see `text::display`).
pub fn clean(s: &str) -> String {
    crate::text::display(s)
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

/// The file as the env's workspace has it now (a `git pull` inside may have changed it).
pub fn read_env(ctx: &Ctx, env: &str) -> Result<Option<String>> {
    let out = ctx
        .rt
        .command()
        .args([
            "exec",
            "-u",
            UID,
            &names::dev(env),
            "sh",
            "-c",
            r#"f=/workspace/luoto.toml; [ -f "$f" ] && [ ! -L "$f" ] || exit 3; head -c "$0" "$f""#,
            &(MAX_BYTES + 1).to_string(),
        ])
        .output()
        .context("read luoto.toml in the env")?;
    match out.status.code() {
        Some(0) if out.stdout.len() > MAX_BYTES => {
            bail!("luoto.toml is larger than {MAX_BYTES} bytes")
        }
        Some(0) => Ok(Some(
            String::from_utf8(out.stdout).context("luoto.toml is not UTF-8")?,
        )),
        Some(3) => Ok(None),
        _ => bail!("{}", String::from_utf8_lossy(&out.stderr).trim()),
    }
}

fn snapshot_path(ctx: &Ctx, env: &str) -> PathBuf {
    ctx.paths.env_state(env).join("project.toml")
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
    match std::fs::remove_file(snapshot_path(ctx, env)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    set_declined(ctx, env, current.map(sha))
}

fn set_declined(ctx: &Ctx, env: &str, hash: Option<String>) -> Result<()> {
    if let Some(mut st) = EnvState::load(ctx, env)?
        && st.project_declined != hash
    {
        st.project_declined = hash;
        st.save(ctx, env)?;
    }
    Ok(())
}

fn declined(ctx: &Ctx, env: &str, text: &str) -> bool {
    EnvState::load(ctx, env)
        .ok()
        .flatten()
        .and_then(|s| s.project_declined)
        .is_some_and(|h| h == sha(text))
}

/// Put the project's settings under the env's own: lists merge, the env's scalars win.
pub fn layer(cfg: &mut EnvConfig, p: &ProjectConfig) {
    let union = |base: &mut Vec<String>, add: &[String]| {
        for x in add {
            if !base.contains(x) {
                base.push(x.clone());
            }
        }
    };
    union(&mut cfg.presets, &p.presets);
    union(&mut cfg.agents, &p.agents);
    for port in &p.ports {
        if !cfg.ports.contains(port) {
            cfg.ports.push(*port);
        }
    }
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
                Some(n) => format!("luoto.toml: {}", clean(n)),
                None => "luoto.toml".into(),
            }),
            ..r.clone()
        })
        .collect();
    rules.append(&mut cfg.allow);
    cfg.allow = rules;
    cfg.deps = deps::merged(&p.deps, &cfg.deps);
}

/// Every setting of a rule, so no change to it can pass the review unseen.
fn rule_line(r: &Rule) -> String {
    let mut parts = vec![match &r.access {
        Access::Level(AccessLevel::Read) => "read".to_string(),
        Access::Level(AccessLevel::Write) => "WRITE".to_string(),
        Access::Methods(m) => clean(&m.join(",").to_uppercase()),
    }];
    if !r.paths.is_empty() {
        parts.push(clean(&r.paths.join(" ")));
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
        parts.push(format!("note: {}", clean(n)));
    }
    format!("{} ({})", clean(&r.host), parts.join(", "))
}

/// Everything accepting `p` sets, as `(label, item)` pairs, egress first.
fn items(p: &ProjectConfig) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let mut add = |label: &'static str, items: Vec<String>| {
        out.extend(items.into_iter().map(|i| (label, i)));
    };
    add("presets", p.presets.iter().map(|s| clean(s)).collect());
    add("allow", p.allow.iter().map(rule_line).collect());
    add(
        "install",
        p.deps
            .hosts
            .iter()
            .map(|h| format!("{} (read)", clean(h)))
            .collect(),
    );
    add("agents", p.agents.iter().map(|s| clean(s)).collect());
    add("system", p.deps.system.iter().map(|s| clean(s)).collect());
    add(
        "run",
        p.deps
            .run
            .iter()
            .map(|s| format!("`{}`", clean(s)))
            .collect(),
    );
    add("ports", p.ports.iter().map(u16::to_string).collect());
    add("image", p.image.iter().map(|s| clean(s)).collect());
    let mut needs: Vec<String> = Vec::new();
    if !p.needs.github.is_empty() {
        needs.push(format!(
            "GitHub push to {}",
            clean(&p.needs.github.join(", "))
        ));
    }
    needs.extend(
        p.needs
            .credentials
            .iter()
            .map(|c| format!("{} credential", clean(c))),
    );
    needs.extend(
        p.needs
            .sandbox_secrets
            .iter()
            .map(|s| format!("secret {}", clean(s))),
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

pub fn print_summary(p: &ProjectConfig, indent: &str) {
    print_entries(&summary(p), indent);
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

#[derive(Debug, PartialEq, Eq)]
pub enum Review {
    /// Nothing to decide (no file, unchanged, or a change the user already declined).
    Unchanged,
    Accepted,
    /// Changed and not accepted (declined, or no terminal to ask on).
    Pending,
}

/// On `up`: compare the workspace's luoto.toml with the accepted one and let the user decide
/// on a change. Never applies anything without a yes on a terminal.
pub fn review(ctx: &Ctx, env: &str) -> Result<Review> {
    let current = match read_env(ctx, env) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: {}", crate::text::lines(&format!("{e:#}")));
            return Ok(Review::Unchanged);
        }
    };
    let old = accepted(ctx, env);
    let Some(text) = current else {
        if old.is_some() {
            println!(
                "note: the project no longer has luoto.toml; its accepted settings still apply \
                 (`luoto project ignore -e {env}` drops them)"
            );
        }
        return Ok(Review::Unchanged);
    };
    if old.as_ref().is_some_and(|(t, _)| *t == text) || declined(ctx, env, &text) {
        return Ok(Review::Unchanged);
    }
    let new = match parse(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "warning: the project's luoto.toml is not applied: {}",
                crate::text::lines(&format!("{e:#}"))
            );
            return Ok(Review::Pending);
        }
    };
    let base = old.map(|(_, p)| p).unwrap_or_default();
    if base == new {
        // Only formatting or comments changed: nothing new is granted.
        accept(ctx, env, &text)?;
        return Ok(Review::Unchanged);
    }
    let mut lines = diff(&base, &new);
    if lines.is_empty() {
        lines.push("settings changed in a way this summary can't show; read luoto.toml".into());
    }
    println!("the project's luoto.toml changed (written in the repository, so review it):");
    for l in &lines {
        println!("  {l}");
    }
    if crate::commands::confirm("Apply these settings to this env?") {
        accept(ctx, env, &text)?;
        println!("applied");
        Ok(Review::Accepted)
    } else {
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            forget_change(ctx, env, &text)?;
            println!(
                "kept the previous settings (`luoto project apply -e {env}` applies it later)"
            );
        } else {
            println!("not applied: run `luoto project apply -e {env}` to review and apply");
        }
        Ok(Review::Pending)
    }
}

/// The project's luoto.toml now: from the running env's workspace, else the host folder.
pub fn current(ctx: &Ctx, env: &str, f: &EnvFile) -> Result<Option<String>> {
    if ctx.rt.container_state(&names::dev(env)).as_deref() == Some("running") {
        return read_env(ctx, env);
    }
    match f
        .cfg
        .workspace
        .dir
        .as_deref()
        .map(crate::workspace::canonical)
    {
        Some(Ok(d)) => read_host(&d),
        _ => Ok(None),
    }
}

/// Where an env stands with its project's luoto.toml.
#[derive(Debug, Serialize)]
pub struct Status {
    /// `none`, `accepted`, `changed`, `new` (never accepted), `declined` (this version was
    /// ignored), `invalid`, `removed` (the file is gone; the accepted settings still apply).
    pub state: &'static str,
    pub accepted: Vec<(String, String)>,
    pub current: Vec<(String, String)>,
    pub diff: Vec<String>,
    pub error: Option<String>,
    /// Config snippets for credentials the project needs and the env lacks.
    pub needs: Vec<String>,
    /// `sha` of the current text; accepting it in the UI must name this.
    pub sha: Option<String>,
    #[serde(skip)]
    pub text: Option<String>,
}

pub fn status(ctx: &Ctx, env: &str) -> Result<Status> {
    let f = EnvFile::load(&ctx.paths, env)?;
    let old = accepted(ctx, env);
    let mut s = Status {
        state: "none",
        accepted: old.as_ref().map(|(_, p)| summary(p)).unwrap_or_default(),
        current: Vec::new(),
        diff: Vec::new(),
        error: None,
        needs: Vec::new(),
        sha: None,
        text: None,
    };
    let text = match current(ctx, env, &f) {
        Ok(t) => t,
        Err(e) => {
            s.state = "invalid";
            s.error = Some(clean(&format!("{e:#}")));
            return Ok(s);
        }
    };
    let Some(text) = text else {
        if let Some((_, p)) = &old {
            s.state = "removed";
            s.needs = missing_needs(p, &f.cfg);
        }
        return Ok(s);
    };
    let new = match parse(&text) {
        Ok(p) => p,
        Err(e) => {
            s.state = "invalid";
            s.error = Some(clean(&format!("{e:#}")));
            return Ok(s);
        }
    };
    s.current = summary(&new);
    s.needs = missing_needs(&new, &f.cfg);
    s.state = match &old {
        Some((t, p)) if *t == text || *p == new => "accepted",
        Some((_, p)) => {
            s.diff = diff(p, &new);
            "changed"
        }
        None => "new",
    };
    if s.state != "accepted" && declined(ctx, env, &text) {
        s.state = "declined";
    }
    s.sha = Some(sha(&text));
    s.text = Some(text);
    Ok(s)
}

/// Decline a changed text but keep whatever was accepted before.
fn forget_change(ctx: &Ctx, env: &str, text: &str) -> Result<()> {
    set_declined(ctx, env, Some(sha(text)))
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

    #[test]
    fn clean_shows_terminal_escapes_in_full() {
        assert_eq!(clean("a\u{1b}[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(clean(&"x".repeat(500)).len(), 500);
    }
}
