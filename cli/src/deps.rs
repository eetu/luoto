//! What an env installs into itself on `up`: system packages and setup commands from
//! `[deps]`, and toolchains through mise — the versions the project's own files pin
//! (`.tool-versions`, `mise.toml`, `.node-version`, `package.json`'s `packageManager`, …),
//! over the env's and config.toml's `[tools]` and what installed agents need.
//!
//! Everything installs inside the sandbox, through the gate. Download hosts are granted only
//! while the install runs: presets that serve the tools being installed, plus `[deps] hosts`.
//! When an install is denied somewhere else, the user sees the hosts and may allow them for
//! installs. Toolchains are checked offline on every `up` (a project may have moved to a new
//! version); packages and commands rerun only when `[deps]` changes or the container is
//! recreated (they live in its filesystem).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use chrono::{TimeDelta, Utc};
use luoto_shared::policy::{Rule, RuleOrigin, Severity, validate_rule};
use luoto_shared::{presets, profiles};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::commands::confirm;
use crate::config::{Deps, EnvConfig, EnvFile};
use crate::connect::LOGIN;
use crate::detect::{self, DEPTH, Detected, IDIOMATIC_TOOLS, SKIP_DIRS};
use crate::env::{self, Ctx, UID};
use crate::{events, names};

const MARKER: &str = "/var/lib/luoto/deps";
const MISE_CONF: &str = "/etc/mise/conf.d/luoto.toml";
/// Bump when the package/command steps change meaning, so every env reruns them.
const VERSION: u32 = 2;

const SYSTEM: &str = r#"set -e
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q --no-install-recommends "$@"
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache "$@"
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y "$@"
elif command -v microdnf >/dev/null 2>&1; then
  microdnf install -y "$@"
else
  echo "no supported package manager (apt, apk, dnf)" >&2
  exit 1
fi"#;

/// config.toml's deps, then the env's: lists append without duplicates.
pub fn merged(global: &Deps, env: &Deps) -> Deps {
    let mut d = global.clone();
    for p in &env.system {
        if !d.system.contains(p) {
            d.system.push(p.clone());
        }
    }
    d.run.extend(env.run.iter().cloned());
    for h in &env.hosts {
        if !d.hosts.contains(h) {
            d.hosts.push(h.clone());
        }
    }
    d
}

/// Default toolchains for the env, lowest precedence first: agents' needs, config.toml's
/// `[tools]`, the env's `[tools]`.
pub fn tools_for(ctx: &Ctx, cfg: &EnvConfig) -> BTreeMap<String, toml::Value> {
    let mut t = BTreeMap::new();
    for a in cfg.agents.iter().filter_map(|a| profiles::agent(a)) {
        for (k, v) in a.tools {
            t.insert(k, toml::Value::String(v));
        }
    }
    t.extend(ctx.global.tools.clone());
    t.extend(cfg.tools.clone());
    t
}

/// How much of each file detection reads in an env: pins sit at the top.
const READ_CAP: usize = 65_536;

/// Prints each file named in its arguments as its length and that many bytes, or `-` when it
/// is not a regular file.
const READ_FILES: &str = r#"cd /workspace || exit 1
for f; do
  if [ -f "$f" ] && [ ! -L "$f" ]; then
    printf '%s\n' "$(head -c "$0" -- "$f" | wc -c)"
    head -c "$0" -- "$f"
  else
    printf -- '-\n'
  fi
done"#;

/// What the env's workspace says about itself ([`detect`]), read inside it: after a clone, the
/// project's files are only there. Two calls into the env: the file list, then the few files
/// detection reads.
pub fn detect_in_env(ctx: &Ctx, env: &str) -> Result<Detected> {
    let e = Env::new(ctx, env)?;
    let files = e.workspace_files();
    let wanted = detect::read_paths(&files);
    let mut texts = std::collections::HashMap::new();
    if !wanted.is_empty() {
        let cap = READ_CAP.to_string();
        let mut argv = vec!["sh", "-c", READ_FILES, &cap];
        argv.extend(wanted.iter().map(String::as_str));
        let out = e
            .ctx
            .rt
            .command()
            .args(e.exec_user("/workspace", &[], &argv))
            .output()
            .context("read the workspace's files in the env")?;
        texts = framed(&wanted, &out.stdout);
    }
    Ok(detect::detect_tree(&detect::Listed { files, texts }))
}

/// `READ_FILES`'s output, by the paths it was given, in order. Stops at anything else.
fn framed(paths: &[String], mut out: &[u8]) -> std::collections::HashMap<String, String> {
    let mut texts = std::collections::HashMap::new();
    for p in paths {
        let Some(nl) = out.iter().position(|b| *b == b'\n') else {
            break;
        };
        let head = String::from_utf8_lossy(&out[..nl]).trim().to_string();
        out = &out[nl + 1..];
        if head == "-" {
            continue;
        }
        let Ok(n) = head.parse::<usize>() else { break };
        if n > out.len() || n > READ_CAP {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&out[..n]) {
            texts.insert(p.clone(), s.to_string());
        }
        out = &out[n..];
    }
    texts
}

fn digest(d: &Deps) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(VERSION, &d.system, &d.run)).unwrap_or_default(),
    ))
}

/// `[deps]` as written by `origin`: hosts from a repository's luoto.toml get the checks the
/// sandbox's own requests get (no `*`, no multi-tenant wildcards, no private addresses).
pub fn check(d: &Deps, origin: RuleOrigin) -> Result<()> {
    for p in &d.system {
        if p.is_empty() || p.starts_with('-') || p.contains(char::is_whitespace) {
            bail!("[deps] system: `{p}` is not a package name");
        }
    }
    for h in &d.hosts {
        if let Some(i) = host_issue(h, origin) {
            bail!("[deps] hosts: {h}: {i}");
        }
    }
    Ok(())
}

fn host_issue(h: &str, origin: RuleOrigin) -> Option<String> {
    validate_rule(&Rule::read(h), origin)
        .into_iter()
        .find(|i| i.severity == Severity::Error)
        .map(|i| i.message)
}

/// mise's system-level config in the env: sandbox settings and the default toolchains.
/// Lowest precedence, so the user's ~/.config/mise and the project's files override it.
fn mise_conf(tools: &BTreeMap<String, toml::Value>) -> Result<String> {
    #[derive(Serialize)]
    struct Settings {
        /// The sandbox is the trust boundary; mise's prompt protects a host.
        trusted_config_paths: [&'static str; 1],
        idiomatic_version_file_enable_tools: &'static [&'static str],
    }
    #[derive(Serialize)]
    struct Conf<'a> {
        settings: Settings,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        tools: &'a BTreeMap<String, toml::Value>,
    }
    Ok(format!(
        "# Managed by luoto (`luoto up`). ~/.config/mise and the project's files take precedence.\n{}",
        toml::to_string(&Conf {
            settings: Settings {
                trusted_config_paths: ["/workspace"],
                idiomatic_version_file_enable_tools: IDIOMATIC_TOOLS,
            },
            tools,
        })?
    ))
}

struct Env<'a> {
    ctx: &'a Ctx,
    dev: String,
    /// The dev user's home directory.
    home: String,
    /// `HOME=<home>`, for exec.
    home_env: String,
}

impl<'a> Env<'a> {
    fn new(ctx: &'a Ctx, env: &str) -> Result<Self> {
        let dev = names::dev(env);
        let home = ctx
            .rt
            .run([
                "exec",
                &dev,
                "awk",
                "-F:",
                &format!("$3=={UID}{{print $6; exit}}"),
                "/etc/passwd",
            ])?
            .trim()
            .to_string();
        Ok(Env {
            ctx,
            dev,
            home_env: format!("HOME={home}"),
            home,
        })
    }

    /// `exec` as the dev user in `cwd`, with `extra` exec flags, running `argv`.
    fn exec_user<'b>(&'b self, cwd: &'b str, extra: &[&'b str], argv: &[&'b str]) -> Vec<&'b str> {
        let mut a = vec!["exec", "-u", UID, "-w", cwd, "-e", &self.home_env];
        a.extend_from_slice(extra);
        a.push(&self.dev);
        a.extend_from_slice(argv);
        a
    }

    fn step(&self, args: &[&str], what: &str) -> Result<()> {
        if !self.ctx.rt.interactive(args)?.success() {
            bail!("{what} failed");
        }
        Ok(())
    }

    /// Folders of the workspace that pin a toolchain (a monorepo's `frontend/`), the
    /// workspace itself first. mise only reads a folder's own pins and its parents'.
    fn project_dirs(&self) -> Vec<String> {
        crate::detect::pin_dirs(self.workspace_files().iter().map(String::as_str))
            .into_iter()
            .map(|d| {
                if d.is_empty() {
                    "/workspace".to_string()
                } else {
                    format!("/workspace/{d}")
                }
            })
            .collect()
    }

    /// The workspace's files, relative: from git in a work tree (.gitignore keeps
    /// dependencies out), else from `find`.
    fn workspace_files(&self) -> Vec<String> {
        let mut prune = String::from("-name '.*' ! -name .");
        for d in SKIP_DIRS {
            prune.push_str(&format!(" -o -name '{d}'"));
        }
        let script = format!(
            "cd /workspace || exit 0
             if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
               git ls-files --cached --others --exclude-standard
             else
               find . -maxdepth {} \\( {prune} \\) -prune -o -type f -print | sed 's|^\\./||'
             fi",
            DEPTH + 1
        );
        self.ctx
            .rt
            .run(self.exec_user("/workspace", &[], &["sh", "-c", &script]))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Tools mise would install in each project folder, decided offline (requested versions
    /// are enough; resolving them needs the network that is granted only afterwards). A
    /// folder that misses only what an earlier one does is left out: one install covers both.
    /// `configured` (the env's default tools) count as missing while none of them is installed:
    /// offline, mise can't resolve a version like `latest` and reports nothing for it.
    fn missing_tools(&self, configured: &[String]) -> Result<Vec<(String, Vec<String>)>> {
        let mut out = Vec::new();
        let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
        for dir in self.project_dirs() {
            let text = self.ctx.rt.run(self.exec_user(
                &dir,
                &["-e", "MISE_OFFLINE=1"],
                &["mise", "ls", "--current", "--missing", "--json"],
            ))?;
            let v: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(text.trim()).context("parse `mise ls` output")?;
            let mut tools = Vec::new();
            let mut new = false;
            for (tool, list) in v {
                let versions: Vec<String> = list
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e["version"].as_str().map(str::to_string))
                    .collect();
                if versions.is_empty() {
                    continue;
                }
                for version in versions {
                    new |= seen.insert((tool.clone(), version));
                }
                tools.push(tool);
            }
            if new {
                out.push((dir, tools));
            }
        }
        if !configured.is_empty() {
            let text = self.ctx.rt.run(self.exec_user(
                "/workspace",
                &["-e", "MISE_OFFLINE=1"],
                &["mise", "ls", "--installed", "--json"],
            ))?;
            let installed: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(text.trim()).context("parse `mise ls` output")?;
            let absent: Vec<String> = configured
                .iter()
                .filter(|t| {
                    installed
                        .get(t.as_str())
                        .and_then(|v| v.as_array())
                        .is_none_or(|a| a.is_empty())
                })
                .cloned()
                .collect();
            if !absent.is_empty() {
                match out.iter_mut().find(|(d, _)| d == "/workspace") {
                    Some((_, tools)) => {
                        for t in absent {
                            if !tools.contains(&t) {
                                tools.push(t);
                            }
                        }
                    }
                    None => out.insert(0, ("/workspace".to_string(), absent)),
                }
            }
        }
        Ok(out)
    }

    fn has_mise(&self) -> bool {
        self.ctx
            .rt
            .succeeds(["exec", &self.dev, "sh", "-c", "command -v mise >/dev/null"])
    }

    fn sync_mise_conf(&self, conf: &str) -> Result<()> {
        let current = self
            .ctx
            .rt
            .run(["exec", &self.dev, "cat", MISE_CONF])
            .unwrap_or_default();
        if current != conf {
            self.ctx.rt.run_stdin(
                [
                    "exec",
                    "-i",
                    "-u",
                    "0",
                    &self.dev,
                    "sh",
                    "-c",
                    r#"mkdir -p "${0%/*}" && cat >"$0""#,
                    MISE_CONF,
                ],
                conf.as_bytes(),
            )?;
        }
        Ok(())
    }
}

/// What still has to run; steps are cleared as they succeed, so a retry resumes.
struct Job {
    system: bool,
    /// Missing tools by the folder whose pins ask for them.
    tools: Vec<(String, Vec<String>)>,
    run: bool,
}

impl Job {
    fn tool_names(&self) -> BTreeSet<&str> {
        self.tools
            .iter()
            .flat_map(|(_, t)| t.iter().map(String::as_str))
            .collect()
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.system {
            parts.push("system packages".to_string());
        }
        if !self.tools.is_empty() {
            // Tool names come from mise in the env.
            let names = self.tool_names().into_iter().collect::<Vec<_>>().join(", ");
            parts.push(crate::text::display(&names));
        }
        if self.run {
            parts.push("setup commands".to_string());
        }
        parts.join(", ")
    }
}

fn run_job(e: &Env, d: &Deps, job: &mut Job) -> Result<()> {
    if job.system {
        let mut args = vec!["exec", "-u", "0", &e.dev, "sh", "-c", SYSTEM, "sh"];
        args.extend(d.system.iter().map(String::as_str));
        e.step(&args, "system packages")?;
        job.system = false;
    }
    while let Some((dir, _)) = job.tools.first().cloned() {
        e.step(
            &e.exec_user(&dir, &[], &["mise", "install", "--yes"]),
            &format!("mise install in {dir}"),
        )?;
        job.tools.remove(0);
    }
    if job.run {
        for cmd in &d.run {
            e.step(
                &e.exec_user(&e.home, &[], &["sh", "-c", LOGIN, cmd]),
                &format!("`{cmd}`"),
            )?;
        }
        job.run = false;
    }
    Ok(())
}

/// Hosts the gate denied for this env since `since`, as install-grant candidates.
fn denied_since(ctx: &Ctx, env: &str, since: chrono::DateTime<Utc>) -> Vec<String> {
    let since = (since - TimeDelta::seconds(5)).to_rfc3339();
    let evs = events::gate_events(&ctx.rt, env, Some(&since)).unwrap_or_default();
    events::summarize(&evs)
        .into_iter()
        .filter(|s| s.denied > 0 && host_issue(&s.host, RuleOrigin::Sandbox).is_none())
        .map(|s| s.host)
        .collect()
}

/// Bring the env's packages and toolchains up to date with its config and its project.
pub fn ensure(ctx: &Ctx, env: &str, cfg: &EnvConfig) -> Result<()> {
    let d = merged(&ctx.global.deps, &cfg.deps);
    check(&d, RuleOrigin::Host)?;
    let e = Env::new(ctx, env)?;
    let tools = tools_for(ctx, cfg);
    let mise = e.has_mise();
    let missing = if mise {
        e.sync_mise_conf(&mise_conf(&tools)?)?;
        e.missing_tools(&tools.keys().cloned().collect::<Vec<_>>())?
    } else {
        if !tools.is_empty() {
            eprintln!("note: the env's image has no mise, so [tools] are not installed");
        }
        Vec::new()
    };
    let marker = ctx
        .rt
        .run(["exec", &e.dev, "cat", MARKER])
        .ok()
        .map(|s| s.trim().to_string());
    let want = digest(&d);
    let packages = !(d.system.is_empty() && d.run.is_empty());
    let due = packages && marker.as_deref() != Some(want.as_str());
    if !due && missing.is_empty() {
        if !packages && marker.is_some() {
            ctx.rt
                .run(["exec", "-u", "0", &e.dev, "rm", "-f", MARKER])?;
        }
        return Ok(());
    }
    let mut job = Job {
        system: due && !d.system.is_empty(),
        tools: missing,
        run: due && !d.run.is_empty(),
    };

    let mut wanted: BTreeSet<String> = BTreeSet::new();
    if job.system
        && let Ok(id) = ctx.rt.run([
            "exec",
            &e.dev,
            "sh",
            "-c",
            r#". /etc/os-release 2>/dev/null; echo "$ID""#,
        ])
        && matches!(id.trim(), "debian" | "ubuntu" | "alpine")
    {
        wanted.insert(id.trim().to_string());
    }
    let names = job.tool_names();
    for p in presets::all() {
        if names.iter().any(|t| p.serves_tool(t)) {
            wanted.insert(p.name.clone());
        }
    }
    let granted: Vec<String> = wanted
        .into_iter()
        .filter(|p| !cfg.presets.contains(p))
        .collect();
    let mut hosts = d.hosts.clone();
    let mut asked = false;
    loop {
        let mut rules: Vec<Rule> = granted
            .iter()
            .filter_map(|p| presets::get(p))
            .flat_map(|p| p.rules)
            .collect();
        rules.extend(hosts.iter().map(|h| Rule::read(h)));
        let access: Vec<&str> = granted
            .iter()
            .chain(hosts.iter())
            .map(String::as_str)
            .collect();
        println!(
            "installing in `{env}`: {}{}…",
            job.describe(),
            if access.is_empty() {
                String::new()
            } else {
                format!(" (temporary access: {})", access.join(", "))
            }
        );
        let since = Utc::now();
        let res = env::with_grants(
            ctx,
            env,
            &rules,
            TimeDelta::minutes(30),
            "installing deps (auto-revoked)",
            || run_job(&e, &d, &mut job),
        )?;
        let Err(err) = res else { break };
        let denied: Vec<String> = denied_since(ctx, env, since)
            .into_iter()
            .filter(|h| !hosts.contains(h))
            .collect();
        if denied.is_empty() {
            return Err(err);
        }
        println!("the install was denied: {}", denied.join(", "));
        if asked
            || !confirm(&format!(
                "Allow them for installs in `{env}` (saved to [deps] hosts) and retry?"
            ))
        {
            bail!(
                "{err:#}; to allow the denied hosts for installs, add them to [deps] hosts: {}",
                denied.join(", ")
            );
        }
        asked = true;
        EnvFile::load(&ctx.paths, env)?.add_install_hosts(&denied)?;
        hosts.extend(denied);
    }
    if due {
        ctx.rt.run([
            "exec",
            "-u",
            "0",
            &e.dev,
            "sh",
            "-c",
            r#"mkdir -p "${1%/*}" && echo "$2" >"$1""#,
            "sh",
            MARKER,
            &want,
        ])?;
    }
    println!("installed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_appends_without_duplicates() {
        let g = Deps {
            system: vec!["git".into()],
            hosts: vec!["a.example".into()],
            ..Default::default()
        };
        let e = Deps {
            system: vec!["git".into(), "jq".into()],
            hosts: vec!["a.example".into(), "b.example".into()],
            ..Default::default()
        };
        let m = merged(&g, &e);
        assert_eq!(m.system, ["git", "jq"]);
        assert_eq!(m.hosts, ["a.example", "b.example"]);
    }

    #[test]
    fn rejects_bad_input() {
        let pkg = |p: &str| Deps {
            system: vec![p.into()],
            ..Default::default()
        };
        assert!(check(&pkg("-oAPT::x"), RuleOrigin::Host).is_err());
        assert!(check(&pkg("postgresql-client"), RuleOrigin::Host).is_ok());
        let hosts = |h: &str| Deps {
            hosts: vec![h.into()],
            ..Default::default()
        };
        assert!(check(&hosts("*.com"), RuleOrigin::Host).is_err());
        // A repository's luoto.toml gets the sandbox's checks: no `*`.
        assert!(check(&hosts("*"), RuleOrigin::Sandbox).is_err());
        assert!(check(&hosts("pypi.org"), RuleOrigin::Sandbox).is_ok());
    }

    #[test]
    fn mise_conf_has_settings_and_tools() {
        let tools = BTreeMap::from([
            ("node".to_string(), toml::Value::String("lts".into())),
            ("npm:pnpm".to_string(), toml::Value::String("latest".into())),
        ]);
        let v: toml::Value = toml::from_str(&mise_conf(&tools).unwrap()).unwrap();
        assert_eq!(v["tools"]["npm:pnpm"].as_str(), Some("latest"));
        assert_eq!(
            v["settings"]["trusted_config_paths"][0].as_str(),
            Some("/workspace")
        );
        let empty: toml::Value = toml::from_str(&mise_conf(&BTreeMap::new()).unwrap()).unwrap();
        assert!(empty.get("tools").is_none());
    }
}

#[cfg(test)]
mod framed_tests {
    use super::*;

    #[test]
    fn each_file_is_read_by_its_length_and_anything_else_stops_it() {
        let paths: Vec<String> = ["a", "b", "c", "d"].map(String::from).to_vec();
        let t = framed(&paths, b"3\nx\ny-\n  2\nzz");
        assert_eq!(t.get("a").map(String::as_str), Some("x\ny"));
        assert_eq!(t.get("c").map(String::as_str), Some("zz"));
        assert_eq!(t.len(), 2, "b is absent and d never came");
        assert!(framed(&paths, b"9\nshort").is_empty());
        assert!(framed(&paths, b"x\n").is_empty());
    }
}
