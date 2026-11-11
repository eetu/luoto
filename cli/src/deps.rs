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
use luoto_shared::policy::{Rule, RuleOrigin, rule_error};
use luoto_shared::{presets, profiles};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{Deps, EnvConfig, EnvFile, extend_unique};
use crate::connect::LOGIN;
use crate::detect::{self, DEPTH, Detected, IDIOMATIC_TOOLS, SKIP_DIRS};
use crate::env::{Ctx, UID};
use crate::logs::InstallLog;
use crate::prompt::confirm;
use crate::workspace::{self, Oversize};
use crate::{events, names, sync};

const MARKER: &str = "/var/lib/luoto/deps";
const MISE_CONF: &str = "/etc/mise/conf.d/luoto.toml";
/// Bump when the package/command steps change meaning, so every env reruns them.
const VERSION: u32 = 2;

const SYSTEM: &str = r#"set -e
# Python packages byte-compile as they install, and older ones warn about their own docstrings.
export PYTHONWARNINGS=ignore::SyntaxWarning
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  # A source the env doesn't allow (luoto-base lists cli.github.com) fails the update; apt
  # leaves that source out and installs from the rest.
  apt-get update -q || echo "luoto: a package source could not be read; using the others" >&2
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
    extend_unique(&mut d.system, env.system.iter().cloned());
    d.run.extend(env.run.iter().cloned());
    extend_unique(&mut d.hosts, env.hosts.iter().cloned());
    d
}

/// Default toolchains for the env, lowest precedence first: agents' needs, config.toml's
/// `[tools]`, the env's `[tools]`.
pub fn tools_for(ctx: &Ctx, cfg: &EnvConfig) -> BTreeMap<String, toml::Value> {
    let mut t = BTreeMap::new();
    for a in cfg.agents.names().filter_map(|a| profiles::agent(a)) {
        for (k, v) in a.tools {
            t.insert(k, toml::Value::String(v));
        }
    }
    t.extend(ctx.global.tools.clone());
    t.extend(cfg.tools.clone());
    t
}

/// What the env's workspace says about itself ([`detect`]), read inside it, where the work
/// happens. Two calls into the env: the file list, then the few files detection reads.
pub fn detect_in_env(ctx: &Ctx, env: &str) -> Result<Detected> {
    let _waiting = crate::progress::waiting("reading the project's files");
    let files = workspace_files(ctx, &names::dev(env));
    let wanted = detect::read_paths(&files);
    let texts = workspace::read_files(ctx, env, &wanted, detect::READ_CAP, Oversize::Truncate)?
        .into_iter()
        .filter_map(|(rel, b)| Some((rel, String::from_utf8(b).ok()?)))
        .collect();
    Ok(detect::detect_tree(&detect::Listed { files, texts }))
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
    rule_error(&Rule::read(h), origin).map(|i| i.message)
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

/// The workspace's files, relative: from git in a work tree (.gitignore keeps dependencies
/// out), else from `find`; and those of each repository directly in it (the env's repos),
/// which git in the folder doesn't list.
fn workspace_files(ctx: &Ctx, dev: &str) -> Vec<String> {
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
         fi
         for d in */; do
           [ -e \"$d.git\" ] || continue
           git -C \"$d\" ls-files --cached --others --exclude-standard |
             while IFS= read -r f; do printf '%s%s\\n' \"$d\" \"$f\"; done
         done
         true",
        DEPTH + 1
    );
    let mut files: Vec<String> = ctx
        .rt
        .run([
            "exec",
            "-u",
            UID,
            "-w",
            "/workspace",
            dev,
            "sh",
            "-c",
            &script,
        ])
        .unwrap_or_default()
        .lines()
        // git lists a repository in the folder as `name/`; its files come from its own git.
        .filter(|l| !l.ends_with('/'))
        .map(str::to_string)
        .collect();
    files.sort();
    files.dedup();
    files
}

/// What `ensure` reads of the env, framed as `workspace::read_files` frames files: mise's path,
/// the mise config at `$0`, the marker at `$1` and the distribution's ID.
const PROBE: &str = r#"word() { printf '%s\n' "$(printf %s "$1" | wc -c)"; printf %s "$1"; }
file() { if [ -f "$1" ]; then printf '%s\n' "$(wc -c <"$1")"; cat -- "$1"; else printf -- '-\n'; fi; }
if m=$(command -v mise); then word "$m"; else printf -- '-\n'; fi
file "$0"
file "$1"
word "$(. /etc/os-release 2>/dev/null; echo "$ID")""#;

/// What the env holds of what `ensure` installs.
struct Probe {
    mise: bool,
    /// The mise config luoto wrote (`MISE_CONF`).
    conf: Option<String>,
    /// The digest of the `[deps]` last installed (`MARKER`).
    marker: Option<String>,
    /// `ID` from os-release.
    os: String,
}

impl Probe {
    fn parse(out: &[u8]) -> Self {
        let mut found = workspace::framed(&["mise", "conf", "marker", "os"], out, detect::READ_CAP);
        let mut text = |k: &str| {
            found
                .remove(k)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        };
        Probe {
            mise: text("mise").is_some(),
            conf: text("conf"),
            marker: text("marker").map(|m| m.trim().to_string()),
            os: text("os").unwrap_or_default().trim().to_string(),
        }
    }
}

struct Env<'a> {
    ctx: &'a Ctx,
    dev: String,
    /// The dev user's home directory.
    home: &'a str,
    /// `HOME=<home>`, for exec.
    home_env: String,
    log: InstallLog,
}

impl<'a> Env<'a> {
    fn new(ctx: &'a Ctx, env: &str, home: &'a str) -> Self {
        Env {
            ctx,
            dev: names::dev(env),
            home_env: format!("HOME={home}"),
            home,
            log: InstallLog::new(&ctx.paths, env),
        }
    }

    fn probe(&self) -> Result<Probe> {
        let out = self
            .ctx
            .rt
            .run(["exec", &self.dev, "sh", "-c", PROBE, MISE_CONF, MARKER])?;
        Ok(Probe::parse(out.as_bytes()))
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
        let status = self.log.run(&self.ctx.rt, args)?;
        if !status.success() {
            self.log.note(&format!("{what} failed ({status})"));
            bail!("{what} failed");
        }
        Ok(())
    }

    /// Folders of the workspace that pin a toolchain (a monorepo's `frontend/`), the
    /// workspace itself first. mise only reads a folder's own pins and its parents'.
    fn project_dirs(&self) -> Vec<String> {
        let files = workspace_files(self.ctx, &self.dev);
        crate::detect::pin_dirs(files.iter().map(String::as_str))
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
                    Some((_, tools)) => extend_unique(tools, absent),
                    None => out.insert(0, ("/workspace".to_string(), absent)),
                }
            }
        }
        Ok(out)
    }

    fn write_mise_conf(&self, conf: &str) -> Result<()> {
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
                &e.exec_user(e.home, &[], &["sh", "-c", LOGIN, cmd]),
                &format!("`{cmd}`"),
            )?;
        }
        job.run = false;
    }
    Ok(())
}

/// The presets (luoto's own data) that serve `tools` and `have` lacks: installing those tools
/// opens them for as long as the install runs.
pub fn install_presets<'a>(
    tools: impl IntoIterator<Item = &'a str>,
    have: &[String],
) -> Vec<String> {
    let tools: BTreeSet<&str> = tools.into_iter().collect();
    presets::all()
        .into_iter()
        .filter(|p| tools.iter().any(|t| p.serves_tool(t)) && !have.contains(&p.name))
        .map(|p| p.name)
        .collect()
}

/// Hosts the gate denied for this env since `since`, as install-grant candidates: neither a
/// muted denial nor an explicit deny's, which no grant lifts.
fn denied_since(
    ctx: &Ctx,
    env: &str,
    since: chrono::DateTime<Utc>,
    mutes: &events::Mutes,
) -> Vec<String> {
    let since = (since - TimeDelta::seconds(5)).to_rfc3339();
    let mut evs = events::gate_events(&ctx.rt, env, Some(&since)).unwrap_or_default();
    mutes.hide(&mut evs);
    evs.retain(|e| e.reason.as_deref() != Some("explicit"));
    events::summarize(&evs, mutes)
        .into_iter()
        .filter(|s| s.denied > 0 && host_issue(&s.host, RuleOrigin::Sandbox).is_none())
        .map(|s| s.host)
        .collect()
}

/// Bring the env's packages and toolchains up to date with its config and its project; `home`
/// is the dev user's.
pub fn ensure(ctx: &Ctx, env: &str, cfg: &EnvConfig, home: &str) -> Result<()> {
    let d = merged(&ctx.global.deps, &cfg.deps);
    check(&d, RuleOrigin::Host)?;
    let e = Env::new(ctx, env, home);
    let mutes = events::Mutes::new(&cfg.mute);
    let tools = tools_for(ctx, cfg);
    let checking = crate::progress::waiting("checking the env's toolchains");
    let found = e.probe()?;
    let missing = if found.mise {
        let conf = mise_conf(&tools)?;
        if found.conf.as_deref() != Some(conf.as_str()) {
            e.write_mise_conf(&conf)?;
        }
        e.missing_tools(&tools.keys().cloned().collect::<Vec<_>>())?
    } else {
        if !tools.is_empty() {
            crate::progress::say(|| {
                eprintln!("note: the env's image has no mise, so [tools] are not installed")
            });
        }
        Vec::new()
    };
    drop(checking);
    let marker = found.marker;
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

    let mut granted = Vec::new();
    if job.system
        && matches!(found.os.as_str(), "debian" | "ubuntu" | "alpine")
        && !cfg.presets.contains(&found.os)
    {
        granted.push(found.os);
    }
    extend_unique(
        &mut granted,
        install_presets(job.tool_names(), &cfg.presets),
    );
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
        let what = format!(
            "installing in `{env}`: {}{}",
            job.describe(),
            if access.is_empty() {
                String::new()
            } else {
                format!(" (temporary access: {})", access.join(", "))
            }
        );
        e.log.note(&what);
        let since = Utc::now();
        let res = crate::progress::step(&what, || {
            sync::with_grants(
                ctx,
                env,
                &rules,
                TimeDelta::minutes(30),
                "installing deps (auto-revoked)",
                || run_job(&e, &d, &mut job),
            )
        })?;
        let Err(err) = res else { break };
        let denied: Vec<String> = denied_since(ctx, env, since, &mutes)
            .into_iter()
            .filter(|h| !hosts.contains(h))
            .collect();
        if denied.is_empty() {
            return Err(err);
        }
        let note = format!("the install was denied: {}", denied.join(", "));
        println!("{note}");
        e.log.note(&note);
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
    e.log.note("installed");
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

    #[cfg(unix)]
    #[test]
    fn the_probe_frames_files_exactly() {
        let d = tempfile::tempdir().unwrap();
        let conf = d.path().join("luoto.toml");
        std::fs::write(&conf, "[settings]\n\n").unwrap();
        let out = std::process::Command::new("sh")
            .args(["-c", PROBE])
            .arg(&conf)
            .arg(d.path().join("absent"))
            .output()
            .unwrap();
        let p = Probe::parse(&out.stdout);
        assert_eq!(p.conf.as_deref(), Some("[settings]\n\n"));
        assert_eq!(p.marker, None);
    }

    #[test]
    fn installs_open_github_release_files_an_env_without_them_leaves_shut() {
        let without: Vec<String> = ["debian", "github", "toolchains"]
            .map(String::from)
            .to_vec();
        assert_eq!(install_presets(["python"], &without), ["github-releases"]);
        assert_eq!(install_presets(["go"], &without), ["go", "github-releases"]);
        let defaults: Vec<String> = crate::init::DEFAULT_PRESETS
            .iter()
            .map(|p| p.to_string())
            .collect();
        assert!(install_presets(["python"], &defaults).is_empty());
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
    }
}
