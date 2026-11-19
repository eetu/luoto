//! Getting into an env: shells and editors. Both go through the runtime's `exec` (editors
//! over SSH via `ssh-proxy`), so no network port is opened into the sandbox.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use luoto_shared::profiles::{self, Editor, EditorSetting};

use crate::env::{Ctx, UID};
use crate::runtime::exec;
use crate::state::EnvState;
use crate::{names, ssh};

pub fn ensure_running(ctx: &Ctx, name: &str) -> Result<()> {
    if !ctx.rt.is_running(&names::dev(name)) {
        bail!("env `{name}` is not running — `luoto up -e {name}`");
    }
    // Forwards and idle stop follow every session (a newer luoto replaces an older watcher).
    crate::watch::spawn(ctx);
    Ok(())
}

/// `sh -c LOGIN <script>` runs the script in a bash (else sh) login shell, so
/// /run/luoto/env.sh and profile.d are sourced.
pub const LOGIN: &str =
    r#"if command -v bash >/dev/null 2>&1; then exec bash -lc "$0"; else exec sh -lc "$0"; fi"#;

/// What a terminal session in the env is told about the terminal it runs in (`exec -e`
/// values). The runtime says only `xterm`: `term` is this terminal's own name where the env
/// has its terminfo entry, else `xterm-256color` (`terminfo::term_for`); and `COLORTERM` as
/// it is here, for true colour.
fn terminal_env(term: &str) -> Vec<String> {
    let mut env = vec![format!("TERM={term}")];
    if let Ok(c) = std::env::var("COLORTERM")
        && (c == "truecolor" || c == "24bit")
    {
        env.push(format!("COLORTERM={c}"));
    }
    env
}

/// Run `inner` with a login shell as the dev user.
pub fn exec_login(ctx: &Ctx, name: &str, inner: &str) -> Result<ExitCode> {
    ensure_running(ctx, name)?;
    login(ctx, name, inner)
}

/// A session in the env (a shell, an agent): `inner` as [`exec_login`] runs it, then what the
/// gate denied meanwhile, on stderr; what ran in it may not have said.
pub fn session(ctx: &Ctx, name: &str, inner: &str) -> Result<ExitCode> {
    ensure_running(ctx, name)?;
    let gate_at_start = crate::agents::GateMark::now(ctx, name);
    let code = login(ctx, name, inner)?;
    if let Ok(evs) = gate_at_start.since(ctx, name) {
        crate::progress::summary(&crate::events::fmt_denials(
            name,
            "session",
            &crate::events::denials(&evs),
        ));
    }
    Ok(code)
}

fn login(ctx: &Ctx, name: &str, inner: &str) -> Result<ExitCode> {
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut e = exec(&names::dev(name)).stdin();
    if tty {
        e = e.tty();
    }
    e = e.user(UID).cwd("/workspace");
    if tty {
        for var in terminal_env(&crate::terminfo::term_for(ctx, name, UID)) {
            e = e.env(&var);
        }
    }
    let args = e.argv(["sh", "-c", LOGIN, inner]);
    let status = ctx.rt.interactive(&args)?;
    // A session (a shell, an agent) is where builds fill the disk.
    if tty {
        crate::disk::hint_growth(ctx, name);
    }
    Ok(ExitCode::from(
        status.code().unwrap_or(1).clamp(0, 255) as u8
    ))
}

pub fn shell(name: &str, cmd: &[String]) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    if cmd.is_empty() {
        // The dev user's own login shell (fish in luoto-base).
        let inner = format!(
            r#"s=$(awk -F: '$3=={UID}{{print $7}}' /etc/passwd); exec "${{s:-/bin/sh}}" -l"#
        );
        return session(&ctx, name, &inner);
    }
    let inner = format!(
        "exec {}",
        cmd.iter()
            .map(|c| crate::text::sh_quote(c))
            .collect::<Vec<_>>()
            .join(" ")
    );
    exec_login(&ctx, name, &inner)
}

/// The settings file an editor profile names, with `{home}` and `{config}` filled in.
fn settings_file(setting: &EditorSetting) -> Option<PathBuf> {
    let base = directories::BaseDirs::new()?;
    let template = match (&setting.windows_file, cfg!(windows)) {
        (Some(w), true) => w,
        _ => &setting.file,
    };
    Some(PathBuf::from(
        template
            .replace("{home}", &base.home_dir().to_string_lossy())
            .replace("{config}", &base.config_dir().to_string_lossy()),
    ))
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|d| {
            d.join(program).is_file()
                || (cfg!(windows) && d.join(format!("{program}.exe")).is_file())
        })
    })
}

use luoto_shared::profiles::Requirement;

/// What an env has that an editor may require ([`Requirement`]), read in the env.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    /// `/workspace` is a git work tree.
    pub git_repo: bool,
    /// Repositories in folders of `/workspace`.
    pub repos: usize,
}

/// Prints `true` where /workspace is a work tree, then the number of repos in its folders.
const FACTS: &str = "git -C /workspace rev-parse --is-inside-work-tree 2>/dev/null; \
                     ls -d /workspace/*/.git 2>/dev/null | wc -l";

impl Facts {
    /// The facts of `env`, as its `user` sees them: one exec. `None` where the env doesn't
    /// answer, and then nothing is held against an editor.
    pub fn of(ctx: &Ctx, env: &str, user: &str) -> Option<Facts> {
        let script = crate::runtime::exec(&names::dev(env)).user(user).sh(FACTS);
        ctx.rt.run(script).ok().map(|out| Facts::read(&out))
    }

    fn read(output: &str) -> Facts {
        let mut lines = output.lines().map(str::trim);
        Facts {
            git_repo: lines.clone().any(|l| l == "true"),
            repos: lines.next_back().and_then(|l| l.parse().ok()).unwrap_or(0),
        }
    }

    fn meets(self, requirement: Requirement) -> bool {
        match requirement {
            Requirement::GitRepo => self.git_repo,
        }
    }
}

/// What `editor` requires that the env lacks; nothing where its facts aren't known.
pub fn unmet(editor: &Editor, facts: Option<Facts>) -> Option<Requirement> {
    let facts = facts?;
    editor.requires.iter().copied().find(|r| !facts.meets(*r))
}

/// The editors an env with `facts` can open, in luoto's order: what `up` offers, what `open`
/// picks from, and the alternatives a refusal names.
pub fn openable(facts: Option<Facts>) -> Vec<Editor> {
    profiles::editor_names()
        .filter_map(profiles::editor)
        .filter(|e| unmet(e, facts).is_none())
        .collect()
}

/// What `up` says to do next with agents and an editor: each a key, its command and what
/// stands after it. Without a terminal workspace the env can run there is no `agents:`.
pub fn offers(env: &str, facts: Option<Facts>) -> Vec<(&'static str, String, String)> {
    let (in_env, editors): (Vec<_>, Vec<_>) = openable(facts).into_iter().partition(Editor::in_env);
    let names = |es: &[Editor]| {
        es.iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>()
            .join("|")
    };
    let mut out = Vec::new();
    if !in_env.is_empty() {
        out.push((
            "agents:",
            format!("luoto open -e {env} --with {}", names(&in_env)),
            String::new(),
        ));
    }
    out.push((
        "editor:",
        format!("luoto open -e {env}"),
        format!("   (or --with {})", names(&editors)),
    ));
    out
}

/// Why `editor` can't open `env`, which lacks `missing`, and what can instead.
pub fn refusal(editor: &Editor, missing: Requirement, facts: Facts, env: &str) -> String {
    let name = &editor.name;
    let (needs, has) = match missing {
        Requirement::GitRepo => (
            "/workspace to be one git repository",
            match facts.repos {
                0 => "this env's isn't one".to_string(),
                1 => "this env's holds 1 repo in a folder".to_string(),
                n => format!("this env's holds {n} repos"),
            },
        ),
    };
    let others: Vec<String> = openable(Some(facts))
        .into_iter()
        .filter(|e| e.in_env() == editor.in_env())
        .map(|e| e.name)
        .collect();
    let mut text = format!("{name} needs {needs}; {has}");
    if let Some((first, rest)) = others.split_first() {
        text.push_str(&format!(": `luoto open -e {env} --with {first}`"));
        if !rest.is_empty() {
            text.push_str(&format!(" (or {})", rest.join(", ")));
        }
        text.push_str(" opens without one");
    }
    if missing == Requirement::GitRepo && facts.repos > 0 {
        text.push_str(&format!(
            ", or start {name} in one repo from `luoto shell -e {env}`"
        ));
    }
    text
}

/// The editor to open: `--with`, then `editor` in config.toml, then the first installed one
/// the env can open (`facts`, read only when an editor requires something).
fn pick_editor(ctx: &Ctx, with: Option<&str>, facts: &dyn Fn() -> Option<Facts>) -> Result<Editor> {
    let name = match with
        .map(str::to_string)
        .or_else(|| ctx.global.editor.clone())
    {
        Some(n) => n,
        // An editor on this machine; a terminal workspace in the env only when asked for.
        None => profiles::editor_names()
            .filter_map(profiles::editor)
            .find(|e| {
                !e.in_env()
                    && e.launch.first().is_some_and(|p| on_path(p))
                    && (e.requires.is_empty() || unmet(e, facts()).is_none())
            })
            .map_or_else(|| "ssh".to_string(), |e| e.name),
    };
    profiles::editor(&name).with_context(|| {
        format!(
            "unknown editor `{name}` (known: {})",
            profiles::editor_names().collect::<Vec<_>>().join(", ")
        )
    })
}

/// Open the env in an editor over SSH: the editor's window runs on the host; its language
/// servers, extensions, tasks and terminals run in the sandbox.
/// How long an install in the env has the access it needs.
const TOOL_INSTALL_FOR: chrono::TimeDelta = chrono::TimeDelta::minutes(15);

/// Install `tool` in the env with mise unless it has it: the presets that serve it open for the
/// install only (as for toolchains), and it runs as the env's user, on its login PATH.
fn ensure_tool(
    ctx: &Ctx,
    env: &str,
    user: &str,
    tool: &luoto_shared::profiles::EditorTool,
) -> Result<()> {
    let dev = names::dev(env);
    let program = crate::text::sh_quote(&tool.program);
    if ctx
        .rt
        .exec_sh(&dev, user, &format!("command -v {program} >/dev/null"))
    {
        return Ok(());
    }
    let cfg = crate::config::EnvFile::load(&ctx.paths, env)?.cfg;
    let presets = crate::deps::install_presets([tool.mise.as_str()], &cfg.presets);
    let rules: Vec<luoto_shared::policy::Rule> = presets
        .iter()
        .filter_map(|p| luoto_shared::presets::get(p))
        .flat_map(|p| p.rules)
        .collect();
    let install = format!("mise use -g --yes {}", crate::text::sh_quote(&tool.mise));
    let args = crate::runtime::exec(&dev).user(user).login_sh(&install);
    let note = format!("installing {} in `{env}`", tool.program);
    let status = crate::progress::step(&note, || {
        crate::sync::with_grants(ctx, env, &rules, TOOL_INSTALL_FOR, &note, || {
            crate::progress::tool(&ctx.rt, &args, &|_| {})
        })
    })??;
    if !status.success() {
        bail!(
            "{} didn't install in `{env}`; `luoto egress -e {env}` shows what the gate refused",
            tool.program
        );
    }
    Ok(())
}

pub fn open(name: &str, with: Option<&str>) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    ensure_running(&ctx, name)?;
    if !ssh::authorize(&ctx, name)? {
        bail!(
            "the env image has no OpenSSH server (/usr/sbin/sshd); install openssh-server in the image"
        );
    }
    let config = ssh::write_config(&ctx)?;
    if !ssh::include_present(&ctx.paths) {
        println!(
            "Editors find envs through ~/.ssh/config. {}",
            ssh::include_hint(&ctx)
        );
        return Ok(ExitCode::FAILURE);
    }
    let host = names::dev(name);
    let user =
        EnvState::load(&ctx.paths, name)?.map_or_else(|| "dev".into(), |s| s.login().to_string());
    let read = std::cell::OnceCell::new();
    let facts = || *read.get_or_init(|| Facts::of(&ctx, name, &user));
    let editor = pick_editor(&ctx, with, &facts)?;
    // Before anything is installed or attached to.
    if !editor.requires.is_empty()
        && let Some(found) = facts()
        && let Some(missing) = unmet(&editor, Some(found))
    {
        bail!("{}", refusal(&editor, missing, found, name));
    }
    let fill = |s: &str| {
        s.replace("{host}", &host)
            .replace("{user}", &user)
            .replace("{path}", "/workspace")
    };
    if let Some(setting) = &editor.setting
        && let Some(file) = settings_file(setting)
        && !std::fs::read_to_string(&file).is_ok_and(|t| t.contains(&fill(&setting.contains)))
    {
        let snippet: Vec<String> = fill(&setting.snippet)
            .lines()
            .map(|l| format!("    {l}"))
            .collect();
        println!(
            "One-time setup: add this to {} {}.\n\n{}\n",
            ssh::tilde(&file),
            setting.why,
            snippet.join("\n")
        );
    }
    // What attaches a terminal over SSH sends its name along.
    let term = (editor.launch.is_empty() || editor.in_env())
        .then(|| crate::terminfo::term_for(&ctx, name, &user));
    if editor.launch.is_empty() {
        out!(
            "Connect to SSH host `{host}` as `{user}` and open /workspace \
             (the host entry is in {}).",
            config.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(tool) = &editor.tool {
        ensure_tool(&ctx, name, &user, tool)?;
    }
    if let Some(hint) = &editor.hint {
        out_text!("{hint}");
    }
    let mut argv: Vec<String> = editor.launch.iter().map(|a| fill(a)).collect();
    if cfg!(windows)
        && let Some(w) = &editor.windows_program
    {
        argv[0] = w.clone();
    }
    let mut launch = std::process::Command::new(&argv[0]);
    launch.args(&argv[1..]);
    if let Some(term) = &term {
        launch.env("TERM", term);
    }
    match launch.status() {
        Ok(s) if s.success() => Ok(ExitCode::SUCCESS),
        // It ran in the env and said why it stopped there.
        Ok(_) if editor.in_env() => Ok(ExitCode::FAILURE),
        _ => {
            out!(
                "could not start `{}`; install its command-line launcher, or run: {}",
                argv[0],
                argv.join(" ")
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

/// SSH transport over `exec -i … sshd -i`. Remote-to-local forwarding (a path out of the
/// sandbox) is refused server-side; agent and X11 forwarding are off.
pub fn ssh_proxy(name: &str) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let status = ctx
        .rt
        .command()
        .args(exec(&names::dev(name)).stdin().user("0").argv([
            "/usr/sbin/sshd",
            "-i",
            "-e",
            "-o",
            "AllowAgentForwarding=no",
            "-o",
            "X11Forwarding=no",
            "-o",
            "PermitTunnel=no",
            "-o",
            "AllowTcpForwarding=local",
            "-o",
            "AllowStreamLocalForwarding=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
        ]))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::null())
        .status()?;
    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Forward one port by hand, e.g. to another local port (`luoto forward 8080:5173`); the
/// watcher already forwards each port an env listens on to the same port here.
pub fn forward(name: &str, spec: &str, open_browser: bool) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    ensure_running(&ctx, name)?;
    let (local, env_port) = crate::ports::parse_spec(spec)?;
    let _forward = crate::ports::Forward::start(&ctx.rt, &names::dev(name), local, env_port)
        .with_context(|| {
            format!("pick another local port: `luoto forward -e {name} <local>:{env_port}`")
        })?;
    let url = format!("http://localhost:{local}");
    out!("{url} → port {env_port} in `{name}` (Ctrl-C stops)");
    if open_browser {
        let _ = open::that(&url);
    }
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAUNCHPAD: Facts = Facts {
        git_repo: false,
        repos: 3,
    };
    const REPO: Facts = Facts {
        git_repo: true,
        repos: 0,
    };

    #[test]
    fn an_envs_facts_are_read_from_what_its_check_prints() {
        assert_eq!(Facts::read("true\n0\n"), REPO);
        assert_eq!(Facts::read("       3\n"), LAUNCHPAD);
        // A bare repository says `false`; nothing printed is nothing known to be there.
        assert!(!Facts::read("false\n1\n").git_repo);
        assert_eq!(
            Facts::read(""),
            Facts {
                git_repo: false,
                repos: 0
            }
        );
    }

    #[test]
    fn an_env_is_offered_only_the_editors_whose_requirements_it_meets() {
        let names =
            |facts| -> Vec<String> { openable(facts).into_iter().map(|e| e.name).collect() };
        let all: Vec<String> = profiles::editor_names().map(str::to_string).collect();
        assert_eq!(names(Some(REPO)), all);
        // Unknown facts hold nothing against an editor.
        assert_eq!(names(None), all);
        let launchpad = names(Some(LAUNCHPAD));
        assert!(!launchpad.contains(&"claude-squad".to_string()));
        assert_eq!(launchpad.len(), all.len() - 1);

        let squad = profiles::editor("claude-squad").unwrap();
        assert_eq!(unmet(&squad, Some(LAUNCHPAD)), Some(Requirement::GitRepo));
        assert_eq!(unmet(&squad, Some(REPO)), None);
        assert_eq!(unmet(&squad, None), None);
        assert_eq!(
            unmet(&profiles::editor("herdr").unwrap(), Some(LAUNCHPAD)),
            None
        );
    }

    #[test]
    fn up_offers_a_launchpad_no_editor_that_needs_one_repository() {
        assert_eq!(
            offers("web", Some(REPO)),
            [
                (
                    "agents:",
                    "luoto open -e web --with herdr|zellij|tmux|claude-squad".to_string(),
                    String::new()
                ),
                (
                    "editor:",
                    "luoto open -e web".to_string(),
                    "   (or --with zed|code|cursor|ssh)".to_string()
                ),
            ]
        );
        let launchpad = offers("web", Some(LAUNCHPAD));
        assert_eq!(launchpad[0].1, "luoto open -e web --with herdr|zellij|tmux");
        assert_eq!(launchpad[1], offers("web", Some(REPO))[1]);
    }

    #[test]
    fn an_editor_that_cant_open_says_what_it_needs_and_what_opens_instead() {
        let squad = profiles::editor("claude-squad").unwrap();
        assert_eq!(
            refusal(&squad, Requirement::GitRepo, LAUNCHPAD, "web"),
            "claude-squad needs /workspace to be one git repository; this env's holds 3 repos: \
             `luoto open -e web --with herdr` (or zellij, tmux) opens without one, or start \
             claude-squad in one repo from `luoto shell -e web`"
        );
        // A folder that is no repository and holds none: nowhere to start it.
        let plain = Facts {
            git_repo: false,
            repos: 0,
        };
        assert_eq!(
            refusal(&squad, Requirement::GitRepo, plain, "web"),
            "claude-squad needs /workspace to be one git repository; this env's isn't one: \
             `luoto open -e web --with herdr` (or zellij, tmux) opens without one"
        );
    }
}
