//! Getting into an env: shells and editors. Both go through the runtime's `exec` (editors
//! over SSH via `ssh-proxy`), so no network port is opened into the sandbox.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use luoto_shared::profiles::{self, Editor, EditorSetting};

use crate::env::{Ctx, UID};
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
/// values). The runtime says only `xterm`, and this terminal's own name (`xterm-ghostty`,
/// `xterm-kitty`) may have no terminfo in the image, so `xterm-256color`, which every image
/// has; and `COLORTERM` as it is here, for true colour.
fn terminal_env() -> Vec<String> {
    let mut env = vec!["TERM=xterm-256color".to_string()];
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
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mut args: Vec<String> = vec!["exec".into(), "-i".into()];
    if tty {
        args.push("-t".into());
    }
    args.extend(["-u".into(), UID.into(), "-w".into(), "/workspace".into()]);
    if tty {
        for e in terminal_env() {
            args.extend(["-e".into(), e]);
        }
    }
    args.extend([
        names::dev(name),
        "sh".into(),
        "-c".into(),
        LOGIN.into(),
        inner.into(),
    ]);
    let status = ctx.rt.interactive(&args)?;
    Ok(ExitCode::from(
        status.code().unwrap_or(1).clamp(0, 255) as u8
    ))
}

pub fn shell(name: &str, cmd: &[String]) -> Result<ExitCode> {
    let ctx = Ctx::load()?;
    let inner = if cmd.is_empty() {
        // The dev user's own login shell (fish in luoto-base).
        format!(r#"s=$(awk -F: '$3=={UID}{{print $7}}' /etc/passwd); exec "${{s:-/bin/sh}}" -l"#)
    } else {
        format!(
            "exec {}",
            cmd.iter()
                .map(|c| crate::text::sh_quote(c))
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
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

/// The editor to open: `--with`, then `editor` in config.toml, then the first installed one.
fn pick_editor(ctx: &Ctx, with: Option<&str>) -> Result<Editor> {
    let name = match with
        .map(str::to_string)
        .or_else(|| ctx.global.editor.clone())
    {
        Some(n) => n,
        None => profiles::editor_names()
            .filter_map(profiles::editor)
            .find(|e| e.launch.first().is_some_and(|p| on_path(p)))
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
    let editor = pick_editor(&ctx, with)?;
    let host = names::dev(name);
    let user =
        EnvState::load(&ctx.paths, name)?.map_or_else(|| "dev".into(), |s| s.login().to_string());
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
    if editor.launch.is_empty() {
        println!(
            "Connect to SSH host `{host}` as `{user}` and open /workspace \
             (the host entry is in {}).",
            config.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(hint) = &editor.hint {
        println!("{hint}");
    }
    let mut argv: Vec<String> = editor.launch.iter().map(|a| fill(a)).collect();
    if cfg!(windows)
        && let Some(w) = &editor.windows_program
    {
        argv[0] = w.clone();
    }
    match std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status()
    {
        Ok(s) if s.success() => Ok(ExitCode::SUCCESS),
        _ => {
            println!(
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
        .args([
            "exec",
            "-i",
            "-u",
            "0",
            &names::dev(name),
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
        ])
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
    println!("{url} → port {env_port} in `{name}` (Ctrl-C stops)");
    if open_browser {
        let _ = open::that(&url);
    }
    loop {
        std::thread::park();
    }
}
