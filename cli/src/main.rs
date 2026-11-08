//! luoto — supply-chain-safe dev sandboxes. Every dev tool runs in a container whose only
//! way out is a policy gate you control; secrets stay in a vault outside the sandbox.

mod agents;
mod azure;
mod azure_identity;
mod ca;
mod commands;
mod compile;
mod complete;
mod config;
mod connect;
mod ctl;
mod deps;
mod detect;
mod env;
mod events;
mod format;
mod idle;
mod init;
mod logs;
mod machine;
mod names;
mod notify;
mod paths;
mod personal;
mod ports;
mod project;
mod prompt;
mod release;
mod report;
mod repos;
mod rules;
mod runtime;
mod secrets;
mod setup;
mod ssh;
mod state;
mod sync;
mod text;
mod ui;
mod uninstall;
mod upgrade;
mod watch;
mod wizard;
mod workspace;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::CompleteEnv;
use clap_complete::engine::ArgValueCandidates;

#[derive(Parser)]
#[command(
    name = "luoto",
    version,
    about = "Supply-chain-safe dev sandboxes: every tool inside, egress only through a policy you control",
    after_help = "Start with `luoto setup`, then run `luoto init` in a project folder; `luoto ui` opens the web UI.\n\
                  Commands act on the env of the current folder; `-e NAME` picks another."
)]
struct Cli {
    /// Env to act on (default: the env of the current folder).
    #[arg(short = 'e', long = "env", global = true, value_name = "ENV",
          add = ArgValueCandidates::new(complete::envs))]
    env: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Detect the host, recommend/install a container runtime, prepare images.
    Setup(setup::SetupOpts),
    /// Check the runtime, images, vault and every env's isolation.
    Doctor {
        /// Also write what a bug report needs to FILE (default: luoto-report-<time>.txt here),
        /// with secrets and what identifies you taken out.
        #[arg(long, value_name = "FILE", num_args = 0..=1)]
        report: Option<Option<String>>,
    },
    /// Update luoto to the latest release.
    Upgrade,
    /// Remove luoto's envs, vault, images, keychain entries, config and data (and its VM when
    /// nothing else uses it), after listing them; the binary stays.
    Uninstall {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Start the local web UI.
    Ui {
        /// Outside the ports envs forward to this machine (1024–32767), so no env can serve
        /// a page on the UI's origin.
        #[arg(long, default_value_t = names::ui_port())]
        port: u16,
        #[arg(long)]
        no_open: bool,
    },
    /// Create an env for a folder (default: the current one), or for a remote cloned inside
    /// it (`luoto init acme/web`), and start it.
    Init(init::InitOpts),
    /// Create or update the env's containers from its config and start it.
    Up {
        /// Every env, asking nothing (what an env needs from you is printed); one that fails
        /// leaves the rest to start.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        no_selftest: bool,
        /// Recreate the dev container (the workspace and home volumes are kept).
        #[arg(long)]
        recreate: bool,
        /// Leave out the summary of how to reach the env (`luoto run` starts it so).
        #[arg(long, hide = true)]
        quiet: bool,
    },
    /// Stop the env (volumes and config are kept).
    Down {
        /// Every env that runs (the vault keeps running).
        #[arg(long)]
        all: bool,
    },
    /// Delete the env: containers, workspace and home volumes, config (your folder stays; an
    /// env cloned from a remote keeps only what was pushed).
    Rm {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Discard the env's home (dotfiles, shell history, agents' logins and state, toolchains)
    /// and recreate its dev container with an empty one; the workspace stays.
    ResetHome {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// List envs.
    #[command(visible_alias = "list")]
    Ls,
    /// Show the env's state, workspace, forwarded ports, credentials, rules, denies and mutes.
    Status {
        /// The compiled policy as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open the env's config in $EDITOR, validate and apply it.
    Edit,
    /// Show the project's luoto.toml (team settings in the repository), apply or ignore it, or
    /// draft one from the env (`suggest`).
    Project {
        #[command(subcommand)]
        action: Option<ProjectCmd>,
    },
    /// Open a shell in the env, or run a command: `luoto shell -- cmd args`.
    Shell {
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Open the env in your editor over SSH (zed, code, cursor; `ssh` prints how to connect).
    Open {
        /// Editor to use (default: `editor` in config.toml, else the first one installed).
        #[arg(long = "with", value_name = "EDITOR", add = ArgValueCandidates::new(complete::editors))]
        with: Option<String>,
    },
    /// Reach a port in the env on another local port: `luoto forward 8080:5173`. Ports an env
    /// listens on are forwarded to the same port here on their own.
    Forward {
        /// The env's port, or `LOCAL:ENV` to use another port here (`8080:5173`).
        port: String,
        /// Open it in your browser.
        #[arg(long)]
        open: bool,
    },
    /// Run an agent on one prompt without a terminal: its answer on stdout (or in --output)
    /// and its exit code, for scripts and scheduled jobs. Brings the env up first, asking
    /// nothing.
    Run {
        #[arg(long, add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// The prompt (else --prompt-file, else stdin).
        #[arg(long)]
        prompt: Option<String>,
        #[arg(long, value_name = "FILE")]
        prompt_file: Option<String>,
        /// Write the agent's answer to this file here instead of stdout.
        #[arg(long, value_name = "FILE")]
        output: Option<String>,
        /// Stop the agent after this long (30m, 2h) and exit with 124.
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
        /// Stop the env when the run ends.
        #[arg(long)]
        down: bool,
    },
    /// Run, add or list coding agents.
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },
    /// Repositories beside the env's folder, each at /workspace/<name>: list, add, remove.
    Repo {
        #[command(subcommand)]
        action: Option<RepoCmd>,
    },
    /// Copy changed files from the env back to its folder, and its repos copied in from
    /// folders back to theirs (reviewed first).
    Pull {
        /// Write here instead of the env's folder (or the `--repo`'s). An env cloned from a
        /// remote has no folder: it pulls only here, into a new or empty folder unless you
        /// confirm. Never your home folder.
        #[arg(long)]
        to: Option<String>,
        /// Only this repo: to its host folder, or else (a clone) the same name in the env's
        /// folder.
        #[arg(long)]
        repo: Option<String>,
        /// Also write files host tools act on (git hooks/config, .envrc, .vscode, …).
        #[arg(long)]
        include_risky: bool,
        /// Include .git (its hooks and config count as risky).
        #[arg(long)]
        include_git: bool,
        #[arg(long, short)]
        yes: bool,
    },
    /// Allow egress to a host.
    Allow(rules::AllowOpts),
    /// Remove rules by id or host.
    Revoke { rule: String },
    /// List requests filed from inside envs (all envs unless one is picked).
    Requests {
        /// Keep watching, and print each new request as it comes.
        #[arg(long)]
        watch: bool,
    },
    /// Approve an access request (adds a rule), as asked or narrowed.
    Approve {
        id: u64,
        #[arg(long)]
        ttl: Option<String>,
        /// Grant read-only access (GET, HEAD, OPTIONS) to a write request.
        #[arg(long, conflicts_with = "methods")]
        read: bool,
        /// Grant only these methods (repeatable), among those the request asked for.
        #[arg(long = "method")]
        methods: Vec<String>,
        /// Grant only these path globs (repeatable), within the request's paths.
        #[arg(long = "path")]
        paths: Vec<String>,
        #[arg(long, short)]
        yes: bool,
        /// Accept the rule's risks without asking.
        #[arg(long)]
        force: bool,
    },
    /// Reject an access request.
    Reject {
        id: u64,
        #[arg(long)]
        note: Option<String>,
    },
    /// What the env tried to reach, per host; `--follow` streams each attempt.
    Egress {
        #[arg(long)]
        denied: bool,
        /// Only attempts newer than this (e.g. 10m, 2h).
        #[arg(long)]
        since: Option<String>,
        /// Stream attempts as they happen.
        #[arg(short, long)]
        follow: bool,
        /// One line per attempt instead of the per-host summary.
        #[arg(long)]
        raw: bool,
        /// Also the denials `[[mute]]` leaves out.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// The env's gate log, the background watcher's, or what its installs printed.
    Logs {
        #[arg(value_enum, default_value_t = logs::Source::Gate)]
        source: logs::Source,
        /// Keep printing what is added.
        #[arg(short, long)]
        follow: bool,
        /// Only the last N lines.
        #[arg(short = 'n', long, value_name = "N")]
        lines: Option<usize>,
    },
    /// The vault that holds secrets for every env: status, unlock, lock.
    Vault {
        #[command(subcommand)]
        action: Option<VaultCmd>,
    },
    /// Internal: stdio transport for SSH (`ProxyCommand luoto ssh-proxy <env>`).
    #[command(hide = true)]
    SshProxy { env: String },
    /// Internal: the background watcher that forwards ports and stops idle envs.
    #[command(hide = true)]
    Watch,
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Run an agent in the env's workspace (installs it on first use).
    Run {
        #[arg(add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// Skip the agent's own permission prompts (the sandbox is the boundary).
        #[arg(long)]
        yolo: bool,
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Remove an agent from the env's config; its files stay in the env's home.
    #[command(visible_alias = "remove")]
    Rm {
        #[arg(add = ArgValueCandidates::new(complete::agents))]
        agent: String,
    },
    /// Install an agent in the env and add it to the config.
    Add {
        #[arg(add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// Its credential without the prompt: `KIND=REF` (`oauth_token=op://…`),
        /// `PROVIDER.KIND=REF`, or `login_inside`; replaces the one the env has.
        #[arg(long, value_name = "KIND=REF")]
        credential: Option<String>,
    },
    /// List known agents and providers.
    #[command(visible_alias = "ls")]
    List,
}

#[derive(Subcommand)]
enum RepoCmd {
    /// The env's repos and where each comes from.
    #[command(visible_alias = "ls")]
    List,
    /// Add a host folder (copied in) or a remote (cloned in the env), at /workspace/<name>.
    Add {
        /// A folder (starts with `/`, `~` or `.`, or exists), else a remote: `owner/repo` on
        /// GitHub, an https or ssh URL, or user@host:path.
        #[arg(value_name = "FOLDER|REMOTE")]
        source: String,
        /// Its folder in the workspace (default: the last part of the path or URL).
        #[arg(long)]
        name: Option<String>,
        /// The branch a clone checks out (default: the remote's).
        #[arg(long)]
        branch: Option<String>,
    },
    /// Remove a repo from the env's config; its copy in the env stays.
    Rm { name: String },
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// Apply the current luoto.toml after reviewing it.
    Apply {
        /// Don't ask.
        #[arg(long, short)]
        yes: bool,
    },
    /// Stop applying it (this version is not offered again).
    Ignore,
    /// Print a luoto.toml for the team from the env's settings, leaving out your credentials,
    /// secrets, folders and temporary grants.
    Suggest {
        /// Write it to the env's folder.
        #[arg(long)]
        write: bool,
        /// Replace the folder's luoto.toml.
        #[arg(long, requires = "write")]
        force: bool,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Locked or not, and each env's credentials.
    Status,
    /// Load secrets into the vault (after a reboot) and re-register every env.
    Unlock,
    /// Wipe secrets from the vault and every gate.
    Lock,
    /// Read the secrets again (after rotating one in your secret store): all the vault holds,
    /// or with `-e` the env's.
    Reload,
}

fn main() -> ExitCode {
    // `COMPLETE=<shell> luoto` prints the shell hook; the hook calls back here to complete.
    // The hook calls `luoto` (`luoto-dev` for a source build, `just link-dev`) from PATH, not
    // argv[0], which in Homebrew is a versioned path.
    CompleteEnv::with_factory(Cli::command)
        .completer(names::instance())
        .complete();
    let cli = Cli::parse();
    match run(cli.env, cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("luoto: {}", text::lines(&format!("{e:#}")));
            ExitCode::FAILURE
        }
    }
}

fn run(env_arg: Option<String>, cmd: Cmd) -> Result<ExitCode> {
    use commands as c;
    let paths = paths::Paths::get()?;
    let env = || workspace::resolve(&paths, env_arg.as_deref());
    match cmd {
        Cmd::Setup(o) => setup::setup(o),
        Cmd::Doctor { report } => setup::doctor(report),
        Cmd::Upgrade => upgrade::upgrade(),
        Cmd::Uninstall { .. } if env_arg.is_some() => {
            anyhow::bail!("uninstall removes every env: leave out -e")
        }
        Cmd::Uninstall { yes } => uninstall::uninstall(yes),
        Cmd::Ui { port, no_open } => ui::serve(port, !no_open),
        Cmd::Init(o) => {
            if env_arg.is_some() {
                anyhow::bail!("`init` names the env with --name, not -e");
            }
            init::init(o)
        }
        Cmd::Up { all: true, .. } | Cmd::Down { all: true } if env_arg.is_some() => {
            anyhow::bail!("--all acts on every env: leave out -e")
        }
        Cmd::Up {
            all: true,
            no_selftest,
            recreate,
            quiet,
        } => c::up_all(!no_selftest, recreate, quiet),
        Cmd::Up {
            all: false,
            no_selftest,
            recreate,
            quiet,
        } => match env() {
            Ok(name) => c::up(&name, !no_selftest, recreate, quiet),
            // A folder without an env: offer to set one up (init shows it and asks first).
            Err(_) if env_arg.is_none() && std::io::stdin().is_terminal() => {
                println!("No env for this folder yet.\n");
                init::init(init::InitOpts::default())
            }
            Err(e) => Err(e),
        },
        Cmd::Down { all: true } => c::down_all(),
        Cmd::Down { all: false } => c::down(&env()?),
        Cmd::Rm { yes } => c::rm(&env()?, yes),
        Cmd::ResetHome { yes } => c::reset_home(&env()?, yes),
        Cmd::Ls => c::ls(),
        Cmd::Status { json } => c::status(&env()?, json),
        Cmd::Edit => c::edit(&env()?),
        Cmd::Project { action } => match action {
            None => c::project(&env()?, false, false, false),
            Some(ProjectCmd::Apply { yes }) => c::project(&env()?, true, false, yes),
            Some(ProjectCmd::Ignore) => c::project(&env()?, false, true, false),
            Some(ProjectCmd::Suggest { write, force }) => c::project_suggest(&env()?, write, force),
        },
        Cmd::Shell { cmd } => connect::shell(&env()?, &cmd),
        Cmd::Open { with } => connect::open(&env()?, with.as_deref()),
        Cmd::Forward { port, open } => connect::forward(&env()?, &port, open),
        Cmd::Run {
            agent,
            prompt,
            prompt_file,
            output,
            timeout,
            down,
        } => {
            let prompt = match (prompt, prompt_file) {
                (Some(p), _) => p,
                (None, Some(f)) => std::fs::read_to_string(workspace::expand(&f))
                    .map_err(|e| anyhow::anyhow!("read {f}: {e}"))?,
                (None, None) if !std::io::stdin().is_terminal() => {
                    std::io::read_to_string(std::io::stdin())?
                }
                (None, None) => anyhow::bail!("give the prompt: --prompt, --prompt-file or stdin"),
            };
            agents::headless(
                &env()?,
                &agent,
                &prompt,
                output.as_deref(),
                timeout.as_deref(),
                down,
            )
        }
        Cmd::Agent { action } => match action {
            AgentCmd::Run { agent, yolo, args } => agents::run(&env()?, &agent, yolo, &args),
            AgentCmd::Rm { agent } => agents::rm(&env()?, &agent),
            AgentCmd::Add { agent, credential } => {
                agents::add(&env()?, &agent, credential.as_deref())
            }
            AgentCmd::List => agents::list(),
        },
        Cmd::Repo { action } => match action.unwrap_or(RepoCmd::List) {
            RepoCmd::List => repos::list(&env()?),
            RepoCmd::Add {
                source,
                name,
                branch,
            } => repos::add(&env()?, &source, name.as_deref(), branch.as_deref()),
            RepoCmd::Rm { name } => repos::rm(&env()?, &name),
        },
        Cmd::Pull {
            to,
            repo,
            include_risky,
            include_git,
            yes,
        } => c::pull(
            &env()?,
            to.as_deref(),
            repo.as_deref(),
            include_risky,
            include_git,
            yes,
        ),
        Cmd::Allow(o) => c::allow(&env()?, o),
        Cmd::Revoke { rule } => c::revoke(&env()?, &rule),
        Cmd::Requests { watch } => {
            // No env picked and none here: every env's requests.
            let picked = match env_arg.as_deref() {
                Some(_) => Some(env()?),
                None => env().ok(),
            };
            c::requests(picked.as_deref(), watch)
        }
        Cmd::Approve {
            id,
            ttl,
            read,
            methods,
            paths,
            yes,
            force,
        } => {
            let narrow = luoto_shared::api::Narrowing {
                read,
                methods,
                paths,
            };
            c::approve(&env()?, id, ttl.as_deref(), &narrow, yes, force)
        }
        Cmd::Reject { id, note } => c::reject(&env()?, id, note),
        Cmd::Egress {
            denied,
            since,
            follow,
            raw,
            all,
            json,
        } => {
            if follow || raw {
                c::logs(&env()?, follow, denied, all, since.as_deref())
            } else {
                c::egress(&env()?, denied, all, since.as_deref(), json)
            }
        }
        Cmd::Logs {
            source,
            follow,
            lines,
        } => logs::show(source, env, follow, lines),
        Cmd::Vault { action } => match action.unwrap_or(VaultCmd::Status) {
            VaultCmd::Status => c::vault_status(),
            VaultCmd::Unlock => c::unlock(),
            VaultCmd::Lock => c::lock(),
            VaultCmd::Reload => c::reload(env_arg.as_deref()),
        },
        Cmd::SshProxy { env: e } => connect::ssh_proxy(&e),
        Cmd::Watch => watch::watch(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn approve_takes_what_narrows_a_request() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat());
        let Ok(Cli {
            cmd:
                Cmd::Approve {
                    id: 3,
                    read: true,
                    methods,
                    paths,
                    ..
                },
            ..
        }) = parse(&[
            "approve", "3", "--read", "--path", "/v1/**", "--path", "/v2",
        ])
        else {
            panic!("approve didn't parse");
        };
        assert!(methods.is_empty());
        assert_eq!(paths, ["/v1/**", "/v2"]);
        assert!(parse(&["approve", "3", "--read", "--method", "GET"]).is_err());
    }

    #[test]
    fn all_is_every_env_not_one() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat());
        for args in [["up", "--all", "-e", "web"], ["-e", "web", "down", "--all"]] {
            let cli = parse(&args).unwrap();
            let e = run(cli.env, cli.cmd).unwrap_err().to_string();
            assert!(e.contains("leave out -e"), "{e}");
        }
        let Ok(Cli {
            cmd:
                Cmd::Logs {
                    source,
                    follow,
                    lines,
                },
            ..
        }) = parse(&["logs", "installs", "-fn", "20"])
        else {
            panic!("logs didn't parse");
        };
        assert!(source == logs::Source::Installs && follow && lines == Some(20));
        assert!(matches!(
            parse(&["logs"]),
            Ok(Cli {
                cmd: Cmd::Logs {
                    source: logs::Source::Gate,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn a_report_file_is_optional_and_uninstall_takes_no_env() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat()).unwrap();
        let report = |args: &[&str]| match parse(args).cmd {
            Cmd::Doctor { report } => report,
            _ => panic!("not doctor"),
        };
        assert_eq!(report(&["doctor"]), None);
        assert_eq!(report(&["doctor", "--report"]), Some(None));
        assert_eq!(
            report(&["doctor", "--report", "bug.txt"]),
            Some(Some("bug.txt".into()))
        );
        let cli = parse(&["uninstall", "-e", "web"]);
        let e = run(cli.env, cli.cmd).unwrap_err().to_string();
        assert!(e.contains("leave out -e"), "{e}");
    }
}
