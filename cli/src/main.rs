//! luoto — supply-chain-safe dev sandboxes. Every dev tool runs in a container whose only
//! way out is a policy gate you control; secrets stay in a vault outside the sandbox.

mod agents;
mod azure;
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
mod machine;
mod names;
mod paths;
mod personal;
mod ports;
mod project;
mod prompt;
mod release;
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
    Doctor,
    /// Update luoto to the latest release.
    Upgrade,
    /// Start the local web UI.
    Ui {
        /// Outside the ports envs forward to this machine (1024–32767), so no env can serve
        /// a page on the UI's origin.
        #[arg(long, default_value_t = names::ui_port())]
        port: u16,
        #[arg(long)]
        no_open: bool,
    },
    /// Create an env for a folder (default: the current one) and start it.
    Init(init::InitOpts),
    /// Create or update the env's containers from its config and start it.
    Up {
        #[arg(long)]
        no_selftest: bool,
        /// Recreate the dev container (the workspace and home volumes are kept).
        #[arg(long)]
        recreate: bool,
    },
    /// Stop the env (volumes and config are kept).
    Down,
    /// Delete the env: containers, workspace and home volumes, config (your folder stays).
    Rm {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// List envs.
    #[command(visible_alias = "list")]
    Ls,
    /// Show the env's state, workspace, credentials and rules.
    Status {
        /// The compiled policy as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open the env's config in $EDITOR, validate and apply it.
    Edit,
    /// Show the project's luoto.toml (team settings in the repository), or apply or ignore it.
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
        /// Write here instead of the env's folder (or the `--repo`'s).
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
    /// Approve an access request (adds a rule).
    Approve {
        id: u64,
        #[arg(long)]
        ttl: Option<String>,
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
        #[arg(long)]
        json: bool,
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
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Locked or not, and each env's credentials.
    Status,
    /// Load secrets into the vault (after a reboot) and re-register every env.
    Unlock,
    /// Wipe secrets from the vault and every gate.
    Lock,
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
        Cmd::Doctor => setup::doctor(),
        Cmd::Upgrade => upgrade::upgrade(),
        Cmd::Ui { port, no_open } => ui::serve(port, !no_open),
        Cmd::Init(o) => {
            if env_arg.is_some() {
                anyhow::bail!("`init` names the env with --name, not -e");
            }
            init::init(o)
        }
        Cmd::Up {
            no_selftest,
            recreate,
        } => match env() {
            Ok(name) => c::up(&name, !no_selftest, recreate),
            // A folder without an env: offer to set one up (init shows it and asks first).
            Err(_) if env_arg.is_none() && std::io::stdin().is_terminal() => {
                println!("No env for this folder yet.\n");
                init::init(init::InitOpts::default())
            }
            Err(e) => Err(e),
        },
        Cmd::Down => c::down(&env()?),
        Cmd::Rm { yes } => c::rm(&env()?, yes),
        Cmd::Ls => c::ls(),
        Cmd::Status { json } => c::status(&env()?, json),
        Cmd::Edit => c::edit(&env()?),
        Cmd::Project { action } => match action {
            None => c::project(&env()?, false, false, false),
            Some(ProjectCmd::Apply { yes }) => c::project(&env()?, true, false, yes),
            Some(ProjectCmd::Ignore) => c::project(&env()?, false, true, false),
        },
        Cmd::Shell { cmd } => connect::shell(&env()?, &cmd),
        Cmd::Open { with } => connect::open(&env()?, with.as_deref()),
        Cmd::Forward { port, open } => connect::forward(&env()?, &port, open),
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
            yes,
            force,
        } => c::approve(&env()?, id, ttl.as_deref(), yes, force),
        Cmd::Reject { id, note } => c::reject(&env()?, id, note),
        Cmd::Egress {
            denied,
            since,
            follow,
            raw,
            json,
        } => {
            if follow || raw {
                c::logs(&env()?, follow, denied, since.as_deref())
            } else {
                c::egress(&env()?, denied, since.as_deref(), json)
            }
        }
        Cmd::Vault { action } => match action.unwrap_or(VaultCmd::Status) {
            VaultCmd::Status => c::vault_status(),
            VaultCmd::Unlock => c::unlock(),
            VaultCmd::Lock => c::lock(),
        },
        Cmd::SshProxy { env: e } => connect::ssh_proxy(&e),
        Cmd::Watch => watch::watch(),
    }
}
