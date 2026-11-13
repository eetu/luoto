//! luoto — supply-chain-safe dev sandboxes. Every dev tool runs in a container whose only
//! way out is a policy gate you control; secrets stay in a vault outside the sandbox.

mod agents;
mod archive;
mod azure;
mod azure_identity;
mod ca;
mod commands;
mod compile;
mod complete;
mod config;
mod connect;
mod credentials;
mod ctl;
mod deps;
mod detect;
mod disk;
mod egress;
mod env;
mod events;
mod format;
mod idle;
mod init;
mod logs;
mod machine;
mod model_servers;
mod names;
mod needs;
mod notify;
mod paths;
mod personal;
mod ports;
mod progress;
mod project;
mod prompt;
mod release;
mod report;
mod repos;
mod rules;
mod runtime;
mod secrets;
mod setup;
mod shares;
mod ssh;
mod state;
mod sync;
mod text;
mod transfer;
#[cfg(unix)]
mod tunlink;
mod ui;
mod uninstall;
mod upgrade;
mod vars;
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
    about = "Supply-chain-safe dev sandboxes: egress only through your policy",
    after_help = "Start with `luoto setup`, then run `luoto init` in a project folder.\n\
                  `luoto ui` opens the web UI.\n\
                  Commands act on the env of the current folder; `-e NAME` picks another."
)]
struct Cli {
    /// Env to act on (default: the env of the current folder).
    #[arg(short = 'e', long = "env", global = true, value_name = "ENV",
          add = ArgValueCandidates::new(complete::envs))]
    env: Option<String>,
    /// Show what tools print as they run, instead of a spinner.
    #[arg(short = 'v', long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Detect the host, set up a container runtime, prepare images.
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
    /// Remove everything luoto made, after listing it; the binary stays.
    ///
    /// Its envs, vault, images, keychain entries, config and data, and its VM when nothing
    /// else uses it.
    Uninstall {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Remove luoto's superseded images and return the freed space.
    ///
    /// None a container uses or this luoto runs, after listing them; the freed space goes back
    /// to this machine, and volumes stay.
    Prune {
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
        /// Don't open it in the browser.
        #[arg(long)]
        no_open: bool,
    },
    /// Create an env for a folder or a remote, and start it.
    ///
    /// A folder (default: the current one) is copied into the env; a remote (`luoto init
    /// acme/web`) is cloned inside it.
    Init(init::InitOpts),
    /// Create or update the env's containers from its config and start it.
    Up {
        /// Every env, asking nothing (what an env needs from you is printed); one that fails
        /// leaves the rest to start.
        #[arg(long)]
        all: bool,
        /// Skip the isolation self-test after a start.
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
    /// Delete the env: its containers, volumes and config.
    ///
    /// Your folder stays; an env cloned from a remote keeps only what was pushed.
    Rm {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Discard the env's home and recreate its dev container.
    ///
    /// The home holds dotfiles, shell history, agents' logins and state, and toolchains; the
    /// new one is empty, and the workspace stays.
    ResetHome {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Write the env (config, workspace, home) to one file.
    ///
    /// To import into another luoto (a source build's into the release, say) or on another
    /// machine; secrets stay refs. A running env is stopped first, after asking.
    Export {
        /// The archive (default: <env>.luoto.tar here; in a folder, that name there).
        file: Option<String>,
        /// Leave the home out: the imported env starts with a new one.
        #[arg(long)]
        no_home: bool,
        /// Stop a running env without asking.
        #[arg(long, short)]
        yes: bool,
    },
    /// Make an env from a file `luoto export` wrote.
    ///
    /// It gets its own subnet, CA and vault token; `luoto up` starts it.
    Import {
        /// The file `luoto export` wrote.
        file: String,
        /// Its name here (default: the one it had).
        #[arg(long)]
        name: Option<String>,
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// List envs.
    #[command(visible_alias = "ls")]
    List {
        /// Also what each env takes on disk (the runtime walks every volume, which takes a
        /// while).
        #[arg(long)]
        size: bool,
    },
    /// Show the env's state, ports, credentials, rules, denies and mutes.
    Status {
        /// The compiled policy as JSON.
        #[arg(long)]
        json: bool,
        /// Also what the env takes on disk, part by part (the runtime walks every volume,
        /// which takes a while).
        #[arg(long)]
        size: bool,
    },
    /// Open the env's config in $EDITOR, validate and apply it.
    Edit,
    /// Show, apply or ignore the project's luoto.toml, or draft one.
    ///
    /// luoto.toml holds the team's settings in the repository; `suggest` drafts one from the
    /// env.
    Project {
        #[command(subcommand)]
        action: Option<ProjectCmd>,
    },
    /// Open a shell in the env, or run a command (`-- cmd args`).
    Shell {
        /// The command and its arguments (default: a login shell).
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Open the env in your editor over SSH (zed, code, cursor).
    ///
    /// `--with ssh` prints how to connect.
    Open {
        /// Editor to use (default: `editor` in config.toml, else the first one installed).
        #[arg(long = "with", value_name = "EDITOR", add = ArgValueCandidates::new(complete::editors))]
        with: Option<String>,
    },
    /// Reach a port in the env on another local port.
    ///
    /// `luoto forward 8080:5173`. Ports an env listens on are forwarded to the same port here
    /// on their own.
    Forward {
        /// The env's port, or `LOCAL:ENV` to use another port here (`8080:5173`).
        port: String,
        /// Open it in your browser.
        #[arg(long)]
        open: bool,
    },
    /// Run an agent on one prompt, for scripts and scheduled jobs.
    ///
    /// No terminal: its answer on stdout (or in --output) and its exit code. Brings the env up
    /// first, asking nothing.
    Run {
        /// The agent (`luoto agent list` lists them).
        #[arg(long, add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// The prompt (else --prompt-file, else stdin).
        #[arg(long)]
        prompt: Option<String>,
        /// Read the prompt from this file.
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
        /// Arguments for the agent, after the env's `args` and `headless_args`
        /// (`luoto run --agent claude --prompt … -- --bare`).
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// List, add, run, authenticate or remove coding agents.
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },
    /// The env's repos at /workspace/<name>: list, add, remove, access.
    ///
    /// Repositories beside the env's folder: a host folder copied in, or a remote cloned in
    /// the env, and what the env may do with each.
    Repo {
        #[command(subcommand)]
        action: Option<RepoCmd>,
    },
    /// Environment variables and secrets for the env's shells.
    ///
    /// Plain values, and secrets code in the env reads (refs resolved on this machine at
    /// `up`).
    Var {
        #[command(subcommand)]
        action: Option<VarCmd>,
    },
    /// Folders of this machine the env reads at /shares/<name>.
    ///
    /// Read-only: data too large for a repo (recordings, datasets).
    Share {
        #[command(subcommand)]
        action: Option<ShareCmd>,
    },
    /// Copy changed files from the env back to its folder, reviewed first.
    ///
    /// Its repos copied in from folders go back to theirs too.
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
        /// Write without asking.
        #[arg(long, short)]
        yes: bool,
    },
    /// Allow egress to a host.
    Allow(rules::AllowOpts),
    /// Remove rules by id or host.
    Revoke {
        /// A rule's id (`luoto status` lists them), or its host.
        rule: String,
    },
    /// List requests filed from inside envs (all unless `-e` picks one).
    Requests {
        /// Keep watching, and print each new request as it comes.
        #[arg(long)]
        watch: bool,
    },
    /// Approve an access request (adds a rule), as asked or narrowed.
    Approve {
        /// The request's number (`luoto requests` lists them).
        id: u64,
        /// Expire the rule after this long: 30m, 1h, 2d.
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
        /// Approve without asking.
        #[arg(long, short)]
        yes: bool,
        /// Accept the rule's risks without asking.
        #[arg(long)]
        force: bool,
    },
    /// Reject an access request.
    Reject {
        /// The request's number (`luoto requests` lists them).
        id: u64,
        /// Why, for the sandbox to read.
        #[arg(long)]
        note: Option<String>,
    },
    /// What the env tried to reach, per host; open or keep egress.
    ///
    /// `--follow` streams each attempt. `open` lets it reach any HTTP(S) host for a while,
    /// `keep` keeps what that reached.
    #[command(args_conflicts_with_subcommands = true)]
    Egress {
        #[command(subcommand)]
        action: Option<EgressCmd>,
        /// Only the hosts with denials (or only lookups).
        #[arg(long)]
        denied: bool,
        /// Only the hosts open egress let through: no rule allows them.
        #[arg(long, conflicts_with_all = ["denied", "follow", "raw"])]
        open: bool,
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
        /// The per-host summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// The env's gate log, the watcher's, or what its installs printed.
    Logs {
        /// Which log.
        #[arg(value_enum, default_value_t = logs::Source::Gate)]
        source: logs::Source,
        /// Keep printing what is added.
        #[arg(short, long)]
        follow: bool,
        /// Only the last N lines.
        #[arg(short = 'n', long, value_name = "N")]
        lines: Option<usize>,
    },
    /// The vault of every env's secrets: status, unlock, lock, reload.
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
    /// List known agents and providers.
    #[command(visible_alias = "ls")]
    List,
    /// Install an agent in the env and add it to the config.
    Add {
        /// The agent (`luoto agent list` lists them).
        #[arg(add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// Its credential without the prompt: `KIND=REF` (`oauth_token=op://…`),
        /// `PROVIDER.KIND=REF`, or `login_inside`; replaces the one the env has.
        #[arg(long, value_name = "KIND=REF")]
        credential: Option<String>,
    },
    /// Run an agent in the env's workspace (installs it on first use).
    Run {
        /// The agent (`luoto agent list` lists them).
        #[arg(add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// Skip the agent's own permission prompts (the sandbox is the boundary).
        #[arg(long)]
        yolo: bool,
        /// Arguments for the agent.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Change how an agent authenticates: a credential or a login inside.
    Auth {
        /// The agent (`luoto agent list` lists them).
        #[arg(add = ArgValueCandidates::new(complete::agents))]
        agent: String,
    },
    /// Remove an agent from the env's config; its files stay.
    ///
    /// Its files stay in the env's home.
    #[command(visible_alias = "remove")]
    Rm {
        /// The agent.
        #[arg(add = ArgValueCandidates::new(complete::agents))]
        agent: String,
    },
}

#[derive(Subcommand)]
enum EgressCmd {
    /// Let the env reach any HTTP(S) host for an hour or `--for`.
    ///
    /// Any host no rule allows; hosts that get your credentials, muted hosts and denies stay
    /// as they are.
    Open {
        /// How long: 30m, 2h, 1d (default 1h). With no end: `open = true` under [egress] in
        /// the env's file.
        #[arg(long = "for", value_name = "DURATION")]
        window: Option<String>,
    },
    /// Close open egress: only the rules allow again.
    Close,
    /// Keep what open egress reached: presets, else a rule per host.
    ///
    /// The presets that cover its hosts, else a rule per host.
    Keep {
        /// Only what it reached this recently (e.g. 2h).
        #[arg(long)]
        since: Option<String>,
        /// Keep what is offered checked (presets and read rules) without asking.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum RepoCmd {
    /// The env's repos and where each comes from.
    #[command(visible_alias = "ls")]
    List,
    /// Add a host folder (copied in) or a remote (cloned in the env).
    ///
    /// Either is at /workspace/<name>.
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
    Rm {
        /// The repo's name in the workspace.
        name: String,
    },
    /// Change what the env may do with a repo: fetch, read or push.
    ///
    /// Fetch it public, or read it or push with a token.
    Auth {
        /// The repo's name in the workspace, or its path on the forge (`acme/api`).
        repo: String,
    },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// The env's shares, and which changed since the last sync.
    #[command(visible_alias = "ls")]
    List,
    /// Share a folder, read-only at /shares/<name> in the env.
    ///
    /// The env reads it as of its last sync.
    Add {
        /// A folder inside your home folder (not a secret one such as ~/.ssh), or on a disk.
        folder: String,
        /// Its name (default: the folder's own, made lowercase).
        #[arg(long)]
        name: Option<String>,
        /// Restart luoto's VM without asking, if it needs the shares folder first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Bring the env's shares up to date now (`luoto up` does too).
    Sync {
        /// Only this share.
        name: Option<String>,
        /// Restart luoto's VM without asking, if it needs the shares folder first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Stop sharing a folder.
    Rm {
        /// The share's name.
        name: String,
    },
}

#[derive(Subcommand)]
enum VarCmd {
    /// The env's variables: plain values, and secrets by their ref.
    #[command(visible_alias = "ls")]
    List,
    /// Set a variable: a plain value, or a secret by its ref.
    ///
    /// `NAME=value` a plain value (it stays in your shell history), `NAME` a secret, asking
    /// where it is kept, or `NAME --ref <ref>`. A token an HTTP API takes is safer under
    /// [credentials.custom.<name>]: the gate adds it and the env never sees it.
    Set {
        /// `NAME=value` for a plain value, `NAME` for a secret.
        #[arg(value_name = "NAME[=VALUE]")]
        var: String,
        /// The secret's ref: op://, keyring:, vault://, env: or file:.
        #[arg(long = "ref", value_name = "REF")]
        reference: Option<String>,
    },
    /// Remove a variable.
    Rm {
        /// The variable's name.
        name: String,
    },
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
    /// Ask again for what luoto.toml needs only you add.
    ///
    /// What the accepted luoto.toml's `[needs]` names: credentials and sandbox secrets, each
    /// question opening on what the env has.
    Needs,
    /// Print a luoto.toml for the team from the env's settings.
    ///
    /// It leaves out your credentials, secrets, folders and temporary grants.
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
    /// Read the secrets again, after rotating one in your secret store.
    ///
    /// All the vault holds, or with `-e` the env's.
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
    if cli.verbose {
        progress::set_verbose();
    }
    prompt::theme();
    match run(cli.env, cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            let msg = text::lines(&format!("{e:#}"));
            eprintln!("{}", text::hang("luoto: ", &msg, text::columns()));
            ExitCode::FAILURE
        }
    }
}

/// Why `cmd` refuses the global `-e`: it acts on no env, on every env, or names its env
/// another way.
fn refuses_env(cmd: &Cmd) -> Option<String> {
    let none = |c: &str| Some(format!("`luoto {c}` acts on no env; drop `-e`"));
    match cmd {
        Cmd::Setup(_) => none("setup"),
        Cmd::Doctor { .. } => none("doctor"),
        Cmd::Upgrade => none("upgrade"),
        Cmd::Uninstall { .. } => none("uninstall"),
        Cmd::Prune { .. } => none("prune"),
        Cmd::Ui { .. } => none("ui"),
        Cmd::List { .. } => none("list"),
        Cmd::Agent {
            action: AgentCmd::List,
        } => none("agent list"),
        Cmd::Logs {
            source: logs::Source::Watcher,
            ..
        } => none("logs watcher"),
        Cmd::Vault {
            action: None | Some(VaultCmd::Status),
        } => none("vault status"),
        Cmd::Vault {
            action: Some(VaultCmd::Unlock),
        } => none("vault unlock"),
        Cmd::Vault {
            action: Some(VaultCmd::Lock),
        } => none("vault lock"),
        Cmd::Watch => none("watch"),
        Cmd::SshProxy { .. } => none("ssh-proxy"),
        Cmd::Up { all: true, .. } | Cmd::Down { all: true } => {
            Some("`--all` acts on every env; drop `-e`".into())
        }
        Cmd::Init(_) => Some("`luoto init` names the env with --name, not -e".into()),
        Cmd::Import { .. } => Some("`luoto import` names the env with --name, not -e".into()),
        _ => None,
    }
}

fn run(env_arg: Option<String>, cmd: Cmd) -> Result<ExitCode> {
    use commands as c;
    if env_arg.is_some()
        && let Some(why) = refuses_env(&cmd)
    {
        anyhow::bail!("{why}");
    }
    let paths = paths::Paths::get()?;
    let env = || workspace::resolve(&paths, env_arg.as_deref());
    match cmd {
        Cmd::Setup(o) => setup::setup(o),
        Cmd::Doctor { report } => setup::doctor(report),
        Cmd::Upgrade => upgrade::upgrade(),
        Cmd::Uninstall { yes } => uninstall::uninstall(yes),
        Cmd::Prune { yes } => disk::prune(yes),
        Cmd::Ui { port, no_open } => ui::serve(port, !no_open),
        Cmd::Init(o) => init::init(o),
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
        Cmd::Export { file, no_home, yes } => {
            transfer::export(&env()?, file.as_deref(), no_home, yes)
        }
        Cmd::Import { file, name, yes } => transfer::import(&file, name.as_deref(), yes),
        Cmd::List { size } => c::list(size),
        Cmd::Status { json, size } => c::status(&env()?, json, size),
        Cmd::Edit => c::edit(&env()?),
        Cmd::Project { action } => match action {
            None => c::project(&env()?, false, false, false),
            Some(ProjectCmd::Apply { yes }) => c::project(&env()?, true, false, yes),
            Some(ProjectCmd::Ignore) => c::project(&env()?, false, true, false),
            Some(ProjectCmd::Needs) => c::project_needs(&env()?),
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
            args,
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
                &args,
                output.as_deref(),
                timeout.as_deref(),
                down,
            )
        }
        Cmd::Agent { action } => match action {
            AgentCmd::List => agents::list(),
            AgentCmd::Add { agent, credential } => {
                agents::add(&env()?, &agent, credential.as_deref())
            }
            AgentCmd::Run { agent, yolo, args } => agents::run(&env()?, &agent, yolo, &args),
            AgentCmd::Auth { agent } => agents::auth(&env()?, &agent),
            AgentCmd::Rm { agent } => agents::rm(&env()?, &agent),
        },
        Cmd::Repo { action } => match action.unwrap_or(RepoCmd::List) {
            RepoCmd::List => repos::list(&env()?),
            RepoCmd::Add {
                source,
                name,
                branch,
            } => repos::add(&env()?, &source, name.as_deref(), branch.as_deref()),
            RepoCmd::Rm { name } => repos::rm(&env()?, &name),
            RepoCmd::Auth { repo } => repos::auth(&env()?, &repo),
        },
        Cmd::Share { action } => match action.unwrap_or(ShareCmd::List) {
            ShareCmd::List => shares::list(&env()?),
            ShareCmd::Add { folder, name, yes } => {
                shares::add(&env()?, &folder, name.as_deref(), yes)
            }
            ShareCmd::Sync { name, yes } => shares::sync_cmd(&env()?, name.as_deref(), yes),
            ShareCmd::Rm { name } => shares::rm(&env()?, &name),
        },
        Cmd::Var { action } => match action.unwrap_or(VarCmd::List) {
            VarCmd::List => vars::list(&env()?),
            VarCmd::Set { var, reference } => vars::set_cmd(&env()?, &var, reference.as_deref()),
            VarCmd::Rm { name } => vars::rm_cmd(&env()?, &name),
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
            action: Some(action),
            ..
        } => match action {
            EgressCmd::Open { window } => c::egress_open(&env()?, window.as_deref()),
            EgressCmd::Close => c::egress_close(&env()?),
            EgressCmd::Keep { since, yes } => c::egress_keep(&env()?, since.as_deref(), yes),
        },
        Cmd::Egress {
            action: None,
            denied,
            open,
            since,
            follow,
            raw,
            all,
            json,
        } => {
            if follow || raw {
                c::logs(&env()?, follow, denied, all, since.as_deref())
            } else {
                let only = if open {
                    c::Only::Opened
                } else if denied {
                    c::Only::Denied
                } else {
                    c::Only::All
                };
                c::egress(&env()?, only, all, since.as_deref(), json)
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
    fn egress_opens_closes_and_keeps_beside_its_views() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat());
        let action = |args: &[&str]| match parse(args).unwrap().cmd {
            Cmd::Egress { action, .. } => action,
            _ => panic!("not egress"),
        };
        assert!(matches!(
            action(&["egress", "open"]),
            Some(EgressCmd::Open { window: None })
        ));
        assert!(matches!(
            action(&["-e", "web", "egress", "open", "--for", "2h"]),
            Some(EgressCmd::Open { window: Some(w) }) if w == "2h"
        ));
        assert!(matches!(
            action(&["egress", "close"]),
            Some(EgressCmd::Close)
        ));
        assert!(matches!(
            action(&["egress", "keep", "--since", "2h", "-y"]),
            Some(EgressCmd::Keep { since: Some(s), yes: true }) if s == "2h"
        ));
        assert!(matches!(
            parse(&["egress", "--open"]).unwrap().cmd,
            Cmd::Egress {
                action: None,
                open: true,
                ..
            }
        ));
        assert!(action(&["egress", "--denied"]).is_none());
        for bad in [
            &["egress", "--denied", "open"][..],
            &["egress", "--open", "--denied"],
            &["egress", "--open", "--follow"],
            &["egress", "open", "--for"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn init_opens_egress_only_with_an_equals_sign() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat()).unwrap();
        let init = |args: &[&str]| match parse(args).cmd {
            Cmd::Init(o) => o,
            _ => panic!("not init"),
        };
        assert_eq!(init(&["init"]).open, None);
        assert_eq!(init(&["init", "--open"]).open.as_deref(), Some("1h"));
        assert_eq!(init(&["init", "--open=2h"]).open.as_deref(), Some("2h"));
        let o = init(&["init", "--open", "acme/web"]);
        assert_eq!(
            (o.open.as_deref(), o.dir.as_deref()),
            (Some("1h"), Some("acme/web"))
        );
    }

    #[test]
    fn a_run_passes_what_follows_the_double_dash_to_the_agent() {
        let cli = Cli::try_parse_from([
            "luoto",
            "run",
            "--agent",
            "claude",
            "--prompt",
            "hi",
            "--",
            "--bare",
            "--tools",
            "Bash,Read",
        ])
        .unwrap();
        let Cmd::Run { prompt, args, .. } = cli.cmd else {
            panic!("not run")
        };
        assert_eq!(prompt.as_deref(), Some("hi"));
        assert_eq!(args, ["--bare", "--tools", "Bash,Read"]);
    }

    #[test]
    fn all_is_every_env_not_one() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat());
        for args in [["up", "--all", "-e", "web"], ["-e", "web", "down", "--all"]] {
            let cli = parse(&args).unwrap();
            let e = run(cli.env, cli.cmd).unwrap_err().to_string();
            assert!(e.contains("drop `-e`"), "{e}");
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
        assert!(e.contains("drop `-e`"), "{e}");
    }

    #[test]
    fn prune_takes_no_env_and_sizes_are_asked_for() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat()).unwrap();
        let cli = parse(&["prune", "-e", "web", "--yes"]);
        let e = run(cli.env, cli.cmd).unwrap_err().to_string();
        assert!(e.contains("drop `-e`"), "{e}");
        assert!(matches!(parse(&["ls"]).cmd, Cmd::List { size: false }));
        assert!(matches!(
            parse(&["list", "--size"]).cmd,
            Cmd::List { size: true }
        ));
    }

    #[test]
    fn a_command_that_acts_on_no_env_refuses_one() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat()).unwrap();
        for args in [
            &["list", "-e", "web"][..],
            &["-e", "web", "vault"],
            &["vault", "lock", "-e", "web"],
            &["agent", "list", "-e", "web"],
            &["logs", "watcher", "-e", "web"],
            &["doctor", "-e", "web"],
        ] {
            let cli = parse(args);
            let e = run(cli.env, cli.cmd).unwrap_err().to_string();
            assert!(e.contains("acts on no env; drop `-e`"), "{args:?}: {e}");
        }
        for args in [
            &["vault", "reload", "-e", "web"][..],
            &["requests", "-e", "web"],
            &["logs", "installs", "-e", "web"],
            &["status", "-e", "web"],
        ] {
            let cli = parse(args);
            assert!(refuses_env(&cli.cmd).is_none(), "{args:?}");
        }
    }

    #[test]
    fn every_command_in_a_list_fits_80_columns() {
        let mut todo = vec![Cli::command()];
        while let Some(mut c) = todo.pop() {
            let help = c.render_help().to_string();
            let listed = help
                .lines()
                .skip_while(|l| *l != "Commands:")
                .take_while(|l| !l.is_empty());
            for line in listed {
                assert!(line.chars().count() <= 80, "{}: {line}", c.get_name());
            }
            for l in help.lines().filter(|l| !l.starts_with(' ')) {
                assert!(l.chars().count() <= 80, "{}: {l}", c.get_name());
            }
            todo.extend(c.get_subcommands().cloned());
        }
    }

    #[test]
    fn every_argument_says_what_it_is() {
        let mut todo = vec![Cli::command()];
        let mut bare = Vec::new();
        while let Some(c) = todo.pop() {
            for a in c.get_arguments() {
                let builtin = ["help", "version"].contains(&a.get_id().as_str());
                if !builtin && !a.is_hide_set() && a.get_help().is_none() {
                    bare.push(format!("{} {}", c.get_name(), a.get_id()));
                }
            }
            todo.extend(c.get_subcommands().filter(|s| !s.is_hide_set()).cloned());
        }
        assert!(bare.is_empty(), "{bare:?}");
    }

    #[test]
    fn import_names_its_env_with_name_and_export_takes_a_file() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["luoto"], args].concat()).unwrap();
        let cli = parse(&["import", "web.luoto.tar", "-e", "web"]);
        let e = run(cli.env, cli.cmd).unwrap_err().to_string();
        assert!(e.contains("--name, not -e"), "{e}");
        assert!(matches!(
            parse(&["import", "web.luoto.tar", "--name", "api", "-y"]).cmd,
            Cmd::Import { name: Some(n), yes: true, .. } if n == "api"
        ));
        assert!(matches!(
            parse(&["export", "--no-home", "-y"]).cmd,
            Cmd::Export {
                file: None,
                no_home: true,
                yes: true
            }
        ));
        assert!(matches!(
            parse(&["-e", "web", "export", "/tmp"]).cmd,
            Cmd::Export { file: Some(f), .. } if f == "/tmp"
        ));
    }
}
