//! luoto — supply-chain-safe dev sandboxes. Every dev tool runs in a container whose only
//! way out is a policy gate you control; secrets stay in a vault outside the sandbox.

// First: its `out!` and `err!` are in scope for the modules after it.
#[macro_use]
mod style;
mod agents;
mod archive;
mod autopull;
mod azure;
mod azure_identity;
mod base;
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
mod feeds;
mod format;
#[cfg(unix)]
mod hostdial;
mod idle;
mod init;
mod logs;
mod machine;
mod model_servers;
mod names;
mod needs;
mod notify;
mod packages;
mod paths;
mod personal;
mod ports;
mod progress;
mod project;
mod prompt;
mod prune;
mod release;
mod report;
mod repos;
mod rules;
mod runtime;
mod secrets;
mod setup;
mod shares;
mod splash;
mod ssh;
mod state;
mod sync;
mod terminfo;
mod text;
mod transfer;
#[cfg(unix)]
mod tunlink;
mod ui;
mod uninstall;
mod upgrade;
mod used;
mod vars;
mod watch;
mod wizard;
mod workspace;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::CompleteEnv;
use clap_complete::engine::{ArgValueCandidates, ArgValueCompleter, PathCompleter};

#[derive(Parser)]
#[command(
    name = "luoto",
    version,
    max_term_width = 80,
    about = "Supply-chain-safe dev sandboxes: egress only through your policy",
    after_help = "Start with `luoto setup`, then run `luoto init` in a project folder.\n\
                  `luoto ui` opens the web UI.\n\
                  Commands act on the env of the current folder; `-e NAME` picks another."
)]
struct Cli {
    /// Show what tools print as they run, instead of a spinner.
    #[arg(short = 'v', long, global = true, display_order = 900)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

/// The env a command acts on.
#[derive(clap::Args, Default)]
struct EnvArg {
    /// Env to act on (default: the env of the current folder).
    #[arg(short = 'e', long = "env", value_name = "ENV", display_order = 0,
          add = ArgValueCandidates::new(complete::envs))]
    env: Option<String>,
}

/// The env a command group acts on, taken by each of its commands.
#[derive(clap::Args, Default)]
struct GroupEnv {
    /// Env to act on (default: the env of the current folder).
    #[arg(short = 'e', long = "env", value_name = "ENV", global = true, display_order = 0,
          add = ArgValueCandidates::new(complete::envs))]
    env: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Detect the host, set up a container runtime, prepare images.
    Setup(setup::SetupOpts),
    /// Check the runtime, images, vault and every env's isolation.
    Doctor {
        /// Also write what a bug report needs to FILE (default: luoto-report-<time>.txt here),
        /// with secrets and what identifies you taken out.
        #[arg(long, value_name = "FILE", num_args = 0..=1, add = ArgValueCompleter::new(PathCompleter::any()))]
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
    ///
    /// With `--envs`, instead: the stopped envs nobody has used for a while, as `luoto rm`
    /// removes one, after listing them. One holding work that is nowhere else stays.
    Prune {
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
        /// Remove stopped envs not used for 30 days (`prune_after` in config.toml), not images.
        #[arg(long)]
        envs: bool,
        /// With `--envs`: envs not used for this long (30m, 2h, 1d; `0d` for every stopped
        /// one).
        #[arg(long, value_name = "DURATION", requires = "envs")]
        older_than: Option<String>,
        /// With `--envs`: only envs whose name matches (`job-*`).
        #[arg(long = "match", value_name = "PATTERN", requires = "envs")]
        matching: Option<String>,
        /// With `--envs`: also envs holding work no remote and no folder of yours has.
        #[arg(long, requires = "envs")]
        with_work: bool,
    },
    /// Start the local web UI.
    Ui {
        /// The UI's port: one no env forwards to this machine, so no env can serve a page on
        /// the UI's origin.
        #[arg(long, value_name = "PORT", default_value_t = names::ui_port())]
        port: u16,
        /// Don't open it in the browser.
        #[arg(long)]
        no_open: bool,
    },
    /// Create an env for a folder, a remote or neither, and start it.
    ///
    /// A folder (default: the current one) is copied into the env; a remote (`luoto init
    /// acme/web`) is cloned inside it; `--virtual` makes one with no folder of its own.
    Init(init::InitOpts),
    /// Create or update the env's containers from its config and start it.
    Up {
        #[command(flatten)]
        e: EnvArg,
        /// Every env, asking nothing (what an env needs from you is printed); one that fails
        /// leaves the rest to start.
        #[arg(long, conflicts_with = "env")]
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
    ///
    /// An env set to pull when it stops (`luoto pull --on-stop on`) has its files pulled into
    /// its folder first; exits with 75 when that pull left something out.
    Down {
        #[command(flatten)]
        e: EnvArg,
        /// Every env that runs (the vault keeps running).
        #[arg(long, conflicts_with = "env")]
        all: bool,
        /// The watcher's stop of an idle env: only the pull's report is printed.
        #[arg(long, hide = true, conflicts_with = "all")]
        idle: bool,
    },
    /// Delete the env: its containers, volumes and config.
    ///
    /// Your folder stays; an env cloned from a remote keeps only what was pushed.
    Rm {
        #[command(flatten)]
        e: EnvArg,
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Discard the env's home and recreate its dev container.
    ///
    /// The home holds dotfiles, shell history, agents' logins and state, and toolchains; the
    /// new one is empty, and the workspace stays.
    ResetHome {
        #[command(flatten)]
        e: EnvArg,
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
    },
    /// Write the env (config, workspace, home) to one file.
    ///
    /// To import into another luoto (a source build's into the release, say) or on another
    /// machine; secrets stay refs. A running env is stopped first, after asking; one set to
    /// pull when it stops pulls then, and the export exits with 75 when that pull left
    /// something out.
    Export {
        #[command(flatten)]
        e: EnvArg,
        /// The archive (default: <env>.luoto.tar here; in a folder, that name there).
        #[arg(add = ArgValueCompleter::new(PathCompleter::any()))]
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
        #[arg(add = ArgValueCompleter::new(PathCompleter::file()))]
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
        /// The list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the env's state, ports, credentials, rules, denies and mutes.
    Status {
        #[command(flatten)]
        e: EnvArg,
        /// The status as JSON.
        #[arg(long, conflicts_with = "policy_json")]
        json: bool,
        /// The env's compiled policy as JSON, as its gate gets it.
        #[arg(long, conflicts_with = "size")]
        policy_json: bool,
        /// Also what the env takes on disk, part by part (the runtime walks every volume,
        /// which takes a while).
        #[arg(long)]
        size: bool,
    },
    /// Open the env's config in $EDITOR, validate and apply it.
    Edit {
        #[command(flatten)]
        e: EnvArg,
    },
    /// Show, apply or ignore the project's luoto.toml, or draft one.
    ///
    /// luoto.toml holds the team's settings in the repository; `suggest` drafts one from the
    /// env.
    Project {
        #[command(flatten)]
        e: GroupEnv,
        #[command(subcommand)]
        action: Option<ProjectCmd>,
    },
    /// Open a shell in the env, or run a command (`-- cmd args`).
    Shell {
        #[command(flatten)]
        e: EnvArg,
        /// The command and its arguments (default: a login shell).
        #[arg(last = true)]
        cmd: Vec<String>,
    },
    /// Open the env in your editor, or a terminal workspace in it.
    ///
    /// `--with ssh` prints how to connect. A terminal workspace (herdr, zellij, tmux,
    /// claude-squad) runs in the env, installed there on first use, and your terminal attaches
    /// to it: the agents it starts stay in the sandbox.
    Open {
        #[command(flatten)]
        e: EnvArg,
        /// Editor to use (default: `editor` in config.toml, else the first one installed).
        #[arg(long = "with", value_name = "EDITOR", add = ArgValueCandidates::new(complete::editors))]
        with: Option<String>,
    },
    /// Reach a port in the env on another local port.
    ///
    /// `luoto forward 8080:5173`. Ports an env listens on are forwarded to the same port here
    /// on their own.
    Forward {
        #[command(flatten)]
        e: EnvArg,
        /// The env's port, or `LOCAL:ENV` to use another port here (`8080:5173`).
        #[arg(value_name = "PORT")]
        port: String,
        /// Open it in your browser.
        #[arg(long)]
        open: bool,
    },
    /// Run an agent on one prompt, for scripts and scheduled jobs.
    ///
    /// No terminal: its answer on stdout (or in `--output`) and its exit code. Brings the env
    /// up first, asking nothing.
    Run {
        #[command(flatten)]
        e: EnvArg,
        /// The agent (`luoto agent list --available` lists them).
        #[arg(value_name = "AGENT", add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// The prompt (else `--prompt-file`, else stdin).
        #[arg(long)]
        prompt: Option<String>,
        /// Read the prompt from this file.
        #[arg(long, value_name = "FILE", add = ArgValueCompleter::new(PathCompleter::file()))]
        prompt_file: Option<String>,
        /// Write the agent's answer to this file here instead of stdout.
        #[arg(long, value_name = "FILE", add = ArgValueCompleter::new(PathCompleter::any()))]
        output: Option<String>,
        /// Stop the agent after this long (30m, 2h, 1d) and exit with 124.
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
        /// Stop the env when the run ends.
        #[arg(long)]
        down: bool,
        /// Remove the env when the run ends, as `luoto rm` does, its config included. An env
        /// holding work no remote has is kept unless you say yes, or `--yes` is given.
        #[arg(long)]
        rm: bool,
        /// With `--rm`: remove the env also with work no remote has.
        #[arg(long, short, requires = "rm")]
        yes: bool,
        /// When the agent has ended, `luoto pull`: its files listed, written into your folder
        /// after your yes. Without a terminal nothing is written.
        #[arg(long)]
        pull: bool,
        /// When the agent has ended, stop the env and write its files into your folder with
        /// nobody reviewing them. What tools here run by themselves is held back, as are
        /// files you changed too; exits with 75 when the agent succeeded and something was.
        #[arg(long, conflicts_with = "pull")]
        dangerously_pull: bool,
        /// Write what the unattended pull did to this file, as JSON.
        #[arg(long, value_name = "FILE", add = ArgValueCompleter::new(PathCompleter::any()))]
        pull_report: Option<String>,
        /// Arguments for the agent, after the env's `args` and `headless_args`
        /// (`luoto run claude --prompt … -- --bare`).
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// List, add, run, authenticate or remove the env's coding agents.
    Agent {
        #[command(flatten)]
        e: GroupEnv,
        #[command(subcommand)]
        action: Option<AgentCmd>,
    },
    /// List, add, remove or change the env's repos at /workspace/<name>.
    ///
    /// Repositories beside the env's folder: a host folder copied in, or a remote cloned in
    /// the env, and what the env may do with each.
    Repo {
        #[command(flatten)]
        e: GroupEnv,
        #[command(subcommand)]
        action: Option<RepoCmd>,
    },
    /// List, set or remove the env's variables and secrets.
    ///
    /// Plain values, and secrets code in the env reads (refs resolved on this machine at
    /// `up`).
    Var {
        #[command(flatten)]
        e: GroupEnv,
        #[command(subcommand)]
        action: Option<VarCmd>,
    },
    /// List, add or remove the private package feeds the env installs from.
    ///
    /// Azure DevOps, GitHub Packages, Gitea, Forgejo and GitLab: the gate adds the feed's token
    /// on its packages, for installs.
    Feed {
        #[command(flatten)]
        e: GroupEnv,
        #[command(subcommand)]
        action: Option<FeedCmd>,
    },
    /// List, add, sync or remove the folders the env reads at /shares/<name>.
    ///
    /// Read-only: data too large for a repo (recordings, datasets).
    Share {
        #[command(flatten)]
        e: GroupEnv,
        #[command(subcommand)]
        action: Option<ShareCmd>,
    },
    /// Copy changed files from the env back to its folder, reviewed first.
    ///
    /// Its repos copied in from folders go back to theirs too.
    Pull {
        #[command(flatten)]
        e: EnvArg,
        /// Write here instead of the env's folder (or the `--repo`'s). An env cloned from a
        /// remote has no folder: it pulls only here, into a new or empty folder (another one
        /// needs a yes on a terminal, even with `--yes`). Never your home folder.
        #[arg(long, value_name = "FOLDER", add = ArgValueCompleter::new(PathCompleter::dir()))]
        to: Option<String>,
        /// Only this repo: to its host folder, or else (a clone) the same name in the env's
        /// folder.
        #[arg(long, value_name = "NAME")]
        repo: Option<String>,
        /// Also write files host tools act on (git hooks/config, .envrc, .vscode, …).
        #[arg(long)]
        include_risky: bool,
        /// Include .git (its hooks and config count as risky).
        #[arg(long)]
        include_git: bool,
        /// Also replace files you changed here since the env's copy with the env's.
        #[arg(long)]
        overwrite: bool,
        /// Write without asking.
        #[arg(long, short)]
        yes: bool,
        /// `on`: from now on every stop of the env first pulls its files into its folder,
        /// with nobody reviewing them. `off` ends that.
        #[arg(
            long,
            value_name = "on|off",
            conflicts_with_all = ["to", "repo", "include_risky", "include_git", "overwrite", "yes"]
        )]
        on_stop: Option<OnOff>,
    },
    /// Allow egress to a host.
    Allow {
        #[command(flatten)]
        e: EnvArg,
        #[command(flatten)]
        o: rules::AllowOpts,
    },
    /// Remove rules by id or host.
    Revoke {
        #[command(flatten)]
        e: EnvArg,
        /// A rule's id (`luoto status` lists them), or its host.
        rule: String,
    },
    /// List requests filed from inside envs: every env's, or the `-e` env's.
    Requests {
        /// Only this env's (default: every env's).
        #[arg(short = 'e', long = "env", value_name = "ENV", display_order = 0,
              add = ArgValueCandidates::new(complete::envs))]
        env: Option<String>,
        /// Keep printing each new request as it comes.
        #[arg(short, long, conflicts_with = "json")]
        follow: bool,
        /// The requests as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Approve an access request (adds a rule), as asked or narrowed.
    Approve {
        #[command(flatten)]
        e: EnvArg,
        /// The request's number (`luoto requests` lists them).
        id: u64,
        /// Expire the rule after this long (30m, 2h, 1d).
        #[arg(long = "for", value_name = "DURATION")]
        window: Option<String>,
        /// Grant read-only access (GET, HEAD, OPTIONS) to a write request.
        #[arg(long, conflicts_with = "methods")]
        read: bool,
        /// Grant only these methods (repeatable), among those the request asked for.
        #[arg(long = "method", value_name = "METHOD")]
        methods: Vec<String>,
        /// Grant only these path globs (repeatable), within the request's paths.
        #[arg(long = "path", value_name = "GLOB")]
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
        #[command(flatten)]
        e: EnvArg,
        /// The request's number (`luoto requests` lists them).
        id: u64,
        /// Why, for the sandbox to read.
        #[arg(long)]
        note: Option<String>,
    },
    /// Show what the env tried to reach, per host; open or keep egress.
    ///
    /// `--follow` streams each attempt. `open` lets it reach any HTTP(S) host for a while,
    /// `keep` keeps what that reached.
    Egress {
        #[command(flatten)]
        e: GroupEnv,
        #[command(subcommand)]
        action: Option<EgressCmd>,
        /// Only the hosts with denials, and those only looked up (a name resolved, nothing
        /// sent).
        #[arg(long)]
        denied: bool,
        /// Only the hosts open egress let through: no rule allows them.
        #[arg(long, conflicts_with_all = ["denied", "follow", "raw"])]
        unruled: bool,
        /// Only attempts newer than this (30m, 2h, 1d, or an RFC 3339 time).
        #[arg(long, value_name = "DURATION")]
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
        #[arg(long, conflicts_with_all = ["follow", "raw"])]
        json: bool,
    },
    /// Show the env's gate log, the watcher's, or what its installs printed.
    Logs {
        #[command(flatten)]
        e: EnvArg,
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
    /// Show, unlock, lock or reload the vault of every env's secrets.
    Vault {
        #[command(subcommand)]
        action: Option<VaultCmd>,
    },
    /// Internal: stdio transport for SSH (`ProxyCommand luoto ssh-proxy <env>`).
    #[command(hide = true)]
    SshProxy {
        #[arg(value_name = "ENV")]
        name: String,
    },
    /// Internal: the background watcher that forwards ports and stops idle envs.
    #[command(hide = true)]
    Watch,
    /// Internal: finish the pulls a crash left owed; the watcher runs it.
    #[command(hide = true)]
    Recover,
}

#[derive(Subcommand)]
enum AgentCmd {
    /// List the env's agents and how each authenticates.
    #[command(visible_alias = "ls")]
    List {
        /// Every agent and model provider luoto knows instead.
        #[arg(long)]
        available: bool,
    },
    /// Install an agent in the env and add it to the config.
    Add {
        /// The agent (`luoto agent list --available` lists them).
        #[arg(value_name = "AGENT", add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// Its credential without the prompt: `KIND=REF` (`oauth_token=op://…`),
        /// `PROVIDER.KIND=REF`, or `login_inside`; replaces the one the env has.
        #[arg(long, value_name = "KIND=REF")]
        credential: Option<String>,
    },
    /// Run an agent in the env's workspace (installs it on first use).
    Run {
        /// The agent (`luoto agent list --available` lists them).
        #[arg(value_name = "AGENT", add = ArgValueCandidates::new(complete::agents))]
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
        /// The agent (`luoto agent list` lists the env's).
        #[arg(value_name = "AGENT", add = ArgValueCandidates::new(complete::agents))]
        agent: String,
        /// The credential without the prompt: `KIND=REF` (`oauth_token=op://…`),
        /// `PROVIDER.KIND=REF`, or `login_inside`.
        #[arg(long, value_name = "KIND=REF")]
        credential: Option<String>,
    },
    /// Remove an agent from the env's config; its files stay in the env's home.
    Rm {
        /// The agent (`luoto agent list` lists the env's).
        #[arg(value_name = "AGENT", add = ArgValueCandidates::new(complete::agents))]
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
        /// How long (30m, 2h, 1d; default: 1h). With no end: `open = true` under [egress] in
        /// the env's file.
        #[arg(long = "for", value_name = "DURATION")]
        window: Option<String>,
    },
    /// Close open egress: only the rules allow again.
    Close,
    /// Keep what open egress reached: presets, else a rule per host.
    ///
    /// Each host goes under the presets that cover it, else under a read rule of its own; you
    /// pick from the offer.
    Keep {
        /// Only what it reached this recently (30m, 2h, 1d, or an RFC 3339 time).
        #[arg(long, value_name = "DURATION")]
        since: Option<String>,
        /// Keep what is offered checked (presets and read rules) without asking.
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum RepoCmd {
    /// List the env's repos and where each comes from.
    #[command(visible_alias = "ls")]
    List,
    /// Add a host folder (copied in) or a remote (cloned in the env).
    ///
    /// Either is at /workspace/<name>; a remote's access is asked after, or given with
    /// `--access`.
    Add {
        /// A folder (starts with `/`, `~` or `.`, or exists), else a remote: `owner/repo` on
        /// GitHub, an https or ssh URL, or user@host:path.
        #[arg(value_name = "FOLDER|REMOTE", add = ArgValueCompleter::new(PathCompleter::dir()))]
        source: String,
        /// Its folder in the workspace (default: the last part of the path or URL).
        #[arg(long)]
        name: Option<String>,
        /// The branch a clone checks out (default: the remote's).
        #[arg(long)]
        branch: Option<String>,
        /// Add it even though the env's workspace is a git repository itself, so the repo sits
        /// inside it (kept out of its `git status`).
        #[arg(long)]
        inside: bool,
        #[command(flatten)]
        access: repos::AccessArgs,
    },
    /// Remove a repo from the env's config; its copy in the env stays.
    Rm {
        /// The repo's name in the workspace.
        name: String,
    },
    /// Change what the env may do with a repo: fetch, read or push.
    ///
    /// Fetching a public repo needs no token; reading a private one or pushing takes the
    /// forge's credential, asked for or given with `--token`.
    Auth {
        /// The repo's name in the workspace, or its path on the forge (`acme/api`).
        repo: String,
        #[command(flatten)]
        access: repos::AccessArgs,
    },
}

#[derive(Subcommand)]
enum FeedCmd {
    /// List the feeds the env installs from.
    #[command(visible_alias = "ls")]
    List,
    /// Install from a feed, with its service's token.
    Add {
        /// The feed's URL as your package manager's settings have it (an index or registry
        /// URL, or an `.npmrc` line); `org/project/feed` for Azure DevOps.
        #[arg(value_name = "FEED")]
        feed: String,
        /// Where the token is kept (`op://…`, `keyring:…`, `env:NAME`), when the env has none
        /// for the feed's service yet; asked on a terminal. Replaces the one it has.
        #[arg(long, value_name = "REF")]
        token: Option<String>,
        /// The CA certificate (a PEM file) a self-hosted forge's certificate is signed by.
        #[arg(long, value_name = "FILE")]
        ca: Option<String>,
        /// The exact host a self-hosted forge's downloads redirect to, its object storage
        /// (repeatable).
        #[arg(long, value_name = "HOST")]
        storage_host: Vec<String>,
    },
    /// Stop installing from a feed.
    Rm {
        /// The feed as `luoto feed list` lists it, or its URL.
        #[arg(value_name = "FEED")]
        feed: String,
    },
}

#[derive(Subcommand)]
enum ShareCmd {
    /// List the env's shares, and which changed since the last sync.
    #[command(visible_alias = "ls")]
    List,
    /// Share a folder, read-only at /shares/<name> in the env.
    ///
    /// The env reads it as of its last sync: `luoto up` and `luoto share sync` bring it up to
    /// date.
    Add {
        /// A folder inside your home folder (not a secret one such as ~/.ssh), or on a disk.
        #[arg(add = ArgValueCompleter::new(PathCompleter::dir()))]
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
    /// List the env's variables: plain values, and secrets by their ref.
    #[command(visible_alias = "ls")]
    List,
    /// Set a variable: a plain value, or a secret by its ref.
    ///
    /// `NAME=value` a plain value (it stays in your shell history), `NAME` a secret, asking
    /// where it is kept, or `NAME --ref <REF>`. A token an HTTP API takes is safer as a
    /// credential the gate adds, outside the env (`[credentials.custom.<name>]`).
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
        /// Don't ask first.
        #[arg(long, short)]
        yes: bool,
        /// Take your folder's luoto.toml into the env first, also over a copy the env
        /// changed.
        #[arg(long)]
        from_folder: bool,
    },
    /// Stop applying it (this version is not offered again).
    Ignore,
    /// Ask again for what luoto.toml needs only you add.
    ///
    /// What the accepted luoto.toml's `[needs]` names: credentials and sandbox secrets, each
    /// question opening on what the env has. Without a terminal, the commands that add each.
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
        overwrite: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OnOff {
    On,
    Off,
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Show whether the vault is locked, and each env's credentials.
    Status,
    /// Load secrets into the vault (after a reboot) and re-register every env.
    Unlock,
    /// Wipe secrets from the vault and every gate.
    Lock,
    /// Read the secrets again, after rotating one in your secret store.
    ///
    /// All the vault holds, or with `-e` the env's.
    Reload {
        /// Only this env's secrets (default: all the vault holds).
        #[arg(short = 'e', long = "env", value_name = "ENV",
              add = ArgValueCandidates::new(complete::envs))]
        env: Option<String>,
    },
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
    match run(cli.cmd) {
        Ok(code) => code,
        Err(e) => {
            let msg = text::lines(&format!("{e:#}"));
            let style = style::err();
            let shown = style.commands(&text::hang("luoto: ", &msg, text::columns()));
            let shown = shown.strip_prefix("luoto: ").unwrap_or(&shown);
            eprintln!("{}{shown}", style.error("luoto: "));
            ExitCode::FAILURE
        }
    }
}

/// Whether `cmd` first sees to pulls a crash left cut short or owed (`autopull::attend`):
/// not the watcher and `recover` (they do the pulling), nor commands that act on no env or
/// whose output is someone else's stream, nor those that start or stop an env or change
/// whether it pulls, which settle what is owed to it themselves.
fn attends(cmd: &Cmd) -> bool {
    !matches!(
        cmd,
        Cmd::Watch
            | Cmd::Recover
            | Cmd::SshProxy { .. }
            | Cmd::Setup(_)
            | Cmd::Doctor { .. }
            | Cmd::Upgrade
            | Cmd::Uninstall { .. }
            | Cmd::Logs { .. }
            | Cmd::Up { .. }
            | Cmd::Down { .. }
            | Cmd::Run { .. }
            | Cmd::Pull {
                on_stop: Some(_),
                ..
            }
    )
}

fn run(cmd: Cmd) -> Result<ExitCode> {
    use commands as c;
    let paths = paths::Paths::get()?;
    if attends(&cmd) {
        autopull::attend(&paths);
    }
    let env = |given: Option<String>| workspace::resolve(&paths, given.as_deref());
    match cmd {
        Cmd::Setup(o) => setup::setup(o),
        Cmd::Doctor { report } => setup::doctor(report),
        Cmd::Upgrade => upgrade::upgrade(),
        Cmd::Uninstall { yes } => uninstall::uninstall(yes),
        Cmd::Prune {
            yes,
            envs: true,
            older_than,
            matching,
            with_work,
        } => prune::envs(prune::Opts {
            older_than,
            matching,
            with_work,
            yes,
        }),
        Cmd::Prune { yes, .. } => disk::prune(yes),
        Cmd::Ui { port, no_open } => ui::serve(port, !no_open),
        Cmd::Init(o) => init::init(o),
        Cmd::Up {
            all: true,
            no_selftest,
            recreate,
            quiet,
            ..
        } => c::up_all(!no_selftest, recreate, quiet),
        Cmd::Up {
            e,
            all: false,
            no_selftest,
            recreate,
            quiet,
        } => {
            let named = e.env.is_some();
            match env(e.env) {
                Ok(name) => c::up(&name, !no_selftest, recreate, quiet),
                // A folder without an env: offer to set one up (init shows it and asks first).
                Err(_) if !named && std::io::stdin().is_terminal() => {
                    out!("no env for this folder yet\n");
                    init::init(init::InitOpts::default())
                }
                Err(err) => Err(err),
            }
        }
        Cmd::Down { all: true, .. } => c::down_all(),
        Cmd::Down {
            e,
            all: false,
            idle,
        } => c::down(&env(e.env)?, idle),
        Cmd::Rm { e, yes } => c::rm(&env(e.env)?, yes),
        Cmd::ResetHome { e, yes } => c::reset_home(&env(e.env)?, yes),
        Cmd::Export {
            e,
            file,
            no_home,
            yes,
        } => transfer::export(&env(e.env)?, file.as_deref(), no_home, yes),
        Cmd::Import { file, name, yes } => transfer::import(&file, name.as_deref(), yes),
        Cmd::List { size, json } => c::list(size, json),
        Cmd::Status {
            e,
            json,
            policy_json,
            size,
        } => {
            let shape = match (json, policy_json) {
                (true, _) => c::StatusAs::Json,
                (_, true) => c::StatusAs::PolicyJson,
                _ => c::StatusAs::Text,
            };
            c::status(&env(e.env)?, shape, size)
        }
        Cmd::Edit { e } => c::edit(&env(e.env)?),
        Cmd::Project { e, action } => {
            let name = env(e.env)?;
            match action {
                None => c::project(&name, None, false, false),
                Some(ProjectCmd::Apply { yes, from_folder }) => {
                    let take = if from_folder {
                        project::Take::Folder
                    } else {
                        project::Take::Newer
                    };
                    c::project(&name, Some(take), false, yes)
                }
                Some(ProjectCmd::Ignore) => c::project(&name, None, true, false),
                Some(ProjectCmd::Needs) => c::project_needs(&name),
                Some(ProjectCmd::Suggest { write, overwrite }) => {
                    c::project_suggest(&name, write, overwrite)
                }
            }
        }
        Cmd::Shell { e, cmd } => connect::shell(&env(e.env)?, &cmd),
        Cmd::Open { e, with } => connect::open(&env(e.env)?, with.as_deref()),
        Cmd::Forward { e, port, open } => connect::forward(&env(e.env)?, &port, open),
        Cmd::Run {
            e,
            agent,
            prompt,
            prompt_file,
            output,
            timeout,
            down,
            rm,
            yes,
            pull,
            dangerously_pull,
            pull_report,
            args,
        } => {
            let prompt = match (prompt, prompt_file) {
                (Some(p), _) => p,
                (None, Some(f)) => std::fs::read_to_string(workspace::expand(&f))
                    .map_err(|err| anyhow::anyhow!("read {f}: {err}"))?,
                (None, None) if !std::io::stdin().is_terminal() => {
                    std::io::read_to_string(std::io::stdin())?
                }
                (None, None) => {
                    anyhow::bail!("give the prompt: `--prompt`, `--prompt-file` or stdin")
                }
            };
            agents::headless(
                &env(e.env)?,
                &agent,
                &prompt,
                &args,
                output.as_deref(),
                timeout.as_deref(),
                agents::Finish {
                    end: agents::End::of(down, rm, yes),
                    pull: agents::RunPull {
                        reviewed: pull,
                        unattended: dangerously_pull,
                        report: pull_report,
                    },
                },
            )
        }
        Cmd::Agent { e, action } => {
            let action = action.unwrap_or(AgentCmd::List { available: false });
            if let AgentCmd::List { available: true } = action {
                if e.env.is_some() {
                    anyhow::bail!("`luoto agent list --available` lists every env's; drop `-e`");
                }
                return agents::available();
            }
            let name = env(e.env)?;
            match action {
                AgentCmd::List { .. } => agents::list(&name),
                AgentCmd::Add { agent, credential } => {
                    agents::add(&name, &agent, credential.as_deref())
                }
                AgentCmd::Run { agent, yolo, args } => agents::run(&name, &agent, yolo, &args),
                AgentCmd::Auth { agent, credential } => {
                    agents::auth(&name, &agent, credential.as_deref())
                }
                AgentCmd::Rm { agent } => agents::rm(&name, &agent),
            }
        }
        Cmd::Repo { e, action } => {
            let name = env(e.env)?;
            match action.unwrap_or(RepoCmd::List) {
                RepoCmd::List => repos::list(&name),
                RepoCmd::Add {
                    source,
                    name: repo,
                    branch,
                    inside,
                    access,
                } => repos::add(
                    &name,
                    &source,
                    repo.as_deref(),
                    branch.as_deref(),
                    inside,
                    &access,
                ),
                RepoCmd::Rm { name: repo } => repos::rm(&name, &repo),
                RepoCmd::Auth { repo, access } => repos::auth(&name, &repo, &access),
            }
        }
        Cmd::Feed { e, action } => {
            let name = env(e.env)?;
            match action.unwrap_or(FeedCmd::List) {
                FeedCmd::List => feeds::list(&name),
                FeedCmd::Add {
                    feed,
                    token,
                    ca,
                    storage_host,
                } => feeds::add(&name, &feed, token.as_deref(), ca.as_deref(), &storage_host),
                FeedCmd::Rm { feed } => feeds::rm(&name, &feed),
            }
        }
        Cmd::Share { e, action } => {
            let name = env(e.env)?;
            match action.unwrap_or(ShareCmd::List) {
                ShareCmd::List => shares::list(&name),
                ShareCmd::Add {
                    folder,
                    name: share,
                    yes,
                } => shares::add(&name, &folder, share.as_deref(), yes),
                ShareCmd::Sync { name: share, yes } => {
                    shares::sync_cmd(&name, share.as_deref(), yes)
                }
                ShareCmd::Rm { name: share } => shares::rm(&name, &share),
            }
        }
        Cmd::Var { e, action } => {
            let name = env(e.env)?;
            match action.unwrap_or(VarCmd::List) {
                VarCmd::List => vars::list(&name),
                VarCmd::Set { var, reference } => vars::set_cmd(&name, &var, reference.as_deref()),
                VarCmd::Rm { name: var } => vars::rm_cmd(&name, &var),
            }
        }
        Cmd::Pull {
            e,
            on_stop: Some(on),
            ..
        } => c::pull_on_stop(&env(e.env)?, on == OnOff::On),
        Cmd::Pull {
            e,
            to,
            repo,
            include_risky,
            include_git,
            overwrite,
            yes,
            on_stop: None,
        } => c::pull(
            &env(e.env)?,
            c::PullOpts {
                to: to.as_deref(),
                repo: repo.as_deref(),
                include_risky,
                include_git,
                overwrite,
                yes,
            },
        ),
        Cmd::Allow { e, o } => c::allow(&env(e.env)?, o),
        Cmd::Revoke { e, rule } => c::revoke(&env(e.env)?, &rule),
        Cmd::Requests {
            env: named,
            follow,
            json,
        } => {
            // No env named: every env's requests.
            let picked = named.map(|n| env(Some(n))).transpose()?;
            c::requests(picked.as_deref(), follow, json)
        }
        Cmd::Approve {
            e,
            id,
            window,
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
            c::approve(&env(e.env)?, id, window.as_deref(), &narrow, yes, force)
        }
        Cmd::Reject { e, id, note } => c::reject(&env(e.env)?, id, note),
        Cmd::Egress {
            e,
            action: Some(action),
            denied,
            unruled,
            since,
            follow,
            raw,
            all,
            json,
        } => {
            // The listing's own flags, before a subcommand, mean nothing to it.
            if denied || unruled || since.is_some() || follow || raw || all || json {
                anyhow::bail!(
                    "`--denied`, `--unruled`, `--since`, `--follow`, `--raw`, `--all` and \
                     `--json` are for `luoto egress` itself, not its subcommands"
                );
            }
            let name = env(e.env)?;
            match action {
                EgressCmd::Open { window } => c::egress_open(&name, window.as_deref()),
                EgressCmd::Close => c::egress_close(&name),
                EgressCmd::Keep { since, yes } => {
                    let since = since.as_deref().map(events::since).transpose()?;
                    c::egress_keep(&name, since.as_deref(), yes)
                }
            }
        }
        Cmd::Egress {
            e,
            action: None,
            denied,
            unruled,
            since,
            follow,
            raw,
            all,
            json,
        } => {
            let name = env(e.env)?;
            let since = since.as_deref().map(events::since).transpose()?;
            if follow || raw {
                c::logs(&name, follow, denied, all, since.as_deref())
            } else {
                let only = if unruled {
                    c::Only::Opened
                } else if denied {
                    c::Only::Denied
                } else {
                    c::Only::All
                };
                c::egress(&name, only, all, since.as_deref(), json)
            }
        }
        Cmd::Logs {
            e,
            source,
            follow,
            lines,
        } => {
            if source == logs::Source::Watcher && e.env.is_some() {
                anyhow::bail!("the watcher's log is every env's; drop `-e`");
            }
            logs::show(source, || env(e.env), follow, lines)
        }
        Cmd::Vault { action } => match action.unwrap_or(VaultCmd::Status) {
            VaultCmd::Status => c::vault_status(),
            VaultCmd::Unlock => c::unlock(),
            VaultCmd::Lock => c::lock(),
            VaultCmd::Reload { env: named } => c::reload(named.as_deref()),
        },
        Cmd::SshProxy { name } => connect::ssh_proxy(&name),
        Cmd::Watch => watch::watch(),
        Cmd::Recover => {
            autopull::recover(&env::Ctx::load()?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from([&["luoto"], args].concat())
    }

    #[test]
    fn the_cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn approve_takes_what_narrows_a_request() {
        let Ok(Cli {
            cmd:
                Cmd::Approve {
                    id: 3,
                    read: true,
                    methods,
                    paths,
                    window,
                    ..
                },
            ..
        }) = parse(&[
            "approve", "3", "--read", "--path", "/v1/**", "--path", "/v2", "--for", "2h",
        ])
        else {
            panic!("approve didn't parse");
        };
        assert!(methods.is_empty());
        assert_eq!(paths, ["/v1/**", "/v2"]);
        assert_eq!(window.as_deref(), Some("2h"));
        assert!(parse(&["approve", "3", "--read", "--method", "GET"]).is_err());
        assert!(parse(&["approve", "3", "--ttl", "2h"]).is_err());
    }

    #[test]
    fn egress_opens_closes_and_keeps_beside_its_views() {
        let action = |args: &[&str]| match parse(args).unwrap().cmd {
            Cmd::Egress { action, .. } => action,
            _ => panic!("not egress"),
        };
        assert!(matches!(
            action(&["egress", "open"]),
            Some(EgressCmd::Open { window: None })
        ));
        // `-e` goes before or after a subcommand, as in every group.
        assert!(parse(&["egress", "-e", "web", "--denied"]).is_ok());
        for args in [
            &["egress", "open", "-e", "web", "--for", "2h"][..],
            &["egress", "open", "--for", "2h", "-e", "web"],
            &["egress", "-e", "web", "open", "--for", "2h"],
        ] {
            let Cmd::Egress { e, action, .. } = parse(args).unwrap().cmd else {
                panic!("not egress");
            };
            assert_eq!(e.env.as_deref(), Some("web"));
            assert!(matches!(action, Some(EgressCmd::Open { window: Some(w) }) if w == "2h"));
        }
        assert!(matches!(
            action(&["egress", "close"]),
            Some(EgressCmd::Close)
        ));
        assert!(matches!(
            action(&["egress", "keep", "--since", "2h", "-y"]),
            Some(EgressCmd::Keep { since: Some(s), yes: true }) if s == "2h"
        ));
        assert!(matches!(
            parse(&["egress", "--unruled"]).unwrap().cmd,
            Cmd::Egress {
                action: None,
                unruled: true,
                ..
            }
        ));
        assert!(action(&["egress", "--denied"]).is_none());
        // A view flag before a subcommand parses; running it refuses it, before anything runs.
        assert!(matches!(
            parse(&["egress", "--denied", "open"]).unwrap().cmd,
            Cmd::Egress {
                denied: true,
                action: Some(EgressCmd::Open { .. }),
                ..
            }
        ));
        for bad in [
            &["egress", "--unruled", "--denied"][..],
            &["egress", "--unruled", "--follow"],
            &["egress", "--json", "--follow"],
            &["egress", "--json", "--raw"],
            &["egress", "--open"],
            &["egress", "open", "--for"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn init_opens_egress_for_an_hour_or_as_long_as_given() {
        let init = |args: &[&str]| match parse(args).unwrap().cmd {
            Cmd::Init(o) => o,
            _ => panic!("not init"),
        };
        assert_eq!(init(&["init"]).open_window(), None);
        assert_eq!(init(&["init", "--open"]).open_window(), Some("1h"));
        assert_eq!(
            init(&["init", "--open-for", "2h"]).open_window(),
            Some("2h")
        );
        let o = init(&["init", "--open", "acme/web"]);
        assert_eq!(
            (o.open_window(), o.dir.as_deref()),
            (Some("1h"), Some("acme/web"))
        );
        assert!(parse(&["init", "--open", "--open-for", "2h"]).is_err());
        assert!(parse(&["init", "--open=2h"]).is_err());
    }

    #[test]
    fn a_run_names_its_agent_and_passes_what_follows_the_double_dash_to_it() {
        let cli = parse(&[
            "run",
            "claude",
            "--prompt",
            "hi",
            "--",
            "--bare",
            "--tools",
            "Bash,Read",
        ])
        .unwrap();
        let Cmd::Run {
            agent,
            prompt,
            args,
            ..
        } = cli.cmd
        else {
            panic!("not run")
        };
        assert_eq!(agent, "claude");
        assert_eq!(prompt.as_deref(), Some("hi"));
        assert_eq!(args, ["--bare", "--tools", "Bash,Read"]);
        assert!(parse(&["run", "--agent", "claude", "--prompt", "hi"]).is_err());
    }

    #[test]
    fn a_run_pulls_reviewed_or_unreviewed_never_both() {
        let run_with = |args: &[&str]| parse(&[&["run", "claude", "--prompt", "x"], args].concat());
        let flags = |args: &[&str]| match run_with(args).unwrap().cmd {
            Cmd::Run {
                pull,
                dangerously_pull,
                pull_report,
                ..
            } => (pull, dangerously_pull, pull_report),
            _ => panic!("not run"),
        };
        assert_eq!(flags(&[]), (false, false, None));
        assert_eq!(flags(&["--pull"]), (true, false, None));
        assert_eq!(
            flags(&["--dangerously-pull", "--rm", "--pull-report", "r.json"]),
            (false, true, Some("r.json".into()))
        );
        assert!(run_with(&["--pull", "--dangerously-pull"]).is_err());
        assert!(run_with(&["--report", "r.json"]).is_err());
    }

    #[test]
    fn pull_on_stop_is_set_by_its_own_command() {
        let pull = |args: &[&str]| parse(&[&["pull"], args].concat());
        let on_stop = |args: &[&str]| match pull(args).unwrap().cmd {
            Cmd::Pull { on_stop, .. } => on_stop.map(|o| o == OnOff::On),
            _ => panic!("not pull"),
        };
        assert_eq!(on_stop(&[]), None);
        assert_eq!(on_stop(&["--on-stop", "on"]), Some(true));
        assert_eq!(on_stop(&["--on-stop", "off"]), Some(false));
        // On is typed out, and never comes with a pull's own flags.
        assert!(pull(&["--on-stop"]).is_err());
        assert!(pull(&["--on-stop", "yes"]).is_err());
        assert!(pull(&["--on-stop", "on", "--yes"]).is_err());
        assert!(pull(&["--on-stop", "on", "--include-risky"]).is_err());
        assert!(pull(&["--overwrite", "--include-risky", "-y"]).is_ok());
        // The watcher's stop names one env.
        let down = |args: &[&str]| parse(&[&["down"], args].concat());
        assert!(down(&["--idle", "-e", "web"]).is_ok());
        assert!(down(&["--idle", "--all"]).is_err());
    }

    #[test]
    fn run_takes_rm_and_yes_only_with_it() {
        let run_with = |args: &[&str]| parse(&[&["run", "claude", "--prompt", "x"], args].concat());
        let flags = |args: &[&str]| match run_with(args).unwrap().cmd {
            Cmd::Run { down, rm, yes, .. } => (down, rm, yes),
            _ => panic!("not run"),
        };
        assert_eq!(flags(&[]), (false, false, false));
        assert_eq!(flags(&["--rm"]), (false, true, false));
        assert_eq!(flags(&["--rm", "--yes"]), (false, true, true));
        assert_eq!(flags(&["--rm", "-y", "--down"]), (true, true, true));
        // Yes to nothing asked is a mistake.
        assert!(run_with(&["--yes"]).is_err());
        assert!(run_with(&["--down", "-y"]).is_err());
        // After `--` they are the agent's.
        let Cmd::Run { rm, args, .. } = run_with(&["--", "--rm"]).unwrap().cmd else {
            panic!("not run")
        };
        assert!(!rm && args == ["--rm"]);
    }

    #[test]
    fn all_is_every_env_not_one() {
        for args in [["up", "--all", "-e", "web"], ["down", "-e", "web", "--all"]] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
        let Ok(Cli {
            cmd:
                Cmd::Logs {
                    source,
                    follow,
                    lines,
                    ..
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
    fn a_report_file_is_optional() {
        let report = |args: &[&str]| match parse(args).unwrap().cmd {
            Cmd::Doctor { report } => report,
            _ => panic!("not doctor"),
        };
        assert_eq!(report(&["doctor"]), None);
        assert_eq!(report(&["doctor", "--report"]), Some(None));
        assert_eq!(
            report(&["doctor", "--report", "bug.txt"]),
            Some(Some("bug.txt".into()))
        );
    }

    #[test]
    fn prune_takes_its_filters_only_for_envs() {
        let Cmd::Prune {
            envs,
            older_than,
            matching,
            with_work,
            yes,
        } = parse(&["prune", "--envs", "--older-than", "7d", "--match", "job-*"])
            .unwrap()
            .cmd
        else {
            panic!("not prune");
        };
        assert!(envs && !with_work && !yes);
        assert_eq!(older_than.as_deref(), Some("7d"));
        assert_eq!(matching.as_deref(), Some("job-*"));
        // The env filters mean nothing to the image prune.
        for alone in [
            &["prune", "--older-than", "7d"][..],
            &["prune", "--match", "job-*"],
            &["prune", "--with-work"],
        ] {
            assert!(parse(alone).is_err());
        }
        assert!(matches!(
            parse(&["ls"]).unwrap().cmd,
            Cmd::List {
                size: false,
                json: false
            }
        ));
        assert!(matches!(
            parse(&["list", "--size", "--json"]).unwrap().cmd,
            Cmd::List {
                size: true,
                json: true
            }
        ));
    }

    #[test]
    fn every_env_flag_is_the_one_flag() {
        fn walk(cmd: &clap::Command, path: &str) {
            for sub in cmd.get_subcommands() {
                let path = format!("{path} {}", sub.get_name());
                for a in sub.get_arguments().filter(|a| a.get_id() == "env") {
                    assert_eq!(a.get_short(), Some('e'), "`luoto{path}`'s `env`");
                }
                walk(sub, &path);
            }
        }
        walk(&Cli::command(), "");
    }

    /// The command lines luoto runs of itself parse and reach their command with their env.
    #[test]
    fn what_luoto_runs_of_itself_parses() {
        // ssh_configs already written run exactly this.
        assert_eq!(ssh::proxy_args("web"), ["ssh-proxy", "web"]);
        let proxy = parse(&ssh::proxy_args("web")).unwrap();
        assert!(matches!(&proxy.cmd, Cmd::SshProxy { name } if name == "web"));

        let watch = parse(&watch::ARGS).unwrap();
        assert!(matches!(watch.cmd, Cmd::Watch));

        let up = parse(&agents::up_args("web")).unwrap();
        assert!(matches!(
            up.cmd,
            Cmd::Up { e: EnvArg { env: Some(ref n) }, all: false, .. } if n == "web"
        ));
        let down = parse(&["down", "-e", "web", "--idle"]).unwrap();
        assert!(matches!(down.cmd, Cmd::Down { idle: true, .. }));
    }

    #[test]
    fn a_command_that_acts_on_no_env_takes_no_env() {
        for args in [
            &["list", "-e", "web"][..],
            &["-e", "web", "vault"],
            &["vault", "-e", "web"],
            &["vault", "lock", "-e", "web"],
            &["doctor", "-e", "web"],
            &["uninstall", "-e", "web"],
            &["prune", "-e", "web", "--yes"],
            &["setup", "-e", "web"],
            &["import", "web.luoto.tar", "-e", "web"],
            &["init", "-e", "web"],
            &["-e", "web", "status"],
        ] {
            assert!(parse(args).is_err(), "{args:?}");
        }
        for args in [
            &["agent", "list", "--available", "-e", "web"][..],
            &["logs", "watcher", "-e", "web"],
        ] {
            let cli = parse(args).unwrap();
            let e = run(cli.cmd).unwrap_err().to_string();
            assert!(e.contains("drop `-e`"), "{args:?}: {e}");
        }
        for args in [
            &["vault", "reload", "-e", "web"][..],
            &["requests", "-e", "web"],
            &["logs", "installs", "-e", "web"],
            &["status", "-e", "web"],
            &["share", "add", "-e", "web", "/tmp/x"],
            &["share", "-e", "web", "add", "/tmp/x"],
            &["agent", "list", "-e", "web"],
            &[
                "repo", "auth", "acme/api", "--access", "push", "--token", "env:T", "-e", "web",
            ],
        ] {
            assert!(parse(args).is_ok(), "{args:?}");
        }
        assert!(parse(&["repo", "auth", "acme/api", "--token", "env:T"]).is_err());
    }

    #[test]
    fn every_line_of_help_fits_80_columns() {
        let mut todo = vec![Cli::command()];
        while let Some(mut c) = todo.pop() {
            for help in [
                c.render_help().to_string(),
                c.render_long_help().to_string(),
            ] {
                for line in help.lines() {
                    assert!(line.chars().count() <= 80, "{}: {line}", c.get_name());
                }
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
        assert!(matches!(
            parse(&["import", "web.luoto.tar", "--name", "api", "-y"]).unwrap().cmd,
            Cmd::Import { name: Some(n), yes: true, .. } if n == "api"
        ));
        assert!(matches!(
            parse(&["export", "--no-home", "-y"]).unwrap().cmd,
            Cmd::Export {
                file: None,
                no_home: true,
                yes: true,
                ..
            }
        ));
        assert!(matches!(
            parse(&["export", "-e", "web", "/tmp"]).unwrap().cmd,
            Cmd::Export { file: Some(f), .. } if f == "/tmp"
        ));
    }

    #[test]
    fn requests_follow_or_print_json() {
        assert!(matches!(
            parse(&["requests", "-f"]).unwrap().cmd,
            Cmd::Requests { follow: true, .. }
        ));
        assert!(parse(&["requests", "--watch"]).is_err());
        assert!(parse(&["requests", "--follow", "--json"]).is_err());
        assert!(parse(&["status", "--json", "--policy-json"]).is_err());
        assert!(parse(&["project", "suggest", "--write", "--overwrite"]).is_ok());
        assert!(parse(&["project", "suggest", "--write", "--force"]).is_err());
        assert!(parse(&["agent", "remove", "claude"]).is_err());
    }
}
