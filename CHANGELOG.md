# Changelog

## 0.3.0 (unreleased)

Related repositories in one env, git on any forge, and an `up` that sets up what an env lacks.

- **Repos:** `--repo` on `luoto init`, `luoto repo add|rm|list` and `[workspace.repos.<name>]`
  put repositories at `/workspace/<name>`: a host folder, copied in and pulled back to it, or a
  remote (`owner/repo`, an https or ssh URL), cloned in the env through the gate on `up`.
  luoto commands in a repo's folder act on its env. The UI lists an env's repos.
- **Repos in `luoto.toml`:** `[repos.<name>] url = …` gives a team the same set of remotes; the
  env's own repo of a name replaces the file's.
- **Pull:** each copied-in repo goes back to its own folder; cloned ones stay out unless named
  with `--repo`. Risky files count in any folder within the pull, so a nested repository's
  `.git`, `.envrc` or `.vscode` is held back like the top folder's.
- **Detection** (`luoto init`, toolchain installs on `up`) reads the repositories in the
  folder, which git in the folder doesn't list.
- **Read-only repos:** `read_repos` in `[credentials.github]` and `[credentials.azure_devops]`
  are fetched and read through the gate, never pushed to or written; a GitHub App mints a
  read-only token for them.
- **A GitHub credential per owner:** `[[credentials.github]]`, once per account. Each repo's
  requests get the credential that lists it, GraphQL the first one's. A single
  `[credentials.github]` stays as it is; a token that reaches several owners is one credential
  listing all their repos, and `up` offers a reference the config has before asking for another.
- **Git on any forge:** `[[credentials.git]]` gives a host (GitLab, Forgejo, Gitea, Bitbucket,
  self-hosted) a token the gate adds to the listed repos' git requests as basic auth, with the
  push guard, `read_repos`, a port, `private = true` for a private network and `ca` for an
  internal CA. Without a token it lets public repos be fetched. `up` asks for one per host.
- **`up` reconciles agents and credentials:** it installs the agents an env's config or its
  `luoto.toml` lists when the env lacks them, so a team's `agents = ["claude"]` reaches
  everyone; `init --agent`, `agent add` and `agent run` list the agent and leave the rest to
  `up`. On a terminal, `up` first asks for what is missing: how an agent authenticates, and
  an HTTPS credential for each GitHub owner and Azure DevOps organization whose repos none
  covers (push or read only, kept in the keychain, 1Password or a reference). Repos answered
  as public aren't asked about again; a removed credential is asked for anew. Without a
  terminal, or with `init --yes`, agents log in inside and `up` prints the git credentials to
  add. `luoto repo add` asks the same before it clones.
- **Packages and toolchains on request:** `sandbox request --package <name>` and
  `--tool <tool>@<version>` (MCP: `sandbox_request_install`) ask you to keep software in the
  env. `luoto approve` (or the UI) installs it and writes it into `[deps] system` or `[tools]`,
  so a recreated container gets it again; the sandbox learns whether the install worked.
- **Agent credentials on the command line:** `--credential oauth_token=op://…` on
  `luoto agent add` and `luoto init` writes the credential without the prompt; the reference
  must resolve.
- **Headless runs:** `luoto run --agent claude --prompt "…"` brings the env up asking nothing,
  runs the agent's non-interactive mode and prints its answer (`--output FILE` writes it,
  `--down` stops the env after), exiting with the agent's code. Claude Code, Codex, OpenCode
  and Copilot CLI have one.
- **Presets from cloned repos:** after `up` clones repos, it offers the presets and default
  toolchains their files suggest, as `luoto init` does for a folder; it adds them only on your
  yes. `luoto init` again on an env no longer adds them without a terminal.
- **`sandbox request --preset npm`** (MCP: `preset` in `sandbox_request_access`) asks for one of
  luoto's presets; approving adds it to the env and opens its hosts at once.
- **`luoto agent rm`** drops an agent from an env's config and its hosts from the policy.
- **`luoto requests --watch`** prints each new request as it comes, with the terminal's bell.
- **Agent model and effort:** `[agents.claude] model = "opus"`, `effort = "medium"` in an
  env's config, its `luoto.toml`, or `config.toml` for every env that has the agent; `up`
  writes them into the agent's settings as the default a session can change. `agents = [...]`
  keeps working.
- **Claude Code starts at its prompt:** luoto answers its first-start questions (onboarding,
  trusting `/workspace`) in the env, as the sandbox is the boundary; an agent profile lists
  such answers under `[[first_run]]`. The text style stays `theme` in your own settings.
- **The UI never waits on a terminal:** an `up` it starts asks nothing on the terminal running
  `luoto ui`, where a changed `luoto.toml` could leave it waiting.
- **Copies follow `.gitignore`:** from a git repository (the folder, a repo, or one inside),
  `up` copies what git doesn't ignore plus `.git`, so ignored secrets (`.env`, `*.tfvars`, state
  files, `.kube/`) stay on your machine. Other folders copy as before, now without
  `.terraform`, which holds the host's provider binaries.

## 0.2.2 (2026-11-06)

- **Image pulls:** `up` and `init` pull every missing image themselves (after an upgrade, all
  of luoto's), naming each and showing the runtime's progress, where a slow pull looked hung
  and luoto's own images waited for `luoto setup`.
- **Terraform and OpenTofu:** `luoto init` finds them by their version files, module
  files (`main.tf`, `versions.tf`, their `.tofu` forms) and the lock file (whose providers' registry tells the two apart), sets the
  version an exact `required_version` names, and adds the `terraform` or `opentofu` preset for
  the provider and module registry. Terraform's update check is off (`CHECKPOINT_DISABLE`).
- **Presets set environment:** a preset's `env` reaches the env's shells, as an agent's does.
- **Path rules:** a path ending in `/**` also covers the path it is under, so `/basedpyright/**`
  (as the UI offers it) allows the package's metadata at `/basedpyright` as well as its files.
  It widens the same way in deny rules and where credentials go.

## 0.2.1 (2026-11-05)

- **Homebrew tap:** luoto is in `eetu/tap` now. `brew install eetu/tap/luoto` installs it and
  trusts that formula only. For an install from `eetu/luoto`, `brew update` names the steps:
  Homebrew moves a formula only into a tap you trust.

## 0.2.0 (2026-11-05)

Fixes from a security review, model APIs kept from fetching for the sandbox, agents that work
without a credential, and a dev build that runs beside a release.

### Security

- **Query credentials:** the gate's Gemini `key` reaches Google instead of the one the sandbox
  sent, and a header the client lists in `Connection` can't drop an injected credential.
- **Tunnels:** an open tunnel closes once no tunnel rule admits its host and port.
- **`approve`** asks to accept the rule's risks, as `allow` does; `--force` (in the UI,
  "approve anyway") skips the question.
- **Self-test:** runs whenever `up` restarts a container, agent installs and project accepts
  included, unless `--no-selftest`.
- **Vault:** refuses an ssh-agent binding before reading its key.
- **Model API server tools:** the gate refuses requests asking Anthropic, OpenAI or Gemini to
  fetch a URL or call an MCP server for the sandbox (web fetch, the MCP connector, URL
  context, remote MCP), and OpenAI's WebSocket API, unless `server_tools = true` under
  `[credentials.<provider>]`.

### Changes

- **Agents without a credential log in inside the env.** With none chosen ("later", no
  terminal, or a new env from the UI), a provider that allows it gets `login_inside = true`, and
  luoto says how to keep a credential outside instead.
- **`init --agent`** asks for each new agent's credential before the env comes up; without a
  terminal it prints the config snippet.
- **`luoto-dev`:** a source build is its own instance in the same VM, with config in
  `~/.config/luoto-dev`, `luoto-dev-<env>` containers, and its own vault, keychain service and
  UI port (47879). `just link-dev` links `~/.local/bin/luoto-dev` to the checkout's debug
  build. Env names can't be `dev` or start with `dev-`.
- **Fewer runtime calls:** `up` inspects images once, writes `/run/luoto` in one go and skips
  steps that changed nothing: 26 calls into the VM for an env that is already up. The UI polls
  with one `ps` per tick.
- **A new gate restarts the dev container:** when `up` replaces an env's gate (a luoto
  upgrade, new ports), a running dev container restarts with it; it couldn't reach the new
  gate, so the self-test failed and stopped it. What runs in it stops.
- **`sandbox check`** normalizes a request as the gate does (upper-case method).
- **UI:** the overview says when the VM is stopped, rebuild starts it first, and the header
  names the instance.
- **Config format:** config files may carry `version` (1 when missing); luoto refuses a file
  from a newer luoto.
- **luoto.toml:** agents it lists stay out of your env file. One declined under 0.1.0 is
  offered once more.

## 0.1.0 (2026-11-04)

First release.
