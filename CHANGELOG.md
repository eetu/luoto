# Changelog

## 0.4.4 (2026-11-12)

- **Apple's `container`:** on macOS 26 on Apple silicon, `luoto setup` offers it first
  (`--runtime container`; `--install` runs `brew install container`). It runs every container
  as a VM of its own, so the dev container's boundary is its VM rather than gVisor. It has no
  network card: its one link goes to its gate through luoto's background process, never to
  your Mac or your network.
  `luoto ui`'s setup page offers the same choice; `luoto status`, `init` and the UI's env
  panel say how the env is isolated there.
- **Vault:** each gate reaches the vault over a socket of its own env instead of a network
  shared with the other envs' gates; a running env takes it at its next `up`.
- **`luoto var`:** lists, sets and removes an env's variables. `luoto var set NAME=value`
  writes a plain value to `[env]`; `luoto var set NAME` asks where a secret is kept and writes
  its ref to `[sandbox_secrets]` (`--ref` without a terminal); `luoto var rm NAME`. A running
  env takes the change at once: new shells have it, and open bash, zsh and fish shells reload
  it at their next prompt. Names luoto sets itself (proxy, CA bundle, `LUOTO_*`, the env's
  credential placeholders) and the shell's own are refused. `luoto ui`'s env panel lists
  them, and names what luoto sets itself. New guide:
  [environment variables](docs/guides/env-vars.md).
- **`luoto share`:** folders of this machine the env reads at `/shares/<name>`, read-only:
  recordings, datasets, data too large for a repo. `luoto share add <folder>`; `luoto up`
  and `luoto share sync` bring what changed. The env reads clones, which take no space on
  APFS, btrfs or XFS until a file changes (a folder on another disk is copied). luoto's
  podman VM mounts luoto's shares folder read-only, added after a yes and one VM restart.
  A folder inside your home folder (not home itself, a dot-folder or `~/Library`) or on a
  disk, never a key folder; only the env's own file names one, and `luoto import` leaves an
  archive's out. `luoto ui`'s env panel lists each share with what changed on this machine
  since the last sync, and syncs them. Not on Windows yet.
- **Variable requests:** code in the env asks for a variable with a plain value, which it may
  suggest (`sandbox request --var NAME[=VALUE]`, MCP `sandbox_request_var`). `luoto approve
  <id>` confirms the value, `luoto ui` shows it filled in to check, and `luoto var set` answers
  it too. Secrets are never requested from inside: you add them with `luoto var set`.
- **Egress view:** a host a rule allows since it was blocked reads as allowed, its denials as
  history ("blocked before rule r1"), instead of "partly" with the old denial's text.
- **`luoto ui`'s vault view:** the vault is a view of its own, every env's credentials in one
  table: what each is for, where its secret is kept (the ref, never the value), the hosts it
  goes to, whether the vault holds it, and refs in memory no env uses. A credential shows
  what else shares its secret and the command that changes it; unlock only while locked, and
  right-click on the vault for unlock, reload and lock. An env's credentials section lists
  the same, with an unlock while secrets are missing.
- **macOS notifications** go through `terminal-notifier`, which the Homebrew formula now
  installs, instead of Script Editor; macOS asks once to allow them. Without it, or until
  allowed, they come through `osascript` as before. A notification says "has a request",
  whatever the request is for.
- **The background watcher follows upgrades:** a new luoto's watcher takes over at once,
  also after a Homebrew upgrade and while envs run on Apple's `container`, where the old one
  kept running until every env was down. Forwarded connections close and an env's network
  pauses for a moment; its connections carry on.
- **1Password sign-in in place:** when `op` isn't signed in on the terminal (no app
  integration, no `eval $(op signin)` in that shell), luoto offers `op signin` where it is,
  mid-question, keeps the session in memory until it exits, and runs the command again.
  Without a terminal, the error names both fixes; the app's CLI integration (Settings >
  Developer) unlocks `op` in every terminal.

## 0.4.3 (2026-11-11)

- **Open egress:** `luoto egress open` lets an env reach any HTTP(S) host and port no rule
  allows, as rule `open`, for an hour (`--for 2h`; `open = true` under `[egress]` in the env's
  file for no end); `luoto egress close` ends it, and a running env takes either at once.
  Hosts that get your credentials keep to their rules, muted hosts stay denied, and denies,
  private addresses and the guards hold; TLS stays intercepted, so every request is logged.
  `luoto egress --open` lists the hosts it reached, and `luoto egress keep` offers presets
  that cover them, checked, else a rule per host (read, or write where a write went out),
  unchecked: code in the env chose those hosts.
  `luoto init --open[=2h]` starts a new env open. `up`, `status`, `sandbox status` and the
  UI's env list say until when (its menu opens and closes it); `luoto run` lists the hosts
  reached through it; the UI marks them `open` and offers its allow form as keep. Only the
  env's own file opens it, not config.toml, a luoto.toml or a request; `luoto import` lists
  it.
- **Progress everywhere:** `setup` (the VM's creation and start, gVisor, image pulls and
  builds), `up` (vault, gate, dev container, setup of the env, toolchain checks), `down`,
  `rm`, `reset-home`, `doctor`, `prune`, `pull`, `--size`, `egress`, `vault unlock`
  and `reload`, `upgrade` and `uninstall` show the spinner; what is quick when all is well
  shows nothing then, and names itself on the spinner's line once it takes a while. What
  podman prints while it pulls, builds or starts the VM is kept off the terminal as
  installers' is (`o`, `-v`, or its last lines on a failure). Questions and `op` sign-ins
  pause it.
- **Model servers:** Claude Code, Codex and OpenCode can use a server of yours with an
  OpenAI- or Anthropic-compatible API (Ollama, LM Studio, MTPLX, llama.cpp, vLLM, LiteLLM, a
  hosted one), on this machine, your network or the internet, beside their cloud provider:
  `[model_servers.<name>]` with `url`, `api` and an optional `token`, and `model_server` under
  `[agents.<agent>]` for the one it starts on. "A model server" in the credential questions
  finds those answering on this machine's usual ports, lists their models and keeps the
  context window a server gives (`context`, which Claude Code can't tell for a model it
  doesn't know). The gate opens
  only the server's port and model endpoints and adds its token; OpenCode switches in its
  model picker, Codex per start (`codex --profile <server>`). A config that can't work is
  refused at `up` and `luoto edit`.
- **Team needs asked:** what a project's `[needs]` names and the env lacks is asked at the
  first `up` after accepting it, as an agent's credential is: a provider's kind and where it
  is kept, a custom credential's host and secret, an Azure subscription, where a sandbox
  secret is kept, and access to the repos to push to. What the team knows goes in a table
  named as the need, offered first: `[needs.custom.<name>] host`, `[needs.azure]
  subscriptions`. `luoto project needs` asks again, opening on what the env has; without a
  terminal, what to add is printed as before.
- **Agent arguments:** `args` (every start through luoto) and `headless_args` (`luoto run`
  only) under `[agents.<agent>]`, in the env, `config.toml` or a team's `luoto.toml`, where
  the agent's command line takes options, and more for one run after `--` (`luoto run …
  -- --bare`); `["--bare", "--tools", "Bash,Read,Edit"]` cuts
  Claude Code's request from 54 KB to 4 KB for a model of yours (`--bare` reads no subscription
  token: with an API key or a model server). A `luoto.toml` can't pass the flags that turn off
  or loosen the agent's own prompts (`prompt_flags` in its file).
- **Agent installs:** an installer piped from a download (`curl … | bash`) fails the install
  when the download does, instead of the agent passing as installed with nothing there.
  OpenCode installs again: its installer moved to raw.githubusercontent.com and asks the npm
  registry for the latest version.
- **Private addresses stay with their rules:** a kept-alive connection the gate dialed for a
  rule that allows private addresses (a self-hosted forge, a model server) carries no request
  another rule or open egress allowed; such a request dials anew and is vetted.
- **Credentials stay on their rules:** the GitHub, Azure DevOps and git tokens, and a read-only
  `[credentials.custom]`, go only on the methods and paths their own rules allow. A wider rule
  (`luoto allow '*' --write`, an approved request) no longer carries them further, to a merge
  or a file or ref write past the push guard: those requests go without the token.
- **Azure login:** an `az` login on this machine that has expired (a refresh token unused for
  90 days) or wants you again (MFA, consent) is one line with its AADSTS reason and the fix,
  `az login --tenant …`, then `luoto up`; secrets that failed the same way are named once,
  and `az` in the env isn't logged in with what would only fail again.
- **Subnets:** a release's envs take 10.213.1–127 and a source build's (`luoto-dev`)
  10.213.128–254, with the user ID ranges that go with them, so an env imported from one into
  the other never shares either. When another network holds an env's subnet, `up` names it
  and the commands that move the env.

## 0.4.2 (2026-11-10)

- **1Password accounts:** an `op://` ref can name the account it is in
  (`op://Private/claude/token?account=<account ID>`, from `op account list`), so refs from a
  work and a personal account work side by side. With several accounts in the app, the wizard
  asks which one holds a reference that didn't read, and which one to save a pasted secret in,
  and writes its ID; luoto shows the account as its address and email. A sign-in address
  works too, unless several accounts share it, as personal and family ones do.
- **Browse 1Password:** "It's already in 1Password" finds a reference for you: account,
  vault and item, filtered as you type, and the field from the item's kind (a Login's,
  Password's or Database's `password`, an API Credential's `credential`, a Secure Note's
  `notesPlain`), or one you type; Esc steps back. Browsing lists names only, never a value,
  so an item's custom fields are typed by name; luoto reads only the field you pick. The
  refs the wizard writes, browsed or saved, name the vault and item by ID, so a rename
  doesn't break them.
- **`luoto agent auth`:** asks again how an agent the env has signs in, each question
  opening on what the env has, marked (current): "Keep the current one" first, a typed
  reference starting from it. Esc at the first question leaves it unchanged. OpenCode picks
  the provider first, so it can have a credential for several; an agent that only signs in
  inside (Antigravity) has nothing to choose. Without a terminal it names the
  `--credential` forms the agent takes (`oauth_token=<ref>`, `api_key=<ref>`,
  `login_inside`). It writes only the provider's kind or `login_inside`, keeping
  `server_tools` and `write`, and a running env takes it at once.
- **Credential questions:** each kind is named with what sets it apart, the provider's usual
  one first and (recommended), and the one you pick says where to get it; then one menu asks
  where it is kept: pasted into your OS keychain or 1Password, already in 1Password, or
  somewhere else (a reference). A value that doesn't start as its kind does (`sk-ant-oat`,
  `sk-ant-api`, `sk-`, …) is asked for again, without being shown. Esc goes back a question;
  at the first, Esc or "Later" writes nothing, and the next `up` or `agent run` asks again.
  `login_inside` is written when you pick it, or without a terminal. A paste into 1Password
  comes after its account and vault. Each menu names its keys and fits 80 columns. The
  questions end with a summary: the credential (its reference) or none yet, and the `luoto
  agent auth` command that changes it. `server_tools = true` alone is no credential: the
  questions are asked. `agent add` asks only about the agent it adds, and prints the env's
  closing block only when it started the env; `luoto init` leaves the questions to the env's
  first `up`, so nothing is stored for an env you don't create.
- **Repo access:** for a repo no credential covers, `up` asks what the env may do with it,
  least privilege first: fetch it if it is public, read it, or read and push, with the token
  scopes its forge names. Every answer ends with a summary and the `luoto repo auth` command
  that changes it; "Later" clones nothing. A clone that fails shows git's errors and the
  gate's reason, not all it printed.
- **`luoto repo auth <repo>`:** asks a repo's access again, opening on what the env has, its
  token kept or replaced; it moves the repo between `repos` and `read_repos` of its
  credential, keeping the credential's other settings, and a running env takes it and clones
  a repo that waited. A new token replaces the credential's for every repo it lists, and the
  question names them first.
- **Progress:** installs, clones and copies print their line and, on a terminal, a dot
  pulsing in the UI's orange with the time so far and the latest line the tool printed; `o`
  shows the tool's whole output from there. What installers and git print goes to the install
  log (`luoto logs installs`), and to the terminal after `o`, with `-v` (`--verbose`, any
  command) or, its last lines, when one fails; it reaches the terminal escaped, as other text
  from the env does. Prompts mark their choices in the same orange; `NO_COLOR` turns colors
  off.
- **Agents:** "ready" only for an agent that can sign in; one without a credential is
  "installed", with the command that gives it one. `up` warns about `login_inside` only for a
  provider whose credential the gate could add instead.
- **Secret reference prompt:** the reference is read after you press enter, not inside the
  prompt: an `op` error no longer garbles it, one that doesn't read says why on one line, and
  the reference comes back to edit.

## 0.4.1 (2026-11-09)

- **Agent credentials:** before you choose one, each kind of credential says where to get it;
  the Claude subscription token links Anthropic's guide (`claude setup-token`, a Pro, Max,
  Team or Enterprise plan) and the API key the Claude Console.
- **1Password refs:** a token in a Secure Note works (`op://<vault>/<item>/notesPlain`): an
  `op://` value loses a trailing line break, as a `file:` one does. When you give a reference,
  the wizard names the field each item type keeps a token in, and refuses one whose value
  holds more than the token.
- **Go modules:** the `go` preset reaches the module proxy and checksum database, which fetch
  from whatever host a module path names, only for modules on GitHub, GitLab, Bitbucket,
  golang.org, google.golang.org, cloud.google.com, k8s.io, sigs.k8s.io, go.etcd.io,
  go.opentelemetry.io, go.uber.org and gopkg.in. Another host's are denied by path; allowing
  one takes `luoto allow proxy.golang.org --path '/<host>/**'` and
  `luoto allow sum.golang.org --path '/lookup/<host>/**'`.
- **GitHub release downloads** have their own preset, `github-releases`, on by default; the
  `github` and `toolchains` presets no longer open them. Without it, they open only while luoto
  installs (`terraform` and `opentofu` keep them for `init`). An env made before 0.4.1 lists
  its presets: add `github-releases` (`luoto edit`) to keep release downloads open in it.
- **Path denials** suggest allowing that path (`--path`), not the whole host.
- **Git over SSH where port 22 is blocked:** `github_port = 443` in `[credentials.ssh]` sends
  GitHub SSH remotes to `ssh.github.com:443`, its host keys pinned there too.
- **`luoto rm`:** before asking, names each repo in the env (the workspace and its `repos`)
  with files not committed, commits on no remote or stashes, for envs from a folder too.
- **Runtimes a dependency needs:** `init` gives the env Java (Temurin 17) for pyspark,
  apache-flink, JPype1 or tabula-py named in `requirements.txt`, `pyproject.toml`, `Pipfile`,
  `uv.lock` or `poetry.lock`, unless a version file pins one.
- **Disk growth:** once luoto's VM disk has grown 10 GB (or a tenth of it) since the last
  hint, `up`, `down`, `luoto run` and the end of a shell or agent session say by how much,
  name the env's biggest build folders (`target/`, `node_modules/`, …) and point to
  `status --size` and `prune`. The watcher notifies when free space falls under 10 GB, and
  again under 3 GB.

## 0.4.0 (2026-11-09)

Cloud credentials that stay outside the sandbox (Azure, Hetzner, UpCloud, DigitalOcean,
Cloudflare), envs started from a remote or moved between machines, and disk use in sight.

- **Azure credentials:** `[credentials.azure]` in an env's config gives it a managed identity:
  the gate answers the instance metadata service (169.254.169.254) with placeholder tokens,
  so `az login --identity`, terraform (`ARM_USE_MSI`) and the Azure SDKs work unchanged, and
  puts the real token on Resource Manager for the listed `subscriptions`, the named
  `key_vaults` and `storage_accounts`, and Microsoft Graph (`graph = true`, read-only).
  `access = "read"` (GET, HEAD, OPTIONS) or `"write"`; the token goes only on those methods,
  whatever other rule allows a request.
- **Token sources:** your `az` login on this machine (renewed before it expires), or a service
  principal (`client_id`, `client_secret`) whose secret the vault keeps and mints with. The
  env's tenant comes from `tenant`, or the token.
- **What write leaves shut:** role assignments and definitions, PIM requests and policies,
  federated identity credentials, Lighthouse delegations, key vault access policies and
  `elevateAccess` (unless `role_assignments = true`); template deployments, deployment
  scripts and stacks, which act beyond the listed subscriptions (unless `deployments = true`).
- **Cloud APIs:** `[credentials.hetzner]`, `upcloud`, `digitalocean` and `cloudflare` take a
  `token` the gate adds for each cloud's CLI and terraform/OpenTofu provider, on reads unless
  `write = true` ([guide](docs/guides/cloud-apis.md)).
- **Start from a remote:** `luoto init acme/web` (or any https or ssh URL) makes an env cloned
  through the gate, with nothing on this machine. The repo's `luoto.toml` and the installs
  its files pin each wait for a yes; `--yes` installs and leaves `luoto.toml` pending.
  `luoto ls` shows where each env comes from.
- **Moving envs:** `luoto export -e <env>` writes an env to one private file (config,
  accepted `luoto.toml`, workspace, and home unless `--no-home`), owners kept; `luoto import
  FILE [--name NAME]` makes it in another luoto or on another machine, with its own subnet, CA
  and vault token, after listing the secret refs it will read. Every entry is checked, and
  nothing is unpacked on this machine.
- **Pull:** never writes into your home folder or one holding it; an env cloned from a remote
  needs `--to <new folder>`.
- **Credentialed hosts:** a rule over a host that gets a credential (yours, an approved
  request's, a `luoto.toml`'s) names that credential among the risks you accept.
- **luoto.toml review:** names `image` (pulled outside the gate), `ports` and `run`.
- **Vault:** a changed secret retires only the tokens minted from it; a mint is shared by
  concurrent requests, bounded in time and size, and a failed one isn't retried for 30 s.
- **Disk use:** `luoto status --size` shows what an env's workspace, home, toolchains and
  containers take, `luoto ls --size` each env's total, `luoto doctor` the VM's disk and its
  file on this machine; the UI shows both, and `up` warns under 10 GB free.
- **`luoto prune`:** removes this luoto's superseded images that nothing uses, keeping the
  other instance's, everything else in the VM and every volume, then trims the VM's disk so
  the space returns to this machine.
- **Quieter installs:** Python packages' byte-compile warnings stay out of `up`'s output.

## 0.3.1 (2026-11-08)

Your own deny and mute rules, notifications and port requests, gate limits, and commands for
every env at once.

- **Deny and mute rules:** `[[deny]]` (in an env, `config.toml` or a project's `luoto.toml`)
  refuses a host, its paths or methods whatever allows them. `[[mute]]` keeps denials you
  leave denied, such as telemetry, out of `luoto egress`, the UI, notifications, run summaries
  and allow offers; `egress --all` shows them. A `luoto.toml` can't mute.
- **Notifications:** a desktop notification (macOS, Linux with `notify-send`) for each access
  request and the first denial at each host; `notifications = false` in `config.toml` turns
  them off; `luoto logs watcher` lists those shown. Without them (off, or on Windows), the
  UI's bell gives browser notifications for requests.
- **Port forwards listed:** `luoto status` and the UI's env panel show forwarded ports as
  links, and ports taken on this machine with a `luoto forward` hint.
- **`luoto run --timeout 30m`:** stops the agent and everything it started in the env, and
  exits 124; Ctrl-C stops them the same way (exit 130). After every run, stderr lists the
  hosts the gate denied, with counts, requests and reasons.
- **`up --all`, `down --all`:** every env in the config dir. `up` asks nothing; an env that
  fails leaves the rest to go, and the exit code says so.
- **`luoto reset-home`:** discards an env's home (dotfiles, history, agents' logins,
  toolchains); the workspace stays.
- **`luoto logs`:** the gate's log, the watcher's, or the env's installs (up to the newest
  1 MiB kept); `-f`, `-n`.
- **Gate limits:** at most 1024 connections per env, refused beyond with an event. A
  response must start within 10 minutes; a stream silent for 5 minutes, or a tunnel or
  websocket for an hour, is closed; a rule's `idle` (`luoto allow --idle 2h`, up to 24h)
  gives its host longer, for long polls such as `kubectl logs -f`. Events never queue
  unbounded, and intercepted hosts' certificates are renewed daily (a gate up for 30 days
  served expired ones). Podman caps the gate's log at 50 MB where it writes files; journald,
  as in luoto's VM, and Docker keep their own settings.
- **System packages:** `[deps] system` installs in an env without the `github` preset, whose
  missing grant for the base image's GitHub CLI source failed the package-list update.
- **Port requests:** `sandbox request db.example.com:5432` asks for an uninspected tunnel to
  that host and port (never 80 or 443, no private addresses); approving it, in the CLI or the
  UI, asks you to confirm the risk.
- **Narrower approvals:** `luoto approve --read`, `--method` and `--path` grant less than a
  request asked, never more; the UI's request panel offers read-only and paths. The sandbox
  is told what it got.
- **Tunnels for every client:** a tunnel rule also passes connections that skip the proxy
  (`psql`, protocols whose server speaks first, TLS a client pins), where only clients using
  `HTTPS_PROXY` got through.
- **`luoto project suggest`:** prints a `luoto.toml` from an env's presets, agents, ports,
  `[deps]`, remote repos, rules and denies, and names what it leaves out (credentials,
  secrets, mutes, folders, expiring grants, rules a sandbox couldn't ask for); `--write` puts
  it in the env's folder, replacing one only with `--force`.
- **CA renewal:** `up` replaces an env CA with less than 60 days of its two years left, or
  already expired; the gate signs with the new one at once and a running dev container
  restarts to trust it. `luoto status` and `doctor` show the expiry when it is that close.
  The vault's and dev container's logs are capped (1 MB, 10 MB; podman).
- **`luoto doctor --report`:** writes doctor's checks, versions, the VM, each env's config
  and state, the watcher's log and the gates' and vault's recent lifecycle and error events
  to a file only you can read, with secret refs, tokens, your home folder, user names and
  emails taken out.
- **`luoto uninstall`:** removes luoto's envs, vault, images, keychain entries, config and
  data after one question, and its VM only when the other instance (a release or a source
  build) has nothing in it; the binary stays.
- **luoto.toml review:** an `up` that can't ask (the UI, `up --all`) leaves a changed
  `luoto.toml` unapplied without recording a decline.

## 0.3.0 (2026-11-07)

Related repositories in one env, git on any forge, and an `up` that sets up what an env lacks.

- **Repos:** `--repo` on `luoto init`, `luoto repo add|rm|list` and `[workspace.repos.<name>]`
  put repositories at `/workspace/<name>`: a host folder, copied in and pulled back to it, or a
  remote (`owner/repo`, an https or ssh URL), cloned in the env through the gate on `up`.
  luoto commands in a repo's folder act on its env. The UI lists an env's repos.
- **Repos in `luoto.toml`:** `[repos.<name>] url = …` gives a team the same set of remotes (by
  host name, not address); the env's own repo of a name replaces the file's. When `up` asks
  for their credentials, Enter answers "later".
- **Pull:** each copied-in repo goes back to its own folder; cloned ones stay out unless named
  with `--repo`. Risky files count in any folder within the pull, so a nested repository's
  `.git`, `.envrc` or `.vscode` is held back like the top folder's.
- **Detection** (`luoto init`, toolchain installs on `up`) reads the repositories in the
  folder, which git in the folder doesn't list.
- **Read-only repos:** `read_repos` in `[credentials.github]` and `[credentials.azure_devops]`
  are fetched through the gate, never pushed to; a GitHub App mints a read-only token for
  them. With a token, GraphQL reaches what the token does.
- **A GitHub credential per owner:** `[[credentials.github]]`, once per account. Each repo's
  requests get the credential that lists it, GraphQL the first one that may write;
  `[credentials.github]` is the form for one. A token that reaches several owners is one credential listing all their
  repos, and `up` offers a reference the config has before asking for another.
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
  terminal `up` changes no config and prints what to add; `init --yes`, `agent add` and the
  UI's new env let an agent without a credential log in inside. `luoto repo add` asks the same
  before it clones.
- **Packages and toolchains on request:** `sandbox request --package <name>` and
  `--tool <tool>@<version>` (MCP: `sandbox_request_install`) ask you to keep software in the
  env. `luoto approve` (or the UI) installs it and writes it into `[deps] system` or `[tools]`,
  so a recreated container gets it again; the sandbox learns whether the install worked. A
  tool from a mise backend anyone publishes to (`ubi:`, `npm:`, …) is marked unvetted.
- **Agent credentials on the command line:** `--credential oauth_token=op://…` on
  `luoto agent add` and `luoto init` writes the credential without the prompt; the reference
  must resolve.
- **Headless runs:** `luoto run --agent claude --prompt "…"` brings the env up asking nothing,
  runs the agent's non-interactive mode and prints its answer (`--output FILE` writes it,
  `--down` stops the env after), exiting with the agent's code; on a terminal its output is
  escaped. Claude Code, Codex, OpenCode and Copilot CLI have one.
- **Presets from cloned repos:** after `up` clones repos, it offers the presets and default
  toolchains their files suggest, as `luoto init` does for a folder; it adds them only on your
  yes, as `luoto init` on a running env does.
- **`sandbox request --preset npm`** (MCP: `preset` in `sandbox_request_access`) asks for one of
  luoto's presets; approving adds it to the env and opens its hosts at once.
- **`luoto agent rm`** drops an agent from an env's config and its hosts from the policy.
- **Rotated secrets:** `luoto vault reload` (or the UI's vault panel) reads the vault's
  secrets again and puts the changed ones in use at once; `-e` limits it to one env's. When an
  upstream refuses a credential (401), the background watcher reads it again itself if its
  source needs no one (the keychain, a 1Password service account, `file:`, Vault), at most
  every 10 minutes; for the 1Password app it notes `luoto vault reload` in its log.
- **Azure DevOps pull requests:** for the repos in `[credentials.azure_devops] repos`, the gate
  adds the PAT to their pull requests' REST paths (by repo name): open, comment, change title,
  description, draft state or target. Completing one, auto-complete and votes are refused.
- **`luoto requests --watch`** prints each new request as it comes, with the terminal's bell.
- **Requests in the UI** can be ticked and approved or rejected together; one whose rule has
  risks stays ticked, for review on its own.
- **Agent model and effort:** `[agents.claude] model = "opus"`, `effort = "medium"` in an
  env's config, its `luoto.toml`, or `config.toml` for every env that has the agent; `up`
  writes them into the agent's settings as the default a session can change. `agents = [...]`
  is the short form.
- **Claude Code starts at its prompt:** luoto answers its first-start questions (onboarding,
  trusting `/workspace`) in the env, as the sandbox is the boundary; an agent profile lists
  such answers under `[[first_run]]`. The text style stays `theme` in your own settings.
- **The UI never waits on a terminal:** an `up` it starts asks nothing on the terminal running
  `luoto ui`, where a changed `luoto.toml` could leave it waiting.
- **Copies follow `.gitignore`:** from a git repository (the folder, a repo, or one inside),
  `up` copies what git doesn't ignore plus `.git`, so ignored secrets (`.env`, `*.tfvars`, state
  files, `.kube/`) stay on your machine. Other folders copy all but heavy directories and
  `.terraform`, which holds the host's provider binaries.

### Security

- **Credentials coming back:** on a credentialed host the gate refuses a response that carries
  the credential it placed, in its headers or the start of its body; from a JSON body (an LFS
  server's answer) it removes the fields that carry it.
- **Pushes:** push options are refused; at a forge they can open merge requests or skip CI.
- **Credentialed paths:** paths with `;` or an encoded `/` or `\`, and `TRACE`, are refused; a
  repo's credential goes on its smart-HTTP and LFS paths only.
- **Private addresses:** `luoto allow --private` and `private = true` never reach loopback,
  cloud metadata or luoto's own networks.
- **Explicit denies** (GitHub Actions, releases, …) match paths in any case.
- **Loopback only:** luoto's SSH config sets `GatewayPorts no`, so an editor's port forwards
  stay on localhost, and a published port's relay refuses the vault network.

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
