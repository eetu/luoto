# Changelog

Notable changes to luoto are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and luoto uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): while it is 0.y, a minor
release may break.

## [Unreleased]

### Added

- `luoto run --dangerously-pull` and `luoto pull --on-stop on` write an env's changes into
  your folder when it stops, unreviewed. Conflicts, deletions, executables and files your tools
  run are held back for `luoto pull`. [Headless
  runs](https://github.com/eetu/luoto/blob/main/docs/guides/headless.md#its-changes-in-your-folder).
- `luoto run --pull` is the reviewed pull after a run. A run, `luoto down` and `luoto export`
  exit with 75 when a pull left something out; `--pull-report FILE` writes what a run's did.
- `luoto run --rm` removes the env when the run ends; one holding work that is nowhere else
  is kept and stopped unless `--yes`.
- `luoto prune --envs` removes stopped envs unused for 30 days (`--older-than 7d`,
  `prune_after` in `config.toml`, `--match 'job-*'`); one holding work is kept unless
  `--with-work`. [Leftover
  envs](https://github.com/eetu/luoto/blob/main/docs/guides/headless.md#leftover-envs).
- `luoto feed add <feed URL>`: an env installs from private package feeds (Azure DevOps, GitHub
  Packages, self-hosted Gitea, Forgejo and GitLab) with a token that stays outside it.
  [Private package feeds](https://github.com/eetu/luoto/blob/main/docs/guides/package-feeds.md).
- `luoto list` shows when each env was last used (USED).
- `luoto list --json` and `luoto requests --json` print what the tables show.
- `luoto repo add` and `luoto repo auth` take `--access fetch|read|push` and `--token <REF>`,
  and `luoto agent auth` takes `--credential`, for use without a terminal.

### Changed

- **Breaking:** `--ttl` of `luoto allow` and `luoto approve` is `--for 1h`. `luoto init
  --open=2h` is `--open-for 2h`; `--open` alone opens egress for an hour.
- **Breaking:** `luoto run --agent claude` is `luoto run claude`.
- **Breaking:** `luoto egress --open` is `--unruled`, `luoto requests --watch` is `--follow`
  (`-f`), `luoto project suggest --write --force` is `--overwrite`, and `luoto agent remove`
  is only `luoto agent rm`.
- **Breaking:** `luoto status --json` prints the status; the compiled policy is `--policy-json`.
- **Breaking:** `-e` comes after the command (`luoto status -e web`), and only commands that
  act on one env take it. `luoto requests` lists every env's requests unless `-e` names one.
- **Breaking:** a duration names its unit (`30m`, `2h`, `1d`); a bare number is refused,
  except as `idle_stop` in a config file, where it stays minutes. A rule's `--idle` takes `1d`.
- **Breaking:** a question that gets no yes (a no, Esc, no terminal) ends the command with
  exit code 1 and nothing done, so `luoto init` without a terminal needs `--yes`.
- `luoto pull` leaves alone a file you changed since the env's copy. Changed on both sides
  it is a conflict, yours kept unless `--overwrite`; a file the env deleted is kept.
- `luoto agent list` lists the env's agents and how each signs in; `--available` lists every
  agent and provider luoto knows.
- `luoto egress --since` takes a duration or an RFC 3339 time and refuses anything else.

### Fixed

- The gate refused scoped npm packages (`@types/node`) on a registry that gets a credential.
- On Apple's `container`, an empty env showed 1.6 GB: its size counted what its containers
  share with their image.
- An env never stopped after `idle_stop`: luoto's own processes in it counted as work.
- `luoto pull` stopped at the first file it couldn't write, reset a file's permissions to
  0644 or 0755, and didn't say when the env's files couldn't all be read.
- `luoto run --down` left the env running when the agent's answer couldn't be written.

### Security

- `luoto pull` holds back more as risky: `.env` and `.env.*`, `bunfig.toml`, `.mcp.json`,
  `AGENTS.md`, `CLAUDE.md`, `.github/workflows` and `luoto.toml`.

## [0.6.2] - 2026-11-19

### Added

- Tab completes folders and files where a command takes one.
- When `luoto.toml` changed in your folder and in the env, `luoto up` and `luoto project
  apply` ask which to go on with; `luoto project apply --from-folder` takes yours.
- New guide: [your settings in every
  env](https://github.com/eetu/luoto/blob/main/docs/guides/your-settings.md).

### Fixed

- A terminal workspace that needs a git repository failed inside an env whose `/workspace`
  is none; it says so before it starts.
- A mistake in a `luoto.toml` taken from your folder can be fixed there: the next `luoto up`
  offers the fixed one.
- A terminal the env's image doesn't know failed with "missing or unsuitable terminal".

## [0.6.1] - 2026-11-18

### Added

- Approving a preset request shows the hosts the preset opens, each with its access.

### Changed

- `luoto setup` on Docker says how an env is isolated there: a plain container, unless gVisor
  is registered with Docker and the env sets `oci_runtime = "runsc"`.

### Fixed

- What luoto says about secrets and isolation matches what holds: a secret you put inside
  (`[sandbox_secrets]`, a login in the env) is in the sandbox, and setup doesn't install gVisor.

## [0.6.0] - 2026-11-18

### Added

- `luoto setup` opens with luoto's island on a terminal; any key ends it.
- `luoto doctor` checks that containers reach the internet on Apple's `container` and in
  luoto's VM, and names the fix.
- luoto has a page: https://eetu.github.io/luoto/.

### Removed

- **Breaking:** `luoto setup` installs no runtime, and `--install` is gone. Install Apple's
  `container`, podman or Docker yourself; with several, setup asks (`--runtime docker`), and
  `--yes` takes the current one or the first.

### Fixed

- `luoto init` took toolchains from samples (`examples/`, `fixtures/`, `testdata/`).

## [0.5.3] - 2026-11-17

### Added

- `luoto agent run` and `luoto shell` end with what the gate denied during the session.

### Changed

- CLI output fits 80 columns, shows folders in your home as `~/…` and times in local time,
  and is styled on a terminal (plain when piped or under `NO_COLOR`).
- `luoto agent run claude --yolo` starts without Claude Code's bypass mode notice.

### Fixed

- Claude Code's first start in an env asked for its plugin marketplace, which the gate denied.

### Security

- On Apple's `container`, a model server on this machine was found through DNS, so a resolver
  on your network could send its token and the agent's prompts to another machine over plain
  HTTP. The next `luoto up` recreates each gate. podman and Docker were not affected.

## [0.5.2] - 2026-11-17

### Added

- `luoto init --virtual --name <env>` makes an env with no folder of its own: `/workspace`
  holds only its repos, or nothing, and is never pulled.
- `luoto open --with <name>` opens a terminal multiplexer or agent manager in the env (listed
  by `luoto open --help`); its session outlives the terminal.

### Changed

- When the env's folder is a git repository, its first `luoto repo add` (and `luoto init
  --repo` there) is refused with the `--virtual` command; `--inside` nests it anyway.

### Fixed

- A repo's folder can't be the env's or another repo's, or inside one; `luoto init` in a
  repo's folder updates its env; two envs with the same folder ask for `-e`.
- A restarted vault reads as locked, with `luoto vault unlock`, not as a missing credential.

## [0.5.1] - 2026-11-16

### Added

- Every port a server in the env listens on is forwarded, also above 32767, so a sign-in's
  callback to `localhost` reaches it: at most 64 at once, off with `auto_forward = false`.
- UI: an env's rules view lists every rule by origin, and adds and edits your own.

### Changed

- A rule for a host on a private address: the UI switches "allow private address" on and
  asks before saving, and `luoto allow` asks on a terminal.
- UI host panel: attempts alike are one row with a count, which expands to the gate's message.

## [0.5.0] - 2026-11-16

### Fixed

- On Apple's `container`, a host your Mac reaches over a VPN timed out from an env. One
  allowed with `--private` is reached from your Mac; the next `luoto up` recreates each gate.
  A `pfctl` NAT rule added for this can go: `sudo pfctl -a com.apple/luoto -F nat`.
- A rule with `--private` beside an older rule for the same host reaches the private address,
  and the UI offers "allow private address" for a host that resolves to one.

## [0.4.8] - 2026-11-16

### Fixed

- Connecting to an env over SSH (`luoto open`, an editor, `ssh luoto-<env>`) failed with
  "`luoto ssh-proxy` acts on no env; drop `-e`" since 0.4.5.

## [0.4.7] - 2026-11-16

### Fixed

- On Apple's `container`, creating the vault, a gate or a dev container failed with "host
  socket … already exists" after the container service stopped or the Mac restarted.
- `luoto setup --build` is refused when the binary wasn't built from a checkout.

## [0.4.6] - 2026-11-15

### Changed

- Secret questions: pasting a secret comes first, and secret stores (the OS keychain,
  1Password, OpenBao / Vault) are queried only when you pick their `(browse)` entry.

### Fixed

- `luoto rm` removes an env whose VM was deleted by hand.

### Security

- The vault and `luoto` wipe secrets and minted tokens from memory, and on podman and Docker
  the vault and gates get no swap; the next `luoto up` recreates them.
- Push guard: signed pushes are refused, and protected branches and tags match in any case.
- On a credentialed host the gate removes the client's own copy of every header and query
  parameter the credential goes in, and token parameters (`access_token`, `private_token`,
  `job_token`, `api_key`). GitHub's `/graphql` gets the token on POST only.
- Anthropic's managed agents, sessions and environments are denied, and files given by URL to
  Anthropic, OpenAI and Gemini are refused without `server_tools = true`.
- A host spelled as a number (`3405803777`, `0x7f.1`) matches rules, denies and credentialed
  hosts as its IPv4 address; IPv6 forms (NAT64, 6to4) of addresses the gate never dials are
  never dialed either. A DNS message with more than one question, and a method over 32
  bytes, are refused.

## [0.4.5] - 2026-11-13

### Added

- `up` notices that a launchpad folder's `luoto.toml` changed on this machine and offers to
  take it in; `luoto project apply` takes it at once, after your yes.
- Claude Code (working, blocked on you, done) and Codex (done) report their status to the
  terminal as OSC 7501.
- New guide: [changing an
  env](https://github.com/eetu/luoto/blob/main/docs/guides/changing-an-env.md).

### Changed

- `-e` is an error on a command that acts on no env. `luoto list` is the command's name;
  `ls` stays as its alias.
- Clone failures are listed last in `up`, each with why and the command that fixes it.
- UI: right-click menus on requests and credential rows; tables reachable from the keyboard.

## [0.4.4] - 2026-11-12

### Added

- Apple's `container` is a runtime on macOS 26 on Apple silicon (`luoto setup --runtime
  container`): every container is a VM of its own, and the dev container's only network link
  goes to its gate.
- `luoto var` lists, sets and removes an env's variables: `luoto var set NAME=value` for a
  plain value, `luoto var set NAME` for a secret's ref, `luoto var rm NAME`. [Environment
  variables](https://github.com/eetu/luoto/blob/main/docs/guides/env-vars.md).
- `luoto share add <folder>`: the env reads a folder of this machine read-only at
  `/shares/<name>`; `luoto up` and `luoto share sync` bring what changed. Not on Windows yet.
- Code in the env can ask for a variable with a plain value (`sandbox request --var
  NAME[=VALUE]`, MCP `sandbox_request_var`), never for a secret.
- UI: a vault view lists every env's credentials (what each is for, its ref, its hosts,
  whether the vault holds it), with unlock, reload and lock.
- When `op` isn't signed in on the terminal, luoto offers `op signin` in place.

### Changed

- macOS notifications come from a notifier the Homebrew formula installs, not Script Editor;
  macOS asks once to allow them.

### Fixed

- Egress view: a host a rule allows since it was blocked reads as allowed, not as "partly".
- After an upgrade the old background watcher kept running until every env was down (Apple's
  `container`); the new one takes over at once.

### Security

- Each gate reaches the vault over a socket of its own env, not a network shared with the
  other envs' gates; a running env takes it at its next `up`.

## [0.4.3] - 2026-11-11

### Added

- `luoto egress open` lets an env reach any HTTP(S) host no rule allows for an hour (`--for
  2h`; `open = true` under `[egress]` for no end), and `luoto egress close` ends it. Hosts
  that get your credentials keep to their rules, denies hold and every request is logged.
- `luoto egress --open` lists the hosts open egress reached, `luoto egress keep` offers
  presets or rules for them, and `luoto init --open[=2h]` starts a new env open.
- Claude Code, Codex and OpenCode can use a model server of yours with an OpenAI- or
  Anthropic-compatible API: `[model_servers.<name>]` (`url`, `api`, an optional `token`) and
  `model_server` under `[agents.<agent>]`.
- What a project's `[needs]` names and the env lacks is asked at the first `up` after
  accepting it, and again by `luoto project needs`; what the team knows goes in
  `[needs.custom.<name>]` and `[needs.azure]`.
- `args` and `headless_args` under `[agents.<agent>]` add to an agent's command line, and
  `luoto run … -- --bare` to one run's.

### Changed

- Every command shows a spinner for what takes a while, and keeps what tools print off the
  terminal unless `o`, `-v` or a failure.
- An `az` login on this machine that has expired is one line with its reason and the fix.
- A release's envs take subnets 10.213.1–127 and a source build's 10.213.128–254; when
  another network holds an env's subnet, `up` names it and the commands that move the env.

### Fixed

- An agent whose installer failed to download passed as installed; OpenCode installs again.

### Security

- A kept-alive connection the gate dialed for a rule that allows private addresses carries
  no request another rule or open egress allowed.
- GitHub, Azure DevOps and git tokens, and a read-only `[credentials.custom]`, go only on the
  methods and paths their own rules allow; a wider rule (`luoto allow '*' --write`, an
  approved request) no longer carries them further.

## [0.4.2] - 2026-11-10

### Added

- 1Password: an `op://` ref can name its account (`?account=<account ID>`), and "It's already
  in 1Password" browses account, vault and item by name and writes a ref by ID.
- `luoto agent auth` asks again how an env's agent signs in; without a terminal it takes
  `--credential` (`oauth_token=<ref>`, `api_key=<ref>`, `login_inside`).
- `luoto repo auth <repo>` asks a repo's access again, its token kept or replaced.

### Changed

- Credential questions name each kind with where to get it, then ask where it is kept; Esc
  goes back and "Later" writes nothing. `luoto init` leaves them to the env's first `up`.
- For a repo no credential covers, `up` asks what the env may do with it: fetch it if it is
  public, read it, or read and push.
- Installs, clones and copies show one line of progress; what they print goes to `luoto logs
  installs`, and to the terminal after `o`, with `-v` or when one fails.
- An agent without a credential is "installed", not "ready".

### Fixed

- An `op` error garbled the secret reference prompt.

## [0.4.1] - 2026-11-10

### Added

- `github_port = 443` in `[credentials.ssh]` sends GitHub SSH remotes to `ssh.github.com:443`.
- `luoto rm` names each repo with uncommitted files, unpushed commits or stashes before asking.
- `luoto init` gives the env Java (Temurin 17) when a Python dependency needs a JVM.
- Once luoto's VM disk has grown 10 GB, `up`, `down` and `luoto run` say so; a notification
  comes under 10 GB free, and again under 3 GB.

### Changed

- **Breaking:** GitHub release downloads have their own preset, `github-releases`, on by
  default; `github` and `toolchains` no longer open them. An env made before 0.4.1 needs it
  added (`luoto edit`) to keep them open.
- Path denials suggest allowing that path (`--path`), not the whole host.

### Fixed

- A token in a 1Password Secure Note works (`op://<vault>/<item>/notesPlain`).

### Security

- The `go` preset reaches the module proxy and checksum database only for modules on
  well-known hosts (GitHub, GitLab, Bitbucket, golang.org, k8s.io and the like). Another
  host's take `luoto allow proxy.golang.org --path '/<host>/**'` and `luoto allow
  sum.golang.org --path '/lookup/<host>/**'`.

## [0.4.0] - 2026-11-09

### Added

- `[credentials.azure]` gives an env a managed identity, so `az login --identity`, terraform
  and the Azure SDKs work unchanged. The real token, from your `az` login or a service
  principal, goes only to the listed `subscriptions`, `key_vaults`, `storage_accounts` and
  Microsoft Graph (`graph = true`), with `access = "read"` or `"write"`.
- Azure write access leaves role assignments (`role_assignments = true`) and template
  deployments (`deployments = true`) shut.
- `[credentials.hetzner]`, `upcloud`, `digitalocean` and `cloudflare` take a `token` the gate
  adds, on reads unless `write = true`
  ([guide](https://github.com/eetu/luoto/blob/main/docs/guides/cloud-apis.md)).
- `luoto init acme/web` (or an https or ssh URL) makes an env cloned through the gate, with
  nothing on this machine; the repo's `luoto.toml` and its installs each wait for a yes.
- `luoto export -e <env>` writes an env to one file (`--no-home` leaves its home out), and
  `luoto import FILE [--name NAME]` makes it in another luoto or on another machine.
- Disk use: `luoto status --size`, `luoto ls --size`, `luoto doctor` and the UI show it, and
  `luoto prune` removes this luoto's superseded images and trims the VM's disk.

### Changed

- A rule over a host that gets a credential names that credential among the risks you accept.
- The review of a `luoto.toml` names `image`, `ports` and `run`.

### Security

- `luoto pull` never writes into your home folder or one holding it; an env cloned from a
  remote needs `--to <new folder>`.

## [0.3.1] - 2026-11-08

### Added

- `[[deny]]` (in an env, `config.toml` or a `luoto.toml`) refuses a host, its paths or methods
  whatever allows them. `[[mute]]` hides denials you leave denied; `luoto egress --all` shows
  them.
- Desktop notifications (macOS, Linux with `notify-send`) for each access request and the
  first denial at each host; `notifications = false` in `config.toml` turns them off.
- `luoto run --timeout 30m` stops the agent and exits 124 (Ctrl-C: 130). Every run ends with
  the hosts the gate denied.
- New commands: `luoto up --all` and `down --all`, `luoto reset-home` (discards an env's
  home), `luoto logs` (the gate's, the watcher's, the env's installs), `luoto doctor --report`
  (a redacted diagnostic file) and `luoto uninstall`.
- `sandbox request db.example.com:5432` asks for an uninspected tunnel to that host and port,
  and `luoto approve --read`, `--method` and `--path` grant less than a request asked.
- `luoto project suggest` prints a `luoto.toml` from an env's config; `--write` puts it in
  the env's folder (`--force` to replace one).
- `luoto status` and the UI list forwarded ports, and ports taken on this machine.
- `up` replaces an env CA with less than 60 days left; a running dev container restarts to
  trust it.

### Changed

- Gate limits: 1024 connections per env; a response must start within 10 minutes, and a
  stream silent for 5 minutes, or a tunnel or websocket for an hour, is closed. A rule's
  `idle` (`luoto allow --idle 2h`, up to 24h) gives its host longer.

### Fixed

- A gate up for 30 days served expired certificates.
- `[deps] system` failed to install in an env without the `github` preset.
- A tunnel rule passed only clients that use `HTTPS_PROXY`.
- An `up` that can't ask (the UI, `up --all`) recorded a changed `luoto.toml` as declined.

## [0.3.0] - 2026-11-07

### Added

- Repos: `--repo` on `luoto init`, `luoto repo add|rm|list` and `[workspace.repos.<name>]`
  put repositories at `/workspace/<name>`: a host folder, copied in and pulled back, or a
  remote, cloned in the env through the gate. `[repos.<name>] url = …` in a `luoto.toml`
  gives a team the same remotes.
- Git credentials: `[[credentials.github]]` once per account, `[[credentials.git]]` for any
  other forge (GitLab, Forgejo, Gitea, Bitbucket, self-hosted; `private = true`, `ca`), and
  `read_repos` for repos that are fetched, never pushed to.
- `up` installs the agents an env's config or its `luoto.toml` lists, and on a terminal asks
  for the agent and repo credentials that are missing. `--credential oauth_token=op://…` on
  `luoto agent add` and `luoto init` writes an agent's without the prompt.
- `luoto run --agent claude --prompt "…"` runs an agent headless and prints its answer
  (`--output FILE`, `--down`), exiting with its code: Claude Code, Codex, OpenCode and Copilot
  CLI.
- `sandbox request --package <name>`, `--tool <tool>@<version>` and `--preset npm` (also over
  MCP) ask for software or a preset; approving installs it and writes it to the env's config.
- `luoto requests --watch` prints each new request as it comes; the UI approves or rejects
  several together.
- `luoto vault reload` reads the vault's secrets again (`-e` for one env's); the watcher
  rereads a credential an upstream refused (401) when its source needs no one.
- Azure DevOps pull requests: for `[credentials.azure_devops] repos` the env can open,
  comment on and edit them; completing one and votes are refused.
- `luoto agent rm` drops an agent from an env; `[agents.claude] model = "opus"`, `effort =
  "medium"` set an agent's defaults.
- After `up` clones repos, it offers the presets and toolchains their files suggest.

### Changed

- From a git repository, `up` copies what git doesn't ignore plus `.git`, so ignored secrets
  (`.env`, `*.tfvars`) stay on your machine; other folders copy all but heavy directories and
  `.terraform`.
- `luoto pull` takes each copied-in repo back to its own folder, cloned ones only with
  `--repo`, and holds back risky files in nested folders too.
- Claude Code starts at its prompt: luoto answers its first-start questions in the env.

### Fixed

- An `up` started from the UI could wait on the terminal running `luoto ui`.

### Security

- On a credentialed host the gate refuses a response that carries the credential it placed,
  paths with `;` or an encoded `/` or `\`, and `TRACE`; a repo's credential goes on its
  smart-HTTP and LFS paths only.
- Push options are refused: at a forge they can open merge requests or skip CI.
- `luoto allow --private` and `private = true` never reach loopback, cloud metadata or
  luoto's own networks, and an editor's port forwards stay on localhost.
- Explicit denies (GitHub Actions, releases, …) match paths in any case.

## [0.2.2] - 2026-11-06

### Added

- `luoto init` detects Terraform and OpenTofu, sets the version an exact `required_version`
  names and adds the `terraform` or `opentofu` preset.
- A preset's `env` reaches the env's shells.

### Changed

- `up` and `init` pull every missing image themselves, showing progress.
- A path ending in `/**` also covers the path it is under (`/pkg/**` allows `/pkg`), in allow
  and deny rules and where credentials go.

## [0.2.1] - 2026-11-05

### Changed

- luoto's Homebrew tap is `eetu/tap`: `brew install eetu/tap/luoto`. For an install from
  `eetu/luoto`, `brew update` names the steps.

## [0.2.0] - 2026-11-05

### Added

- `luoto-dev`: a source build is its own instance, with config in `~/.config/luoto-dev` and
  its own containers, vault, keychain service and UI port (47879). Env names can't be `dev`
  or start with `dev-`.
- Config files may carry `version` (1 when missing); luoto refuses a file from a newer luoto.

### Changed

- An agent with no credential chosen logs in inside the env (`login_inside = true`) where
  its provider allows it; `init --agent` asks for each new agent's credential first.
- `up` makes fewer calls into the VM: 26 for an env that is already up.

### Fixed

- When `up` replaced an env's gate (a luoto upgrade, new ports), a running dev container
  couldn't reach the new one and was stopped; it restarts with the gate.
- Agents a `luoto.toml` lists stay out of your env file.
- `sandbox check` reads a lower-case method as the gate does.

### Security

- The gate refuses requests asking Anthropic, OpenAI or Gemini to fetch a URL or call an MCP
  server for the sandbox, and OpenAI's WebSocket API, unless `server_tools = true` under
  `[credentials.<provider>]`.
- The gate's Gemini `key` replaces the one the sandbox sent, and a header the client lists in
  `Connection` can't drop an injected credential.
- An open tunnel closes once no tunnel rule admits its host and port.
- `luoto approve` asks to accept the rule's risks, as `allow` does; `--force` skips the
  question.
- The self-test runs whenever `up` restarts a container, unless `--no-selftest`.
- The vault refuses an ssh-agent binding before reading its key.

## [0.1.0] - 2026-11-04

### Added

- First release.

[Unreleased]: https://github.com/eetu/luoto/compare/v0.6.2...HEAD
[0.6.2]: https://github.com/eetu/luoto/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/eetu/luoto/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/eetu/luoto/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/eetu/luoto/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/eetu/luoto/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/eetu/luoto/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/eetu/luoto/compare/v0.4.8...v0.5.0
[0.4.8]: https://github.com/eetu/luoto/compare/v0.4.7...v0.4.8
[0.4.7]: https://github.com/eetu/luoto/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/eetu/luoto/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/eetu/luoto/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/eetu/luoto/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/eetu/luoto/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/eetu/luoto/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/eetu/luoto/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/eetu/luoto/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/eetu/luoto/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/eetu/luoto/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/eetu/luoto/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/eetu/luoto/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/eetu/luoto/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/eetu/luoto/releases/tag/v0.1.0
