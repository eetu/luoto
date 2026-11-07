# Roadmap

Roughly in order; intent, not a schedule. What shipped is in [CHANGELOG.md](CHANGELOG.md).

## Security

- **GitHub: App only, pushes to a fork.** Pushing a branch runs the repository's own workflows
  with its secrets and open network; push to a secrets-free fork and open pull requests across
  instead. Drop personal-access-token support: a token is long-lived, and the repositories it
  reaches are set at GitHub, where luoto can't check them (a classic token reaches all).
- **Relay hosts as a class.** The Go module proxy fetches from any domain on request; allow it
  only during installs or limit it to the project's modules.
- **Install windows bound to the installer.** A per-run proxy credential for installs, so other
  processes can't use the window or get their denied hosts offered for saving.
- **Container hardening:** drop capabilities, `nosuid,nodev` mounts, user namespaces on Docker;
  tunnel rules check the SNI inside the tunnel; strip client credentials on every host.
- **A VM per env on macOS:** a runtime driver for Apple's `container` (a lightweight VM per
  container, any number at once). Re-verify first that its host-only networks can't be bypassed
  with raw-IP TCP.
- **Defaults for GitHub release downloads** (`toolchains`, `github` presets): public download
  counters are a slow covert channel; consider install-only grants and narrower paths.
- **Cloud credentials outside the sandbox,** for `terraform plan`/`apply`, state backends and
  the cloud CLIs. AWS signs every request with its secret key (SigV4), so the gate re-signs
  with a key the vault holds; Azure and GCP take short-lived tokens the vault mints, as for a
  GitHub App. Until then a cloud credential is a `sandbox_secret`, readable inside the env.

## Workflow

- **Git-based work transfer:** seed the workspace from a git bundle (CRLF and exec bits on
  Windows), `luoto fetch` the env's commits into `refs/remotes/luoto/<env>`, apply `pull`
  through git.
- **A folder shared live** (Linux, or a runtime whose VM shares folders), for host tools that
  need the files as they change. The sandbox can then write where host tools act on their own
  (`.git/config` and hooks, `.envrc`, editor and pre-commit configs), so it comes with an
  audit of those files.
- **Presets from cloned repos:** after `up` clones a repo, offer the presets its files suggest,
  as `luoto init` does for a folder (today a second `luoto init` in the env's folder does).
- **Headless runs:** `luoto run` starts an env from a folder and its config, runs an agent on a
  prompt (an audit, fixes opened as pull requests until review agrees, a value computed from a
  data set) and hands back its result as a file or on stdout, then stops; for scheduled or
  triggered jobs. Pull requests and merges stay behind the gate's write rules.
- **More commands:** `fork` (copy an env), `push` (a reviewed copy-in),
  `reset-home`, `agent rm`.
- **Notifications** for access requests (UI and OS), `luoto requests --watch`; `sandbox request`
  for presets and ports; `approve` that narrows a request.
- **Editing envs in the UI:** presets, tools, `[deps]`, agents, ports, credentials and repos
  (the UI shows them; changes go through `luoto edit`).
- **Azure DevOps beyond git:** pull requests through its REST API (`az repos pr`), with writes
  allowlisted as for GitHub, and Git LFS objects, which it serves from blob storage.

## Git over SSH

`[credentials.ssh]` makes the vault the env's ssh-agent and passes SSH through to its hosts on
port 22. Left for later:

- **A key per env,** derived by the vault from a root secret in your store (nothing on disk),
  its public key added as a deploy key so it reaches one repo.
- **`ssh.github.com:443`**, for networks that block port 22.
- **An SSH proxy in the gate**, if repo scoping and the push guard over SSH prove necessary:
  the gate ends the session, logs in with the vault's key and allows only `git-upload-pack`,
  `git-receive-pack` and `git-lfs-authenticate` on configured repos.

## Toolchains and agents

- **More ecosystems verified.** mise installs them from their version files and presets exist
  for Maven, Gradle, RubyGems and Composer, but none has been run end to end: Java builds
  (Maven, Gradle), Ruby (Bundler), PHP (Composer), bun, deno, pipenv, pdm, hatch, conda, .NET.
  Each gets an end-to-end run, and detection where a file names its tool (`bun.lock`,
  `deno.json`, `Pipfile`, `pdm.lock`, `.sdkmanrc`).
- **A toolchain matrix in CI.** The verified toolchains were run by hand; a job per toolchain,
  from `luoto init` to a build or test run in the env, keeps them working.
- **Containers in an env:** podman or docker inside the dev container, for builds and tests
  that start containers (testcontainers, compose), with image pulls through the gate. Needs a
  check of what gVisor allows and what a nested runtime opens up.
- **Runtimes a dependency needs.** A pyspark project needs Java and often says so only in its
  README. Suggest the runtime from known dependencies (pyspark → Java) at `init`.
- **GitHub Copilot CLI, verified.** It ships untested: the token goes to the
  `api.*.githubcopilot.com` hosts and GitHub's `/copilot_internal/**` and `/user`. A licence
  holder's run settles the hosts and paths it really needs, whether its briefing file loads
  without `applyTo` frontmatter, and its telemetry hosts (left denied).
- **Antigravity CLI with a Gemini API key** the gate holds: the `gemini` provider plus
  `modelProvider: "gemini"` in `~/.gemini/config/settings.json`, with no Google session in
  the env. Its login inside is verified; the key route needs a run with API credits.

## Configuration

Each change is a format migration (`cli/src/format.rs`): older files keep loading for at least
two minor releases.

- One schema at every layer, a credential library in `config.toml` referenced with
  `uses = […]`, `[install]` replacing `[deps]` and `[tools]`, `-name` to drop an inherited item,
  `luoto config show --origin`.
- With the first migration: `luoto doctor` reports files in an older format, and `--fix`
  migrates them (a copy kept).

## Internals

- Windows: verified end to end, or documented as WSL2-only.
- Prompts and progress through an interface the UI streams, so it can run what the CLI asks
  about (`init`, agent credentials, installs).
- `sandbox provision`: one call into the env instead of the 26 runtime calls an `up` makes
  when nothing changed.
- Gate limits: connection cap, bounded event queue, log rotation, certificate expiry, response
  timeouts.
- Generated frontend types; tests for the UI's Host and Origin checks, the gate's TLS
  interception and the vault's GitHub App tokens.
