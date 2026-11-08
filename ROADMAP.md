# Roadmap

Roughly in order; intent, not a schedule. What shipped is in [CHANGELOG.md](CHANGELOG.md).

## Security

- **GitHub: App only, pushes to a fork.** A pushed branch runs the repo's workflows with its
  secrets; push to a secrets-free fork and open pull requests across. Drops personal access
  tokens, whose reach luoto can't check. Needs a guided App setup (the manifest flow) first.
- **Narrower relay hosts:** the Go module proxy fetches from any domain (allow it only during
  installs, or for the project's modules); GitHub release downloads only during installs.
- **Install windows bound to the installer:** a per-run proxy credential, so other processes
  can't use the window.
- **Container hardening:** dropped capabilities, `nosuid,nodev` mounts, user namespaces on
  Docker; tunnel rules check the SNI inside the tunnel; client credentials stripped on every
  host.
- **A VM per env on macOS** with Apple's `container`, once its host-only networks are verified
  against raw-IP TCP.
- **gVisor on Linux** installed by `luoto setup --install`.
- **The process behind a request,** named from outside by gVisor's runtime monitoring.
- **Malicious and brand-new package versions** refused at registry hosts (OSV `MAL-*`, a
  minimum release age).
- **Cloud credentials outside the sandbox** for terraform and the cloud CLIs: the gate re-signs
  AWS requests (SigV4); the vault mints Azure and GCP tokens. Today they are
  `sandbox_secret`s, readable inside.

## Workflow

- **Start from a remote:** `luoto init <url|owner/repo>` clones into a new env with nothing on
  the host.
- **Services that come back:** a command on every start (a database after `up` or an idle
  stop), then sidecars.
- **Corporate networks:** a CA for every upstream (Zscaler, Netskope) and egress through a
  company proxy.
- **Moving work:** `rm` names repos with unpushed work first; `export`/`import` and `fork` of
  an env; seed from a git bundle and `luoto fetch` into `refs/remotes/luoto/<env>`.
- **A folder shared live** (Linux, or a VM that shares folders), with an audit of the files
  host tools act on (`.git/config`, hooks, `.envrc`, editor and pre-commit configs).
- **`luoto run` jobs:** `--timeout`, a summary of denials, a clean-checkout start, a CI recipe.
- **Detached agents:** `agent run --detach`, `agent ps`, `agent attach`.
- **Notifications** (UI and OS) for access requests and the first denial at a new host;
  `sandbox request` for ports; `approve` that narrows a request.
- **Your own deny and mute rules:** block a path a preset allows; keep telemetry out of
  `egress`.
- **More commands:** `push` (a reviewed copy-in), `reset-home`, `--all` on `up` and `down`,
  `logs`, `doctor --report`, `uninstall`.
- **Port forwards** listed in `status` and the UI, with links.
- **`luoto project suggest`:** an env's working rules as a `luoto.toml` for the team.
- **The UI does what the CLI does:** editing an env's presets, tools, agents, ports,
  credentials and repos, removing it, and the questions `init` and installs ask (prompts and
  progress the UI streams).
- **Azure DevOps:** the `az` CLI (it addresses repos by ID) and Git LFS (served from blob
  storage).

## Git over SSH

- **A key per env,** derived by the vault from a root secret, added as a deploy key.
- **`ssh.github.com:443`** for networks that block port 22.
- **Commit signing** by the vault (`gpg.format = ssh`).
- **An SSH proxy in the gate,** if repo scoping and the push guard prove necessary over SSH.

## Toolchains and agents

- **More ecosystems verified, in CI:** Maven, Gradle, Bundler, Composer, bun, deno, pipenv,
  pdm, hatch, conda, .NET, each run end to end with detection from its files; a job per
  toolchain.
- **Containers in an env** (testcontainers, compose), after checking what gVisor allows.
- **`devcontainer.json` read at `init`:** image, features, `postCreateCommand`, `forwardPorts`.
- **Model gateways:** Bedrock, Vertex, Azure OpenAI, a base URL (LiteLLM), a local Ollama.
- **Your MCP servers** with their tokens in the vault (`[mcp.<name>]`).
- **Runtimes a dependency needs,** suggested at `init` (pyspark → Java).
- **Agents verified end to end:** GitHub Copilot CLI (hosts, paths, briefing file), Antigravity
  with a Gemini API key the gate holds.

## Configuration

Each change is a format migration (`cli/src/format.rs`); the first one also brings
`luoto doctor --fix`.

- One schema at every layer, a credential library in `config.toml` (`uses = […]`), `[install]`
  replacing `[deps]` and `[tools]`, `-name` to drop an inherited item,
  `luoto config show --origin`.
- An organization baseline envs can't loosen: no `*`, no tunnels, gVisor required.

## Internals

- Windows verified end to end, or documented as WSL2-only.
- `sandbox provision`: one call into the env instead of the 26 an unchanged `up` makes.
- Gate limits: connection cap, bounded event queue, log rotation, certificate expiry, response
  timeouts.
- Generated frontend types; tests for the UI's Host and Origin checks, the gate's TLS
  interception and the vault's GitHub App tokens.
