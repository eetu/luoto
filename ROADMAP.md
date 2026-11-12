# Roadmap

Roughly in order; intent, not a schedule. What shipped is in [CHANGELOG.md](CHANGELOG.md).

## Security

- **GitHub: App only, pushes to a fork.** A pushed branch runs the repo's workflows with its
  secrets; push to a secrets-free fork and open pull requests across. Drops personal access
  tokens, whose reach luoto can't check. Needs a guided App setup (the manifest flow) first.
- **Install windows bound to the installer:** a per-run proxy credential, so other processes
  can't use the window.
- **Container hardening:** dropped capabilities, `nosuid,nodev` mounts, user namespaces on
  Docker; tunnel rules check the SNI inside the tunnel; client credentials stripped on every
  host.
- **gVisor on Linux** installed by `luoto setup --install`.
- **The process behind a request,** named from outside by gVisor's runtime monitoring.
- **Malicious and brand-new package versions** refused at registry hosts (OSV `MAL-*`, a
  minimum release age).
- **AWS and GCP credentials outside the sandbox,** as Azure's are: the gate re-signs AWS
  requests (SigV4); the vault mints GCP tokens.

## Workflow

- **Services that come back:** a command on every start (a database after `up` or an idle
  stop), then sidecars.
- **Corporate networks:** a CA for every upstream (Zscaler, Netskope) and egress through a
  company proxy.
- **Moving work:** `fork` of an env; seed from a git bundle and `luoto fetch` into
  `refs/remotes/luoto/<env>`.
- **A folder shared live** (Linux, or a VM that shares folders), with an audit of the files
  host tools act on (`.git/config`, hooks, `.envrc`, editor and pre-commit configs).
- **`luoto run` jobs:** a clean-checkout start, a CI recipe.
- **Detached agents:** `agent run --detach`, `agent ps`, `agent attach`.
- **Orchestrators drive envs:** agent orchestrators (Paperclip; the parallel-agent tools that
  give each agent only a git worktree) run each task in a luoto env through `luoto run` or an
  API, with the env's access requests and denials in the orchestrator's own approvals.
- **`luoto push`:** a reviewed copy-in.
- **The UI does what the CLI does:** editing an env's presets, tools, agents, ports,
  credentials and repos, removing it, and the questions `init` and installs ask (prompts and
  progress the UI streams).
- **Azure DevOps:** the `az` CLI (it addresses repos by ID) and Git LFS (served from blob
  storage).

## Git over SSH

- **A key per env,** derived by the vault from a root secret, added as a deploy key.
- **Commit signing** by the vault (`gpg.format = ssh`).
- **An SSH proxy in the gate,** if repo scoping and the push guard prove necessary over SSH.

## Toolchains and agents

- **More ecosystems verified, in CI:** Maven, Gradle, Bundler, Composer, bun, deno, pipenv,
  pdm, hatch, conda, .NET, each run end to end with detection from its files; a job per
  toolchain.
- **Containers in an env** (testcontainers, compose), after checking what gVisor allows.
- **`devcontainer.json` read at `init`:** image, features, `postCreateCommand`, `forwardPorts`.
- **Model gateways:** Bedrock, Vertex, Azure OpenAI.
- **Your MCP servers** with their tokens in the vault (`[mcp.<name>]`).
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
