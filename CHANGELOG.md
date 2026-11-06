# Changelog

## 0.2.2 (unreleased)

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
