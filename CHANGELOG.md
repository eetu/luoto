# Changelog

## 0.2.0 (unreleased)

Fixes from a security review, agents that work without a credential, and a dev build that runs
beside a release.

### Security

- **Query credentials:** the gate's Gemini `key` reaches Google instead of the one the sandbox
  sent, and a header the client lists in `Connection` can't drop an injected credential.
- **Tunnels:** an open tunnel closes once no tunnel rule admits its host and port.
- **`approve`** asks to accept the rule's risks, as `allow` does; `--force` (in the UI,
  "approve anyway") skips the question.
- **Self-test:** runs whenever `up` restarts a container, agent installs and project accepts
  included, unless `--no-selftest`.
- **Vault:** refuses an ssh-agent binding before reading its key.

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
- **`sandbox check`** normalizes a request as the gate does (upper-case method).
- **UI:** the overview says when the VM is stopped, rebuild starts it first, and the header
  names the instance.
- **luoto.toml:** agents it lists stay out of your env file. One declined under 0.1.0 is
  offered once more.

## 0.1.0 (2026-11-04)

First release.
