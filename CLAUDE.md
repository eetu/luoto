# luoto — repo overview

Dev sandboxes that contain supply-chain attacks: tools run in a container whose only egress is
a per-env policy gate; a per-VM vault holds secrets outside the sandbox. CLI + local web UI.
User-facing docs: README.md. Threat model: SECURITY.md.

## Layout

```text
shared/      types + policy engine (no I/O); presets/, agents/, providers/, editors/ are TOML data
gate/        luoto-gate: explicit proxy, TLS interception, DNS, transparent catch-all, ctl socket
vault/       luoto-vault: in-memory secrets, per-env bindings, GitHub App token minting
tools/       `sandbox` helper (status/check/request/relay/mcp/selftest, internal ssh-agent and
             agent-setup) + init.sh + AGENTS.md
cli/         `luoto` host binary: runtime driver, env lifecycle, commands, `luoto ui` (axum)
frontend/    SvelteKit SPA embedded into `luoto` (rust-embed of frontend/dist)
image/       luoto-base dev image
docs/        agents.md (per-agent facts), screenshots/
packaging/   Homebrew/Scoop templates + render.sh (release steps in its README)
install.sh   curl-pipe installer
integration/ spawned gate + vault against wiremock (`just it`)
Containerfile  gate / vault / tools images from one static (musl) build stage
```

## Conventions

- The boundary is runtime-agnostic: everything goes through `cli/src/runtime.rs` (podman and
  docker flavours). Never call a runtime binary elsewhere; never rely on runtime DNS — the dev
  container's resolver and default route are the gate, set by luoto.
- Adding an ecosystem, agent, model provider or editor is a TOML file in `shared/{presets,
  agents,providers,editors}`, not code. Presets use exact hosts; the preset test rejects
  risky wildcards. An agent or provider also gets its entry in `docs/agents.md` (hosts, known
  denials, what is verified).
- Policy order in the gate: parse destination once → policy → (only if allowed) resolve, vet
  every address, dial that address. Denied requests cause no upstream DNS/TCP/SNI.
- Events are serde-serialized JSON lines with `seq` + `run`; never hand-format event output.
- Every env has a folder (`[workspace] dir`), copied into its workspace volume on the first
  `up`; `luoto init` creates a missing one. `workspace.rs` owns env-from-cwd resolution and
  push/pull (tar over exec, so no VM file sharing needed). Anything that brings
  sandbox-written files to the host goes through its `risky()` and path/symlink checks.
- Toolchains are mise's job, driven by the project's own version files (`deps.rs` writes
  mise's system config; `detect.rs` previews the files at `luoto init`). Installs inside an env
  (`deps.rs`, agents) get egress only via `env::with_grants`: expiring rules from preset data
  (`tools`) or hosts the user confirmed. Never install from the host side, and never grant a
  host just because sandbox output named it. `luoto init` again on a running env reads the
  same files inside it (`deps::detect_in_env`: size-capped, printed through
  `project::clean`) and adds presets only after the user confirms.
- Git hosts read repo paths in any case and a remote keeps the case it was cloned with, so
  their rules and injections set `ignore_case`. Remote rewrites are one file,
  `Compiled::git_config`, written to `/run/luoto/gitconfig` at `up`.
- The SSH key is a vault binding (`SshAgent`) that never leaves the vault, not even to the
  gate. The agent signs only logins to sessions a pinned host key bound
  (`shared/src/forges.rs`, plus `host_keys`; `vault/src/agent.rs`).
- `project.rs`: a repo's `luoto.toml` is untrusted. It layers in (`env::plan`) only as the
  exact text the user accepted (kept in the env's state); changes need a fresh accept. Never
  let it carry secret refs or skip `RuleOrigin::Sandbox` validation, and print its strings
  through `project::clean`.
- `personal.rs` data only flows host → sandbox, on every `up`.
- `ssh.rs` owns `<config>/ssh_config`; never edit the user's `~/.ssh/config`.
- Secret values never touch disk or argv: host resolves refs and pipes them over `exec -i`
  stdin to the vault. Per-run env for the sandbox goes to its `/run/luoto` tmpfs.
- `machine.rs` owns luoto's podman VM on macOS/Windows: no host mounts, a subordinate ID range
  per env, gVisor plus the `luoto-runsc` wrapper (podman keeps a container's runtime path but
  not its flags). The remote podman client can't choose a runtime, so gVisor containers are
  created by podman inside the VM (`podman machine ssh`); every later call uses the connection.
- `watch.rs` is the one background process per config dir; port forwarding (`ports.rs`) goes
  through `exec … sandbox relay`, never a network path.
- Control of gate/vault is only via the ctl unix socket reached through the runtime's exec.
- The UI API requires the per-run token; keep Host/Origin checks on any new route.
- Gate, vault and `sandbox` are Linux binaries; Linux-only modules are `cfg(target_os =
  "linux")` so the workspace still builds on macOS/Windows.

## Working on this repo

- `just images` builds images (tag `dev`); `luoto setup --build` does the same.
- `LUOTO_HOME=<dir>` isolates config/state for experiments (copy `config.toml` in: it names
  luoto's VM and gVisor). `LUOTO_TRACE=1` prints every runtime call with start time and
  duration; each call is a round trip into the VM, so `up` is as fast as its call count.
- `just dev`: `luoto ui` API on :7878 + Vite on :5173 (proxying /api). Open the token link
  printed by the backend on :5173 instead of :7878.
- `just test` (unit), `just it` (integration), `just test-ui` (Playwright), `just lint`,
  `just format`, `just shots` (README screenshots; needs a runtime).
- After changing gate/vault/tools code, rebuild images and `luoto up <env>` to pick them up;
  dev containers keep running (`luoto up --recreate` recreates them, volumes kept).

## Out of scope

See Limits in README.md.
