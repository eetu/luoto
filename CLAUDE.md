# luoto — repo overview

Dev sandboxes that contain supply-chain attacks: tools run in a container whose only egress is
a per-env policy gate; a per-VM vault holds secrets outside the sandbox. CLI + local web UI.
User-facing docs: README.md (the overview and getting started), docs/ (the reference and
guides). Threat model: SECURITY.md. A user-visible change gets an entry in
CHANGELOG.md's top section (the release notes); ROADMAP.md holds only what isn't done.
main is protected: it changes only by squash-merged pull request, from a branch named for the
release (`packaging/README.md`). CI runs on pull requests (path-filtered) and weekly on main.

## Layout

```text
shared/      types + policy engine (no I/O but `tun`: the tun link, Linux-only, behind its feature;
             `frame` frames its packets); presets/, agents/, providers/, editors/ are TOML data
gate/        luoto-gate: explicit proxy, TLS interception, DNS, transparent catch-all, ctl socket
vault/       luoto-vault: in-memory secrets, per-env bindings, GitHub App token minting
tools/       `sandbox` helper (status/check/request/relay/mcp/selftest, internal ssh-agent,
             agent-setup and net) + init.sh + AGENTS.md
cli/         `luoto` host binary: runtime driver, env lifecycle, commands, `luoto ui` (axum)
frontend/    SvelteKit SPA embedded into `luoto` (rust-embed of frontend/dist)
image/       luoto-base dev image
docs/        first-session.md, configuration.md, projects.md, how-it-works.md, install.md
             (the reference), agents.md (per-agent facts), guides/ (task by task), examples/,
             screenshots/,
             logo/ (README header; its Inter is a subset of the letters it uses, so new text
             needs a new subset)
packaging/   Homebrew/Scoop templates + render.sh (release steps in its README)
install.sh   curl-pipe installer
integration/ spawned gate + vault against wiremock (`just it`)
Containerfile  gate / vault / tools images from one static (musl) build stage
```

## Conventions

- The boundary is runtime-agnostic: everything goes through `cli/src/runtime.rs` (podman,
  docker and Apple `container` flavours). Never call a runtime binary elsewhere; never rely on runtime DNS — the dev
  container's resolver and default route are the gate, set by luoto.
- Adding an ecosystem, agent, model provider or editor is a TOML file in `shared/{presets,
  agents,providers,editors}`, not code. Presets use exact hosts; the preset test rejects
  risky wildcards. An agent or provider also gets its entry in `docs/agents.md` (hosts, known
  denials, what is verified).
- Policy order in the gate: parse destination once → policy → (only if allowed) resolve, vet
  every address, dial that address. Denied requests cause no upstream DNS/TCP/SNI.
- Events are serde-serialized JSON lines with `seq` + `run`; never hand-format event output.
  A `[[mute]]` only hides: every view of denials (egress, UI, notifications, run summary)
  filters through `events::Mutes`.
- Every env has a folder (`[workspace] dir`), copied into its workspace volume on the first
  `up` (`luoto init` creates a missing one), or a remote (`[workspace] url`), cloned into
  `/workspace` inside the env on the first `up` (`repos::clone_workspace`), never both. Of a
  clone, nothing reaches the host but `read_files` text and luoto.toml, and nothing it wrote
  runs, installs or is granted before the user's yes to its luoto.toml (`project::review`)
  and to its installs (`env::ask_installs`). `workspace.rs` owns env-from-cwd resolution and
  push/pull (tar over exec, so no VM file sharing needed). Anything that brings
  sandbox-written files to the host goes through its `risky_nested()` and path/symlink checks;
  `pull` never writes into the home folder or one that holds it.
- `repos.rs` owns an env's repos at `/workspace/<name>`: a host folder copied in, or a remote
  cloned in the env (through the gate, as the dev user) on `up`; seeded names live in the env's
  state. A `luoto.toml` names remotes only, never host folders.
- Toolchains are mise's job, driven by the project's own version files (`deps.rs` writes
  mise's system config; `detect.rs` previews the files at `luoto init`). Installs inside an env
  (`deps.rs`, agents) get egress only via `sync::with_grants`: expiring rules from preset data
  (`tools`) or hosts the user confirmed. Never install from the host side, and never grant a
  host just because sandbox output named it. `luoto init` again on a running env reads the
  same files inside it (`deps::detect_in_env`: size-capped, printed through
  `text::display`) and adds presets only after the user confirms; `up` offers the same after
  it clones repos.
- Git hosts read repo paths in any case and a remote keeps the case it was cloned with, so
  their rules and injections set `ignore_case`. Remote rewrites are one file,
  `Compiled::git_config`, written to `/run/luoto/gitconfig` at `up`.
- The SSH key is a vault binding (`SshAgent`) that never leaves the vault, not even to the
  gate. The agent signs only logins to sessions a pinned host key bound
  (`shared/src/forges.rs`, plus `host_keys`; `vault/src/agent.rs`).
- Azure (`[credentials.azure]`, not Azure DevOps' `azure.rs`): audiences, their hosts and
  name rules in `shared/src/azure_identity.rs`; one binding per audience. The gate answers IMDS
  itself (`gate/src/imds.rs`) with placeholders (real header, the claims tools read, unusable
  signature) and never returns a real token; injections carry the methods their rule allows.
  The vault mints service principal tokens (`vault/src/entra.rs`, only
  `login.microsoftonline.com`); `azcli:` refs read the host's `az`
  (`cli/src/azure_identity.rs`) and are only the Azure bindings' (`compile` refuses them
  elsewhere), and the watcher renews them before they expire, into a vault that holds them.
  An env's own file is the only place for it.
- `project.rs`: a repo's `luoto.toml` is untrusted. It layers in (`env::plan`) only as the
  exact text the user accepted (kept in the env's state); changes need a fresh accept. Never
  let it carry secret refs or mutes or skip `RuleOrigin::Sandbox` validation, and print its
  strings through `text::display`.
- `needs.rs` owns its `[needs]`: one `Need` variant per kind, with its check, review line,
  snippet and question in one `impl`. What the team knows of a need is a table named as it
  (`[needs.azure]`, `[needs.custom.<name>]`), offered first; the answer goes in the
  developer's own env file.
- `vars.rs` owns `[env]` and `[sandbox_secrets]` (`luoto var`): a name lives in one of the
  two, never one `luoto_shared::luoto_sets`; a project's `needs.sandbox_secrets` and the
  sandbox's variable requests (`Install::Var`, a plain value it may suggest; never a secret)
  ask through it, on a terminal or in the UI (`vars::approve_with`). It refuses the names luoto
  sets in the env (`vars::luoto_names`) and the shell's own (`luoto_shared::variable_refused`).
- Config files carry their format (`version`, 1 when missing); `format.rs` upgrades every
  file in memory before it is parsed, and saving an env file writes the current format,
  keeping the old file beside it. A config change that would break an existing file is a
  step in `MIGRATIONS` instead: its notes name each key it drops or renames, and a test loads
  a file in the old format. With the first step, `luoto doctor` reports files in an older
  format and `--fix` rewrites them (a copy kept); a `luoto.toml` is only shown as a diff for
  the team to commit. Unknown keys stay errors.
- `model_servers.rs` owns `[model_servers]`: a server's exact host and port, only the model
  endpoints of its APIs, its token added by the gate (over plain HTTP only to this machine,
  `Policy.plain_http_credentials`). How an agent uses one is data (`[model_server]` in
  `shared/agents`); `agents::configure` writes it, and removes what a gone server had.
- `personal.rs` data only flows host → sandbox, on every `up`.
- `archive.rs` is the file `luoto export` writes and `luoto import` reads (`transfer.rs`):
  untrusted input, so every entry is decoded, checked and written anew. Volume contents move
  only through a container in the env's user namespace (`env::dev_id_map`), never onto the
  host; secrets, the CA and the vault token never go in.
- `ssh.rs` owns `<config>/ssh_config`; never edit the user's `~/.ssh/config`.
- Secret values never touch disk or argv: host resolves refs and pipes them over `exec -i`
  stdin to the vault. Per-run env for the sandbox goes to its `/run/luoto` tmpfs.
- `machine.rs` owns luoto's podman VM on macOS/Windows: no host mounts, a subordinate ID range
  per env, gVisor plus the `luoto-runsc` wrapper (podman keeps a container's runtime path but
  not its flags). The remote podman client can't choose a runtime, so gVisor containers are
  created by podman inside the VM (`podman machine ssh`); every later call uses the connection.
- On Apple's `container` (`Flavor::Apple`) every container is a VM; there is no luoto VM. The
  dev container has no NIC: its only path is the tun link to the gate (`shared/src/tun.rs`;
  `sandbox net` at the dev end, `gate/src/system.rs` `tun_link` at the gate's), whose two
  published sockets the watcher joins (`tunlink.rs`). Never give it a vmnet network: Apple's
  are host-only and reach every Mac service listening on all interfaces. The gate is only on
  the env's NAT network; its vault socket is a broker (`gate/src/uplink.rs`) over links the
  watcher opens to the gate's published uplink socket and joins to the vault's published
  socket after a line naming the env (`tunlink::Uplinks`). Apple caps no container's output: a gate writes its events to a capped file in its volume
  (`LUOTO_EVENTS_FILE`), which luoto reads through `luoto-gate events` (`events::in_file`),
  and init.sh closes the dev container's output once ready (`LUOTO_OUTPUT=startup`).
- `disk.rs` reads sizes and free space (podman and docker print them differently; its parsers
  read both) and picks what `luoto prune` removes: this instance's images by repository (an
  unnamed one by podman's names history, or the build stages' `luoto.build` label), never one
  a container uses or either instance runs, never a volume. Sizes walk every volume: never on
  the UI's polls.
- `watch.rs` is the one background process per config dir; port forwarding (`ports.rs`) goes
  through `exec … sandbox relay`, never a network path; on Apple it keeps the tun links and
  the gates' vault links. Its desktop notifications
  (`notify.rs`) pass sandbox text to the OS notifier cleaned, capped and as arguments, never
  inside a script.
- `report.rs` (`doctor --report`) writes nothing that hasn't passed its `Redactor`;
  `uninstall.rs` removes only what this instance (`names::instance`) made.
- Control of gate/vault is only via the ctl unix socket reached through the runtime's exec.
- Gates share no network with each other or the vault: a gate reaches the vault on a unix
  socket of its env's (`luoto_shared::VAULT_SOCKET`), and the vault takes a token only on its
  own env's channel. On podman and Docker that is `<env>/vault.sock` in the vault's socket
  volume (`names::vault_sockets`), made by the vault's `Bind` (so `start_gate` binds before
  the gate starts), and the gate mounts only that folder, read-only.
- The UI API requires the per-run token; keep Host/Origin checks on any new route.
- `ui/api.rs` holds no policy logic: its routes call the core the CLI uses (`rules.rs`,
  `init.rs`, `project.rs`, `sync.rs`, `credentials.rs`), so the two can't drift.
  `credentials.rs` lists an env's credentials as people see them (what for, the ref through
  `secrets::shown_ref`, hosts, vault state, the command that changes it), never a value.
- Gate, vault and `sandbox` are Linux binaries; Linux-only modules are `cfg(target_os =
  "linux")` so the workspace still builds on macOS/Windows.

## CLI conventions

What the CLI asks and prints follows one grammar, whatever the feature:

- **Questions** (inquire, through `wizard.rs` and `prompt.rs`): the recommended or least
  privileged answer comes first and is preselected, marked `(recommended)` where the choice
  needs it. Labels are plain words with a short description, never config keys
  (`oauth_token`); a long how-to shows once, after the pick. Every menu carries the shared
  help line naming its keys. Esc goes back one question; at the first it means "later"
  (nothing written) or, when changing a setting, "unchanged". A weaker choice (login inside,
  a write grant) is written only when picked, never because of Esc, a bare Enter or a missing
  terminal, unless that no-terminal default is documented. A menu with one option is no
  question.
- **Nothing is stored before what it is for is confirmed:** a pasted secret reaches the
  keychain or 1Password only for an env that exists or is being changed.
- **A step that writes config ends with one summary:** the thing, what it is set to (a ref
  through `secrets::shown_ref`, never a value) and the command that changes it (`luoto agent
  auth`, `luoto repo auth`), never `luoto edit` or hand-edited TOML.
- **Say a thing once.** A warning repeated on every `up` is one the user can act on. "Ready"
  means it works; an agent without a credential is "installed". A command asks only about what
  it names.
- **Errors and hints** give the cause in one line and the command that fixes it, in
  backticks. Without a terminal nothing blocks: the message gives the scripted form with the
  real choices (`--credential oauth_token=<ref>`).
- **Output** fits 80 columns. Text from the sandbox or a remote goes through `text::display` /
  `text::Relay`; what a command prints, through `progress::tool` (in the env) or
  `progress::host` (on this machine): on the terminal after `o`, with `-v`, or its last lines
  when it fails. Anything that can take over a second runs in a `progress::step` (an action
  the user should see: its own line) or a `progress::wait` (quick when all is well: named on
  the spinner's line only while slow); a line printed during either goes through
  `progress::say`, and a question or `op` runs in `progress::pause` (`prompt::Ask::ask`
  does). Color only through `progress::accent` / `prompt::theme` (the UI's accent), none
  under `NO_COLOR`.

## Working on this repo

- A source build is the `luoto-dev` instance (`names::instance`): its own config dirs, vault,
  env subnets and ID ranges (`names::env_octets`), `luoto-dev-<env>` names,
  keychain service and UI port, in the same VM as an installed release, whose envs it never
  touches. `just link-dev` links
  `~/.local/bin/luoto-dev` to the debug build.
- `just images` builds images (tag `dev`); `luoto-dev setup --build` does the same. On Apple's
  `container`, `LUOTO_RUNTIME=container just images`: both size its builder VM (every CPU, half
  the RAM; its default 2 GB is too small for the workspace).
- `LUOTO_HOME=<dir>` isolates config/state for experiments (copy `config.toml` in: it names
  luoto's VM and gVisor). `LUOTO_TRACE=1` prints every runtime call with start time and
  duration; each call is a round trip into the VM, so `up` is as fast as its call count.
- `just dev`: `luoto ui` API on :7878 + Vite on :5173 (proxying /api). Open the token link
  printed by the backend on :5173 instead of :7878.
- `just types` regenerates the UI's API types (`frontend/src/lib/generated/api.ts`) from the
  Rust types `ui/api.rs` sends and takes (`cli/tests/api_types.rs`); `cargo test` fails while
  the committed file differs, and `yarn typecheck` checks the UI and the e2e fixtures against it.
- `just test` (unit), `just it` (integration), `just test-ui` (Playwright), `just lint`,
  `just format`, `just shots` (README screenshots; needs a runtime).
- After changing gate/vault/tools code, rebuild images and `luoto up <env>` to pick them up;
  dev containers keep running (`luoto up --recreate` recreates them, volumes kept).

## Out of scope

See Limits in README.md.
