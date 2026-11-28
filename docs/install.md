# Install details

The overview is the [README](../README.md); step by step, the [guides](guides/README.md).

The script installs into `~/.local/bin` without root, checks the download against the
release's checksums and, with the GitHub CLI logged in, its build provenance. Every release
carries checksums and build provenance (`gh attestation verify <file> --repo eetu/luoto`); its
container images are signed and pinned by digest in the binary.

`luoto upgrade` updates a script or tarball install (Homebrew: `brew upgrade luoto`, Scoop:
`scoop update luoto`); `luoto upgrade --check` only says whether a newer one is out. After an
update, the next `luoto up` pulls the release's images, showing progress, and moves the env's
gate and the vault onto them; `luoto up --recreate` moves its dev container too, keeping its volumes.
The images it replaced stay in luoto's VM until `luoto prune` removes them (`up` says how much
they take).
What each release changed is in [CHANGELOG.md](../CHANGELOG.md).

`luoto setup` runs envs on a container runtime you installed, and installs none itself:

| runtime                                                            | oldest | an env's boundary                                         |
| ------------------------------------------------------------------ | ------ | --------------------------------------------------------- |
| Apple's [`container`](https://github.com/apple/container/releases) | 1.7.1  | every container is a VM of its own                        |
| [podman](https://podman.io/docs/installation)                      | 5.2    | luoto's own VM and gVisor (Linux: gVisor where installed) |
| [Docker](https://docs.docker.com/engine/install/)                  | 28     | Docker's VM, or on Linux this machine's kernel            |

Apple's runs on macOS 26 or later on Apple silicon. With one of them installed, setup uses
it; with several it asks, listing them in this order and starting at the one `config.toml`
names. `luoto setup --runtime container` (or `podman`, `docker`) chooses without asking, and
so do `--yes` and a run without a terminal, which keep the current runtime or take the first
in the list. With none, or one too old or not running, setup says what it found and stops.
For Apple's it starts the service (`container system start --enable-kernel-install`, whose
first start downloads its kernel) and pulls the release's images with `container image pull`.
What differs between them: [Platforms](how-it-works.md#platforms).

`luoto uninstall` lists what it removes and asks once: every env's containers and volumes,
the vault, luoto's images and keychain entries, its config and data folders, and luoto's VM
unless a source build uses it or anything else is in it. The binary stays:
`brew uninstall luoto`, `scoop uninstall luoto`, or delete `~/.local/bin/luoto`.

`luoto doctor --report` writes a file only you can read, for a bug report: versions, the
runtime and VM, doctor's checks, `config.toml`, each env's config and state, the background
watcher's log and the gates' and vault's recent lifecycle and error events, with secret
references, tokens, your home folder, user names and email addresses taken out. Host and
repository names stay, so read it before you share it.

luoto itself contacts only GitHub, for `luoto upgrade` (also with `--check`) and the install
script; `ghcr.io`, for its images (`luoto setup`, the first `up` after an update); the [model
servers](guides/model-servers.md) you add; and, with `luoto doctor --network`, `1.1.1.1` and
`example.com`, from a container. `luoto doctor` has each running env's gate look up a host its
rules already allow. All other traffic is your envs', as their policy allows.

A source build runs as `luoto-dev`, beside a release in the same VM: its config is in
`~/.config/luoto-dev`, its envs' containers are `luoto-dev-<env>`, it has a vault of its own,
keeps new keychain entries under `luoto-dev`, and serves `luoto ui` on port 47879;
`luoto-dev uninstall` removes only what it made, and `luoto-dev prune` only its superseded
builds and older build cache. Its tab completion calls `luoto-dev`;
`just link-dev` links that name to the checkout's debug build. `luoto-dev export -e web`, then
`luoto import web.luoto.tar`, moves its env `web` to the release
([docs/guides/moving-envs.md](guides/moving-envs.md)).

Tab completion covers commands, flags, env names, agents, editors and presets, and folders and
files where a command takes one. Homebrew installs it; otherwise add one line to your shell's
startup file:

| shell      | line                                                                                                | file                                    |
| ---------- | --------------------------------------------------------------------------------------------------- | --------------------------------------- |
| fish       | `COMPLETE=fish luoto \| source`                                                                     | `~/.config/fish/completions/luoto.fish` |
| zsh        | `source <(COMPLETE=zsh luoto)`                                                                      | `~/.zshrc`                              |
| bash       | `source <(COMPLETE=bash luoto)`                                                                     | `~/.bashrc`                             |
| PowerShell | `$env:COMPLETE = "powershell"; luoto \| Out-String \| Invoke-Expression; Remove-Item Env:\COMPLETE` | `$PROFILE`                              |
