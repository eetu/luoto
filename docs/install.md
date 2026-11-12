# Install details

The overview is the [README](../README.md); step by step, the [guides](guides/README.md).

The script installs into `~/.local/bin` without root, checks the download against the
release's checksums and, with the GitHub CLI logged in, its build provenance. Every release
carries checksums and build provenance (`gh attestation verify <file> --repo eetu/luoto`); its
container images are signed and pinned by digest in the binary.

`luoto upgrade` updates a script or tarball install (Homebrew: `brew upgrade luoto`, Scoop:
`scoop update luoto`); `luoto doctor` says when a newer release is out. After an update, the
next `luoto up` pulls the release's images, showing progress, and moves the env's gate and
the vault onto them; `luoto up --recreate` moves its dev container too, keeping its volumes.
The images it replaced stay in luoto's VM until `luoto prune` removes them (`up` says how much
they take).
What each release changed is in [CHANGELOG.md](../CHANGELOG.md).

On macOS 26 or later on Apple silicon, `luoto setup` offers Apple's
[`container`](https://github.com/apple/container) (1.7.1 or later) first, where every container
is a VM of its own; podman stays the other choice. Without a terminal, setup keeps the runtime
`config.toml` names, or picks `container` for a new one; `luoto setup --runtime podman` (or
`container`) chooses. `--install` runs `brew install container`; setup then starts its service
(`container system start --enable-kernel-install`, whose first start downloads its kernel) and
pulls the release's images with `container image pull`. What differs there:
[Platforms](how-it-works.md#platforms).

`luoto uninstall` lists what it removes and asks once: every env's containers and volumes,
the vault, luoto's images and keychain entries, its config and data folders, and luoto's VM
unless a source build uses it or anything else is in it. The binary stays:
`brew uninstall luoto`, `scoop uninstall luoto`, or delete `~/.local/bin/luoto`.

`luoto doctor --report` writes a file only you can read, for a bug report: versions, the
runtime and VM, doctor's checks, `config.toml`, each env's config and state, the watcher's
log and the gates' and vault's recent lifecycle and error events, with secret references,
tokens, your home folder, user names and email addresses taken out. Host and repository names
stay, so read it before you share it.

A source build runs as `luoto-dev`, beside a release in the same VM: its config is in
`~/.config/luoto-dev`, its envs' containers are `luoto-dev-<env>`, it has a vault of its own,
keeps new keychain entries under `luoto-dev`, and serves `luoto ui` on port 47879;
`luoto-dev uninstall` removes only what it made, and `luoto-dev prune` only its superseded
builds and older build cache. Its tab completion calls `luoto-dev`;
`just link-dev` links that name to the checkout's debug build. `luoto-dev export -e web`, then
`luoto import web.luoto.tar`, moves its env `web` to the release
([docs/guides/moving-envs.md](guides/moving-envs.md)).

Tab completion covers commands, flags, env names, agents, editors and presets. Homebrew
installs it; otherwise add one line to your shell's startup file:

| shell      | line                                                                                                | file                                    |
| ---------- | --------------------------------------------------------------------------------------------------- | --------------------------------------- |
| fish       | `COMPLETE=fish luoto \| source`                                                                     | `~/.config/fish/completions/luoto.fish` |
| zsh        | `source <(COMPLETE=zsh luoto)`                                                                      | `~/.zshrc`                              |
| bash       | `source <(COMPLETE=bash luoto)`                                                                     | `~/.bashrc`                             |
| PowerShell | `$env:COMPLETE = "powershell"; luoto \| Out-String \| Invoke-Expression; Remove-Item Env:\COMPLETE` | `$PROFILE`                              |
