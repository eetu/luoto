# Moving an env

`luoto export` writes an env to one file: its config, its workspace and its home. `luoto
import` makes an env from that file, in another luoto (a source build's env into the release)
or on another machine. Use it when the env holds more than its remote does: work not pushed,
an agent's login and history, toolchains you don't want to install again.

## From a source build to the release

A source build is its own luoto, `luoto-dev`, beside the release in the same VM (see
[Install details](../install.md)). Its envs aren't the release's; export one and import it:

```console
$ luoto-dev export -e infra
`infra` goes into infra.luoto.tar:
  config     ~/.config/luoto-dev/envs/infra.toml, the accepted luoto.toml, its repos and your answers about them
  workspace  /workspace, all of it
  home       /home/dev: dotfiles, shell history, agents' logins and state, toolchains
Not in it: secret values (the config's refs are read where it is imported), its CA and vault token (import makes new ones), and what `up` rebuilds.

`infra` is running, and its files would change under the copy: it stops for the export (`luoto up -e infra` starts it again).
Stop `infra` and export it? [y/N] y
env `infra` stopped
workspace: 1.2 GB
home: 3.4 GB

wrote infra.luoto.tar (4.6 GB): `luoto import infra.luoto.tar` makes the env in another luoto, here or on another machine.
It holds the env's workspace and home, agents' logins included: keep it as you would a secret.

$ luoto import infra.luoto.tar
infra.luoto.tar: env `infra`, exported by luoto-dev 0.4.0 at 2026-11-08T10:12:03Z
  holds      config, luoto.toml, state, workspace, home
  folder     /Users/you/dev/infra: `luoto pull` writes the workspace's files here
  secrets    read on this machine at `up`, from:
             credentials.anthropic.oauth_token = keyring:luoto-dev/anthropic
             credentials.azure: your `az` login here
  sent to    each credential, by the gate, on:
             anthropic  api.anthropic.com
             …
  luoto.toml accepted where it was exported, not here: `up` reviews the workspace's as a new one
  becomes    env `infra` of luoto, with a CA and vault token of its own
Import it as `infra`? [y/N] y
importing: 4.6 GB of 4.6 GB
env `infra` imported (subnet 10.213.4.0/24)
note: keychain entries don't move with the archive, and the config reads keyring:luoto-dev/anthropic. …
note: luoto-dev still has `infra`: `luoto-dev rm -e infra` removes it once this one works
`luoto up -e infra` starts it, and asks for what it needs here
```

A running env is stopped for the export, after you say yes (`--yes` doesn't ask): its files
would change under the copy. `luoto import` doesn't start the env; `luoto up -e infra` does,
with a self-test, a new CA in the env's trust stores, and the questions a new env gets about
credentials the config doesn't hold. The two envs can run side by side, each on its own
subnet; remove the source build's once the release's works.

A keychain entry the source build stored (`keyring:luoto-dev/…`) works for the release on the
same machine as long as it exists, but `luoto-dev uninstall` removes it. To keep the secret,
delete that credential from the env's config (`luoto edit -e infra`) and `luoto up` asks for
it, storing it under `luoto`'s own name.

## To another machine

Copy the file over (`scp`, a drive you own) and run `luoto import` there; `--name` picks
another name if the env's is taken. `--no-home` leaves the home out, for a smaller file: the
imported env starts with a new home and installs its agents and toolchains again.

What only the old machine has stays there:

- **Secrets.** The config's refs are read on the new machine at `up`: `op://` and `vault://`
  work wherever you are signed in, `env:` and `file:` need the variable or file there,
  `keyring:` needs the secret stored again, and `[credentials.azure]` needs `az login` there.
  `luoto import` lists every ref before it asks; `luoto up` warns about any it can't read.
- **Folders.** An env made from a folder keeps `[workspace] dir`, and its repos' folders. Its
  workspace came in the file, so nothing is copied in from them: they are where `luoto pull`
  writes. Where that folder doesn't exist, the env still works, but `luoto pull` needs `--to`
  until `luoto edit` points `dir` at a folder there. An env cloned from a remote has none.

## What moves

| in the file | not in it |
| --- | --- |
| the env's config file as you wrote it, refs as refs | secret values |
| the accepted luoto.toml (the first `up` after import reviews it again), the repos in the workspace, the repos you called public, a luoto.toml you declined | the CA, its key and the vault token: import makes new ones |
| the workspace, with owners, modes and links as they were | its subnet: import takes a free one |
| the home, unless `--no-home` | luoto's tools and the gate's state, which `up` rebuilds, and the egress history |

The file is a tar archive: `manifest.json` first, then `env/`, then `volumes/work/` and
`volumes/home/`, then `end.json`, which counts what came before, so a file cut short in a copy
is refused rather than imported in part. Owners are the env's own IDs (the dev user is 1000),
so they come out right whichever subnet each env has.

## Keep the file as a secret

It holds the env's whole workspace and home: work not pushed, files the sandbox wrote (an
`.env`, a state file), shell history, and agents' logins, which work from the file. luoto
writes it readable only by you; delete it once the env is imported.

An archive from someone else is their env: its config decides which of your secrets `up`
reads and which hosts get them. Read what `luoto import` lists before you say yes. The
rest of the file is handled as untrusted: nothing in it is unpacked on your machine, and the
volumes are written by a container that sees only the new env's volume.
