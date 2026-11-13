# Changing an env

An env that runs keeps its workspace and home; most changes are one command, taken by the
running env without a restart. `luoto status` shows what it has now.

## Repositories

| You want                                          | Run                                               |
| ------------------------------------------------- | ------------------------------------------------- |
| another repo, for yourself                        | `luoto repo add acme/api` (or a URL, or a folder) |
| one gone from the env's list                      | `luoto repo rm api` (its copy in the env stays)   |
| another token for a repo, or push instead of read | `luoto repo auth acme/api`                        |

`repo add` asks what the env may do with the repo when no credential covers it
([credentials](multi-repo.md#credentials)), then clones it at once in a running env. When a
clone fails, `luoto up` names the repo and the fix last, after "is up": a token the remote
refused (one for another forge or account, or expired) is fixed with `luoto repo auth`.

**For the team,** add the repo to the launchpad's `luoto.toml` (`[repos.api] url = "…"`) and
commit it. Each developer's env reads its own copy of the file in `/workspace`:

- a launchpad in git: `git pull` in `/workspace`, then `luoto up`;
- a launchpad folder you edit on this machine: `luoto up` notices that your folder's file
  changed since the env took its copy and offers to take it in (`luoto project apply` does
  it without asking).

Either way `up` shows what changed in `luoto.toml` and applies it only after your yes, then
clones the new repo, asking for its access the same way. More in
[Several repositories](multi-repo.md).

## Reach and credentials

| You want                                           | Run                                                                     |
| -------------------------------------------------- | ----------------------------------------------------------------------- |
| a host the env may reach                           | `luoto allow api.example.com` (`--write` for more than reads)           |
| what the env asked for                             | `luoto requests`, then `luoto approve <id>` or `luoto reject <id>`      |
| what it tried and was denied                       | `luoto egress --denied`                                                 |
| another credential for an agent, or a login inside | `luoto agent auth claude`                                               |
| an environment variable, plain or secret           | `luoto var set NAME=value`, `luoto var set NAME` ([guide](env-vars.md)) |
| a folder of this machine, read-only                | `luoto share add ~/Recordings`                                          |

Each writes the env's own file and ends with a summary: what it set, and the command that
changes it again.

## Toolchains and packages

Toolchains come from the project's own version files (`mise.toml`, `.tool-versions`,
`.nvmrc`, …): change those in the env and open a new shell. `luoto init` on a running env
reads the files again and offers the presets they suggest (the `npm` preset for a
`package.json`). A package the env installs asks for its hosts as it goes
(`luoto requests`).

## The container

| You want                                             | Run                                                  |
| ---------------------------------------------------- | ---------------------------------------------------- |
| a changed image, memory or CPUs, or new luoto images | `luoto up --recreate` (volumes kept); `up` says when |
| a fresh home: dotfiles, logins, toolchains           | `luoto reset-home`                                   |
| everything gone but your folder                      | `luoto rm`                                           |

`luoto up` applies rules, credentials, variables and shares to a running env as it is; only
`--recreate` makes its dev container anew.
