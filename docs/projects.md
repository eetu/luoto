# Projects and repositories

The overview is the [README](../README.md); step by step, the [guides](guides/README.md).

## Team settings: `luoto.toml`

A team commits what the project needs from a sandbox, so `luoto init` in a fresh clone gets it
right:

```toml
# luoto.toml
presets = ["npm", "maven"]
ports = [5173]

[[allow]]
host = "api.stripe.com"
note = "payments test API"

[deps]
system = ["libpq-dev"]

[needs]                          # each developer adds these to their own env config
github = ["acme/web"]
credentials = ["anthropic"]
sandbox_secrets = ["DATABASE_URL"]
```

It also takes `image`, `agents`, `[[deny]]` and the team's repositories (`[repos.<name>]`,
[below](#several-repositories)); toolchains belong in `mise.toml`. Layering:
`config.toml` < the accepted `luoto.toml` < the env's own config.

`luoto project suggest` drafts one from an env that works: the accepted `luoto.toml` with the
env's own presets, agents, ports, `[deps]`, remote repos, allow rules (notes kept, such as
`approved request #3`) and denies on top. It lists on stderr what it leaves out as yours or
not a `luoto.toml`'s to carry: credentials and secrets, mutes, your folders, toolchain
defaults, your own `image`, expiring grants, and rules the sandbox couldn't ask for (`*`,
multi-tenant wildcards, address ranges, private addresses). `--write` puts it in the env's
folder; one already there is replaced only with `--force`, after the changes are listed.

Anyone who can write the repository writes this file, code in the sandbox included, so it
only proposes:

- `luoto init` shows its settings and asks about them separately (default: no); accepting
  records that exact text. `--yes` accepts it, `--no-project` leaves it out. An env cloned
  from a remote reads it in the env, so its first `up` asks, after the clone, and `--yes`
  leaves it for `luoto project apply`.
- A changed file (from a `git pull` in the env, or the sandbox itself) applies only after you
  accept the difference: `up` lists it and asks; where it can't ask (no terminal, the UI,
  `up --all`) it waits for `luoto project apply`. `luoto project ignore` stops applying it.
- It can't hold credentials, secret refs or `[[mute]]` (which would hide denials from you),
  and its rules pass the checks the sandbox's own access requests get (no `*`, no multi-tenant
  wildcards, no private addresses). Write access and uninspected tunnels are spelled out in
  the review. Its denies only tighten.

## Folders and remotes

An env belongs to a folder, and gets a copy of it: the first `up` puts the folder, git
history included, into the env, and the sandbox never writes to your folder. From a git
repository it copies what git doesn't ignore, so ignored files such as `.env`, `*.tfvars` or
state files stay on your machine. Development happens inside, in Zed or VS Code attached to
the env, and work leaves as git pushes (with a `[credentials.github]`,
`[credentials.azure_devops]` or `[[credentials.git]]` for the repo, or `[credentials.ssh]` for
an SSH remote; `up` asks for the ones the env's remotes need, `luoto repo auth` changes one). `luoto pull` brings files back when you need them on the host: it lists changed
files, skips risky ones (in the folder or any folder within it, such as a repository's own
`.git` or `.envrc`) unless you pass `--include-risky`, refuses paths or symlinks that leave
the folder, and never writes through host symlinks. `.git` and heavy directories
(`node_modules`, `target`, …) are skipped.

Or it belongs to a remote, with nothing on your machine: `luoto init acme/web` (an https or
ssh URL, `user@host:path` or Azure DevOps too; `--branch` picks one) clones it into
`/workspace` inside the env, through the gate, on the first `up`. An argument that could be a
folder is one (it exists, or its parent does, or it starts with `.`, `/` or `~`), so
`./acme/web` is a new folder; the proposal says which it took. Before the gate starts, `up`
asks for the remote's access (Enter: it is public). After the clone it shows the repository's
`luoto.toml` (Enter: not applied) and then what installing would do (the toolchains its files
pin, which mise installs, and the presets those installs open for a while), asking once
before anything runs. `--yes` installs, and leaves `luoto.toml` for `luoto project apply`.
`luoto init acme/web` again finds the env and offers what the clone suggests now; `--name`
makes a second one. Work leaves by git push; `luoto pull --to <new folder>` copies files out
(into a new or empty folder unless you confirm, never your home folder), and `luoto rm` first
says what isn't pushed. The UI lists these envs and reviews their `luoto.toml`; they are
created in a terminal. [docs/guides/untrusted-repo.md](guides/untrusted-repo.md) walks
through one.

## Several repositories

An env can hold related repositories beside its folder, each at `/workspace/<name>`, so an
agent sees them together and changes them in one session:

```console
$ luoto init ~/dev/platform --repo ~/dev/api --repo acme/web
```

- A folder (`~/dev/api`) is copied in like the env's own, and `luoto pull` writes it back
  there. luoto commands run in that folder act on this env.
- A remote (`acme/web` on GitHub, an https or ssh URL) is cloned in the env, through the gate,
  on the next `up`. Its work leaves by git push; `luoto pull --repo web` copies it into the
  env's folder.
- `luoto repo add|rm|list` changes an existing env; a repo added while the env runs is copied
  or cloned at once.

A public GitHub repo needs only the `github` preset. Private ones and pushes take HTTPS
credentials, which `up` asks for on a terminal (and prints without one): each lists the repos
it may write (`repos`) or only read (`read_repos`), and the gate refuses pushes to protected
branches. SSH remotes use them as they are. `[credentials.ssh]` works too, but a key reaches
every repo its account can.

The env's folder can be a repository of its own whose `luoto.toml` lists the team's repos, so
a clone of it and `luoto init` give every developer the same set:

```toml
# luoto.toml
[repos.api]
url = "acme/api"

[repos.web]
url = "git@github.com:acme/web.git"
branch = "develop"
```

`luoto.toml` names remotes only, never your folders; `luoto repo add ~/dev/api` makes your own
checkout replace its `api` in your env. In the env, the repos are listed in the folder's
`.git/info/exclude`, so they stay out of its `git status`.

[docs/guides/multi-repo.md](guides/multi-repo.md) has the three ways to set one up (command line,
launchpad, both) and a [launchpad example](examples/launchpad/).
