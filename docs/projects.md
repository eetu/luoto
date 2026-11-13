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

[needs]                          # what each developer gives their own env
github = ["acme/web"]            # repos to push to
credentials = ["hetzner"]
sandbox_secrets = ["DATABASE_URL"]

[needs.custom.stripe]            # a table names a need and what the team knows of it
host = "api.stripe.com"

[needs.azure]
subscriptions = ["<subscription id>"]
```

The first `up` after accepting it asks each developer for what `[needs]` names and their env
lacks, with the questions an agent's credential gets: a provider's kind and where it is kept,
a custom credential's host (the team's filled in) and secret, an Azure subscription (the
team's offered first, read through their `az` login), where a sandbox secret is kept, and
each repo's access. The answers go in the developer's own env file. "Later" leaves one for
the next `up`; `luoto project needs` asks them all again, opening on what the env has.
Without a terminal it prints what to add instead.

It also takes `image`, `agents`, `[[deny]]` and the team's repositories (`[repos.<name>]`,
[below](#several-repositories)); toolchains belong in `mise.toml`. Layering: `config.toml` <
the accepted `luoto.toml` < the env's own config.

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
- It can't hold credentials, secret refs, model servers, `[egress]` or `[[mute]]` (which would
  hide denials from you), nor pick an agent's model server or pass the flags that loosen its
  permission prompts, and its rules pass the checks the sandbox's own access requests get (no
  `*`, no multi-tenant wildcards, no private addresses). Write access and uninspected tunnels
  are spelled out in the review. Its denies only tighten.

## Folders and remotes

An env belongs to a folder, and gets a copy of it: the first `up` puts the folder, git history
included, into the env, and the sandbox never writes to your folder. From a git repository it
copies what git doesn't ignore, so ignored files such as `.env`, `*.tfvars` or state files stay
on your machine. Development happens inside, in Zed or VS Code attached to the env, and work
leaves as git pushes (with a `[credentials.github]`, `[credentials.azure_devops]` or
`[[credentials.git]]` for the repo, which SSH remotes to those hosts use over HTTPS, or
`[credentials.ssh]`; `up` asks for the ones the env's remotes need, `luoto repo auth` changes
one). `luoto pull` brings files back when you need them on the host: it lists changed files,
skips risky ones (in the folder or any folder within it, such as a repository's own `.git` or
`.envrc`) unless you pass `--include-risky`, refuses paths or symlinks that leave the folder,
and never writes through host symlinks. `.git` and heavy directories (`node_modules`, `target`,
…) are skipped.

Or it belongs to a remote, with nothing on your machine: `luoto init acme/web` clones it into
`/workspace` inside the env, through the gate, on the first `up`, and nothing of it applies
or installs before your yes. The UI lists these envs and reviews their `luoto.toml`; they are
created in a terminal. [A repository you don't trust](guides/untrusted-repo.md) walks through
one.

## Several repositories

An env can hold related repositories beside its folder, each at `/workspace/<name>`, so an
agent sees them together: a folder of yours, copied in and pulled back to it (luoto commands
run in that folder act on this env), or a remote cloned in the env. `luoto init --repo`,
`luoto repo add|rm|list` or a launchpad's `luoto.toml` (`[repos.<name>]`, remotes only) sets
them up, and `luoto repo auth` what the env may do with each.
[Several repositories](guides/multi-repo.md) has the three ways, their credentials and a
[launchpad example](examples/launchpad/).
