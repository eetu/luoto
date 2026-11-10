# A repository you don't trust

`luoto init <remote>` makes an env whose workspace is cloned inside it, through the gate:
nothing of the repository lands on your machine, and nothing it wrote runs, installs or is
granted before you say yes. Use it to try a project you found, review a contributor's branch,
or work on a repository you haven't cloned.

## Create it

```console
$ luoto init acme/web
env `web` from acme/web
  workspace  a remote: acme/web cloned in the env through the gate; nothing on this machine
  isolation  gVisor: its own user-space kernel (builds about 1.6× slower)
  presets    debian, github, github-releases, toolchains
  toolchains and luoto.toml: read from the clone, shown before anything applies

Create it? [Y/n/c = customize]
```

The argument is `owner/repo` on GitHub, an `https://` or `ssh://` URL, `user@host:path`, or an
Azure DevOps URL; `--branch dev` checks out another branch, `--name` picks the env's name.
Anything that could be a folder is one: it exists, its parent exists, or it starts with `.`,
`/` or `~`. So `./acme/web` makes a new folder, and the proposal's `workspace` line says which
it took.

## The first `up`

1. **Access to the remote**, before the gate starts:

   ```console
   acme/web (GitHub, the env is cloned from it) has no credential, so the env can only fetch
   it if it is public.
   ? What can the env do with acme/web?
   > Fetch only, it's public            no token
     Read it, it's private              token with Contents: read
     Read and push, open pull requests  token with Contents + Pull requests: write
     Later
   ```

   Enter keeps it public. A private repository needs `Read it` (a token that reads it);
   `Read and push` lets the env push branches, never to protected ones. Other hosts take
   `[[credentials.git]]` the same way. `Later` clones nothing yet; `luoto repo auth -e web
   acme/web` asks again, as it does to change the answer.
2. **The clone**, once the self-test has passed: into `/workspace`, as the env's user. Git
   brings no hooks, submodules aren't fetched, and LFS files stay pointers. A clone that fails
   leaves nothing behind; `luoto up -e web` tries again, and asks for access again if you had
   called the repository public.
3. **Its `luoto.toml`**, shown in full; Enter leaves it out. Read what reaches past the gate:
   `image` (pulled outside the gate; it becomes the dev container), `ports` (published on
   127.0.0.1 here), `run` (commands the env runs), `repos` (more clones), and any `WRITE`,
   `TUNNEL` or `PRIVATE` in its `allow` rules. Left out, it waits: `luoto project -e web` shows
   it, `luoto project apply -e web` applies it.
4. **What the clone suggests**: presets for the registries its files use (Enter: no), then
   what installing would do, asked once:

   ```console
   Installing reads the clone: mise installs what its files pin, and a mise.toml can run commands in the env.
     toolchains node 22 (.nvmrc), pnpm 9.12.0 (package.json)
     presets    npm, opened only while they install
   Install them now? [Y/n]
   ```

   No leaves the env without them; each `luoto up -e web` asks again until a yes, and one
   that can't ask (the UI, `up --all`) installs nothing.

`luoto init acme/web --yes` asks nothing: the remote is public, the installs run, and its
`luoto.toml` waits for `luoto project apply`. With `--no-up`, `luoto up -e web` does all of the
above later.

Until you answer, the env reaches what its default presets allow (Debian packages, GitHub and
toolchain downloads, read-only) and the access you gave the remote.

## Working in it

The env has no folder on this machine, so commands take `-e web`: `luoto shell -e web`,
`luoto open -e web`, `luoto agent run -e web claude`. A shell, an editor or an agent starts
mise in `/workspace`, which reads the clone's `mise.toml`: that runs inside the sandbox, with
the egress the env has.

`luoto status -e web` says where the workspace comes from, and `luoto ls` lists it under FROM.

## Getting work out

Push from the env, with a credential that covers the repository (`luoto edit -e web`, or
`luoto up` on a terminal asks). To copy files to your machine:

```console
$ luoto pull -e web --to ~/review/web
```

`--to` is required: a new or empty folder, or one you confirm on a terminal, never your home
folder or one that holds it. The pull is reviewed like any other: `.git` stays out, and files
your own tools act on (`.envrc`, `.vscode`, build wrappers, hooks) are held back unless you pass
`--include-risky`.

## Later

- `luoto init acme/web` again finds the env (any spelling of the same repository), starts it
  if needed, and offers what the clone suggests now. `--name web2` makes a second env.
- A new VM (or a removed workspace volume) starts empty: the next `up` clones again.
- `luoto rm -e web` first names each repo in the env with what no remote has: files not
  committed, commits not pushed, stashes.

A large repository fills the disk of luoto's VM, which your other envs share: that costs space,
not isolation.
