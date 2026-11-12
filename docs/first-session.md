# A first session: from folder to pull request

The overview is the [README](../README.md); step by step, the [guides](guides/README.md).

## 1. Make an env for a project

```console
$ cd ~/dev/my-app
$ luoto init
env `my-app` from ~/dev/my-app
  workspace  copy: the env works on its own copy; changes leave by git push or `luoto pull`
  isolation  gVisor: its own user-space kernel (builds about 1.6× slower)
  presets    debian, github, github-releases, toolchains, npm (package.json)
  toolchains node 24 (.nvmrc)
             installed by mise in the env; the project's files keep deciding versions

Create it? [Y/n/c = customize]
```

luoto read the folder before creating anything: node 24 from `.nvmrc`, the npm registry
because of `package.json`. `Y` copies the folder, git history included, into the env and
starts it; your folder stays as it was. `c` goes through the settings one at a time.

## 2. Give it credentials, without giving them to it

Two tokens: one for Claude Code (`claude setup-token` on your machine uses your Claude
subscription) and a fine-grained GitHub token for this repository only, with Contents and Pull
requests set to read and write. Keep both in your secret store and point the env at them with
`luoto edit`:

```toml
[credentials.anthropic]
oauth_token = "op://Private/claude-code/token"

[credentials.github]
token = "op://Private/github-my-app/token"
repos = ["you/my-app"]
protected_branches = ["main"]
```

Saving applies it. luoto reads the secrets on your machine and hands them to the vault, which
lives outside the sandbox. Inside, `GH_TOKEN` and Claude's token are placeholders; the gate
puts the real ones on requests to GitHub and Anthropic, for `you/my-app` only, and refuses
pushes to `main`. No secret store? `luoto agent add claude` asks for the token and keeps it in
your OS keychain; `luoto agent auth claude` asks again to change it.

`luoto ui` shows which credentials an env has, never their values:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="screenshots/vault-dark.png">
  <img alt="luoto ui: vault unlocked, the env's credential bound to its host, request allowed" src="screenshots/vault-light.png">
</picture>

## 3. Let an agent work

```sh
luoto agent add claude          # installs Claude Code in the env
luoto agent run claude --yolo   # no permission prompts: the sandbox is the boundary
```

Ask it to fix something small and open a pull request. Or do it yourself: `luoto open`
attaches Zed, VS Code or Cursor over SSH, and `luoto shell` opens a terminal.

## 4. Run it and open it

Start the project as usual in the env's terminal: `yarn dev` prints
`http://localhost:5173/`, and clicking it opens the app in your browser. A background watcher
(started by `up`, `shell` and editor sessions) forwards each port a server in the env listens
on, 1024–32767, to the same port on your machine for as long as it listens. It goes through
the runtime rather than a network path, so servers bound to the env's own localhost work too;
a port already taken here is skipped (`luoto forward LOCAL:ENV` maps it elsewhere).
`luoto status` and the env's panel in `luoto ui` list the forwarded ports as links.

## 5. See what it reached

`luoto ui` (or `luoto egress`) lists every host the env tried: npm and GitHub allowed,
anything else blocked, with a scoped allow next to it. One click lets a host through, for an
hour if you like:

<img alt="luoto ui: example.com allowed for one hour after the earlier block" src="screenshots/egress-allowed.png">

An agent that needs a host asks with `sandbox request`; only you can approve it, on your
machine (`luoto approve`, which asks you to accept the rule's risks like `luoto allow` does;
`--force` accepts them without asking). You can grant less than it asked, never more:
`--read` for a write request, `--method`, `--path` within its paths. A protocol other than
HTTP(S) is a host and port (`sandbox request db.example.com:5432`), which approved becomes an
uninspected tunnel, a risk you confirm. It asks the same way for a system package or a
toolchain the env should keep (`sandbox request --package postgresql-client`,
`--tool node@24`): approving installs it and writes it into the env's `[deps] system` or
`[tools]`, so a recreated container has it too. A variable the code needs comes with a value
to confirm (`sandbox request --var RUST_LOG=debug`), or a secret by name only (`--secret
DATABASE_URL`), for which `luoto approve` asks where it is kept, as `luoto var set` does;
`luoto ui` takes either ([environment variables](guides/env-vars.md)).

Trying luoto on a project whose needs you don't know yet: `luoto init --open` (or `luoto
egress open` later) lets the env reach any HTTP(S) host for an hour (`--open=2h`, `--for 2h`
for longer), every request still logged. `luoto egress keep` then offers presets that cover
what it reached, else a rule per host, and when the hour ends the env is default-deny again.
Hosts that get your credentials keep to their rules throughout, and muted hosts stay denied.

## 6. Bring files back and stop

`luoto pull` brings files back to your folder when you need them there; it holds back git
hooks and other files your own tools would run. `luoto down` stops the env, and it stops by
itself after 30 minutes with nothing running in it (`idle_stop`); luoto's VM stops once no
env has run for as long. `luoto up` brings it back in about 10 s and unlocks the vault anew.
