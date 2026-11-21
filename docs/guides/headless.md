# Headless runs

`luoto run` gives an agent one prompt with no one at the terminal: it brings the env up
without asking anything, installs the agent if the env lacks it, runs the agent's
non-interactive mode with its own permission prompts off (the sandbox is the boundary) and
prints its answer. Progress goes to stderr, the answer to stdout (or `--output FILE`), and
the exit code is the agent's. `--timeout` caps the agent's time; `--down` stops the env after,
`--rm` removes it, and `--pull` or `--dangerously-pull` bring what it changed into your folder
([below](#its-changes-in-your-folder)).

```console
$ luoto run claude --prompt "Summarize what changed on main this week"
$ luoto run -e web codex --prompt-file task.md --output answer.md --down
$ luoto run -e web claude --prompt-file task.md --timeout 45m
$ git diff | luoto run claude          # the prompt from stdin
```

Claude Code, Codex, OpenCode and Copilot CLI have a headless mode; the agent's profile says
how it is started (`headless` in `shared/agents/<agent>.toml`).

## Timeout, exit code and denials

`--timeout 30m` (or `90s`, `2h`) counts from the agent's start, so bringing the env up and
installing the agent don't use it. When it passes, luoto stops the agent and everything it
started in the env, even processes in a group of their own: SIGTERM, then SIGKILL 10 seconds
later. Ctrl-C stops it the same way (a second one doesn't wait), and so does an answer that
can't be written. The env keeps running unless `--down` is given. A run luoto stopped pulls
nothing ([below](#its-changes-in-your-folder)).

## Its changes in your folder

The agent works on the env's copy. What it changed reaches your folder by `git push` from the
env, or by a pull:

| | |
| --- | --- |
| `luoto run … --pull` | after the agent, `luoto pull`: the files listed, written after your yes. Without a terminal nothing is written |
| `luoto run … --dangerously-pull` | after the agent the env stops, and its files are written with nobody reviewing them |
| `luoto pull --on-stop on` | from now on every stop of this env does that: `luoto down`, the stop after `idle_stop`, the UI's stop, a run's `--down` or `--rm`. `off` ends it |

```console
$ luoto run -e web claude --prompt-file task.md --dangerously-pull
env `web` stopped
pulled 3 file(s) from `web` into ~/dev/web
wrote:
  src/export.rs
  src/reports.rs
  tests/export.rs
held back for your review:
  vite.config.ts — a tool's config that is code: editors and dev servers load it
changed here and in the env (yours kept):
  README.md
`luoto up -e web`, then `luoto pull -e web` reviews what was left
```

An unattended pull is narrower than a reviewed one, because nobody chooses when its files
land:

- **Only what the env changed.** luoto keeps a fingerprint of every file as it was copied
  in. A file is written when the env changed it and you didn't. One you changed too is a
  conflict: yours stays. One the env deleted stays. Nothing is ever deleted.
- **Nothing that runs by itself.** Held back: everything `luoto pull` calls risky, executable
  files, tool configs that are code (`vite.config.*`, `eslint.config.*`, `build.rs`,
  `conftest.py`, Gradle scripts, `Gemfile`, `flake.nix`, yarn's own files), the folder your
  repository runs hooks from, and anything laid out as a git repository.
- **No manifest.** A project's manifests are held back too, because editors, language servers
  and installs evaluate them without being asked: `package.json`, `Cargo.toml`,
  `pyproject.toml`, `setup.py`, `setup.cfg`, `pytest.ini`, `tox.ini`, `go.mod`, `go.work`,
  `Makefile`, `CMakeLists.txt`, `pom.xml`, `build.sbt`, `mix.exs`, `Package.swift`,
  `build.zig`, MSBuild project files (`*.csproj`, `Directory.Build.props`, …) and
  `.eslintrc*` and `.prettierrc*`. So is `.gitignore`, which decides what the next copy into
  an env leaves out of your folder. The price: a change that adds a dependency or touches the
  build lands without its manifest, the run exits with 75 and `--rm` keeps the env, until
  you have reviewed the rest.
- **Within limits.** At most 5000 files and 256 MB of changes per folder, 64 MB per file; over
  that, nothing is written. The folder itself may be any size up to a million files. A folder
  in the middle of a merge or rebase is left alone; `luoto down -e web` tries again.
- **Not what git ignores.** What your folder's `.gitignore` ignores is build output by your
  own rules: it stays in the env, and it doesn't keep `--rm` or `luoto prune --envs` from
  removing the env. Have the agent write what you want back to a path git doesn't ignore.
- **From the stopped env.** The files are read from the env's volume once it has stopped,
  never while code in it could still change them.
- **Not after a run cut short.** Ctrl-C, `--timeout`, an answer that couldn't be written, a
  `luoto run` that was killed, an env stopped under its agent: the half-done files are not
  pulled and the env is kept (stopped, where the run was to stop or remove it). After that
  the env's stops pull nothing until `luoto pull -e web` has reviewed them.

The env is stopped by the time a pull reports, and a reviewed pull asks a running one:
`luoto up -e web`, then `luoto pull -e web` reviews what was held back, and `--overwrite`
there takes the env's side of a conflict. `luoto down` exits with 75, as a run does, when its
pull left something out. `luoto ui` shows on an env's panel that it pulls when it stops, and
what its last such pull came to.

Anything watching your folder (a dev server, a test watcher, an editor's language server)
acts on a file the moment it lands, which is what `dangerously` says: the code in it is the
sandbox's, and it then runs on your machine. Stop watchers you don't want fed, or use `--pull`.

An env made before luoto kept fingerprints, or imported, has none: its stops pull nothing
until a reviewed `luoto pull` has left the folder with every file the env has.

A pull cut short (a crash, a power cut) is cleaned up by the next luoto command: it removes
the half-written temporary files and says how many files had landed. An env set to pull when
it stops that stopped without luoto seeing it (a crash, a restart of the machine) is pulled
from its volume in the background, by the watcher: no command waits for it, `luoto logs
watcher` shows it and a notification says what it came to. Where that needs luoto's VM
started, luoto says once that `luoto down -e web` pulls them. After a one-off
`--dangerously-pull` it says so and a reviewed pull takes the rest. An env a run was to
remove (`--rm`) is never removed later.
The last pull's report stays in luoto's data folder (`pulls/<env>/report.json`);
`--pull-report FILE` writes a run's own, with every file name.

## A one-off env

`--rm` removes the env when the run ends, as `luoto rm` does: containers, volumes and its
config file, so a job that makes its env leaves nothing behind. Work no remote has would go
with it, so luoto looks first, as `luoto rm` does (files changed, commits not pushed and
stashes, in `/workspace` and each of its repos). For an env with a folder on this machine it
also compares the env's files with the folder's, as `luoto pull` does: files new or changed
in the env, ones a pull refuses or couldn't read, and what no pull takes (`node_modules`,
`target`, …). What the folder's `.gitignore` ignores doesn't count. An env holding any of
that is kept and stopped, and the run says what it holds; on a terminal it asks. `--rm --yes`
removes it whatever the run leaves. Either way the exit code is the agent's.

With `--dangerously-pull` (or pull-on-stop) the folder gets the files first, and the env is
removed only if they all landed: nothing held back, in conflict, refused or unread, no
`node_modules`-like folder your `.gitignore` doesn't ignore. Changed files and commits on the
checked-out branch no longer keep it, since their files are in your folder (the commits
themselves go with the env); stashes and commits on other branches still do.

```console
$ luoto run -e nightly claude --prompt-file task.md --rm
Work in `nightly` that no remote has:
  /workspace/api: 2 files changed, 1 commit not pushed
env `nightly` kept, stopped: it holds work that is nowhere else. `luoto rm -e nightly
--yes` removes it; `luoto run … --rm --yes` removes an env whatever its run leaves
```

| exit code   | when                                                                             |
| ----------- | -------------------------------------------------------------------------------- |
| the agent's | the agent finished                                                               |
| 124         | the agent ran past `--timeout` and was stopped (as `timeout(1)` exits)           |
| 130         | Ctrl-C stopped it                                                                |
| 75          | the agent succeeded, and its unattended pull left something out (above)          |
| 1           | luoto itself failed, the reason on stderr: the env didn't come up, no credential |

After the run, stderr lists what the gate denied while the agent ran, without what a
`[[mute]]` hides: each host, how often, the requests (or ports) it refused and why. stdout and
`--output` keep only the answer.

```text
the gate denied 4 attempts to reach 2 hosts during the run:
  docs.rs          3  GET /serde (2), GET /tokio: no rule allows docs.rs
  evil.example     1  port 22: no rule allows evil.example
`luoto egress -e web --denied` says how to allow each.
```

## Leftover envs

`--rm` is how a job leaves nothing behind. Envs that stayed anyway (kept for their work, made
without `--rm`, left by a run that was killed) go with `luoto prune --envs`: it removes the
stopped envs nobody has used for 30 days, as `luoto rm` removes one, after listing them and
one question.

```console
$ luoto prune --envs --match 'job-*' --older-than 7d
`luoto prune --envs` removes 2 stopped env(s) named `job-*` not used for 7d,
3.2 GB:
  ENV     LAST USED  SIZE
  job-12  9d ago     1.6 GB
  job-15  8d ago     1.6 GB
1 stopped env(s) named `job-*` not used for 7d stay for the work they hold,
1.6 GB (`--with-work` removes them too):
  ENV     LAST USED  SIZE
  job-14  8d ago     1.6 GB
      /workspace: 2 files changed, 1 commit not pushed
? Remove 2 env(s) (3.2 GB)? [y/N]
```

- **Which envs.** An env is used when it starts, while something runs in it (a shell, an
  agent, an editor session, a dev server: what `idle_stop` goes by) and when it stops.
  `--older-than` sets the age (`7d`, `12h`; `0d` is every stopped env), `prune_after` in
  `config.toml` its default. `--match` narrows them to the names a shell pattern matches
  (`*`, `?`, `[a-z]`; case matters). A running env is never removed. `luoto list` shows each
  env's last use under USED.
- **Work stays.** An env holding work that is nowhere else is listed with what it holds and
  kept: what `luoto rm` names (files changed, commits not pushed, stashes), as luoto found it
  when the env stopped, and for an env with a folder on this machine the files that folder
  lacks, read from the stopped env's volume (what its `.gitignore` ignores doesn't count). An
  env luoto didn't see stop (a restart of the machine, or its last stop was an earlier
  luoto's) counts as holding work until a `luoto up` and `luoto down` of it. `--with-work`
  removes these too: `luoto prune --envs --match 'job-*' --with-work` clears a pile of them
  you know to hold nothing.
- **As listed.** An env started, used or stopped since the list was made stays, as does one
  another luoto is starting or pulling.
- **In a script.** `--yes` skips the question. Without a terminal and without `--yes` the
  envs are only listed, with the command that removes them, and the exit code is 1. An env
  that can't be removed leaves the rest to go, and the exit code is 1.
- **Envs from before 0.7.0** have no record of their last use: they show `unknown`, and
  their age counts from when luoto last wrote their config or state.

`luoto prune` without `--envs` removes luoto's superseded images and no env.

## Before it runs unattended

- **Credentials that need no one.** `up` loads the env's secrets into the vault, and a 1Password
  desktop prompt waits for your Touch ID. For a job, use refs that resolve on their own: the
  OS keychain (`keyring:luoto/anthropic.oauth_token`, where the prompt's "paste it into your
  keychain" keeps it), a 1Password service account (`[sources.op] mode = "service-account"`
  and its `service_account_token` ref in `config.toml`), `env:` or `file:`. Set one without the
  prompt with `luoto agent add claude --credential oauth_token=<ref>`. A token rotated in such
  a source is read again once an upstream refuses the old one.
- **Access up front.** An agent that hits a blocked host asks for it (`sandbox request`), and
  only you can approve, so an unattended run would wait for nobody. Give the env the presets
  and rules the task needs first; a trial run ends with what the gate denied, and
  `--timeout` ends a run that waits anyway.
- **A login inside, done once.** An agent that logs in inside the env (`login_inside`) needs
  that login done by hand first: `luoto shell`, then the agent.

## Smaller requests

An agent sends its system prompt and tool definitions with every request: about 54 KB for
Claude Code's `hello`, 42 KB for OpenCode's. A cloud model reads that in a moment; a model
of yours (a [model server](model-servers.md)) can take a minute. Arguments that trim it, for
`luoto run` only:

```toml
[agents.claude]
headless_args = ["--bare", "--tools", "Bash,Read,Edit"]
```

`--bare` leaves out hooks, skills, plugins, MCP servers, memory and CLAUDE.md; `--tools` the
tools a job doesn't use. Claude Code's `hello` is then 4 KB. Its answer can only use what you
left it. `--bare` reads no subscription token: with `oauth_token` the run isn't signed in, so
use it with an `api_key` or a model server. For one run, give them after `--`:

```sh
luoto run claude --prompt "Summarize this repo in 5 bullets" -- --bare --tools Bash,Read
```

## Examples

**A report.** The env reads the code; the answer lands on your machine.

```console
$ luoto run claude --output audit.md --prompt "Audit /workspace for
  injection risks. Report each finding with file, line and a fix; change nothing."
```

**A value for a script.** Ask for the bare answer, and check the exit code.

```sh
count=$(luoto run claude --prompt "How many rows of data/orders.csv have \
  status=failed? Print only the number.") || exit 1
```

**A feature through to a pull request.** The env needs the repo in `[credentials.github]
repos`; the gate refuses pushes to protected branches, so the prompt names a branch.

```markdown
<!-- task.md -->

Add CSV export to the reports page (issue #142).

1. Work on a new branch `feat/csv-export` from `main`.
2. Implement it with tests; run the test suite until it passes.
3. Commit, push the branch and open a pull request with `gh pr create`, its body
   summarizing the change and how it was tested.
```

```console
$ luoto run -e web claude --prompt-file task.md --down
```

In a [multi-repo env](multi-repo.md) the same prompt can change several repos and open a pull
request in each.

**On a schedule.** cron (or a CI runner with luoto set up) runs it like any command; keep the
command in a script, as cron treats `%` specially.

```sh
#!/bin/sh
# ~/jobs/weekly-deps.sh, from cron: 0 6 * * 1 ~/jobs/weekly-deps.sh
luoto run -e web claude --down --timeout 1h \
  --output "$HOME/jobs/deps-$(date +%F).md" \
  --prompt "Update the npm dependencies that have patch releases, run the tests, and open
  a pull request with what changed."
```

## Merging on its own

The gate denies merging: REST's merge endpoint, and GraphQL mutations other than creating
and updating pull requests. A pull request from the sandbox waits for you.

GitHub can merge it once branch protection is satisfied (auto-merge). To let the agent turn
that on, allow the mutation behind `gh pr merge --auto`:

```toml
[credentials.github]
graphql_mutations = ["createPullRequest", "updatePullRequest", "enablePullRequestAutoMerge"]
```

The repository needs "Allow auto-merge" enabled and the token Contents and Pull requests
write; the prompt ends with `gh pr merge --auto --squash`. With several `[[credentials.github]]`,
GraphQL goes with the first that may write, so its list applies.

Keep a required review in the branch protection: auto-merge then means "merged as soon as a
person approves and CI is green". Without one, code the sandbox wrote reaches `main` with
only CI checking it, and the code that wrote it could be a compromised dependency in the env,
which is what luoto is there to stop. CI runs that code with the repository's secrets
either way, as for any branch pushed from the env ([ROADMAP.md](../../ROADMAP.md): pushes to a
fork).
