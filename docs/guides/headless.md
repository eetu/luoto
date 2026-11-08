# Headless runs

`luoto run` gives an agent one prompt with no one at the terminal: it brings the env up
without asking anything, installs the agent if the env lacks it, runs the agent's
non-interactive mode with its own permission prompts off (the sandbox is the boundary) and
prints its answer. Progress goes to stderr, the answer to stdout (or `--output FILE`), and
the exit code is the agent's. `--timeout` caps the agent's time; `--down` stops the env after.

```console
$ luoto run --agent claude --prompt "Summarize what changed on main this week"
$ luoto run -e web --agent codex --prompt-file task.md --output answer.md --down
$ luoto run -e web --agent claude --prompt-file task.md --timeout 45m
$ git diff | luoto run --agent claude          # the prompt from stdin
```

Claude Code, Codex, OpenCode and Copilot CLI have a headless mode; the agent's profile says
how it is started (`headless` in `shared/agents/<agent>.toml`).

## Timeout, exit code and denials

`--timeout 30m` (or `90s`, `2h`) counts from the agent's start, so bringing the env up and
installing the agent don't use it. When it passes, luoto stops the agent and everything it
started in the env, even processes in a group of their own: SIGTERM, then SIGKILL 10 seconds
later. Ctrl-C stops it the same way (a second one doesn't wait), and so does an answer that
can't be written. The env keeps running unless `--down` is given.

| exit code   | when                                                                             |
| ----------- | -------------------------------------------------------------------------------- |
| the agent's | the agent finished                                                               |
| 124         | the agent ran past `--timeout` and was stopped (as `timeout(1)` exits)           |
| 130         | Ctrl-C stopped it                                                                |
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

## Examples

**A report.** The env reads the code; the answer lands on your machine.

```console
$ luoto run --agent claude --output audit.md --prompt "Audit /workspace for
  injection risks. Report each finding with file, line and a fix; change nothing."
```

**A value for a script.** Ask for the bare answer, and check the exit code.

```sh
count=$(luoto run --agent claude --prompt "How many rows of data/orders.csv have \
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
$ luoto run -e web --agent claude --prompt-file task.md --down
```

In a [multi-repo env](multi-repo.md) the same prompt can change several repos and open a pull
request in each.

**On a schedule.** cron (or a CI runner with luoto set up) runs it like any command; keep the
command in a script, as cron treats `%` specially.

```sh
#!/bin/sh
# ~/jobs/weekly-deps.sh, from cron: 0 6 * * 1 ~/jobs/weekly-deps.sh
luoto run -e web --agent claude --down --timeout 1h \
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
