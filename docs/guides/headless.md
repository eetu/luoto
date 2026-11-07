# Headless runs

`luoto run` gives an agent one prompt with no one at the terminal: it brings the env up
without asking anything, installs the agent if the env lacks it, runs the agent's
non-interactive mode with its own permission prompts off (the sandbox is the boundary) and
prints its answer. Progress goes to stderr, the answer to stdout (or `--output FILE`), and
the exit code is the agent's. `--down` stops the env after.

```console
$ luoto run --agent claude --prompt "Summarize what changed on main this week"
$ luoto run -e web --agent codex --prompt-file task.md --output answer.md --down
$ git diff | luoto run --agent claude          # the prompt from stdin
```

Claude Code, Codex, OpenCode and Copilot CLI have a headless mode; the agent's profile says
how it is started (`headless` in `shared/agents/<agent>.toml`).

## Before it runs unattended

- **Credentials that need no one.** `up` loads the env's secrets into the vault, and a 1Password
  desktop prompt waits for your Touch ID. For a job, use refs that resolve on their own: the
  OS keychain (`keyring:luoto/anthropic.oauth_token`, where the prompt's "paste it into your
  keychain" keeps it), a 1Password service account (`[sources.op] mode = "service-account"`
  and its `service_account_token` ref in `config.toml`), `env:` or `file:`. Set one without the
  prompt with `luoto agent add claude --credential oauth_token=<ref>`.
- **Access up front.** An agent that hits a blocked host asks for it (`sandbox request`), and
  only you can approve, so an unattended run would wait for nobody. Give the env the presets
  and rules the task needs first; `luoto egress -e <env> --denied` after a trial run shows
  what was missing.
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
luoto run -e web --agent claude --down --output "$HOME/jobs/deps-$(date +%F).md" \
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
