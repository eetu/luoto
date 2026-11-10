# Agent settings

How to set up the agents in your envs: their model and effort, their credentials without the
prompt, your own settings in every env, and commits without AI attribution. What luoto knows
about each agent (hosts, credentials, what is verified) is in [agents.md](../agents.md).

## Model and effort

Per env in its config, for a team in `luoto.toml`, or for every env that has the agent in
`config.toml`; the closest setting wins:

```toml
[agents.claude]
model = "opus"        # an alias or a model name
effort = "medium"     # Claude: low, medium, high, xhigh; Codex adds minimal
```

luoto writes them into the agent's own user settings on `up`, so they are the default and
`/model` or `/effort` in a session still changes them until the next `up`. Claude Code and
Codex take both, OpenCode takes `model`. `config.toml` gives options only: it adds no agent to
an env.

## Credentials without the prompt

Scripts, and setups without a terminal, give the credential on the command line:

```console
$ luoto agent add claude --credential oauth_token=op://Private/claude/token
$ luoto init --agent claude --credential oauth_token=op://Private/claude/token
```

It takes `KIND=REF`, `PROVIDER.KIND=REF` where two agents' providers share a kind, or
`login_inside`; the reference must resolve. It replaces the provider's kind or `login_inside`,
and its other settings (`server_tools`, `write`) stay. On a terminal, `luoto agent auth claude`
does the same through the questions, opening on what the env has.

## Your settings in every env

`~/.config/luoto/home/` is copied into every env's home on `up`: a portable subset of your
agent settings goes there (`.claude/settings.json`, `CLAUDE.md`, `rules/`, `skills/`), never
`~/.claude.json` or your history, which code in the sandbox could read. Each `up` overwrites
the copies, so edit them on the host.

Claude Code's first start asks nothing in an env (luoto answers onboarding and trusting
`/workspace`); its text style stays yours, `"theme": "auto"` (or `dark`, `light`) in that
`settings.json`.

## Commits without AI attribution

Claude Code adds a `Co-Authored-By` trailer to commits and a "Generated with Claude Code" line
to pull requests. `attribution` in its settings turns both off, but only by changing what
Claude is told; a model can still write them. A `PreToolUse` hook enforces it: it refuses
such a commit or pull request and Claude writes it again. In
`~/.config/luoto/home/.claude/`:

```json
{
  "attribution": { "commit": "", "pr": "" },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "sh \"$HOME/.claude/hooks/no-ai-attribution.sh\""
          }
        ]
      }
    ]
  }
}
```

`hooks/no-ai-attribution.sh`:

```sh
#!/bin/sh
# Refuse a commit or pull request that carries AI attribution; exit 2 tells Claude why.
input=$(cat)
case $input in
  *"git commit"* | *"gh pr create"* | *"gh pr edit"* | *"/pulls"*) ;;
  *) exit 0 ;;
esac
if printf "%s" "$input" |
  grep -qiE "co-authored-by:[^\"]*(claude|anthropic|noreply@openai)|generated with \[?(claude|codex)"; then
  echo "Leave out AI attribution: no Co-Authored-By trailer for an AI and no \"Generated with\" line." >&2
  exit 2
fi
```

A line in `CLAUDE.md` beside them says the same, so Claude rarely needs the hook. A commit
message read from a file (`git commit -F`) passes the hook unseen.
