# Your settings in every env

An env starts with luoto's defaults: your login shell with completion, your git name, agents
that ask nothing on their first start. Your own shell config, git aliases, themes and agent
settings come from one folder on your machine. An agent's model, effort and arguments are
luoto's config instead: [Agent settings](agent-settings.md).

## How it works

`~/.config/luoto/home/` mirrors an env's home: `luoto up` copies every file in it to the same
path under the home of every env, on every `up`. `luoto setup` creates the folder (a source
build's is `~/.config/luoto-dev/home/`).

```text
~/.config/luoto/home/
  .zshrc
  .gitconfig
  .tmux.conf
  .config/zellij/config.kdl
  .claude/settings.json
  .claude/CLAUDE.md
```

- An edit here reaches an env at its next `luoto up`, not before. A running env takes it with
  `luoto up -e <env>`, which copies it in and keeps the env running; each env gets it at its
  own next `up`.
- The copy overwrites the env's file of the same name, so edit on your machine: a change made
  in the env lasts until the next `up`. A file you remove from the folder stays in the envs
  that have it; delete it there too.
- Symlinks are followed, so a link to a folder of your dotfiles repository copies what it
  points at. `.git` folders are skipped.
- Files only go in. Nothing an env wrote is copied back.
- Code in the sandbox can read everything there. Keep tokens, credential helpers and rc files
  that export secrets out; a value the env needs goes through `luoto var` or a credential
  ([Environment variables](env-vars.md)).
- Copy config, not programs: install a tool inside the env (`mise use -g <tool>`, through the
  gate), where it is built for the env's system.

## Shell and prompt

The rc files of the shell luoto starts (`.zshrc`, `.config/fish/`), which is your machine's
own unless `shell` says otherwise ([configuration](../configuration.md#shell)). The image's
defaults are system-wide, so yours override them.

A prompt program is installed per env and configured once, in `.config/starship.toml` for
example. Start it only where it is installed, so a new env's shell opens without an error:

```sh
command -v starship >/dev/null && eval "$(starship init zsh)"
```

Leave out lines that name paths or programs of your machine.

## Git

`.gitconfig` carries your aliases, diff and merge settings:

```ini
[alias]
    st = status --short
    lg = log --oneline --graph
[pull]
    rebase = true
```

luoto sets `user.name` and `user.email` from your machine's git config as the env's system
config; a `[user]` section in this file overrides it. No credential helper or token belongs
here: the gate adds them to what the env's rules allow, outside the sandbox.

## Terminal workspaces

The ones `luoto open --with` starts run in the env and read their config from its home:

| workspace | file | theme |
| --- | --- | --- |
| zellij | `.config/zellij/config.kdl` | `theme "<name>"`, one it ships or one of `.config/zellij/themes/` |
| tmux | `.tmux.conf` | its `status-style` and other options |
| herdr | `.config/herdr/config.toml` | `name` under `[theme]`; `terminal` follows your terminal's colors |

```kdl
theme "gruvbox-dark"
```

Pick a theme that fits your terminal's background: with zellij's default on a dark terminal
theme, its key tips can be hard to read. A session that is running keeps its config until it
ends or reloads it.

## Editors in the env

An editor that runs in the env takes its config the same way, Neovim's in `.config/nvim/`.
Install it there (`mise use -g neovim`); the plugins it downloads on its first start go through
the gate, and `luoto egress --denied` lists a host that was refused. An editor whose window
runs on your machine (`luoto open`) keeps its settings there.

## Agents

An agent's user settings are files in the env's home, so yours go in the folder. Write short
ones for the envs instead of copying your machine's: those tend to hold hooks and paths that
exist only there. Never copy `~/.claude.json`, a login or your history.

| agent | yours | what you set there |
| --- | --- | --- |
| Claude Code | `.claude/settings.json`, `.claude/CLAUDE.md`, `rules/`, `skills/` | `theme`, `statusLine`, hooks, permissions |
| Codex | `.codex/config.toml`, `.codex/AGENTS.md` | its options, `notify` |
| OpenCode | `.config/opencode/opencode.json`, `.config/opencode/AGENTS.md` | its options |

```json
{
  "theme": "dark",
  "statusLine": { "type": "command", "command": "sh \"$HOME/.claude/statusline.sh\"" }
}
```

`theme` takes `auto`, `dark` or `light`. A script a setting names goes in the folder too
(`.claude/statusline.sh`).

After the copy, on every `up`, luoto merges its own entries into the same files and keeps the
rest. These keys are luoto's; set them through luoto, not in your file:

| file | luoto writes | when |
| --- | --- | --- |
| `.claude/settings.json` | `skipDangerousModePermissionPrompt` | always |
| | an entry in `hooks.UserPromptSubmit`, `hooks.Notification` and `hooks.Stop`, added beside yours | always |
| | `model`, `effortLevel` | `[agents.claude]` sets them |
| | `model`, and `ANTHROPIC_*` and `CLAUDE_CODE_MAX_CONTEXT_TOKENS` under `env` | the agent starts on a model server |
| `.codex/config.toml` | `[mcp_servers.luoto-sandbox]` | always |
| | `notify` | you set none |
| | `model`, `model_reasoning_effort` | `[agents.codex]` sets them |
| | `model_providers.luoto-<name>`, `profiles.luoto-<name>`, `profiles.cloud`, `profile`, `model_context_window` | the env has model servers |
| `.config/opencode/opencode.json` | `mcp.luoto-sandbox` | always |
| | `model` | `[agents.opencode]` sets it |
| | `provider.luoto-<name>` | the env has model servers |

A `model` of your own stays where luoto's config sets none. Codex's and OpenCode's `AGENTS.md`
get one line that points at luoto's briefing; Claude Code reads the briefing from the system's
instructions, and your `CLAUDE.md` stays as it is. The first-run answers (onboarding, trusting
`/workspace`) and the sandbox's MCP server for Claude Code are in the env's `~/.claude.json`.

Keep the JSON files plain JSON, without comments: luoto can't merge into one it can't read, and
`up` warns that the agent is not set up.

## Terminal

Nothing to copy for `TERM`. luoto's sessions (`luoto shell`, `luoto agent run`, a terminal
workspace) keep your terminal's name, and where the env has no terminfo entry for it luoto
installs your machine's in the env's `~/.terminfo`, or the session gets `xterm-256color`.
