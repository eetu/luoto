# Agents and model providers

What luoto knows about each coding agent it sets up: how it installs, which credential it
takes and where to get one, which hosts it reaches, what it is denied on purpose, and what is
still unverified. The profiles themselves are TOML files in
[`shared/agents`](../shared/agents) and [`shared/providers`](../shared/providers), which also
holds the cloud APIs ([guides/cloud-apis.md](guides/cloud-apis.md) has their facts).

Status: run with a real account for Claude Code and Antigravity CLI (its login inside; a
Gemini API key is untested); installed only for OpenCode and Codex; untested for Copilot CLI
([ROADMAP.md](../ROADMAP.md)).

## How an agent is set up

`luoto agent add <agent>` (or the first `luoto agent run <agent>`) adds the agent to the env's
`agents`, and `up` installs it inside the env, never on your machine. `up` installs every agent
listed there, or in the accepted `luoto.toml`, that the env lacks, so `agents = ["claude"]` in
a team's `luoto.toml` gives everyone Claude Code; for one with no credential it first asks
how it authenticates, as `agent add` does, and writes the answer into the env's config. The
install gets its download hosts only for that run, as expiring rules; `luoto egress` shows
them. Then luoto:

- links its user-level instructions to the luoto briefing (`/opt/luoto/AGENTS.md`), which
  tells it that egress is filtered and how to ask you for access;
- registers the sandbox MCP server (`sandbox mcp`), so it can read the policy and file access
  requests;
- sets the variables that turn off its auto-update and telemetry where it has them.

Model and effort, credentials without the prompt and your own settings in every env:
[guides/agent-settings.md](guides/agent-settings.md).

`--yolo` maps to the agent's own flag for skipping permission prompts, where it has one. The
sandbox is the boundary, so the prompts guard nothing luoto doesn't.

## Credentials

A provider credential lives outside the sandbox. luoto reads it on your machine, the vault
keeps it in memory, and the gate adds it to the agent's requests to that provider. The agent
sees a placeholder of the right format. Without one, the env's first `up` (also after `init`),
`agent add` and `agent run` ask how the agent signs in, the provider's usual kind first and
marked (recommended), then say where to get the one you pick and ask where it is kept: pasted
into your OS keychain (`keyring:luoto/<provider>.<kind>`, reused by later envs) or into a new
1Password item (the secret reaches `op` on stdin), found by browsing 1Password, or somewhere
else (`op://`, `vault://`, `keyring:`, `env:`, `file:`), read once you press enter. A pasted
or referenced value that doesn't start as its kind does (`sk-ant-oat` for a Claude
subscription token, `sk-ant-api` for an Anthropic API key) is asked for again. Browsing goes
account, vault and item, filtered as you type, then the field the item's kind keeps a secret
in (or one you type); with several 1Password accounts it asks which one, and the ref names it
by ID (`?account=<account ID>`). `agent add` asks only about the agent it adds.

Esc goes back a question. At the first, Esc or "Later" writes nothing, and the next `up` or
`agent run` asks again. The questions end with a summary: the credential the env has now
(its reference, never its value) and `luoto agent auth -e <env> <agent>`, which asks them
again for an agent the env has, each opening on what it has, marked (current); Esc at the
first leaves it unchanged. For OpenCode it first asks which provider, so it can have a
credential for several. Without a terminal, `agent add --credential` sets it
([guides/agent-settings.md](guides/agent-settings.md#credentials-without-the-prompt)). Either
replaces only the provider's kind or `login_inside`: its `server_tools` and `write` stay.

`login_inside = true` is the exception: the agent signs in itself and keeps the session in
the env's home, where any code in the sandbox can read it. Providers that allow it open their
sign-in hosts for it; luoto warns about it at `up`. On a terminal it is set only when you pick
it. Without one (`init --yes`, `agent add` in a script, a new env from the UI) it is what an
agent with no credential gets, so an agent you add can work at once; `luoto agent auth`
replaces it with a credential kind, which moves the credential outside.

Server tools have the provider reach the network for a request: fetch a URL, call an MCP
server. Code in the sandbox could use them to send data anywhere, so the gate reads requests
to the endpoints that take them and refuses one that asks for them, along with the
provider's WebSocket API, whose messages it can't read. The agents luoto sets up fetch and run
MCP servers on their own side, through the gate. `server_tools = true` under
`[credentials.<provider>]` allows them.

| provider | hosts the credential goes to | kinds | where to get one | kept out of reach |
| --- | --- | --- | --- | --- |
| `anthropic` | `api.anthropic.com` | `oauth_token`, `api_key`, login inside | `claude setup-token` on your machine (Claude plan); platform.claude.com (API billing) | files, message batches, organization admin, skills; server tools: web fetch, the MCP connector |
| `openai` | `api.openai.com` (over WebSocket only with server tools) | `api_key`, login inside | platform.openai.com/api-keys; a ChatGPT plan only through login inside | files, uploads, batches, organization, fine-tuning, vector stores; server tools: remote MCP servers |
| `openrouter` | `openrouter.ai` `/api/**` | `api_key` | openrouter.ai/keys | |
| `gemini` | `generativelanguage.googleapis.com` | `api_key` | aistudio.google.com/apikey | uploads, files, cached contents, batches; server tools: URL context, remote MCP servers |
| `mistral` | `api.mistral.ai` | `api_key` | console.mistral.ai/api-keys | |
| `groq` | `api.groq.com` | `api_key` | console.groq.com/keys | |
| `copilot` | `api.githubcopilot.com` and its `individual`, `business`, `enterprise` hosts; `api.github.com` `/copilot_internal/**`, `/user` | `token` | github.com/settings/personal-access-tokens (fine-grained, Copilot Requests) | |
| `antigravity` | none: sign-in only | login inside | your Google account | |

A Google AI Pro plan doesn't pay for a Gemini API key: a key is free tier, where Google may
use prompts to improve its products, until its Google Cloud project has billing.

## Claude Code

- Installs with Anthropic's installer (`claude.ai`, `downloads.claude.ai`,
  `storage.googleapis.com`). Runs with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` and
  `DISABLE_AUTOUPDATER=1`.
- Also reaches `platform.claude.com` `/v1/oauth/hello`, which first-run onboarding checks
  whatever the credential.
- `oauth_token` from `claude setup-token` uses your Claude subscription; `api_key` is billed
  as API usage and can have its own spend limit.
- A setup token carries only the `user:inference` scope, so Claude in the env can't see your
  plan: `/usage` shows a cost estimate instead of session and weekly limits, and the default
  model is Sonnet (`/model opus`, or `luoto agent run claude -- --model opus`). The limits are
  shared with your other Claude sessions; `/usage` on the host shows them.
- The env has its own `~/.claude` in its home volume. Give it a portable subset of yours
  through `~/.config/luoto/home/.claude/`: a short `settings.json` of its own (`luoto setup`
  starts one; your host's usually has hooks and `env` entries that point at your machine), and
  `CLAUDE.md`, `rules/` or `skills/` (symlinks are followed). Leave out `~/.claude.json` and
  your history: code in the sandbox can read everything there.
- `login_inside = true` under `[credentials.anthropic]` logs in with full scopes instead, and
  keeps a refresh token in the env.
- The briefing goes in as managed instructions (`/etc/claude-code/CLAUDE.md`).
- Its first start skips onboarding (text style, security notes), the auto mode notice and the
  question whether to trust `/workspace` and the folders in it: luoto answers them in
  `~/.claude.json`, as the sandbox is the boundary. Commits and pull requests without its AI
  attribution: [guides/agent-settings.md](guides/agent-settings.md#commits-without-ai-attribution).

## OpenCode

- Installs with OpenCode's installer from its GitHub releases, and runs with auto-update and
  session sharing off (`OPENCODE_DISABLE_AUTOUPDATE`, `OPENCODE_DISABLE_SHARE`).
- Takes any of `anthropic`, `openai`, `openrouter` or `gemini`.
- Reads its model catalogue from `models.dev` and `models.opencode.ai`.
- `--yolo` passes nothing: its profile has no `yolo` flags.

## Codex

- Installs from npm (`@openai/codex`); mise brings Node LTS for it.
- `openai` `api_key`, or `login_inside = true` to sign in with ChatGPT (opens
  `auth.openai.com` and `chatgpt.com`).
- Streams over `wss://api.openai.com/v1/responses` before falling back to HTTPS. The gate
  refuses the WebSocket upgrade unless `server_tools = true`; that Codex then falls back is
  unverified.

## GitHub Copilot CLI

- Installs from npm (`@github/copilot`) and runs with `COPILOT_AUTO_UPDATE=false`.
- Takes a fine-grained personal access token with the Copilot Requests account permission
  and no repository access. Its placeholder is `COPILOT_GITHUB_TOKEN`, which the CLI reads
  before `GH_TOKEN` (set by a GitHub credential).
- The gate adds the token on the Copilot API hosts and on GitHub's `/copilot_internal/**` and
  `/user`, apart from a GitHub credential's repository paths.
- The briefing goes to `~/.copilot/instructions/luoto.instructions.md`, without `applyTo`
  frontmatter. Unverified: whether Copilot loads it, and which hosts and paths it needs
  ([ROADMAP.md](../ROADMAP.md)); telemetry hosts are left denied.

## Antigravity CLI

- Installs with Google's installer: `antigravity.google` for the script, a Cloud Run updater
  (`antigravity-cli-auto-updater-974169037036.us-central1.run.app`) for the manifest, and
  `storage.googleapis.com` for the binary, which it checks against the manifest's SHA-512.
  The installer appends a `PATH` line to `.bashrc`, `.zshrc`, `.profile` and fish's
  `config.fish` (luoto already has `~/.local/bin` on `PATH`), and logs
  `ERROR: logging before google.Init` lines that are only its own logging.
- Signs in with your Google account inside the env (`[credentials.antigravity] login_inside
  = true`, which you pick when `agent add` asks, and which it sets without a terminal): run
  `agy` in `luoto shell`, open the URL it prints in your
  browser and paste the code back. Its backend is `cloudcode-pa.googleapis.com` and
  `daily-cloudcode-pa.googleapis.com`; the token comes from `oauth2.googleapis.com`.
- Also reads the signed-in profile (`www.googleapis.com` `/oauth2/v2/userinfo` and
  `/oauth2/v3/userinfo` only, since that host serves many Google APIs) and its remote
  configuration (`aicode.googleapis.com` `/v1alpha:fetchConfig`).
- Runs with `AGY_CLI_DISABLE_AUTO_UPDATE=1`. MCP servers live in
  `~/.gemini/config/mcp_config.json`, the briefing in `~/.gemini/GEMINI.md`.
- Denied on purpose, and it works without them (a `[[mute]]` keeps their denials out of
  `luoto egress`, the UI and notifications):

  | host | what it is | why it stays closed |
  | --- | --- | --- |
  | `play.googleapis.com` | usage statistics | telemetry |
  | `lh3.googleusercontent.com` | your profile picture | it also serves files people upload to Google Photos, Blogger and Sites: a download route for anything |
  | `www.gstatic.com` | static images and fonts | nothing a terminal needs |
  | the updater manifest | an update check it makes even with auto-update off | the binary stays the version luoto installed |

## Model servers

How each agent uses a `[model_servers]` entry
([guides/model-servers.md](guides/model-servers.md)):

- **Claude Code:** the one it starts on goes in `~/.claude/settings.json` (`ANTHROPIC_BASE_URL`,
  a placeholder token, every model alias set to the server's model, the server's `context` as
  `CLAUDE_CODE_MAX_CONTEXT_TOKENS`); one endpoint a session.
  Verified with a server on this machine (MTPLX, and a stand-in): reached through the gate,
  its token added over plain HTTP, `claude -p` sending its requests there.
- **Codex:** a provider and a profile per server in `~/.codex/config.toml` (Responses API,
  `env_key = "LUOTO_MODEL_TOKEN"`), the one it starts on as the default profile and `cloud`
  for OpenAI. Written as unit tests expect; not run against a server yet.
- **OpenCode:** an `@ai-sdk/openai-compatible` provider per server (bundled with OpenCode, no
  download) beside the cloud's in its model picker, the one it starts on as `model`. Not run
  against a server yet.

## Not built in

- **Gemini CLI.** Its Google sign-in finds no Code Assist project for a personal Google AI
  Pro account and falls back to asking for an API key; Antigravity CLI signs in with the same
  account. A Gemini API key works through OpenCode.
- **Antigravity (the desktop IDE)** runs on your machine and is not an agent luoto installs.

## Adding an agent

An agent is a file in `shared/agents/`: `command`, the `yolo` flags, `providers`, the
`install` commands and their `install_hosts`, `tools` it needs from mise, `env`, `briefing`
paths, the `mcp` registration kind, its `headless` command line for `luoto run` (`{prompt}`
where the prompt goes), `[[first_run]]` answers to its first-start questions (a value at a
path in a JSON config of the home), `[settings.<option>]` for `model` and `effort`, and
`[[rule]]`s for hosts it reads besides its provider.
A provider is a file in `shared/providers/`: its `host` (and `also` hosts with their paths),
the credential kinds and how each is placed, `[[deny]]`d endpoints, and `login_hosts` for a
login inside. Presets and rules use exact hosts; the profile tests reject risky wildcards.
