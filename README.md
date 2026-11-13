<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/luoto-dark.svg">
    <img alt="luoto: no tool is an island, except on luoto." src="docs/logo/luoto-light.svg" width="540">
  </picture>
</p>

## Why

A malicious package runs with everything you have. Its install script can read `~/.ssh`,
your cloud and npm tokens and your other repos, send them anywhere, and — as worms like
Shai-Hulud did — use your GitHub token to publish itself further. Coding agents run more code,
faster, often with their permission prompts off.

luoto gives each project a sandbox where that doesn't work:

- **It can't see your files.** The project is copied in; your home folder, SSH keys and other
  repositories stay on your machine.
- **It reaches only what you allowed.** Every request leaves through a gate with per-host
  rules, read-only unless you say otherwise. Anything else is blocked and shown to you, with a
  one-click allow.
- **Your secrets never enter it.** Agent, GitHub, Azure DevOps and Azure tokens stay in a
  vault outside the sandbox; the gate adds them to the requests you allowed, and code inside sees
  placeholders. Git tokens work only for the repositories you named.

You keep working as usual: your editor attaches over SSH, agents run with their prompts off
because the sandbox is the boundary, and work leaves as a pull request.

Something in an env tried to reach `example.com`. The gate blocked it, and `luoto ui` shows
the attempt with a scoped allow next to it:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/egress-blocked-dark.png">
  <img alt="luoto ui: example.com blocked, with the allow form open" src="docs/screenshots/egress-blocked-light.png">
</picture>

> luoto is a personal hobby project in beta, maintained on a best-effort basis.

## Install

| platform                                     | install                                                                                           |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| macOS, Linux                                 | `curl -fsSL https://raw.githubusercontent.com/eetu/luoto/main/install.sh \| sh`                   |
| macOS, Linux (Homebrew)                      | `brew install eetu/tap/luoto` (a full name trusts that formula only)                              |
| Linux, no script                             | a `.tar.gz` from [Releases](https://github.com/eetu/luoto/releases), checked against `SHA256SUMS` |
| from source                                  | `just install-cli`, then `luoto setup --build`                                                    |
| Windows (Scoop; not yet verified end to end) | `scoop bucket add luoto https://github.com/eetu/scoop-luoto` then `scoop install luoto`           |

Then, once:

```sh
luoto setup
```

It checks your container runtime (podman ≥ 5.2 or Docker ≥ 28; on macOS 26 on Apple silicon
it offers Apple's `container` first; `--install` installs the one picked after showing the
command), creates luoto's own VM where podman needs one, and gets the images. Updates, tab completion and checking a download: [Install details](docs/install.md).

## Getting started

```sh
cd ~/dev/my-app
luoto init                      # an env for this folder, from the toolchains its files name
luoto agent add claude          # installs Claude Code; asks for its credential
luoto agent run claude --yolo   # it works inside; the sandbox is the boundary
luoto open                      # your editor over SSH (or `luoto shell`)
luoto ui                        # what the env reached and what the gate blocked
luoto pull                      # bring files back when you need them here
luoto down                      # stop it; `luoto up` brings it back
```

[A first session](docs/first-session.md) goes through it step by step: credentials that stay
outside the env, ports, what it reached, a pull request.

## Guides

Step by step, for a task:

| guide                                                         | when you want to                                                              |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [Changing an env](docs/guides/changing-an-env.md)             | add a repo, fix a token, allow a host, recreate the container                 |
| [A repository you don't trust](docs/guides/untrusted-repo.md) | clone and try one with nothing of it on your machine                          |
| [Several repositories](docs/guides/multi-repo.md)             | work on more than one repo in an env, or give a team a launchpad              |
| [Headless runs](docs/guides/headless.md)                      | run an agent from a script or a schedule, and let it open pull requests       |
| [Agent settings](docs/guides/agent-settings.md)               | set an agent's model, effort and arguments, or your own settings in every env |
| [Model servers](docs/guides/model-servers.md)                 | use Ollama, LM Studio, MTPLX or another server of yours beside the cloud      |
| [Azure](docs/guides/azure.md)                                 | run `az`, terraform and the SDKs on your subscriptions                        |
| [Cloud APIs](docs/guides/cloud-apis.md)                       | use Hetzner, UpCloud, DigitalOcean or Cloudflare from an env                  |
| [Moving an env](docs/guides/moving-envs.md)                   | take an env to the release, or to another machine                             |

Reference:

- [Configuration](docs/configuration.md): the env's file and `config.toml`, credentials,
  rules, toolchains, shells and editors.
- [Projects and repositories](docs/projects.md): a team's `luoto.toml`, folders and remotes,
  several repositories in an env.
- [Agents](docs/agents.md): what luoto knows of each agent (hosts, credentials, what is
  verified).
- [How it works](docs/how-it-works.md): the gate, the vault, the sandbox, platforms.
- [Install details](docs/install.md): updates, tab completion, checking a download.
- [SECURITY.md](SECURITY.md): the threat model, what holds and what doesn't.

## Day to day

Commands act on the env of the current folder; `-e NAME` picks another (`luoto status -e web`).
An env cloned from a remote has no folder here, so it always takes `-e`.

| you want                                                                                             | run                                                                                                                                |
| ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| an env for a folder (copied in)                                                                      | `luoto init [DIR]`                                                                                                                 |
| an env for a repository you haven't cloned, or don't trust: cloned inside, nothing on this machine   | `luoto init acme/web`<br>`luoto init git@gitlab.com:acme/web.git --branch dev`                                                     |
| related repositories beside it (a host folder, or a remote cloned in the env)                        | `luoto init --repo ~/dev/api --repo acme/web`<br>`luoto repo add acme/lib`<br>`luoto repo list`                                    |
| a new project (the folder is created)                                                                | `luoto init ~/dev/new-app`                                                                                                         |
| to review, apply or ignore the team's `luoto.toml`, or draft one from your env                       | `luoto project`<br>`luoto project apply`<br>`luoto project ignore`<br>`luoto project suggest`                                      |
| your editor, or a shell                                                                              | `luoto open`<br>`luoto open --with code`<br>`luoto shell`                                                                          |
| to see what the sandbox tried to reach                                                               | `luoto egress --since 10m`<br>`luoto egress --denied`<br>`luoto egress --follow`                                                   |
| to find what a project needs: any HTTP(S) host for a while (default 1h), then keep what it reached   | `luoto egress open --for 2h`<br>`luoto egress --open`<br>`luoto egress keep`<br>`luoto egress close`                               |
| to allow a host (read-only unless `--write`)                                                         | `luoto allow docs.rs --ttl 1h`<br>`luoto allow api.example.com --write --path '/v1/**'`<br>`luoto allow grpc.example.com --tunnel` |
| to see or remove rules                                                                               | `luoto status`<br>`luoto revoke <id-or-host>`                                                                                      |
| to answer access requests from inside                                                                | `luoto requests` (`--watch` waits)<br>`luoto approve 3 --ttl 1h`<br>`luoto approve 3 --read --path '/v1/**'`<br>`luoto reject 3`   |
| an agent (installed on first run)                                                                    | `luoto agent run claude --yolo`<br>`luoto agent list`                                                                              |
| another credential for an agent, or a login inside instead                                           | `luoto agent auth claude`                                                                                                          |
| what the env may do with a repo: fetch it if public, read it, or push                                | `luoto repo auth acme/api`                                                                                                         |
| environment variables: a plain value, or a secret the code reads                                     | `luoto var set RUST_LOG=debug`<br>`luoto var set DATABASE_URL`<br>`luoto var`                                                      |
| a folder of this machine the env reads, read-only (recordings, datasets)                             | `luoto share add ~/Recordings`<br>`luoto share sync`                                                                               |
| a dev server in your browser                                                                         | run it: its port is forwarded to localhost here (`luoto status` lists it)<br>`luoto forward 8080:5173` (to another local port)     |
| your work out: push from the env (with a GitHub, Azure DevOps or SSH credential), or copy files back | `git push`<br>`luoto pull`                                                                                                         |
| image or config changes applied (volumes are kept)                                                   | `luoto up --recreate`                                                                                                              |
| a fresh home: dotfiles, shell history, agents' logins and state, toolchains (the workspace stays)    | `luoto reset-home`                                                                                                                 |
| to stop an env, or delete it with its volumes and config (your folder stays)                         | `luoto down` (`--all`: every env)<br>`luoto rm`                                                                                    |
| an env in another luoto (a source build's in the release) or on another machine, in one file         | `luoto export` (`--no-home`)<br>`luoto import web.luoto.tar`                                                                       |
| the env back after a reboot or an idle stop (unlocks the vault if needed)                            | `luoto up` (`--all`: every env)<br>`luoto vault unlock`                                                                            |
| a secret you rotated in your secret store, in use                                                    | `luoto vault reload` (`-e <env>` for one env's)                                                                                    |
| the gate's log, the background watcher's, or what the env's installs printed                         | `luoto logs`<br>`luoto logs watcher`<br>`luoto logs installs -f`                                                                   |
| what installs and clones print as they come, instead of a spinner                                   | `o` while one runs<br>`-v` on any command (`luoto up -v`)                                                                          |
| what each env takes on disk, and how full luoto's VM is                                              | `luoto status --size`<br>`luoto ls --size`<br>`luoto doctor`                                                                             |
| the space luoto's superseded images take, back on this machine (volumes stay)                        | `luoto prune`                                                                                                                      |
| to check isolation, or a bug report with secrets and what identifies you taken out                   | `luoto doctor`<br>`luoto doctor --report`                                                                                          |
| to remove luoto: envs, vault, images, keychain entries, config and data (the binary stays)           | `luoto uninstall`                                                                                                                  |

Inside the sandbox, `sandbox status` shows the policy and `sandbox request <host> --reason …`
asks you for access (`<host>:<port>` for a tunnel; `--preset npm` for a registry's hosts at
once; `--package <name>` or `--tool <tool>@<version>` for software to keep; `--var <NAME>=<value>`
for a plain variable); only you can approve, on the host. A new request gets a desktop notification, as does the first denial at
each host (macOS through `terminal-notifier`, which Homebrew installs with luoto, else
`osascript`, whose come from Script Editor; Linux with `notify-send`). Without
them (turned off, or on Windows), the bell in `luoto ui` gives browser notifications for
requests.

## Agents

`luoto agent run <agent>` installs the agent on first run (`up` installs those listed in the
env's `agents` or its `luoto.toml`), applies the env's current config and starts the agent in
`/workspace`; `--yolo` turns off its own permission prompts (OpenCode has no
flag for it), since the sandbox is the boundary. After that first run the command (`claude`,
`codex`, …) also works in any env terminal, including an editor's. Each agent needs a credential
for one of its providers under `[credentials.<provider>]`, or a model server of yours; the gate
adds it to every request and the sandbox sees only a placeholder. `luoto agent auth <agent>` changes it, its questions
opening on what the env has. [docs/agents.md](docs/agents.md#credentials) covers where
to get one, how the prompt keeps it, and logins inside the sandbox, with the hosts and
verification status of each agent. `luoto agent list` shows agents and providers. Model,
effort, your own agent settings and commits without AI attribution:
[docs/guides/agent-settings.md](docs/guides/agent-settings.md). Claude Code, Codex and OpenCode
can also use a model server of yours, on this machine (Ollama, LM Studio, MTPLX, …), your
network or the internet, beside the cloud:
[docs/guides/model-servers.md](docs/guides/model-servers.md).

Without a terminal, `luoto run --agent claude --prompt "…"` runs one prompt: it brings the env
up (asking nothing), runs the agent in its non-interactive mode and prints its answer (or
writes it with `--output FILE`), exiting with the agent's code; `--timeout 30m` stops the agent
and what it started once it has run that long (exit 124), `--down` stops the env after, and
what the gate denied during the run is listed on stderr.
A cron job or CI step can run it; pull requests it opens go through the gate as any other.
[docs/guides/headless.md](docs/guides/headless.md) has examples, what an unattended run needs,
and how to let GitHub merge its pull requests.

| agent                         | command    | credential                                                  |
| ----------------------------- | ---------- | ----------------------------------------------------------- |
| Claude Code                   | `claude`   | Claude subscription token (`claude setup-token`) or API key |
| OpenCode                      | `opencode` | Anthropic, OpenAI, OpenRouter or Gemini API key             |
| Codex                         | `codex`    | OpenAI API key, or a ChatGPT login inside                   |
| GitHub Copilot CLI (untested) | `copilot`  | fine-grained token with Copilot Requests                    |
| Antigravity CLI               | `agy`      | Google account, signed in inside the env                    |

## Limits

- Outside HTTP(S), only tunnel rules (`luoto allow --tunnel`) and git over SSH to
  `[credentials.ssh]` hosts leave an env. Run databases inside the dev container. Open egress
  covers HTTP(S) only.
- No Docker-in-docker inside envs.
- The gate speaks HTTP/1.1 to the sandbox, so gRPC needs a tunnel rule.
- The gate holds up to 1024 connections per env. It closes a request whose response hasn't
  started 10 minutes after it was sent, a response that sends nothing for 5 minutes, and a
  tunnel or websocket after an hour without traffic. A rule's `idle` (`luoto allow
  k8s.example.com --idle 2h`, at most 24h) gives its host that long instead, for long polls
  such as `kubectl logs -f`.
- luoto's VM keeps its disk in a file on yours (up to 100 GB, podman's default) that grows as
  images, toolchains and workspaces fill it and doesn't shrink when they go. A full VM disk
  stops every env: `luoto doctor` shows how full it is and what the file takes here, `luoto up`
  and the UI warn under 10 GB free, and `luoto prune` removes luoto's superseded images and
  trims the VM so the freed space returns to this machine. Each time the VM's disk has grown
  10 GB (or a tenth of it) since luoto last said so, `up`, `down`, `luoto run` and the end of
  a shell or agent session say so, with the env's biggest build folders (`target/`,
  `node_modules/`, …); the watcher notifies when free space falls under 10 GB and 3 GB.
- On Apple's `container` ([Platforms](docs/how-it-works.md#platforms)): an env's egress
  history shows only while its gate runs, and a volume attaches to one running container at a
  time, so refilling the tools volume stops the dev container briefly.

## Development

`CLAUDE.md` has the map of the repo and the `just` recipes; `just test` runs the unit tests.
`LUOTO_TRACE=1` prints every runtime call with its timing. `SECURITY.md` has the threat model.
