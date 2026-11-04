# You are working inside a luoto sandbox

This environment is an isolated container that contains supply-chain attacks. Nothing in it
can read the user's host files or secrets, and every network connection goes through a
policy gate that only the user controls, from the host. Run `sandbox status` to see this
env's name and its current rules.

## What that means for you

- **Network.** Allowed destinations work normally (the package registries and services the
  user enabled). Anything else gets HTTP 403 with the header `x-proxy-error: blocked-by-luoto`
  and a plain-text explanation. Built-in web search tools usually run on the model provider's
  side and keep working; fetching a page or calling an API from here only works for allowed
  hosts.
- **Credentials.** Real secrets never enter the sandbox. Tokens you see in the environment
  (`GH_TOKEN`, `ANTHROPIC_*`, `OPENAI_API_KEY`, …) are placeholders; the gate swaps in the real
  credential only for the hosts the user granted. This is expected. Do not look for "real"
  tokens.
- **Writes.** Remote writes only work where the user granted them (for example pushing
  feature branches to one GitHub repository). Protected branches, tags, workflow files and
  GitHub Actions are off-limits.
- **Files.** Only this container exists; the project is in `/workspace`. `/workspace` and your
  home directory persist; the rest of the container's filesystem is reset when luoto recreates
  it.

## Toolchains and packages

- Language toolchains come from **mise** (asdf-compatible; `mise registry` lists tools). The
  project's own files decide versions, and are trusted automatically here: `mise.toml`,
  `.tool-versions`, `.node-version`/`.nvmrc`, `.python-version`, `.java-version`,
  `.ruby-version`, `go.mod`, `rust-toolchain.toml`, and `packageManager` in `package.json`
  (yarn, pnpm). Run `mise install` in `/workspace` after changing them.
- To start a project or add a language, pin it in the project:
  `mise use node@24 python@3.13 java@temurin-21` in `/workspace` writes `mise.toml` and
  installs. Use the versions the user asked for, otherwise the current LTS or stable release,
  and keep the version file in the repository.
- Runtime downloads are allowed when the env has the `toolchains` preset; package registries
  (npm, PyPI, crates, Maven, …) need their own presets. A blocked download is a host to
  request (below), never a reason to switch to an unofficial mirror or binary.
- CLI tools installed for the user (`npm i -g`, `pipx install`) land in `~/.local/bin` and
  persist. System packages (`sudo apt-get install …`) work but vanish when the container is
  recreated: tell the user to add the ones the project needs to `[deps] system` in the env's
  config (`luoto edit -e <env>` on the host), which reinstalls them on `luoto up`.

## When something is blocked

1. Run `sandbox status` or `sandbox check <url>` (also available as tools of the
   `luoto-sandbox` MCP server) to see the policy and recent denials.
2. If access is genuinely needed for the task, request it. Never try to work around the gate
   with other proxies, raw sockets, DNS tricks, mirrors or alternative hosts.

       sandbox request <host> [--write] --reason "<why>" --wait

3. Tell the user what you requested and why. They approve it on the host with
   `luoto approve -e <env> <id>` or in `luoto ui`, or grant it directly, optionally time-boxed:
   `luoto allow -e <env> <host> [--write] [--ttl 1h]`.
4. Ask for the narrowest access that works: read over write, one exact host over a wildcard,
   and a time limit for one-off research such as reading API documentation.
