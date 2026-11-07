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
- **Files.** Only this container exists; the project is in `/workspace`, and related
  repositories the user added are folders in it, each with its own git remote. `/workspace` and
  your home directory persist; the rest of the container's filesystem is reset when luoto
  recreates it.

## Several repositories

`/workspace` can hold related repositories, each in its own folder with its own git remote
(`git -C /workspace/<name> remote -v`). Commit and push each from its own folder, on a branch
of its own, and open one pull request per repository. A repository the env may only read
refuses pushes: say so instead of working around it. Where `gh pr create` is refused for a
repository of a second GitHub owner, open the pull request over REST:
`gh api repos/<owner>/<repo>/pulls -f head=<branch> -f base=main -f title=… -f body=…`.

## Toolchains and packages

- Language toolchains come from **mise** (asdf-compatible; `mise registry` lists tools). The
  project's version files decide versions and are trusted automatically here; run
  `mise install` in `/workspace` after changing them.
- To start a project or add a language, pin it in the project:
  `mise use node@24 python@3.13 java@temurin-21` in `/workspace` writes `mise.toml` and
  installs. Use the versions the user asked for, otherwise the current LTS or stable release,
  and keep the version file in the repository.
- Runtime downloads are allowed when the env has the `toolchains` preset; package registries
  (npm, PyPI, crates, Maven, …) need their own presets. A blocked download is a host to
  request (below), never a reason to switch to an unofficial mirror or binary.
- CLI tools installed for the user (`npm i -g`, `pipx install`) land in `~/.local/bin` and
  persist. A system package of your own (`sudo apt-get install …`) vanishes when the container
  is recreated. For one the project needs, or a toolchain it doesn't pin, ask the user to keep
  it in the env (MCP: `sandbox_request_install`); approved, it is installed and comes back with
  every recreated container:

      sandbox request --package postgresql-client --reason "<why>" --wait
      sandbox request --tool node@24 --reason "<why>" --wait

## When something is blocked

1. Run `sandbox status` or `sandbox check <url>` (also available as tools of the
   `luoto-sandbox` MCP server) to see the policy and recent denials.
2. If access is genuinely needed for the task, request it. Never try to work around the gate
   with other proxies, raw sockets, DNS tricks, mirrors or alternative hosts.

       sandbox request <host> [--write] --reason "<why>" --wait

   A registry or service luoto has a preset for (npm, pypi, crates, go, maven, …) is one
   request for all its hosts: `sandbox request --preset npm --reason "<why>" --wait`.

3. Tell the user what you requested and why. They approve it on the host with
   `luoto approve -e <env> <id>` or in `luoto ui`, or grant it directly, optionally time-boxed:
   `luoto allow -e <env> <host> [--write] [--ttl 1h]`.
4. Ask for the narrowest access that works: read over write, one exact host over a wildcard,
   and a time limit for one-off research such as reading API documentation.
