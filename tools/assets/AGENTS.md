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
  hosts. The gate ends a request whose response hasn't started within 10 minutes (HTTP 504),
  a response silent for 5 minutes, and a tunnel or websocket silent for an hour; a long poll
  such as `kubectl logs -f` needs the user to give its host longer, on the host:
  `luoto allow -e <env> <host> --idle 2h`.
- **Credentials.** Real secrets never enter the sandbox. Tokens you see in the environment
  (`GH_TOKEN`, `ANTHROPIC_*`, `OPENAI_API_KEY`, …) are placeholders; the gate swaps in the real
  credential only for the hosts the user granted. This is expected. Do not look for "real"
  tokens.
- **Azure.** Where the user granted Azure, the env is a managed identity: `az` is logged in
  through the gate, and terraform (`ARM_USE_MSI`) and the Azure SDKs find the identity on their
  own. Never run `az login` here, interactively or with a secret. Access tokens you see are
  placeholders that work nowhere; the gate adds the real one on the subscriptions, key vaults
  and storage accounts the user named. A 403 from Azure itself (`AuthorizationFailed`) is the
  identity's Azure role, which only the user can change.
- **Cloud APIs.** `HCLOUD_TOKEN`, `UPCLOUD_TOKEN`, `DIGITALOCEAN_*TOKEN` and
  `CLOUDFLARE_API_TOKEN` are placeholders too: use the CLIs and terraform as they are, and
  never log them in. They read only unless the user set `write = true` for that cloud; a
  write the gate refuses means asking the user, not working around it.
- **Writes.** Remote writes only work where the user granted them (for example pushing
  feature branches to one GitHub repository). Protected branches, tags, workflow files and
  GitHub Actions are off-limits.
- **Files.** Only this container exists; the project is in `/workspace`, and related
  repositories the user added are folders in it, each with its own git remote. `/workspace` and
  your home directory persist; the rest of the container's filesystem is reset when luoto
  recreates it. `/workspace` may exist only here (an env cloned from a remote has no copy on
  the user's machine), so push work to keep it: what isn't pushed is lost with the env.

## Several repositories

`/workspace` can hold related repositories, each in its own folder with its own git remote
(`git -C /workspace/<name> remote -v`). Commit and push each from its own folder, on a branch
of its own, and open one pull request per repository. A repository the env may only read
refuses pushes: say so instead of working around it. Where `gh pr create` is refused for a
repository of a second GitHub owner, open the pull request over REST:
`gh api repos/<owner>/<repo>/pulls -f head=<branch> -f base=<base branch> -f title=… -f body=…`.
On Azure DevOps, open it over REST by the repository's name (no token: the gate adds it);
completing it stays with the user:
`curl -sf -X POST -H 'Content-Type: application/json' "https://dev.azure.com/<org>/<project>/_apis/git/repositories/<repo>/pullrequests?api-version=7.1" -d '{"sourceRefName":"refs/heads/<branch>","targetRefName":"refs/heads/<base>","title":"…","description":"…"}'`.

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
- Files from GitHub releases (Python, Java, Bun, pnpm, many CLI tools) come through only while
  luoto installs. For a toolchain from there, keep the pin and ask for the install:
  `sandbox request --tool python@3.13 --reason "<why>" --wait`.
- Go modules come through the proxy only from GitHub, GitLab, Bitbucket and well-known module
  domains (golang.org, google.golang.org, k8s.io, go.uber.org, gopkg.in, …). A module on
  another host takes two requests, its modules and its checksums:
  `sandbox request proxy.golang.org --path '/<host>/**' --reason "<why>" --wait`, then
  `sandbox request sum.golang.org --path '/lookup/<host>/**' --reason "<why>" --wait`.
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
   A protocol other than HTTP(S), such as a database, is a host and port:
   `sandbox request db.example.com:5432 --reason "<why>" --wait`. Approved, it is an
   uninspected tunnel: clients connect to the host and port as they are.

3. Tell the user what you requested and why. They approve it on the host with
   `luoto approve -e <env> <id>` or in `luoto ui`, possibly for less than you asked (read
   instead of write, fewer paths; the approval's note says), or grant it directly, optionally
   time-boxed: `luoto allow -e <env> <host> [--write] [--ttl 1h]`.
4. Ask for the narrowest access that works: read over write, one exact host over a wildcard,
   and a time limit for one-off research such as reading API documentation.
