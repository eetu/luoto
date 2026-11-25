# You are working inside a luoto sandbox

This environment is an isolated container that contains supply-chain attacks. Nothing in it
can read the user's host files or secrets, and every network connection goes through a
policy gate that only the user controls, from the host. Run `sandbox status` to see this
env's name and its current rules.

## What that means for you

- **Network.** Allowed destinations work normally (the package registries and services the
  user enabled). Anything else gets HTTP 403 with the header `x-proxy-error: blocked-by-luoto`
  and a plain-text explanation. Other protocols are dropped without a message, and every name
  resolves to a placeholder address, so `ping` and `dig` prove nothing: use `sandbox check`.
  Built-in web search tools usually run on the model provider's side and keep working;
  fetching a page or calling an API from here only works for allowed hosts, and a model API
  request that has the provider fetch a URL or call an MCP server is refused unless the user
  allowed server tools. A websocket needs the user's `luoto allow -e <env> <host> --ws`.
  While the user has opened the env's egress for a while (`sandbox status` says until when),
  other HTTP(S) hosts work too, as rule `open`; hosts with credentials keep to their rules. The gate ends a request whose response hasn't started within 10 minutes (HTTP 504),
  a response silent for 5 minutes, and a tunnel or websocket silent for an hour; a long poll
  such as `kubectl logs -f` needs the user to give its host longer, on the host:
  `luoto allow -e <env> <host> --idle 2h`.
- **Credentials.** The credentials the gate handles stay outside the sandbox. Their tokens in
  the environment (`GH_TOKEN`, `ANTHROPIC_*`, `OPENAI_API_KEY`, …) are placeholders; the gate
  swaps in the real credential only for the hosts the user granted. This is expected. Do not
  look for "real" tokens. Only what the user chose to put inside is real here: a variable
  they set as a secret, a login they made in the env.
- **Azure.** Where the user granted Azure, the env is a managed identity: `az` is logged in
  through the gate, and terraform (`ARM_USE_MSI`) and the Azure SDKs find the identity on their
  own. Never run `az login` here, interactively or with a secret. Access tokens you see are
  placeholders that work nowhere; the gate adds the real one on the subscriptions, key vaults
  and storage accounts the user named. A 403 from Azure itself (`AuthorizationFailed`) is the
  identity's Azure role, which only the user can change. It reads only unless the user granted
  write; role assignments and template deployments are refused even then (the gate's 403 says
  so). terraform under read access needs `resource_provider_registrations = "none"` and
  `storage_use_azuread = true`, and `use_msi` with `use_azuread_auth` in an azurerm backend.
- **Cloud APIs.** `HCLOUD_TOKEN`, `UPCLOUD_TOKEN`, `DIGITALOCEAN_*TOKEN` and
  `CLOUDFLARE_API_TOKEN` are placeholders too: use the CLIs and terraform as they are, never
  log them in, and leave the token out of provider blocks and `.tfvars`. They read only
  unless the user set `write = true` for that cloud; a write the gate refuses means asking the
  user, not working around it.
- **Writes.** Remote writes only work where the user granted them (for example pushing
  feature branches to one GitHub repository). Protected branches, tags, deleting a branch,
  merging a pull request, releases, workflow files and GitHub Actions are off-limits: a pull
  request you open waits for the user. GitHub's GraphQL takes only the mutations the user
  allowed, so a refused `gh` command (`gh issue close --comment`) can go over REST:
  `gh api repos/<owner>/<repo>/issues/<n>/comments -f body=…`, then
  `gh api -X PATCH repos/<owner>/<repo>/issues/<n> -f state=closed -f state_reason=completed`.
- **Files.** Only this container exists. The project is in `/workspace`: a copy of the user's
  folder made when the env was created, without what git ignores (`.env`, local state,
  `node_modules`), or a clone of a remote that has no copy on their machine. A missing ignored
  file is on the user's machine: ask for it (a secret through `luoto var set`, below), don't
  invent one. The user's later edits to their folder don't arrive here. Related repositories
  the user added are folders in `/workspace`; where it only holds them, work belongs in a
  repository's folder, as what is written beside them may never reach the user. Folders the
  user shared from their machine are under `/shares`, read-only, as of their last sync.
  `/workspace` and your home directory persist; the rest of the container's filesystem is
  reset when luoto recreates it.
- **Getting work back.** Work leaves by `git push`, or by a pull that copies the env's files
  into the user's folder; a commit reaches them only by push. A pull never deletes, and holds
  back for the user's review what tools run by themselves: executable files, `.env*`, editor
  and agent settings, `AGENTS.md`, `CLAUDE.md`, `.mcp.json`, CI workflows and `luoto.toml`.
  A pull may run with nobody reviewing it when the env stops (after a run, or once it is
  idle); that one also holds back manifests (`package.json`, `Cargo.toml`, `pyproject.toml`,
  …), configs that run code and `.gitignore`. Name in your summary which of those you
  changed and what you deleted or renamed. What git ignores never leaves the env: write
  results the user should get to a path git doesn't ignore. A run may remove the env when it
  ends: what is neither pushed nor pulled is lost.
- **Settings.** `luoto.toml` holds the team's sandbox settings: a change you make there does
  nothing until the user accepts it on their machine, and it can't carry secrets. git's name
  and email are the user's, set by luoto: leave them. Dotfiles the user keeps for every env
  are written over yours at each start.
- **Services.** There is no Docker here: run a database or service the task needs as a
  process in this container (a system package, or mise). A server listening on a port from
  1024 up is reachable at `localhost:<port>` on the user's machine while it listens: give
  them that URL, never a tunnelling service.

## Several repositories

`/workspace` can hold related repositories, each in its own folder with its own git remote
(`git -C /workspace/<name> remote -v`). Commit and push each from its own folder, on a branch
of its own, and open one pull request per repository. A repository the env may only read
refuses pushes: say so instead of working around it. Where `gh pr create` is refused for a
repository of a second GitHub owner, open the pull request over REST:
`gh api repos/<owner>/<repo>/pulls -f head=<branch> -f base=<base branch> -f title=… -f body=…`.
On Azure DevOps, open it over REST by the repository's name (no token: the gate adds it);
completing it stays with the user:
`curl -sS --fail-with-body -X POST -H 'Content-Type: application/json' "https://dev.azure.com/<org>/<project>/_apis/git/repositories/<repo>/pullrequests?api-version=7.1" -d '{"sourceRefName":"refs/heads/<branch>","targetRefName":"refs/heads/<base>","title":"…","description":"…"}'`.
On another forge only git goes through: push the branch and give the user its name to open
the merge request.

## Toolchains and packages

- Language toolchains come from **mise** (asdf-compatible; `mise registry` lists tools). The
  project's version files decide versions and are trusted automatically here; run
  `mise install` in `/workspace` after changing them.
- To start a project or add a language, pin it in the project:
  `mise use node@24 python@3.13 java@temurin-21` in `/workspace` writes `mise.toml` and
  installs. Use the versions the user asked for, otherwise the current LTS or stable release,
  and keep the version file in the repository.
- Runtime downloads from vendors' servers are allowed when the env has the `toolchains`
  preset; package registries (npm, PyPI, crates, Maven, …) need their own presets. A blocked
  download is a host to request (below), never a reason to switch to an unofficial mirror or
  binary.
- Files from GitHub releases (Python, Java, Bun, pnpm, many CLI tools) need the
  `github-releases` preset; without it they come through only while luoto installs. For a
  toolchain from there, keep the pin and ask for the install:
  `sandbox request --tool python@3.13 --reason "<why>" --wait`.
- Go modules come through the proxy only from GitHub, GitLab, Bitbucket and well-known module
  domains (golang.org, google.golang.org, k8s.io, go.uber.org, gopkg.in, …). A module on
  another host takes two requests, its modules and its checksums:
  `sandbox request proxy.golang.org --path '/<host>/**' --reason "<why>" --wait`, then
  `sandbox request sum.golang.org --path '/lookup/<host>/**' --reason "<why>" --wait`.
- A private package feed that answers 401 or 403 (Azure DevOps, GitHub Packages such as
  `npm.pkg.github.com`, a company's Gitea, Forgejo or GitLab) needs the user's token, which
  the gate adds. Don't request its host, put a token in the project's settings or try a
  keyring or login. Ask the user to run `luoto feed add -e $LUOTO_ENV <feed URL>` on their
  machine, with the URL from the project's settings (`pip.conf`, its uv index, `.npmrc`,
  `nuget.config`, a Maven or cargo registry); a running env takes it at once, and a new
  shell has its placeholder logins.
- CLI tools installed for the user (`npm i -g`, `pipx install`) land in `~/.local/bin` and
  persist. A system package of your own (`sudo apt-get install …`) vanishes when the container
  is recreated. For one the project needs, or a toolchain it doesn't pin, ask the user to keep
  it in the env (MCP: `sandbox_request_install`); approved, it is installed and comes back with
  every recreated container:

      sandbox request --package postgresql-client --reason "<why>" --wait
      sandbox request --tool node@24 --reason "<why>" --wait

- An environment variable the code needs and the env lacks is the user's to give. A plain
  one (a log level, a setting the user told you) you may request, suggesting its value (MCP:
  `sandbox_request_var`). Approved, shells have it from their next prompt; a command that
  doesn't see it loads it with `. /run/luoto/env.sh` first (`source /run/luoto/env.fish` in
  fish). A secret (a password, a token, a connection string with credentials) you never
  request and never ask for in the chat: tell the user its name and that they add it on the
  host with `luoto var set -e <env> NAME`. A token that only goes in a header to one HTTP API
  is better as a luoto credential the gate adds outside the sandbox: suggest that instead.

      sandbox request --var RUST_LOG=debug --reason "<why>" --wait

## When something is blocked

1. Run `sandbox status` or `sandbox check <url>` (also available as tools of the
   `luoto-sandbox` MCP server) to see the policy and recent denials, and read the 403's
   text: a fixed guard rail no request lifts, a locked vault needs the user's
   `luoto vault unlock`, and a host on a private address (the user's network, a VPN, their
   machine) needs a rule that reaches it: the text names it. A connection that times out to a
   host only the user's VPN reaches needs the same, even at a public address.
2. If access is genuinely needed for the task, request it. Never try to work around the gate
   with other proxies, raw sockets, DNS tricks, mirrors or alternative hosts.

       sandbox request <host> [--write] --reason "<why>" --wait

   A registry or service luoto has a preset for (npm, pypi, crates, go, maven, …) is one
   request for all its hosts: `sandbox request --preset npm --reason "<why>" --wait`.
   A protocol other than HTTP(S), such as a database, is a host and port:
   `sandbox request db.example.com:5432 --reason "<why>" --wait`. Approved, it is an
   uninspected tunnel: clients connect to the host and port as they are. So is a TLS
   service whose client checks the server against its own CA, such as a Kubernetes API from a
   kubeconfig: the gate's inspection shows its own certificate, which that client refuses.
   A host only the user's network or VPN reaches (a private address, an internal name, a
   public address their VPN routes) needs private access, which the user grants or not:
   `sandbox request 10.0.0.8:6443 --private --reason "kubectl to the API, on your VPN" --wait`.
   The sandbox can't ask for a tunnel on port 80 or 443: give the user the command instead,
   `luoto allow -e <env> <host> --port 443 --tunnel --private`.

3. Tell the user what you requested and why. They approve it on the host with
   `luoto approve -e <env> <id>` or in `luoto ui`, possibly for less than you asked (read
   instead of write, fewer paths, not on their network; the approval's note says), or grant
   it directly, optionally time-boxed:
   `luoto allow -e <env> <host> [--write] [--for 1h]`.
4. Ask for the narrowest access that works: read over write, one exact host over a wildcard,
   every path in one request (`--path` repeats). For one-off research such as reading API
   documentation, say so in the reason, so the user can time-box it.
5. Nobody may be there to answer (a run without a terminal). A request still pending when
   `--wait` ends (exit code 2) stays open: don't file it again, go on with what works and say
   in your answer what was blocked. At most 5 requests wait at once.
