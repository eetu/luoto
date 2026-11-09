# Security model

luoto keeps dependencies, editor extensions and coding agents from reading your files, stealing
your secrets or sending data anywhere you did not allow.

## Trust boundaries

| trusted (TCB) | untrusted |
| --- | --- |
| the host OS and user, the `luoto` binary | everything inside the dev container: dependencies, build scripts, extensions, agents, the repository content |
| the container runtime and its VM | anything the sandbox prints or writes (it has root inside via sudo; the host UI is the only source of policy truth) |
| the gate and vault containers | text in access requests (shown as untrusted in the UI and CLI) |
| secret sources (1Password, keyring, OpenBao) | |

Host malware is out of scope: anything that can run as the user can `exec` into any container.

## What holds the line

- **Network.** The dev container sits on an internal network with no route out. Its default
  route and resolver are the env's gate. The gate is the only egress: HTTP(S) is inspected
  (per-env CA, key only in the gate, renewed by `up` 60 days before its two years end) and
  checked against a default-deny policy of host, port, method, path, body size and expiry;
  explicit denies, luoto's and the user's `[[deny]]`, beat
  every allow. Non-HTTP TCP goes nowhere except through tunnel rules
  you grant (`luoto allow --tunnel`, a host and port, or an approved port request, after you
  confirm it goes uninspected) and SSH to the hosts an SSH credential
  names, on port 22 (GitHub's on `ssh.github.com:443` with `github_port = 443`); both pass
  through uninspected. UDP goes nowhere. DNS is answered locally
  with fake addresses and never forwarded. Destinations are resolved by the gate only after a
  request is allowed, every resolved address is checked against private, loopback,
  link-local, CGNAT and host-gateway ranges (including IPv4 inside IPv6), and the gate
  connects to exactly the vetted address. Host, SNI and CONNECT authority must agree.
- **Path matching.** A path is matched and forwarded in one canonical form; dot segments, empty
  segments and backslashes are refused.
- **Secrets.** Root secrets live only in the vault's memory, loaded from the host's secret
  store at unlock and wiped by `luoto vault lock` or a VM restart. `luoto vault reload` reads
  them again; one an upstream refuses (401) is read again on its own, at most every 10
  minutes, when its source needs no one (the keychain, a 1Password service account, `file:`,
  Vault, `az`). Those background reads only replace what the vault holds, so a locked vault
  stays empty. Each gate authenticates to the
  vault with its own token and receives only its env's bindings, as short-lived values
  (GitHub installation tokens restricted to the env's repositories and permissions). On a
  credentialed host the gate removes any credential the client sent before injecting its own,
  so a dependency carrying an attacker's token cannot use it, and it injects only over TLS:
  plain HTTP to a credentialed host is refused.
- **GitHub writes.** Pushes only to the granted repositories, never to protected branches
  (default `main`, `master`), tags or branch deletions. REST writes are an allowlist — pull
  requests, reviews, issues and comments — so the contents, git-data, ref, merge, release and
  settings endpoints can't route around the push guard; GraphQL mutations outside an
  allowlist are refused. Workflows/Actions/Secrets/Administration permissions are refused at
  configuration time. Configure branch rulesets on GitHub as well; the gate is a guard-rail.
  GraphQL names no repository in its path, so with a token (not an App) it reaches what the
  token does, `read_repos` and unlisted repositories included; only an App's minted token is
  limited to the env's repositories.
- **Azure DevOps writes.** The PAT goes only on the granted repositories' git paths and their
  pull requests' REST paths, and pushes pass the same guard as on GitHub. A pull request's
  body is an allowlist of fields (title, description, branches, draft, reviewers, work items,
  labels), so completing one (a merge) or setting auto-complete is refused, as are votes. A PAT
  reaches its whole organization, so the gate's paths are the only repository boundary; the
  rest of its REST API is not reachable. Configure branch policies in Azure DevOps as well.
- **Other forges** (`[[credentials.git]]`). The token goes only on the granted repositories'
  smart-HTTP and LFS paths, pushes pass the same guard, and push options (which can open merge
  requests or skip CI) are refused. The forge's API is not reachable with it; the token's
  scope at the forge is the boundary, so prefer a project or repository token. A pushed branch
  runs the forge's CI as any branch does: keep CI secrets in protected variables. `ca` is
  trusted for that host only. `private = true` lets the gate dial that host's private address,
  never loopback, cloud metadata or luoto's own networks.
- **Azure** (`[credentials.azure]`). Tokens live in the vault: read from your `az` login on
  the host (and read again before they expire), or minted there from a service principal's
  secret, which never leaves it; the vault reaches only `login.microsoftonline.com` for them,
  one mint at a time per token, and answers a refused mint again for 30 seconds rather than
  asking. The gate answers the instance metadata service itself and never dials it. What it
  hands the sandbox is a placeholder: the real token's header and the claims tools read
  (audience, issuer, times, tenant, object and application IDs, subject, identity type,
  version) with a signature that can't verify; names, addresses, roles and scopes stay out.
  The real token goes, over TLS, only on Resource Manager paths of the listed subscriptions
  (plus reading the subscription and tenant lists and the resource providers), the key vaults
  and storage accounts named exactly, and Graph, and only with the methods `access` allows
  there (Graph and those lists: read); IMDS serves no other audience. Only the env's own config
  grants it: not `config.toml`, not a `luoto.toml`, and an `azcli:` ref (your `az` login's
  token) works nowhere else. A rule you add or an access request you approve may open more of
  those hosts, but adds no token: the gate strips the client's and adds its own only within the
  above, and `luoto allow` and `luoto approve` say whose credential a rule's host gets before
  adding it.
- **Credentials coming back.** On a credentialed host the gate looks for the credential it
  placed in the response's headers and the start of its body (all of a JSON body, from which
  it removes the fields carrying it, as LFS servers echo it); a response that still carries it
  is refused.
- **Git over SSH.** The private key stays in the vault, which answers the env's ssh-agent: it
  signs only a public-key login (`SSH_MSG_USERAUTH_REQUEST`) for a session the server bound
  (`session-bind@openssh.com`) with a host key luoto pins or the credential names, and never a
  forwarded one. Code in the env can log in with the key while the env runs, but can't read it
  or use it for anything but those hosts. The gate passes the session through unread, so
  neither the repository nor the push guard applies there: what the key reaches at the forge
  is the boundary. Prefer a deploy key; use HTTPS credentials where repo scoping matters.
- **Filesystem.** The sandbox sees only its env's folder and the folders of the repos you add
  to it (a repository's `luoto.toml` names remotes only). It gets a copy, without what git
  ignores in a repository, and never writes to the host; work leaves through git pushes or a
  reviewed `pull`. `pull` reviews changes, holds back risky files in any folder within the pull
  (compared case-insensitively, as macOS and Windows name them), refuses `.git` under any
  spelling, names that collide by case, and paths and symlinks that leave the folder. A
  pulled `.gitignore` decides what later copies leave out, so review its changes. `pull`
  never writes into your home folder or a folder that holds it. With podman on macOS and Windows, envs run only in
  luoto's own VM, which mounts none of your folders (`luoto doctor` checks), so an escape
  doesn't reach your home directory.
- **Repositories cloned inside** (`luoto init <remote>`). The env's workspace is cloned in the
  env, through the gate, as the unprivileged user, with nothing on the host: git brings no
  hooks, submodules aren't fetched and LFS files stay pointers, and `.gitattributes` filters
  need git config the repository can't set. Of the clone, only what detection reads (as the
  dev user, never through a symlink, size-capped, escaped) and its `luoto.toml` reach the host
  before a reviewed `pull --to`, which goes into a new or empty folder unless you confirm.
  Nothing in it runs, installs or is granted before your yes, at two steps of the first `up`:
  its `luoto.toml` (Enter answers no; `--yes` leaves it pending), then what installing would
  do, where mise reads its version files and `mise.toml` (which can run commands in the env).
  Both questions stay open until answered: an `up` cut short or without a terminal (the UI,
  `up --all`) installs nothing. Until then the env has its default presets and the access you
  gave the remote. A shell or editor you open in it starts mise there. git's output on the
  way, the remote's messages included, is shown escaped.
- **Moving an env** (`luoto export`, `luoto import`). An archive holds no secret value, CA
  key or vault token: the config's refs stay refs, read where the env is imported, and import
  makes a new CA, vault token and subnet. The archive is untrusted input (the sandbox wrote
  its volumes, and it may come from elsewhere): each entry is decoded with capped names,
  checked (a plain relative path, nothing under a symbolic link the archive made or a hard
  link to one, hard links within their volume, only files, folders, links and FIFOs) and
  written anew to a container that mounts only the new volume, with no network, in the new
  env's user namespace. Nothing of a volume is unpacked on the host. Before it asks, import
  lists what the config opens: the secret refs it reads on this machine, the hosts each
  credential goes to, secrets put in the sandbox, `isolation`, `image`, `ports`, `[[allow]]`
  rules, `[deps] run` and private git hosts. Until your yes, the folders it names are only
  text, never looked up; it refuses your home folder or one that holds it, and nothing is
  copied in from them afterwards (the workspace came in the archive): they are where `pull`
  writes, which the list says. The `luoto.toml` accepted where it was exported is not
  accepted here: the next `up` reviews it as a new one. Folders, CA files and `file:` refs on
  another machine (`\\server\share`, `/net/<host>`) are refused in any config, since looking
  one up sends your Windows credentials there or mounts it.
- **Isolation.** With podman, dev containers run on gVisor (in luoto's VM on macOS and
  Windows; on Linux once `runsc` is installed): the sandbox's system calls reach gVisor's
  user-space kernel, not the VM's or the host's. In luoto's VM each env's dev container has its
  own user ID range, and none maps to the VM user that owns podman (and so the vault and the
  other envs). `isolation = "container"` opts an env out of gVisor, leaving the VM's kernel as
  the boundary. With Docker, dev
  containers are plain containers, in Docker's VM on macOS and Windows (which shares your
  folders) and on the host on Linux.
- **Control plane.** Policy, CA and credentials reach the gate and vault through the
  runtime's `exec` into a unix socket — there is no admin port. The local UI binds
  127.0.0.1, requires a per-run token, checks Host (DNS rebinding) and Origin, and sets a
  strict CSP.
- **Project settings.** A repository's `luoto.toml` is untrusted input: it applies only in the
  exact version the user accepted, never carries credentials or secret refs, and its rules
  pass the sandbox's own request checks. Its denies only tighten; it can't mute denials,
  which would hide what code from the repository tries. luoto reads it as the unprivileged
  user, refuses symlinks and caps its size. The review spells out what reaches past the gate:
  an `image` is pulled by the runtime outside the gate and becomes the dev container, `ports`
  are published on your machine's 127.0.0.1, `[deps] run` commands run in the env, and its
  repositories are cloned.
- **Self-test.** `luoto up` verifies from inside, whenever a container restarts (skip with
  `--no-selftest`), that raw-IP TCP, UDP and DNS cannot leave before any secret, dotfile or SSH
  key enters the env; an env that fails is stopped.
  `luoto doctor` also checks that host services are unreachable. The test runs inside the
  container it checks, so it confirms the configuration rather than proving isolation.
- **Sandbox output.** Values read back from the sandbox are checked against a strict format
  before the host uses them (the login name in the generated ssh config), and text from it
  — file names, request paths, event messages — is shown with control and bidi characters
  escaped.

## Residual risks

- **Covert channels through allowed hosts.** Anything with write access is an upload path
  (that is what write means). Reads can leak a little through URLs to hosts whose logs an
  attacker can see, and through public counters (package download counts). A `*` read grant
  turns every host into such a channel; luoto asks for confirmation and offers time limits.
- **Model APIs.** Prompts to an allowed model API can carry data, and the API key can be
  spent by anything in the sandbox. Anthropic's, OpenAI's and Gemini's file and batch
  endpoints are denied, and so are requests asking them to fetch a URL or call an MCP server
  (unless `server_tools = true`); the other providers' are not.
- **Azure write access.** With `access = "write"`, code in the sandbox can do on the listed
  subscriptions whatever the identity's roles allow: create resources that reach the internet,
  read keys that `listKeys` returns. The gate refuses, at every scope, the writes that give
  access (role assignments and definitions, PIM requests and policies, federated identity
  credentials, Lighthouse delegations, key vault access policies, `elevateAccess`) unless
  `role_assignments = true`, and template deployments, deployment scripts and stacks, which
  act with all of the identity's roles beyond the listed subscriptions, unless
  `deployments = true`. A key vault's own write still carries its access policies. Azure RBAC
  is the boundary, and with your own `az` login it is your roles: prefer a service principal
  with a role scoped to the env's resource groups. Whatever the identity reads reaches the
  sandbox, Key Vault secret values included. A storage SAS URL (`sig=` in its query) works
  from anywhere, as any secret the sandbox reads does.
- **Cloud API write access.** With `write = true` under a Hetzner, UpCloud, DigitalOcean or
  Cloudflare credential, code in the sandbox can do whatever the token allows, such as create
  a server or Worker that reaches the internet with data from the env. The token's own
  permissions are the limit; UpCloud tokens can't be read-only. A read-only token, for these
  or for Azure, still gives the sandbox whatever it reads: a database's password, a cluster's
  kubeconfig, secret values in Key Vault, each usable from anywhere.
- **Large clones.** A repository cloned in an env can fill the disk of luoto's VM, which the
  other envs and the vault share: their availability, not their isolation.
- **Exhausting the gate.** Code in the sandbox can hold the gate's 1024 connections and
  so stop the env's own traffic, which it could break anyway; other envs have their own gates.
  The event queue, cached certificates and the logs of the gate, the vault and the dev container
  (which root in the sandbox can write to) stay bounded; Docker keeps its daemon's log settings.
- **Container or VM escape.** An exploit that escapes gVisor (or a plain container) lands in
  luoto's VM as the env's own unprivileged IDs; one more kernel exploit there reaches the other
  envs and the vault, which share the VM, and through podman's network helper also the
  services on your machine's loopback, and the helper's API, which can publish a port on your
  machine. On Linux there is no VM: gVisor is the boundary to
  the host, so install `runsc`. With Docker, an escape lands in Docker's VM, which shares your
  folders (on Linux, on the host).
- **Forwarded ports.** A server in the sandbox on ports 1024–32767 is reachable at localhost
  on your machine while it listens. Code in the sandbox can hold a port a host tool expects
  first (a local OAuth callback, say), and the tool's browser redirect then reaches the
  sandbox. Ports already taken on the host are never taken over: a port anything on this
  machine answers on at localhost is skipped. `luoto ui` defaults to a port outside the range,
  so no env can serve a page on its origin. `auto_forward = false` turns this off.
- **Notifications.** A desktop notification shows the host and reason of a request, and a
  denied host, as the sandbox wrote them: control and format characters become spaces, the
  text is capped, and it reaches the notifier as an argument, never as script. Denials notify
  at most twice a minute per env. The UI's browser notifications carry no sandbox text.
- **IDE attachment.** VS Code's host-side client talks to the server in the container; UI
  extensions run on the host. Keep host-side extensions minimal.
- **SSH logins relayed out.** The vault checks that a session is bound to a pinned host key,
  not that it runs through the env's tunnel. While the env runs, sandbox code can pass it a
  session someone else opened to that host from anywhere and hand back the signed login, so
  that party logs in with the key too. The key's reach at the forge is the limit: prefer a
  deploy key.
- **Risky pulls.** `luoto pull --include-risky` writes the sandbox's symlinks. Each target is
  checked to stay in the folder as written, but it can lead through another link (one on the
  host, or one the same pull writes) that points elsewhere.
- **Social engineering.** Access requests are written by code in the sandbox. Read the host
  and access, not the reason; grant less than asked where that will do (`luoto approve --read`,
  `--path`). A request can't name an address range or a private address, and one for a port
  is an uninspected tunnel to that host and port, never 80 or 443. An install request names a
  package or toolchain the gate has checked to be a plain name; approving it runs that
  package's install scripts as root inside the env (still the sandbox), and its downloads take
  the env's usual presets and install windows.
- **Env archives.** A `luoto export` file holds the env's whole workspace and home: work not
  pushed, files the sandbox wrote, shell history and agents' logins, which work from it. It is
  written readable only by you; keep it as a secret and delete it once imported. Importing
  someone else's adopts their config, which decides which of your secrets `up` reads and which
  hosts get them, and their home and workspace, which run in the env: read what import lists.
- **Images.** Release images are pinned by digest in the binary; images from
  `luoto setup --build` are as trustworthy as your source tree.
- **Install windows.** The project's version files, which the sandbox controls, decide which
  toolchains `luoto up` installs, and so which presets it grants for the install (only from
  luoto's own preset data; other hosts need your yes). While a grant is open, any code in the
  env can use it. The default `toolchains` preset keeps vendor download servers readable
  permanently; downloading more code is not a new risk inside the sandbox. GitHub release
  files, which anyone can publish, are readable only in install windows unless the env has
  `github-releases`, `terraform` or `opentofu`.
- **Relays.** The Go module proxy and checksum database fetch from whatever host a module path
  names, so a path the sandbox writes is a request to a domain it chooses. The `go` preset
  opens them only for modules on code hosts and on domains the Go project, Google, the CNCF
  and Uber run, and gopkg.in; allowing another host's paths opens a request to that host.
- **`sandbox_secrets`** and `login_inside` provider logins put credentials inside the sandbox
  by design. An agent added without a credential logs in inside where its provider allows it,
  so its session is in the sandbox until you configure a credential instead.

## Reporting

Report vulnerabilities privately to the maintainer rather than in a public issue.
