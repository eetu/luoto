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
  (per-env CA, key only in the gate) and checked against a default-deny policy of host, port,
  method, path, body size and expiry. Non-HTTP TCP goes nowhere except through tunnel rules
  you grant (`luoto allow --tunnel`, a host and port) and SSH to the hosts an SSH credential
  names, on port 22; both pass through uninspected. UDP goes nowhere. DNS is answered locally
  with fake addresses and never forwarded. Destinations are resolved by the gate only after a
  request is allowed, every resolved address is checked against private, loopback,
  link-local, CGNAT and host-gateway ranges (including IPv4 inside IPv6), and the gate
  connects to exactly the vetted address. Host, SNI and CONNECT authority must agree.
- **Path matching.** A path is matched and forwarded in one canonical form; dot segments, empty
  segments and backslashes are refused.
- **Secrets.** Root secrets live only in the vault's memory, loaded from the host's secret
  store at unlock and wiped by `luoto vault lock` or a VM restart. Each gate authenticates to the
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
- **Azure DevOps writes.** The PAT goes only on the granted repositories' git paths, and pushes
  pass the same guard as on GitHub. A PAT reaches its whole organization, so the gate's paths
  are the only repository boundary; its REST API is not reachable. Configure branch policies
  in Azure DevOps as well.
- **Git over SSH.** The private key stays in the vault, which answers the env's ssh-agent: it
  signs only a public-key login (`SSH_MSG_USERAUTH_REQUEST`) for a session the server bound
  (`session-bind@openssh.com`) with a host key luoto pins or the credential names, and never a
  forwarded one. Code in the env can log in with the key while the env runs, but can't read it
  or use it for anything but those hosts. The gate passes the session through unread, so
  neither the repository nor the push guard applies there: what the key reaches at the forge
  is the boundary. Prefer a deploy key; use HTTPS credentials where repo scoping matters.
- **Filesystem.** The sandbox sees only its env's folder. It gets a copy and never writes to
  the host; work leaves through git pushes or a reviewed `pull`. `pull` reviews changes, holds
  back risky files (compared case-insensitively, as macOS and Windows name them), refuses
  `.git` under any spelling, names that collide by case, and paths and symlinks that leave the
  folder. With podman on macOS and Windows, envs run only in luoto's own VM, which mounts none
  of your folders (`luoto doctor` checks), so an escape doesn't reach your home directory.
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
  pass the sandbox's own request checks. luoto reads it as the unprivileged user, refuses
  symlinks and caps its size.
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
  endpoints are denied; the other providers' are not.
- **Container or VM escape.** An exploit that escapes gVisor (or a plain container) lands in
  luoto's VM as the env's own unprivileged IDs; one more kernel exploit there reaches the other
  envs and the vault, which share the VM. On Linux there is no VM: gVisor is the boundary to
  the host, so install `runsc`. With Docker, an escape lands in Docker's VM, which shares your
  folders (on Linux, on the host).
- **Forwarded ports.** A server in the sandbox on ports 1024–32767 is reachable at localhost
  on your machine while it listens. Code in the sandbox can hold a port a host tool expects
  first (a local OAuth callback, say), and the tool's browser redirect then reaches the
  sandbox. Ports already taken on the host are never taken over: a port anything on this
  machine answers on at localhost is skipped. `luoto ui` defaults to a port outside the range,
  so no env can serve a page on its origin. `auto_forward = false` turns this off.
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
  and access, not the reason.
- **Images.** Release images are pinned by digest in the binary; images from
  `luoto setup --build` are as trustworthy as your source tree.
- **Install windows.** The project's version files, which the sandbox controls, decide which
  toolchains `luoto up` installs, and so which presets it grants for the install (only from
  luoto's own preset data; other hosts need your yes). While a grant is open, any code in the
  env can use it. The default `toolchains` preset keeps vendor download servers readable
  permanently; downloading more code is not a new risk inside the sandbox.
- **`sandbox_secrets`** and `login_inside` provider logins put credentials inside the sandbox
  by design.

## Reporting

Report vulnerabilities privately to the maintainer rather than in a public issue.
