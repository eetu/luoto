# Configuration

The overview is the [README](../README.md); step by step, the [guides](guides/README.md).

`~/.config/luoto/envs/<name>.toml` (on Windows, `~/.config/luoto` is `%APPDATA%\luoto\config`
throughout). `luoto edit -e <name>` opens it in `$EDITOR` and applies it when you save; edited
any other way, it applies at the next `luoto up`. The UI adds and removes rules. `version` in
a config file is its format (1 when missing): luoto reads older formats and refuses a file
from a newer luoto.

```toml
presets = ["debian", "github", "github-releases", "toolchains", "npm"]   # see ../shared/presets/
agents = ["claude"]           # with options: [agents.claude] tables (guides/agent-settings.md)
ports = [5173]                # published by the gate itself (servers listening on all interfaces)
# isolation = "container"     # default gVisor; this shares the VM's kernel, builds ~1.6× faster
# idle_stop = "2h"            # default 30m; "off" disables
# auto_forward = false        # don't forward listening ports to localhost here

[tools]                       # default toolchains; the project's own version files win
node = "lts"

[workspace]
dir = "/Users/me/dev/web"     # the project folder, copied in on the first `up`
# url = "acme/web"            # instead of `dir`: a remote cloned into the env (`branch = "dev"`)

[[allow]]
host = "docs.rs"
paths = ["/serde/**"]         # /serde and below; `*` stays within one path segment
expires = "2026-12-01T00:00:00Z"
# idle = "2h"                 # how long it may sit silent before the gate closes it (see Limits in the README)

[egress]                      # open: any HTTP(S) host no rule allows (`luoto egress open`)
open_until = "2026-12-01T15:00:00Z"   # or `open = true`: until you remove it

[[deny]]                      # refused whatever allows it, a preset included
host = "registry.npmjs.org"
paths = ["/-/npm/v1/security/**"]   # matched in any case; none: the whole host
methods = ["POST"]            # none: every method

[[mute]]                      # still denied, but left out of `luoto egress` and the UI
host = "telemetry.example.com"   # `paths` mutes only those

[credentials.github]          # a GitHub App: tokens minted per env, scoped to these repos
app_id = "123456"             # (or `token = "<ref>"` for a fine-grained token)
installation_id = 7890123
private_key = "op://Dev/luoto-github-app/private key"
repos = ["owner/repo"]        # read and write: pushes, pull requests
read_repos = ["owner/lib"]    # fetched and read only (an App mints a read-only token for them)
permissions = { contents = "write", pull_requests = "write" }
protected_branches = ["main"]

[credentials.azure_devops]    # Azure DevOps git over HTTPS
token = "op://Dev/ado/pat"    # a PAT with Code (Read & write)
repos = ["myorg/Project/repo"]   # `org/project/repo`, or the clone URL
# read_repos = ["myorg/Project/lib"]   # fetched only
protected_branches = ["main"]

[credentials.azure]           # Azure: az, terraform and the SDKs see a managed identity
subscriptions = ["<subscription id>"]   # Resource Manager paths the env may reach
access = "read"               # GET, HEAD, OPTIONS; "write": every method, as your Azure role allows
# tenant = "contoso.onmicrosoft.com"    # required with a service principal; else az's current
# key_vaults = ["kv-prod"]    # data planes, by name: read or write as `access` says
# storage_accounts = ["acct"] # its blob, queue, table, file and dfs hosts
# graph = true                # Microsoft Graph, read-only
# role_assignments = true     # under write, also what gives access: role assignments and
                              # definitions, PIM requests and policies, federated identity
                              # credentials, Lighthouse, key vault access policies, elevateAccess
# deployments = true          # under write, also template deployments, deployment scripts and
                              # stacks, which act with all of the identity's roles, anywhere
# client_id = "<app id>"      # a service principal instead of your `az login` on this machine
# client_secret = "op://Dev/azure-sp/secret"

[[credentials.git]]           # git over HTTPS on any other host: GitLab, Forgejo, Gitea, …
host = "gitlab.example.com"   # `host:port` for another port
token = "op://Dev/gitlab/token"
username = "oauth2"           # sent with the token: GitLab takes oauth2; Forgejo, the token's owner
repos = ["group/api"]         # pushes, under the same guard; `read_repos` to fetch only
# private = true              # a self-hosted one on a private network
# ca = "~/certs/corp-ca.pem"  # the internal CA its certificate is signed by

[credentials.ssh]             # git over SSH: the vault keeps the key and signs logins
key = "op://Private/github-ssh/private key?ssh-format=openssh"
hosts = ["github.com"]        # GitHub's and Azure DevOps' host keys are pinned
# host_keys = ["git.example.com ssh-ed25519 AAAA…"]   # known_hosts lines for other hosts
# github_port = 443           # GitHub over ssh.github.com:443, where port 22 is blocked

[credentials.anthropic]       # or openai, openrouter, gemini, mistral, groq, copilot
oauth_token = "op://Private/claude-code/token"

[credentials.hetzner]         # or upcloud, digitalocean, cloudflare: their CLI and terraform
token = "op://Dev/hcloud-web/token"
# write = true                # every method (apply); without it GET, HEAD and OPTIONS only

[credentials.custom.stripe]   # any API: inject a header on one host
host = "api.stripe.com"
secret = "op://Dev/stripe-test/key"
placeholder_env = { STRIPE_API_KEY = "sk_test_luoto_placeholder" }   # what the code reads
# header = "authorization", format = "Bearer {secret}" are the defaults
write = true

[sandbox_secrets]             # deliberately exposed to code in the sandbox (env vars)
DATABASE_URL = "op://Dev/local-db/url"

[env]                         # plain environment variables in the env's shells
RUST_LOG = "debug"

[resources]                   # the dev container's share of the VM; not with gVisor on podman
cpus = 4
memory = "8g"

[deps]                        # installed in the env on `up`
system = ["postgresql-client"]                  # apt / apk / dnf, whichever the image has
run = ["git config --global pull.rebase true"]  # as you, in your home; keep them repeatable
hosts = ["dl.k8s.io"]         # extra hosts readable only while installs run
```

`config.toml` takes `[tools]`, `[deps]`, `[[deny]]`, `[[mute]]`, `idle_stop` and
`auto_forward` too, for every env, and `[agents.<name>]` options (`model`, `effort`, `args`,
`headless_args`) for every
env that has that agent; an env's own, and its `luoto.toml`'s, come on top. Credentials go
only in each env's own file. `notifications = false` there turns desktop notifications off.
`runtime = "container"` there (`luoto setup` offers it) runs envs on Apple's `container`
([install.md](install.md)).

A `[[deny]]` beats every allow: a preset's, a rule's, an approved request's. It applies to the
HTTP(S) the gate reads: a tunnel rule can't cover a denied host, and SSH to
`[credentials.ssh] hosts` doesn't pass through it. A `[[mute]]` is
for telemetry you keep denied: its denials are still recorded, but stay out of `luoto egress`,
the UI and the offers to allow them; `luoto egress --all` shows them.

Secret refs: `op://…` (1Password CLI, desktop or service account), `vault://mount/path#field`
(OpenBao / HashiCorp Vault), `keyring:service/account` (OS keychain), `env:NAME`, `file:path`.
In 1Password, a token is an API Credential's `credential` field, a Password's `password`, or a
Secure Note's `notesPlain` holding the token alone. With several accounts in the app,
`?account=<account ID>` on a ref reads it from that one (`op account list` shows the IDs;
`[sources.op] account` sets the default). A sign-in address works where only one account has
it; every personal and family account signs in at `my.1password.com`. When you give a
reference, the wizard can browse 1Password for it: account, vault and item, the field from the
item's kind, or one you type: it lists names only, and 1Password lists custom fields only
with their values. The refs it writes name the vault and item by ID, so a rename doesn't
break them. Sources are configured in `~/.config/luoto/config.toml`. `[credentials.azure]`
reads your `az` login itself, with no ref.

`[sandbox_secrets]` are resolved on your machine at `up` and written to a memory-only file in
the dev container that every shell loads; they leave with the container. Anything that only
needs a token in an HTTP header belongs under `[credentials.custom.<name>]` instead, where the
sandbox never sees it.

A GitHub App for luoto needs only repository permissions such as Contents and Pull requests;
luoto refuses Workflows, Actions, Secrets and Administration ([why](../SECURITY.md#what-holds-the-line)).
A token or App installation reaches one owner's repos; for another owner's, write
`[[credentials.github]]` once per owner instead of `[credentials.github]`. Each repo's requests
get the credential that lists it, and GraphQL (`gh pr create`) the first one that may write,
so the others open pull requests over REST (`gh api repos/<owner>/<repo>/pulls`).

An Azure DevOps credential lets the env fetch and push its repos over HTTPS. Remotes keep
working as they are: SSH ones (`git@ssh.dev.azure.com:v3/…`, or a host alias from your
`~/.ssh/config` that the folder's remotes use) and `*.visualstudio.com` ones are rewritten to
`https://dev.azure.com` in the env. Pull requests for the repos in `repos` go over its REST
API by the repository's name (`…/_apis/git/repositories/<repo>/pullrequests`): opened,
commented on, their title, description, draft state and target changed; completing them, and
votes, stay with you. `az repos pr` addresses repos by ID, which the gate doesn't match.

An Azure credential gives the env a managed identity: the gate answers the instance metadata
service (`169.254.169.254`) itself, so `az` (logged in by `up`), terraform's azurerm
(`ARM_USE_MSI`) and the SDKs' `DefaultAzureCredential` work unchanged. The token they get is a
placeholder with the claims tools read; the gate puts the real token on Resource Manager
requests for the listed subscriptions and on the key vaults, storage accounts and Graph you
name, with the methods `access` allows there. It comes from your `az login` on this machine,
refreshed before it expires, or from a service principal whose secret the vault keeps and
mints with ([guide](guides/azure.md)).

A Hetzner, UpCloud, DigitalOcean or Cloudflare credential puts its API token on that cloud's
API for its CLI and terraform provider, which see a placeholder; the token goes with GET, HEAD
and OPTIONS only, unless `write = true` ([guide](guides/cloud-apis.md)).

A `[[credentials.git]]` works with any forge, as git speaks the same protocol to all: the gate
adds the token to the listed repos' git requests only and guards pushes as on GitHub. It
covers git, not the forge's API (merge requests), which a `[credentials.custom]` can reach.
Without a token it lists public repos to fetch. Its host's SSH remotes go over HTTPS with it.

An SSH credential lets git use SSH remotes as they are, to `hosts` on port 22 only;
`github_port = 443` sends GitHub's to `ssh.github.com:443` instead, for networks that block 22.
GitHub SSH remotes go to HTTPS when github.com isn't in `hosts`, as do Azure DevOps ones with
an Azure DevOps credential; other forges' SSH remotes work only through `hosts`. SSH sessions are
unscoped by repository, so use a deploy key where that matters
([SECURITY.md](../SECURITY.md#what-holds-the-line)). From 1Password, the key's ref is
`op://<vault>/<item>/private key?ssh-format=openssh`.

## Toolchains

The project chooses its toolchains, as it would on your machine: luoto runs
[mise](https://mise.jdx.dev) (asdf-compatible) in the env and has it read the project's
`mise.toml`, `.tool-versions`, `.node-version`/`.nvmrc`, `.python-version`, `.java-version`,
`.ruby-version`, `go.mod`, `rust-toolchain.toml` and `package.json` (`packageManager`, for
yarn and pnpm). Anything in mise's registry or an asdf/vfox plugin installs: node, python,
java, go, rust, php, ruby, terraform, ….

Terraform and OpenTofu are found by `.terraform-version`, `.opentofu-version`, `main.tf`,
`versions.tf`, `terraform.tf` (or `main.tofu`, `versions.tofu`) and `.terraform.lock.hcl`,
whose providers' registry tells the two apart; an exact `required_version` sets the version.
Their presets (`terraform`, `opentofu`) open the provider and module registry and the
providers' GitHub release downloads. Azure credentials for `plan` and `apply` come from
`[credentials.azure]` ([guide](guides/azure.md)); Hetzner, UpCloud, DigitalOcean and
Cloudflare ones from `[credentials.<cloud>]` ([guide](guides/cloud-apis.md)); AWS and
Google Cloud ones aren't handled yet ([ROADMAP.md](../ROADMAP.md)).

- `luoto init` reads the folder first and shows what it found (toolchains with the file that
  pins each, presets for the registries it uses) before creating anything. It looks three
  levels into subfolders (a monorepo's `frontend/` and `backend/`), skipping ignored,
  dependency, build and hidden folders. A runtime the project needs but pins nowhere gets a
  default: Rust stable, node LTS or Python 3.14, and Java 17 for a Python dependency that
  runs on it (pyspark). `c` goes through the settings one at a time
  (isolation, presets, toolchains, agents and their credentials, ports); `--preset` and
  `--tool node=24` override what it detected. A new or empty folder has nothing to detect, so
  `init` starts with those settings; `luoto up` in a folder without an env offers the same.
  `luoto init` again in an env's folder offers what the project suggests now and the env lacks
  (it only adds).
- `up` installs whatever the project now pins and the env lacks, in every folder that pins
  something (checked offline, so it is quick when nothing changed). `[tools]` in the env or
  `config.toml` gives defaults for tools the project doesn't pin; your own `~/.config/mise`
  (via `~/.config/luoto/home/`) sits in between.
- A runtime the project names only in prose, such as Java for a pyspark project, goes in with
  `luoto init --tool java=21` (or `java = "21"` under the env's `[tools]`): mise installs
  Temurin 21, and `corretto-21` or `zulu-21` pick another vendor. A committed `.java-version`
  or `mise.toml` gives it to every clone.
- Inside the env, you or an agent add a language with `mise use go@1.23` (it writes
  `mise.toml`). The `toolchains` preset, on by default, lets runtime downloads through: mise
  metadata and the vendors' download servers, read-only. Without it, `up` grants it only while
  installing. Files from GitHub releases (Python, Java, Bun, pnpm, aqua tools, npm packages'
  prebuilt binaries) come through the `github-releases` preset, also on by default; without
  it, only while luoto installs: pin the version and run `up`, or `sandbox request --tool
  python@3.13` from the env.
- The `go` preset opens the module proxy and checksum database, which fetch from whatever host
  a module path names, only for modules on code hosts and well-known module domains
  ([the list](../shared/presets/go.toml)). Another host's modules are denied by path; allowing
  one takes `luoto allow proxy.golang.org --path '/<host>/**'` and
  `luoto allow sum.golang.org --path '/lookup/<host>/**'`.
- When an install is denied a host the presets don't know, `up` lists it and offers to allow
  it for installs (saved to `[deps] hosts`).

No runtime is baked into luoto-base. `npm i -g` and `pipx` install into `~/.local/bin`, which
persists with the home volume, as do mise's toolchains.

Verified by hand, from `luoto init` to a build or test run in the env: npm, Yarn 1 and 4, pnpm,
pip, uv, Poetry, Cargo, Go, Java (pyspark with `--tool java=21`), Terraform and OpenTofu
(`init` and `plan`), and a Rust + Yarn + uv monorepo. Other toolchains mise installs are untested ([ROADMAP.md](../ROADMAP.md)).

## Shell

`luoto shell` (and editor terminals over SSH) start the dev user's login shell: your host's
own (fish, zsh or bash), or `shell = "zsh"` in `config.toml` or an env's config. luoto-base
ships defaults for all three: fzf (ctrl-r history, ctrl-t files, alt-c cd), mise, completion,
and for zsh autosuggestions, syntax highlighting and a `user@env` prompt with the git branch.
They are system-wide, so your own rc files override them.

Your own config goes in `~/.config/luoto/home/`: `luoto up` copies it into every env's home
(symlinks followed, `.git` skipped), e.g. `.zshrc`, `.config/fish/`, `.config/starship.toml`,
`.gitconfig`. Keep these files on the host: each `up` overwrites the copies in the env. It is
a separate folder on purpose: rc files tend to export tokens, and everything there is readable by
code in the sandbox. luoto also sets your git `user.name` and `user.email` in each env. Install
plugins and prompts inside the env (through the gate) rather than copying binaries in.

## Editors

Editors connect over SSH through the runtime (no network port). luoto keeps the host entries
in its own file, `~/.config/luoto/ssh_config`, updated on `luoto up`/`rm`; add one line at the
top of `~/.ssh/config` and every env is reachable as `luoto-<env>`:

```text
Include ~/.config/luoto/ssh_config
```

`luoto open` launches your editor on `luoto-<env>:/workspace`: `--with zed|code|cursor`, or
`editor = "zed"` in `config.toml` (default: the first one installed). The editor's window runs
on your machine; its language servers, extensions, tasks and terminals run in the sandbox.
The first time, luoto prints a one-time editor setting so the editor installs its remote
server from your machine instead of the sandbox downloading it (Zed's
`upload_binary_over_ssh`, VS Code's and Cursor's `remote.SSH.localServerDownload`).
`--with ssh` prints the connection for anything else (JetBrains Gateway, Neovim). Editors are
data: one TOML file each in `shared/editors/`. Install extensions in the remote window, where
they are sandboxed; keep host-side ones to themes and keymaps.

The sandbox side refuses SSH agent forwarding and reverse port forwards, so a session can't
reach back to your machine. Don't open the env's folder directly in a host editor: its
language servers would run project code outside the sandbox.
