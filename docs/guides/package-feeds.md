# Private package feeds

A private feed installs in an env with your token, which the gate adds on the way out: code
in the env never sees it. The project keeps its settings as they are, with the feed's URL and
no credential in them. luoto knows Azure DevOps, GitHub Packages, and self-hosted Gitea,
Forgejo and GitLab.

## Add a feed

```sh
luoto feed add https://pkgs.dev.azure.com/acme/web/_packaging/packages/pypi/simple/
luoto feed add @acme:registry=https://npm.pkg.github.com
luoto feed add https://git.acme.internal/api/packages/acme/pypi/simple
luoto feed add https://gitlab.acme.internal/api/v4/projects/12/packages/npm/
```

The URL is the feed's as the project's settings have it (`pip.conf`, a uv index, `.npmrc`,
`nuget.config`, a Maven or cargo registry), in any of its protocols; luoto tells the service
from it. When the env has no token for that service yet, luoto asks where it is kept: pasted
into your keychain or 1Password, or a reference. Without a terminal, `--token <ref>` names it.
A running env's gate takes the feed at once; the placeholders below reach shells started
after it (a first feed, in a shell already open, waits for a new one). `luoto feed` lists the
env's feeds and
`luoto feed rm <feed>` removes one.

What each service's token reaches, with GET and HEAD only (installs, never a publish):

| Service | Token | Reaches |
| --- | --- | --- |
| Azure DevOps | a PAT with **Packaging (Read)** | every feed of the feed's organization |
| GitHub Packages | a classic token with **read:packages** | the owner's packages on GitHub's npm, Maven, NuGet and RubyGems registries |
| Gitea, Forgejo | a token with **read:package** | the owner's packages |
| GitLab | a personal, group or project access token with **read_api** | the project's packages; for a group's or the instance's endpoints, every project's |

## Azure DevOps

```toml
[credentials.azure_devops]
token = "op://Dev/ado-feeds/token"
feeds = ["acme/web/packages"]
```

`acme/web/packages` (`acme/packages` for a feed of the organization) names a feed too. Make
the PAT at `dev.azure.com/acme/_usersSettings/tokens`. An env whose Azure DevOps credential
already has repos uses its token for the feeds too, so that PAT needs Packaging (Read) as well
as Code.

- The token goes, as basic auth, on every feed of the organization, on `pkgs.dev.azure.com`
  and `acme.pkgs.visualstudio.com`: a feed's index links its files by the project's and the
  feed's IDs, not their names.
- A package the feed stores downloads from Azure Storage, at a signed URL on a host of its
  own. The gate lets the env reach only the URL the feed sent it to, for reads, for ten
  minutes ([SECURITY.md](../../SECURITY.md#what-holds-the-line)).
- A feed with upstream sources (PyPI, npm, NuGet, Maven, crates.io) passes their packages
  through. The first install of one the feed hasn't stored yet saves it into the feed, which
  takes the **Feed and Upstream Reader (Collaborator)** role on the feed; with Reader it
  fails with 401 or 403, outside luoto too.

## GitHub Packages

```toml
[[credentials.github]]
token = "op://Dev/gh-packages/token"
feeds = ["acme"]
```

An owner's packages, on every registry of theirs: `https://npm.pkg.github.com/acme`, the
`.npmrc` line `@acme:registry=https://npm.pkg.github.com`, `https://maven.pkg.github.com/acme/web`,
`https://nuget.pkg.github.com/acme/index.json` and `https://rubygems.pkg.github.com/acme` all
name the same feed. GitHub's package registries take a classic token (or the GitHub CLI's
own login, `gh auth token`), not a fine-grained one or an App, so feeds get a credential of
their own beside the one for repos; more owners go in its `feeds`.

- The token goes on the owners' paths of the four registries; github.com and its API stay as
  the env's repos make them.
- Downloads redirect to one host per registry (`pkg-npm.githubusercontent.com`,
  `github-registry-files.githubusercontent.com`, and two on Azure Storage for NuGet and
  RubyGems), reached as above: only at the URL the registry sent, for reads, ten minutes.

## Gitea and Forgejo

```toml
[[credentials.git]]
host = "git.acme.internal"
token = "op://Dev/gitea-packages/token"
private = true
ca = "~/certs/acme-ca.pem"
feeds = ["/api/packages/acme"]
```

A feed is an owner's (`…/api/packages/acme/<type>/…`), every type of theirs. A host that
already has a `[[credentials.git]]` for its repos keeps one, with its token; the token goes
to the feeds as `Authorization: Bearer`, which every package endpoint takes.

## GitLab

```toml
[[credentials.git]]
host = "gitlab.acme.internal"
token = "op://Dev/gitlab-packages/token"
feeds = ["/api/v4/projects/12"]
```

A project's feed (`…/api/v4/projects/12/packages/…`) is named by the project's ID, which its
page shows under the name; the path form (`acme%2Fweb`) is refused, as the gate refuses an
escaped slash where it adds a credential. A group's endpoint (`…/api/v4/groups/7/-/packages/…`)
and the instance's (`…/api/v4/packages/npm/`) link their files to each project's own path, so
their token reaches every project's packages the token can read. The token goes as
`Authorization: Bearer` (GitLab's npm endpoints refuse basic auth), so a personal, group or
project access token works; a deploy token, which GitLab takes only as basic auth or its own
header, doesn't.

## On a company network

A self-hosted instance often runs on a private network and with a certificate an internal CA
signed:

- A host that resolves only to private addresses here is reached there (`private = true`),
  as luoto's VM or Apple's container would otherwise never dial it. `luoto feed add` sets it
  for such a host.
- `ca` names the CA certificate (a PEM file on this machine) the gate checks the host's
  certificate against, for that host only; `luoto feed add --ca <file>` sets it, and a
  terminal asks for a new private host.
- An instance whose object storage redirects downloads (GitLab without proxied downloads,
  Gitea with direct serving) sends them to its storage host, which `luoto egress` then shows
  refused. Name it exactly: `luoto feed add <feed URL> --storage-host minio.acme.internal`
  (`storage_hosts` in the credential). The env then reaches only the URL a feed sent it to,
  for reads, ten minutes, on the private network when the credential is, and the
  credential's `ca` covers that host too. Don't allow the storage host with a rule: that
  opens every object on it. Never name a public registry (`registry.npmjs.org`, `pypi.org`)
  there: GitLab redirects a package it lacks to one, so the env would pick the URL.

## In the project

The project's settings stay as they are: the feed's URL, and no credential. Where a client
sends nothing without a login of its own, the env gives it a placeholder, which the gate
replaces with your token:

- uv with `authenticate = "always"` on the index (and pip and poetry, which read it too)
  finds a netrc login for the feeds' hosts: `NETRC` names luoto's, so a `~/.netrc` of your
  own in the env isn't read. A keyring setup (`keyring-provider = "subprocess"`,
  `VssSessionToken@` in the URL) needs no keyring in the env.
- cargo, for a registry that requires authentication, gets a token from a credential
  provider luoto sets (`CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS`), after a real token in a
  `CARGO_REGISTRIES_<NAME>_TOKEN` variable or `credentials.toml`, which wins. A provider list
  in your own `.cargo/config.toml` is replaced by it.
- npm needs nothing: an `.npmrc` that reads its token or password from a variable works with
  the variable unset.

## When it fails

- `luoto egress` shows a denial with `→ a GitLab feed: luoto feed add …` (or another
  service): the env has no credential for the feed yet; uv calls it `403 Forbidden` and asks
  to check the credentials.
- 401 from the feed: the token lacks the scope above, has expired, or belongs to another
  account; `luoto vault status` shows whether the vault holds it.
- A self-hosted host times out: `private = true` is missing, or the network or VPN that
  reaches it is down on this machine. A certificate error: `ca` is missing or names another
  CA.
- Azure DevOps answers 403 when installing a package for the first time: the upstream role
  above.
