# Private package feeds

An Azure DevOps feed installs in an env with your personal access token (PAT), which the gate
adds on the way out: code in the env never sees it. The project keeps its settings as they
are, with the feed's URL and no credential in them.

## Add a feed

```sh
luoto feed add https://pkgs.dev.azure.com/acme/web/_packaging/packages/pypi/simple/
```

The URL is the feed's as the project's settings have it (`pip.conf`, a uv index, `.npmrc`,
`nuget.config`, a Maven or cargo registry), any of its protocols, or `acme/web/packages`
(`acme/packages` for a feed of the organization). When the env has no Azure DevOps credential
yet, luoto asks where the PAT is kept: pasted into your keychain or 1Password, or a reference.
Make one at `dev.azure.com/acme/_usersSettings/tokens` with **Packaging (Read)**. Without a
terminal, `--token <ref>` names it. A running env takes the feed at once.

The env's file then has:

```toml
[credentials.azure_devops]
token = "op://Dev/ado-feeds/token"
feeds = ["acme/web/packages"]
```

An env whose Azure DevOps credential already has repos uses its token for the feeds too, so
that PAT needs Packaging (Read) as well as Code. `luoto feed` lists the env's feeds and
`luoto feed rm <feed>` removes one.

## What the env reaches

- The token goes, as basic auth, on every feed of the feeds' organizations, on
  `pkgs.dev.azure.com` and `acme.pkgs.visualstudio.com`, with GET and HEAD only: installs,
  never a publish. Every feed of the organization, because a feed's index links its files by
  the project's and the feed's IDs, not their names; a PAT with only Packaging (Read) keeps it
  to reading.
- A package the feed stores downloads from Azure Storage, at a signed URL on a host of its
  own. The gate lets the env reach only the URL the feed sent it to, for reads, for ten
  minutes ([SECURITY.md](../../SECURITY.md#what-holds-the-line)).
- A feed with upstream sources (PyPI, npm, NuGet, Maven, crates.io) passes their packages
  through. The first install of one the feed hasn't stored yet saves it into the feed, which
  takes the **Feed and Upstream Reader (Collaborator)** role on the feed; with Reader it
  fails with 401 or 403, outside luoto too.

## In the project

The project's settings stay as they are: the feed's URL, and no credential. Where a client
sends nothing without a login of its own, the env gives it a placeholder, which the gate
replaces with your PAT:

- uv with `authenticate = "always"` on the index (and pip and poetry, which read it too)
  finds a netrc login for the feed's hosts: `NETRC` names luoto's, so a `~/.netrc` of your
  own in the env isn't read. A keyring setup (`keyring-provider = "subprocess"`,
  `VssSessionToken@` in the URL) needs no keyring in the env.
- cargo, as the feed's registry requires authentication, gets a token from a credential
  provider luoto sets (`CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS`).
- npm needs nothing: an `.npmrc` that reads the password from a variable works with the
  variable unset.

## When it fails

- `luoto egress` shows `no rule allows pkgs.dev.azure.com → an Azure DevOps feed: luoto feed
  add …`: the env has no credential for the feed yet; uv calls it `403 Forbidden` and asks to
  check the credentials.
- 401 from the feed: the PAT lacks Packaging (Read), has expired, or belongs to another
  organization; `luoto vault status` shows whether the vault holds it.
- 403 from the feed when installing a package for the first time: the upstream role above.
