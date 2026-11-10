# Several repositories in one env

An env's folder can have related repositories beside it, each at `/workspace/<name>` in the
env, so an agent sees them together and changes them in one session. Set them up from the
command line, from a file the team commits, or both.

## From the command line

```console
$ luoto init ~/dev/platform --repo ~/dev/api --repo acme/web
```

`--repo` takes a folder (it starts with `/`, `~` or `.`, or exists), copied in on the first
`up` and pulled back to it, or a remote (`owner/repo` on GitHub, an `https://` or `ssh://`
URL, or `user@host:path`), cloned in the env through the gate. The repo's name is the last
part of its path or URL. For an env that exists:

```console
$ luoto repo add ~/dev/lib
$ luoto repo add https://dev.azure.com/acme/Platform/_git/infra --name infra --branch main
$ luoto repo list
$ luoto repo rm lib
```

They land in the env's config, which you can also edit (`luoto edit`):

```toml
[workspace]
dir = "/Users/me/dev/platform"

[workspace.repos.api]
dir = "/Users/me/dev/api"       # a host folder

[workspace.repos.web]
url = "acme/web"                # a remote
branch = "develop"              # default: the remote's
```

## From a launchpad

A launchpad is a repository that holds a `luoto.toml` listing the remotes, and usually a
`mise.toml` with the toolchains: [examples/launchpad](../examples/launchpad/). A clone of it and
`luoto init` give every developer the same env:

```console
$ git clone https://github.com/acme/platform && cd platform && luoto init
```

Or with nothing on your machine: `luoto init acme/platform` clones the launchpad inside the
env, and its repos once you accept its `luoto.toml` there
([untrusted-repo.md](untrusted-repo.md)).

`luoto.toml` is reviewed before it applies, like any repository's, and names remotes only,
never your folders. Presets, agents, ports, `[deps]`, `allow` rules and denies can go there
too; `luoto project suggest` drafts one from an env that works.
`mise.toml` at the launchpad applies to every repo under it; a repo's own version files win.
Once `up` has cloned the repos, it offers the presets and toolchains their files suggest (the
`npm` preset for a `package.json`), as `luoto init` does for a folder.

## Both

A local checkout replaces the launchpad's clone of the same name, as the env's own repo of a
name always wins:

```console
$ luoto init --repo ~/dev/api
```

## Credentials

On a terminal, `luoto up` (and `luoto repo add`) asks what the env may do with each repo no
credential covers: fetch it if it is public, read it, or read and push, with a token kept in
your keychain, 1Password or wherever a reference points; one credential per GitHub owner and
per Azure DevOps organization. It writes them into the env's config, and `luoto repo auth
<repo>` asks again for one; without a terminal it prints them for you to add. Each lists the
repos it may write (push, pull requests; the gate refuses protected branches) and those it may
only read:

```toml
[[credentials.github]]              # one per GitHub owner: a token reaches one owner's repos
token = "op://Dev/github-acme/token"
repos = ["acme/api", "acme/web"]
read_repos = ["acme/secrets-schema"]

[[credentials.github]]
token = "op://Dev/github-acme-oss/token"
repos = ["acme-oss/design-system"]

[credentials.azure_devops]
token = "op://Dev/ado/pat"          # PAT with Code (Read & write)
repos = ["acme/Platform/infra"]
```

Any other forge (GitLab, Forgejo, Gitea, Bitbucket, a self-hosted one) gets a
`[[credentials.git]]` per host, which `up` asks for the same way:

```toml
[[credentials.git]]
host = "git.acme.internal"
token = "op://Dev/forgejo/token"
username = "me"                     # GitLab takes oauth2; Forgejo and Gitea, the token's owner
repos = ["platform/api"]
private = true                      # on a private network
ca = "~/certs/acme-ca.pem"          # its internal CA
```

When it asks for a token, the references the config already has come first: one token that
reaches several owners (a classic token) becomes one credential listing all their repos, which
also lets `gh pr create` reach every one of them.

A public GitHub repo needs none to be cloned. SSH remotes use these as they are; with
`[credentials.ssh]` they stay on SSH, with a key luoto can't limit to repos. GraphQL
(`gh pr create`) goes with the first GitHub credential that may write; the others open pull
requests over REST (`gh api repos/<owner>/<repo>/pulls`).

## Moving files

- **In:** from a git repository, `up` copies what git doesn't ignore, so ignored files
  (`.env`, `*.tfvars`, state, `.kube/`) stay on your machine. A repo added later is copied or
  cloned on the next `up`, or at once when the env runs.
- **Out:** work leaves by `git push`. `luoto pull` writes the env's folder back, and each repo
  copied from a host folder back to that folder; a cloned repo comes back only with
  `luoto pull --repo <name>`, into the env's folder. Files host tools act on (`.git`,
  `.envrc`, `.vscode`, …) are held back in every folder.
- In the env, the repos are listed in the folder's `.git/info/exclude`, so a launchpad's
  `git status` stays clean.
