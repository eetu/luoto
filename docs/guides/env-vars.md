# Environment variables

An env's shells get variables from three places in its own file. The difference is who can
read the value:

| what | where | code in the env sees | set with |
| --- | --- | --- | --- |
| a plain value | `[env]` | the value | `luoto var set NAME=value` |
| a secret the code reads | `[sandbox_secrets]` | the secret | `luoto var set NAME` |
| a token one HTTP API takes | `[credentials.custom.<name>]` | a placeholder | `luoto edit` |

Neither `config.toml` nor a repository's `luoto.toml` carries them.

## Plain values

```sh
luoto var set RUST_LOG=debug
```

The value is in your shell history and the env's file; keep secrets out of it.

## Secrets the code reads

```sh
luoto var set DATABASE_URL
```

luoto asks where the secret is kept: a 1Password item, the OS keychain, or pasted into either.
The env's file keeps only the ref. Without a terminal, give the ref:

```sh
luoto var set DATABASE_URL --ref op://Dev/local-db/url
```

Refs are `op://`, `keyring:`, `vault://`, `env:` and `file:`
([configuration](../configuration.md)). luoto reads the secret on your machine at `up` and
writes it to a file in the env's memory that every shell loads, gone when the container stops.
Any code in the env can read it, including whatever a dependency's install script runs, and
send it anywhere the env's rules allow.

A repository's `luoto.toml` can name the secrets its code needs (`[needs] sandbox_secrets =
["DATABASE_URL"]`); `up` then asks each developer where theirs is kept.

## When the code asks

An agent in the env can ask for a variable: a plain one with a value it suggests
(`sandbox request --var RUST_LOG=debug`, MCP `sandbox_request_var`), or a secret by name
only (`sandbox request --secret DATABASE_URL`, MCP `sandbox_request_secret`).
`luoto approve <id>` shows the suggested value to confirm, or asks where the secret is kept;
`luoto var set` answers either. `luoto ui` opens on the kind asked for, with the suggested
value filled in, and accepts a plain value or a secret's ref; a secret itself never goes
through the page, so pasting one into 1Password or the keychain is the terminal's.

Read the name and the value, not the reason: code asking for `AWS_SECRET_ACCESS_KEY` is
asking for your credentials, and a suggested value is the sandbox's.

## Tokens the code never sees

A token that only goes in a header to one API is safer outside the env: the gate adds it to
requests to that host, over TLS, and the code gets a placeholder.

```toml
[credentials.custom.example]
host = "api.example.com"
secret = "op://Dev/example/token"
placeholder_env = { EXAMPLE_API_KEY = "luoto-placeholder" }
# header = "authorization", format = "Bearer {secret}" are the defaults
```

It reads (GET, HEAD and OPTIONS) unless you add `write = true`. Cloud CLIs and Azure have
theirs ready: [cloud APIs](cloud-apis.md), [Azure](azure.md).

## Listing, removing, applying

`luoto var` lists the env's variables, a secret by its ref, as does the env's panel in
`luoto ui`, which also names what luoto sets itself (credentials' placeholders, agents'
settings). `luoto var rm NAME` removes one. A
name is in `[env]` or `[sandbox_secrets]`, never both: setting it moves it.

A running env takes a change at once: new shells have it, and open bash, zsh and fish shells
reload it at their next prompt (saying so), unsetting a removed one. A program already running
keeps what it started with, and so may a command an agent runs without a prompt: `.
/run/luoto/env.sh` loads the current ones. Otherwise it applies at the next `luoto up`.

luoto refuses names it sets itself in every env: the proxy variables, the CA bundle ones
(`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …) and `LUOTO_*`.
