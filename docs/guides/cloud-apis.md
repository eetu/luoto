# Cloud APIs: Hetzner, UpCloud, DigitalOcean, Cloudflare

`[credentials.hetzner]`, `[credentials.upcloud]`, `[credentials.digitalocean]` and
`[credentials.cloudflare]` let each cloud's CLI and its terraform or OpenTofu provider work in
an env while the API token stays outside the sandbox. The env has a placeholder of the shape
the clients check, and the gate puts the real token on requests to the cloud's API. Azure has
its own guide: [azure.md](azure.md).

## Set it up

In the env's own config (`luoto edit`). Neither `config.toml` nor a repository's `luoto.toml`
can carry it; a `luoto.toml` can name `hetzner` (or another) under `[needs] credentials`, and
`up` then asks each developer for it.

```toml
[credentials.hetzner]
token = "op://Dev/hcloud-web/token"
# write = true            # every method (apply, deploy); without it GET, HEAD and OPTIONS only
```

| cloud | token | where to get one |
| --- | --- | --- |
| `hetzner` | project API token | Hetzner Console > your project > Security > API tokens. Read, unless the env writes |
| `upcloud` | API token (`ucat_…`) | UpCloud Control Panel > Account > API tokens, best under a subaccount with only the permissions the env needs |
| `digitalocean` | personal access token (`dop_v1_…`) | cloud.digitalocean.com/account/api/tokens. Read Only or custom scopes, unless the env writes |
| `cloudflare` | API token | dash.cloudflare.com/profile/api-tokens, or an account token under Manage Account > API Tokens, with only the permissions the env needs |

UpCloud's username and password (basic auth) and Cloudflare's Global API Key with its email
aren't supported: use an API token, which both recommend.

## Read and write

Infrastructure tools change real things, so a cloud credential reads by default: the token
goes with GET, HEAD and OPTIONS to the API, which is what `terraform plan`, `hcloud server
list` or `doctl compute droplet list` send. `write = true` allows every method, for `apply`,
`wrangler deploy` or `hcloud server create`. A rule you add or a request you approve that
allows more on the API host gets it without the token.

The token's own permissions are the other limit, and the only one under write: a Hetzner Read
token, a DigitalOcean Read Only or custom-scoped token, Cloudflare permissions on only the
zones and accounts the env works on. UpCloud tokens have no read-only kind, so luoto's read is
their only read limit; a subaccount's permissions narrow them.

Write is a way out of the env: a server's user data, a Worker's script or anything else you
create runs outside it, with the internet, carrying what code in the env gave it. Give write
to the envs that apply, with a token scoped to what they apply.

Some reads are POSTs, such as Cloudflare's GraphQL Analytics API (`/client/v4/graphql`), and
need write. What the API returns reaches the sandbox: kubeconfigs, database connection strings
with their passwords, tunnel tokens.

## Inside the env

| cloud | the token goes to | placeholders set | CLI | terraform provider |
| --- | --- | --- | --- | --- |
| `hetzner` | `api.hetzner.cloud`, `api.hetzner.com` (Storage Boxes) | `HCLOUD_TOKEN` | `hcloud` | `hetznercloud/hcloud` |
| `upcloud` | `api.upcloud.com` | `UPCLOUD_TOKEN` | `upctl` | `UpCloudLtd/upcloud` |
| `digitalocean` | `api.digitalocean.com` | `DIGITALOCEAN_ACCESS_TOKEN` (doctl), `DIGITALOCEAN_TOKEN` (terraform) | `doctl` | `digitalocean/digitalocean` |
| `cloudflare` | `api.cloudflare.com` `/client/v4/**` | `CLOUDFLARE_API_TOKEN` | `wrangler` | `cloudflare/cloudflare` |

The variable is the login: don't log in inside the env (`hcloud context create`, `doctl auth
init`, `upctl account login`, `wrangler login`), and keep doctl on its `default` context,
the only one that reads `DIGITALOCEAN_ACCESS_TOKEN`. Leave `UPCLOUD_USERNAME` and
`UPCLOUD_PASSWORD` unset: UpCloud's Go client refuses them beside a token. With a Cloudflare
credential, Wrangler also runs with `WRANGLER_SEND_METRICS=false` and
`WRANGLER_SEND_ERROR_REPORTS=false`.

Leave the token out of the provider block and of any `.tfvars`; the provider reads the
variable:

```hcl
terraform {
  required_providers {
    hcloud = { source = "hetznercloud/hcloud" }
  }
}

provider "hcloud" {}   # HCLOUD_TOKEN; likewise upcloud {}, digitalocean {}, cloudflare {}
```

`terraform init` needs the `terraform` (or `opentofu`) preset: both registries point each of
these four providers at its GitHub release
(`github.com/<owner>/<repo>/releases/download/…`, then `release-assets.githubusercontent.com`),
which the preset opens.

S3-compatible storage (DigitalOcean Spaces, Cloudflare R2, UpCloud Managed Object Storage,
Hetzner Object Storage) signs every request with its keys, which the gate can't add: a
terraform backend there needs its keys in `[sandbox_secrets]`, inside the sandbox.

## Denied on purpose

The CLIs work without these:

| host | who calls it | what it is | why it stays closed |
| --- | --- | --- | --- |
| `sparrow.cloudflare.com` | wrangler | usage statistics (off with the variable above) | telemetry |
| `platform.dash.cloudflare.com` | wrangler | error reports (off with the variable above) | telemetry |
| `dash.cloudflare.com` | `wrangler login` | browser sign-in | the token is the login |
| `cloud.digitalocean.com` | `doctl auth init`, `doctl auth login` | token check, browser sign-in | the token is the login |
| `checkpoint-api.hashicorp.com` | terraform | update and telemetry check (off with `CHECKPOINT_DISABLE=1` from the `terraform` preset) | telemetry |

Two update checks go through other presets, as reads of public data: Wrangler asks
`registry.npmjs.org` for its latest version (`npm`), and `doctl version` asks `api.github.com`
for doctl's latest release (`toolchains`). The source of `hcloud`, `upctl` and the four
terraform providers shows no other host.

## What is verified

Checked against the clients' source: the hosts, the `Authorization: Bearer` header, the
variables each reads, and the placeholders' shape.

- Hetzner: hcloud-go sends the token as a bearer to `api.hetzner.cloud/v1` and, for Storage
  Boxes, `api.hetzner.com/v1`. The `hcloud` CLI and terraform-provider-hcloud read
  `HCLOUD_TOKEN`; the provider, and the CLI for a context, refuse a token that isn't exactly
  64 characters.
- UpCloud: upcloud-go-api sends a token as a bearer (basic auth otherwise) to
  `api.upcloud.com`; upctl and terraform-provider-upcloud read `UPCLOUD_TOKEN`, which wins over
  a username and password. API tokens start with `ucat_`; no client checks more.
- DigitalOcean: godo sends a bearer to `api.digitalocean.com`. terraform-provider-digitalocean
  reads `DIGITALOCEAN_TOKEN`, then `DIGITALOCEAN_ACCESS_TOKEN`; doctl reads the latter. Only
  doctl's token prompt checks the shape: 64 characters, or 71 starting with `do`, which the
  `dop_v1_` placeholder is.
- Cloudflare: cloudflare-go and terraform-provider-cloudflare (v5) read `CLOUDFLARE_API_TOKEN`
  and send it as a bearer to `api.cloudflare.com/client/v4`; the provider takes 40 to 80
  letters, digits, `-` and `_`. Wrangler reads the same variable.

Not yet run against the live APIs.

## Troubleshooting

- **403 with `x-proxy-error: blocked-by-luoto`** on a POST, PUT, PATCH or DELETE: the env
  reads. Add `write = true` under the cloud's credential.
- **403 from the cloud** (its own JSON error): the token's permissions refused it, such as a
  Hetzner Read token on a write (`forbidden`). A 401 is a token the cloud doesn't know:
  revoked, expired, or a placeholder that reached it some other way.
- **`only one authentication method`** from an UpCloud tool: `UPCLOUD_USERNAME` or
  `UPCLOUD_PASSWORD` is set in the env (`[env]`, a shell profile); remove it.
- **doctl uses another token**: a context other than `default` is active; `doctl auth switch
  --context default`.
- **`luoto vault unlock`** in an error: the vault was locked or restarted.
