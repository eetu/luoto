# Azure

`[credentials.azure]` lets `az`, terraform's azurerm provider and the Azure SDKs in an env work
on your subscriptions while the tokens stay outside the sandbox. To them the env looks like an
Azure VM with a managed identity: the gate answers the instance metadata service
(`169.254.169.254`) itself and hands out placeholder tokens, then puts the real token on the
requests to Azure that the env is allowed to make.

## Set it up

In the env's config (`luoto edit`), or in `~/.config/luoto/config.toml` for every env that has
none of its own. A repository's `luoto.toml` can't carry it.

### With your own `az` login

The default: luoto asks the Azure CLI on your machine for tokens, as you.

```toml
[credentials.azure]
subscriptions = ["0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"]
access = "read"                       # the default
# tenant = "contoso.onmicrosoft.com"  # another tenant than az's current one
```

Run `az login` on your machine first (`az login --tenant <tenant>` for another tenant). `luoto
up` reads a token for each audience the env needs with `az account get-access-token`, and the
background watcher reads it again before it expires (az tokens last 60 to 90 minutes), so the
env keeps working as long as your `az` login does.

### With a service principal

For an env that writes, or one that should not act as you. Create one with only the role it
needs, on your machine:

```console
$ az ad sp create-for-rbac --name luoto-web --role Contributor \
    --scopes /subscriptions/<id>/resourceGroups/web-dev
```

Keep its `password` in your secret store and name it:

```toml
[credentials.azure]
subscriptions = ["0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"]
access = "write"
tenant = "<tenant from the output>"
client_id = "<appId from the output>"
client_secret = "op://Dev/azure-luoto-web/password"
```

The vault keeps the secret and mints tokens with it at `login.microsoftonline.com` (the only
host it reaches for this), each reused until ten minutes before it expires. A changed secret
(`luoto vault reload`) retires the tokens minted with the old one.

### Data planes

Resource Manager is always there. Key Vault, Storage and Microsoft Graph take tokens of their
own, so name what the env may reach:

```toml
key_vaults = ["kv-web-dev"]           # kv-web-dev.vault.azure.net
storage_accounts = ["webdevstate"]    # its blob, queue, table, file and dfs hosts
graph = true                          # graph.microsoft.com, read-only
```

Names, not URLs: luoto checks them against Azure's naming rules, so no other host can be
smuggled in.

## Read and write

| | `access = "read"` | `access = "write"` |
| --- | --- | --- |
| Resource Manager, under `subscriptions` | GET, HEAD | every method |
| role assignments and definitions, federated identity credentials | read | read; every method with `role_assignments = true` |
| `GET /subscriptions`, `/tenants`, `/providers/…` | read | read |
| `key_vaults`, `storage_accounts` | GET, HEAD | every method |
| Microsoft Graph | read | read |

Read is plan-only for most tools. Some reads are POSTs at Azure and need write: listing a
storage account's keys (`listKeys`, which terraform does when it refreshes a storage account),
Resource Graph queries, and Key Vault's `decrypt` and `sign`. Write lets code in the env do
whatever the identity's Azure roles allow, so the role is the real limit: give a service
principal the narrowest one that works rather than writing as yourself.

Under write, role assignments, role definitions and federated identity credentials stay
read-only, at any scope: each can give someone outside the env lasting access to the
subscription. `role_assignments = true` allows them, for terraform that manages roles. The
gate only sees the requests that make them directly; an identity that may assign roles
(Owner, User Access Administrator) can still do so through a template deployment or a
deployment script, so for write prefer a service principal with Contributor, which Azure
itself stops from assigning roles.

## Inside the env

`up` logs `az` in when the image has it (`az login --identity`, then `az account set` to the
first subscription), so `az group list` just works. Never run `az login` inside: the gate is
the identity.

Terraform's azurerm provider reads `ARM_USE_MSI=true` and `ARM_SUBSCRIPTION_ID` (and
`ARM_TENANT_ID` when you set `tenant`), which the env has:

```hcl
provider "azurerm" {
  features {}
  # With access = "read", don't register resource providers on plan:
  resource_provider_registrations = "none"   # azurerm 4; 3.x: skip_provider_registration = true
  storage_use_azuread = true                  # storage data through its token, not account keys
}

terraform {
  backend "azurerm" {
    use_msi          = true
    use_azuread_auth = true   # list the state's account under storage_accounts
    # storage_account_name, container_name, key, resource_group_name as usual
  }
}
```

`DefaultAzureCredential` (Python, JavaScript, Go, .NET, Java) finds the managed identity on its
own; `ManagedIdentityCredential` does too. `AZURE_SUBSCRIPTION_ID` holds the first
subscription.

A token the env sees (`az account get-access-token`, the SDKs', IMDS's) is a placeholder: the
real token's header and claims (your object ID, tenant, expiry, and for your own login your
user name) with a signature that can't verify. Tools that read the claims, such as terraform's
`azurerm_client_config`, get true values; the token itself works nowhere.

## What the env can't do

- Reach other subscriptions, key vaults or storage accounts, or Azure hosts you didn't list
  (`*.azurewebsites.net`, `login.microsoftonline.com`, …): the gate denies them.
- Write through Graph, or reach Graph without `graph = true`.
- Get a token for another audience: IMDS refuses one the env isn't granted, naming it.
- Carry a real token anywhere: the env never has one.

What it reads does reach the sandbox: Key Vault secret values, blobs, and with write the keys
`listKeys` returns.

## Troubleshooting

- **`the Azure CLI on this machine is not logged in`** at `up`: run `az login` (with
  `--tenant` if you set one) on your machine, then `luoto vault reload` or `luoto up`.
- **401 from Azure after the laptop slept**: the token expired while the watcher wasn't
  running. It is read again within a minute; `luoto vault reload` does it at once.
- **403 with `AuthorizationFailed`** in the body (JSON from Azure): Azure's RBAC refused the
  identity, not luoto. Give it a role on that scope, or use an identity that has one. A 403
  from luoto has the header `x-proxy-error: blocked-by-luoto` and says why in plain text.
- **A denied host such as `kv-other.vault.azure.net`**: add the vault to `key_vaults` (or the
  account to `storage_accounts`). `luoto allow` alone opens the host without a token.
- **`has no Azure credential for resource …`** from IMDS: the tool asked for an audience the
  env isn't granted; name the data plane, or `graph = true`.
- **`luoto vault unlock`** in an IMDS error: the vault was locked or restarted.
- **`az login --identity` failed** at `up`: `luoto egress -e <env> --denied --since 10m`
  shows what it was refused; `luoto up` tries again.
- Only Azure's public cloud: sovereign clouds (Azure Government, Azure China) aren't
  supported.
