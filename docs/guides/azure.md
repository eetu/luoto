# Azure

`[credentials.azure]` lets `az`, terraform's azurerm provider and the Azure SDKs in an env work
on your subscriptions while the tokens stay outside the sandbox. To them the env looks like an
Azure VM with a managed identity: the gate answers the instance metadata service
(`169.254.169.254`) itself and hands out placeholder tokens, then puts the real token on the
requests to Azure that the env is allowed to make.

## Set it up

In the env's own config (`luoto edit`), so each env names what it reaches. Neither
`config.toml` nor a repository's `luoto.toml` can carry it.

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
| Resource Manager, under `subscriptions` | GET, HEAD, OPTIONS | every method |
| what gives access (below) | read | read; every method with `role_assignments = true` |
| deployments, deployment scripts and stacks | read | read; every method with `deployments = true` |
| `GET /subscriptions`, `/tenants`, `/providers`, `/providers/<namespace>` | read | read |
| `key_vaults`, `storage_accounts` | GET, HEAD, OPTIONS | every method |
| Microsoft Graph | read | read |

The token goes only with the methods in this table. A rule you add for one of these hosts, or
an access request you approve, may let more through (`luoto allow` and `luoto approve` say
whose credential the host gets and ask first), but those requests go without the token, and
without whatever token the client sent.

Read is plan-only for most tools. Some reads are POSTs at Azure and need write: listing a
storage account's keys (`listKeys`, which terraform does when it refreshes a storage account)
and Key Vault's `decrypt` and `sign`. Resource Graph queries (`az graph query`) are a POST
outside the subscriptions, so they are refused either way. Write lets code in the env do
whatever the identity's Azure roles allow on the listed subscriptions, so the role is the
real limit: give a service principal the narrowest one that works rather than writing as
yourself.

What gives someone access stays read-only, at every scope from the tenant root down, whatever
rule allows it: role assignments and definitions, PIM's assignment and eligibility requests
and its policies, federated identity credentials, Azure Lighthouse delegations, key vault
access policies, and `elevateAccess`. Each can give someone outside the env lasting access.
`role_assignments = true` allows them under write, for terraform that manages roles.

Template deployments, deployment scripts and deployment stacks stay read-only too: they run
with all of the identity's roles, so a nested deployment can name any subscription it may
write to, and a template or script can assign roles. `deployments = true` allows them under
write, and with them whatever the identity may do anywhere.

Contributor, which Azure stops from assigning roles, is the usual choice for a service
principal that writes, but not a harmless one. On a key vault that uses access policies
rather than Azure RBAC it can give anyone the vault's secrets: the gate refuses the
`accessPolicies` endpoint unless `role_assignments = true`, but a write of the vault itself
carries its access policies too. And under write `listKeys` hands the env a storage account's
keys, which work from anywhere. Scope the role to the resource groups the env works on.

## Inside the env

`up` logs `az` in when the image has it (`az login --identity`, then `az account set` to the
first subscription), so `az group list` just works. Never run `az login` inside: the gate is
the identity.

Terraform's azurerm provider reads `ARM_USE_MSI=true`, `ARM_SUBSCRIPTION_ID` and
`ARM_TENANT_ID` (`tenant`, or the tenant of your `az` login's token), which the env has:

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
subscription, `AZURE_TENANT_ID` the tenant.

A token the env sees (`az account get-access-token`, the SDKs', IMDS's) is a placeholder: the
real token's header and the claims tools read (audience, issuer, times, tenant, object and
application IDs, subject, identity type, version) with a signature that can't verify. Tools
that read the claims, such as terraform's `azurerm_client_config`, get true values; names,
addresses, roles and scopes stay out, and the token itself works nowhere.

## What the env can't do

- Reach other subscriptions, key vaults or storage accounts, or Azure hosts you didn't list
  (`*.azurewebsites.net`, `login.microsoftonline.com`, …): the gate denies them. With
  `deployments = true`, a deployment reaches every subscription the identity may write to.
- Write through Graph, or reach Graph without `graph = true`: the Graph token goes on reads
  only, whatever rule allows a write.
- Get a token for another audience: IMDS refuses one the env isn't granted, naming it.
- Carry a real token anywhere: the env never has one.

What it reads does reach the sandbox: Key Vault secret values, blobs, and with write the keys
`listKeys` returns.

## Troubleshooting

- **`the Azure CLI on this machine is not logged in`** at `up`: run `az login` (with
  `--tenant` if you set one) on your machine, then `luoto vault reload -e <env>` or `luoto up`.
- **`gave no answer within 30 s`**: `az account get-access-token` hung on your machine and was
  stopped; run it yourself to see why.
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
