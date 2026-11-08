//! Azure credentials as an env sees them: a managed identity. The gate answers the instance
//! metadata service (IMDS) itself, with placeholder tokens for the audiences the env's
//! `[credentials.azure]` grants, and adds the real token on those audiences' hosts. The
//! audiences, the spellings clients use for them and the hosts their tokens go to are named
//! once here, so the CLI's compiled rules, the gate's IMDS and the vault agree on them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The instance metadata service's address: the gate answers it and never dials it.
pub const IMDS_HOST: &str = "169.254.169.254";
/// IMDS's managed identity token endpoint.
pub const IMDS_TOKEN_PATH: &str = "/metadata/identity/oauth2/token";
/// Microsoft Entra ID's token endpoint host: the only one the vault reaches for Azure.
pub const LOGIN_HOST: &str = "login.microsoftonline.com";
/// Azure Resource Manager.
pub const ARM_HOST: &str = "management.azure.com";
/// Microsoft Graph.
pub const GRAPH_HOST: &str = "graph.microsoft.com";
/// The storage services an account's hosts serve (`<account>.<service>.core.windows.net`).
pub const STORAGE_SERVICES: &[&str] = &["blob", "queue", "table", "file", "dfs"];

/// What a token is for.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// Azure Resource Manager.
    Arm,
    KeyVault,
    Storage,
    /// Microsoft Graph.
    Graph,
}

impl Audience {
    pub const ALL: [Audience; 4] = [
        Audience::Arm,
        Audience::KeyVault,
        Audience::Storage,
        Audience::Graph,
    ];

    /// The resource a token is asked for with (`az --resource`; a scope is this and
    /// `/.default`).
    pub fn resource(self) -> &'static str {
        match self {
            Audience::Arm => "https://management.azure.com/",
            Audience::KeyVault => "https://vault.azure.net",
            Audience::Storage => "https://storage.azure.com/",
            Audience::Graph => "https://graph.microsoft.com/",
        }
    }

    /// The vault binding that holds the env's token for it.
    pub fn binding(self) -> &'static str {
        match self {
            Audience::Arm => "azure-arm",
            Audience::KeyVault => "azure-keyvault",
            Audience::Storage => "azure-storage",
            Audience::Graph => "azure-graph",
        }
    }

    /// The audience an IMDS `resource` (or a `scope`) names, in the spellings clients use:
    /// with or without a trailing slash, as a `/.default` scope, in any case, and ARM by its
    /// classic name (`https://management.core.windows.net/`, which the Azure CLI asks for).
    pub fn parse(resource: &str) -> Option<Audience> {
        let lower = resource.trim().to_ascii_lowercase();
        let base = lower.strip_suffix("/.default").unwrap_or(&lower);
        match base.strip_suffix('/').unwrap_or(base) {
            "https://management.azure.com" | "https://management.core.windows.net" => {
                Some(Audience::Arm)
            }
            "https://vault.azure.net" => Some(Audience::KeyVault),
            "https://storage.azure.com" => Some(Audience::Storage),
            "https://graph.microsoft.com" => Some(Audience::Graph),
            _ => None,
        }
    }
}

/// What the gate's IMDS serves an env: the vault binding of each audience it grants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct AzureIdentity {
    pub audiences: BTreeMap<Audience, String>,
}

/// `8-4-4-4-12` hex digits: a subscription, tenant or application ID.
pub fn is_guid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A tenant ID, or one of its domains (`contoso.onmicrosoft.com`): one segment of a login URL
/// and one argument, with nothing that could reach another path or option.
pub fn tenant_ok(s: &str) -> bool {
    is_guid(s)
        || (s.len() <= 253
            && s.contains('.')
            && s.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            && !s.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// Azure's rule for a key vault name: 3–24 letters, digits and single hyphens, from a letter
/// to a letter or digit.
pub fn key_vault_name_ok(s: &str) -> bool {
    (3..=24).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && s.starts_with(|c: char| c.is_ascii_alphabetic())
        && !s.ends_with('-')
        && !s.contains("--")
}

/// Azure's rule for a storage account name: 3–24 lower-case letters and digits.
pub fn storage_account_ok(s: &str) -> bool {
    (3..=24).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A key vault's host, for a name [`key_vault_name_ok`] accepts.
pub fn key_vault_host(name: &str) -> String {
    format!("{}.vault.azure.net", name.to_ascii_lowercase())
}

/// A storage account's hosts, one per service, for a name [`storage_account_ok`] accepts.
pub fn storage_hosts(account: &str) -> Vec<String> {
    STORAGE_SERVICES
        .iter()
        .map(|s| format!("{account}.{s}.core.windows.net"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audiences_parse_in_every_spelling_clients_use() {
        for (spelling, aud) in [
            ("https://management.azure.com/", Audience::Arm),
            ("https://management.azure.com", Audience::Arm),
            ("https://management.azure.com/.default", Audience::Arm),
            ("https://management.azure.com//.default", Audience::Arm),
            ("https://management.core.windows.net/", Audience::Arm),
            ("HTTPS://Management.Azure.com/", Audience::Arm),
            ("https://vault.azure.net", Audience::KeyVault),
            ("https://vault.azure.net/.default", Audience::KeyVault),
            ("https://storage.azure.com/", Audience::Storage),
            ("https://storage.azure.com/.default", Audience::Storage),
            ("https://graph.microsoft.com/", Audience::Graph),
            ("https://graph.microsoft.com//.default", Audience::Graph),
        ] {
            assert_eq!(Audience::parse(spelling), Some(aud), "{spelling}");
        }
        for other in [
            "",
            "https://management.azure.com.evil.example/",
            "https://evil.example/https://management.azure.com/",
            "https://kv.vault.azure.net",
            "https://acct.blob.core.windows.net",
            "https://database.windows.net/",
            "management.azure.com",
        ] {
            assert_eq!(Audience::parse(other), None, "{other}");
        }
        for aud in Audience::ALL {
            assert_eq!(Audience::parse(aud.resource()), Some(aud));
        }
    }

    #[test]
    fn names_follow_azures_rules_and_carry_no_other_host() {
        assert!(is_guid("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"));
        assert!(!is_guid("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f"));
        assert!(!is_guid("0b1c2d3e4f5061728394a5b6c7d8e9f0"));
        assert!(!is_guid("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9fg"));

        assert!(tenant_ok("contoso.onmicrosoft.com"));
        assert!(tenant_ok("0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0"));
        for bad in [
            "contoso",
            "contoso.com/../x",
            "a.b?x=1",
            "a.b#x",
            "user@a.b",
            "10.0.0.1",
            "-a.b",
            "a..b",
            "",
        ] {
            assert!(!tenant_ok(bad), "{bad}");
        }

        assert!(key_vault_name_ok("kv-prod-01"));
        for bad in [
            "kv",
            "1kv",
            "kv-",
            "kv--a",
            "kv.evil.example",
            "kv*",
            &"a".repeat(25),
        ] {
            assert!(!key_vault_name_ok(bad), "{bad}");
        }
        assert_eq!(key_vault_host("KV-Prod"), "kv-prod.vault.azure.net");

        assert!(storage_account_ok("acct01"));
        for bad in ["ab", "Acct", "acct-1", "acct.evil", "*", &"a".repeat(25)] {
            assert!(!storage_account_ok(bad), "{bad}");
        }
        assert_eq!(
            storage_hosts("acct"),
            [
                "acct.blob.core.windows.net",
                "acct.queue.core.windows.net",
                "acct.table.core.windows.net",
                "acct.file.core.windows.net",
                "acct.dfs.core.windows.net",
            ]
        );
    }

    #[test]
    fn the_identity_serializes_audiences_by_name() {
        let id = AzureIdentity {
            audiences: BTreeMap::from([(Audience::KeyVault, "azure-keyvault".to_string())]),
        };
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, r#"{"audiences":{"key_vault":"azure-keyvault"}}"#);
        assert_eq!(serde_json::from_str::<AzureIdentity>(&json).unwrap(), id);
    }
}
