//! SSH host keys of the forges luoto knows, pinned: GitHub's from its meta API
//! (`api.github.com/meta`, `ssh_keys`), Azure DevOps' as its documentation gives the
//! fingerprint (`SHA256:ohD8VZEXGWo6Ez8GSEJQ9WpafgLFsOfLOtGGQCQo6Og`). The vault signs an SSH
//! login only for a session one of these keys (or one from `[credentials.ssh] host_keys`)
//! bound, and the env's `known_hosts` holds the same lines.
//!
//! The forge hosts are named once here: the gate's guards, the policy's tunnel check and the
//! CLI's compiled rules must agree on them, or a guard silently stops applying.

/// GitHub's git host (smart HTTP, and SSH on port 22).
pub const GITHUB: &str = "github.com";
/// GitHub's SSH on the HTTPS port, for networks that block 22; it serves github.com's host
/// keys.
pub const GITHUB_SSH_443: &str = "ssh.github.com";
/// GitHub's REST and GraphQL API.
pub const GITHUB_API: &str = "api.github.com";
/// Azure DevOps Services, where its git repositories are served over HTTPS.
pub const AZURE_DEVOPS: &str = "dev.azure.com";
/// Azure DevOps' git over SSH.
pub const AZURE_DEVOPS_SSH: &str = "ssh.dev.azure.com";

/// `(host, "algorithm base64")`, as a `known_hosts` line writes them.
pub const HOST_KEYS: &[(&str, &str)] = &[
    (
        GITHUB,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    ),
    (
        GITHUB,
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
    ),
    (
        GITHUB,
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
    ),
    (
        AZURE_DEVOPS_SSH,
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7Hr1oTWqNqOlzGJOfGJ4NakVyIzf1rXYd4d7wo6jBlkLvCA4odBlL0mDUyZ0/QUfTTqeu+tm22gOsv+VrVTMk6vwRU75gY/y9ut5Mb3bR5BV58dKXyq9A9UeB5Cakehn5Zgm6x1mKoVyf+FFn26iYqXJRgzIZZcZ5V6hrE0Qg39kZm4az48o0AUbf6Sp4SLdvnuMa2sVNwHBboS7EJkm57XQPVU3/QpyNLHbWDdzwtrlS+ez30S3AdYhLKEOxAG8weOnyrtLJAUen9mTkol8oII1edf7mWWbWVf0nBmly21+nZcmCTISQBtdcyPaEno7fFQMDD26/s0lfKob4Kw8H",
    ),
];

/// The pinned keys of `host`.
pub fn host_keys(host: &str) -> impl Iterator<Item = &'static str> + '_ {
    HOST_KEYS
        .iter()
        .filter(move |(h, _)| h.eq_ignore_ascii_case(host))
        .map(|(_, k)| *k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_pinned_key_is_an_algorithm_and_its_data() {
        for (host, key) in HOST_KEYS {
            let parts: Vec<&str> = key.split(' ').collect();
            assert_eq!(parts.len(), 2, "{host}");
            assert!(parts[1].len() > 60, "{host}");
        }
        assert_eq!(host_keys("GitHub.com").count(), 3);
        assert_eq!(host_keys("gitlab.com").count(), 0);
    }
}
