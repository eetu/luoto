//! Azure DevOps git over HTTPS: the repositories `[credentials.azure_devops]` names, the
//! forms a remote URL takes, and the rewrites that send SSH and legacy remotes to
//! `https://dev.azure.com`, where the gate adds the PAT.

use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::config::extend_unique;

pub use luoto_shared::forges::{AZURE_DEVOPS as HOST, AZURE_DEVOPS_SSH as SSH_HOST};
/// Its legacy SSH host, where the user name is the organization.
const LEGACY_SSH_HOST: &str = "vs-ssh.visualstudio.com";

/// A repository, each part as its URLs write it (percent-encoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub org: String,
    pub project: String,
    pub name: String,
}

impl Repo {
    /// `org/project/repo`, lowercase, as the gate's push guard compares it.
    pub fn key(&self) -> String {
        format!("{}/{}/{}", self.org, self.project, self.name).to_ascii_lowercase()
    }

    /// Its smart-HTTP and LFS paths on `dev.azure.com`, in both URL forms; `write` adds
    /// pushes.
    pub fn git_paths(&self, write: bool) -> Vec<String> {
        let mut bases = vec![format!("/{}/{}/_git/{}", self.org, self.project, self.name)];
        if self.project.eq_ignore_ascii_case(&self.name) {
            bases.push(format!("/{}/_git/{}", self.org, self.name));
        }
        let mut paths = Vec::new();
        for base in bases {
            for b in [base.clone(), format!("{base}.git")] {
                paths.extend(crate::compile::smart_http_paths(&b, write));
            }
        }
        paths
    }
}

/// A path segment as Azure DevOps' clone URLs write it: unreserved characters as they are,
/// everything else (a space in a project name) percent-encoded.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// A segment that must already be a URL path segment: no separators, no blanks.
fn segment(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty() && !s.contains(['/', '?', '#', ' ', '\\'])).then(|| s.to_string())
}

/// The repository a remote URL names and, for an SSH remote, the host it uses when that is
/// an alias from `~/.ssh/config` (`git@my-azure:v3/…`).
pub fn parse_url(url: &str) -> Option<(Repo, Option<String>)> {
    let url = url.trim();
    let repo = |org: &str, project: &str, name: &str| {
        let name = name.trim_end_matches('/');
        let name = name.strip_suffix(".git").unwrap_or(name);
        Some(Repo {
            org: segment(org)?,
            project: segment(project)?,
            name: segment(name)?,
        })
    };
    if let Some(rest) = url.strip_prefix("https://") {
        let (authority, path) = rest.split_once('/')?;
        let host = authority.rsplit('@').next()?.to_ascii_lowercase();
        let seg: Vec<&str> = path.split('/').collect();
        if host == HOST {
            return match seg.as_slice() {
                [org, project, "_git", name] => Some((repo(org, project, name)?, None)),
                [org, "_git", name] => Some((repo(org, name, name)?, None)),
                _ => None,
            };
        }
        let org = host.strip_suffix(".visualstudio.com")?;
        let seg = match seg.as_slice() {
            ["DefaultCollection", rest @ ..] => rest,
            s => s,
        };
        return match seg {
            [project, "_git", name] => Some((repo(org, project, name)?, None)),
            ["_git", name] => Some((repo(org, name, name)?, None)),
            _ => None,
        };
    }
    // SSH: `user@host:v3/org/project/repo` or `ssh://user@host/v3/org/project/repo`.
    let (host, path) = match url.strip_prefix("ssh://") {
        Some(rest) => {
            let (authority, path) = rest.split_once('/')?;
            (authority.rsplit('@').next()?.to_string(), path.to_string())
        }
        None => {
            let (authority, path) = url.split_once(':')?;
            (authority.rsplit('@').next()?.to_string(), path.to_string())
        }
    };
    let seg: Vec<&str> = path.split('/').collect();
    let ["v3", org, project, name] = seg.as_slice() else {
        return None;
    };
    let host = host.split(':').next().unwrap_or(&host).to_ascii_lowercase();
    let alias = (host != SSH_HOST && host != LEGACY_SSH_HOST).then_some(host);
    Some((repo(org, project, name)?, alias))
}

/// One `repos` entry: `org/project/repo` (names as you see them) or a clone URL (as it is).
pub fn parse_repo(entry: &str) -> Result<Repo> {
    if entry.contains("://") || entry.contains('@') {
        let Some((r, _)) = parse_url(entry) else {
            bail!("credentials.azure_devops: `{entry}` is not an Azure DevOps clone URL");
        };
        return Ok(r);
    }
    let part = |s: &str| {
        let s = s.trim();
        (!s.is_empty()).then(|| encode(&decode(s)))
    };
    let seg: Vec<&str> = entry.trim().split('/').collect();
    let [org, project, name] = seg.as_slice() else {
        bail!(
            "credentials.azure_devops: repos are `org/project/repo` or clone URLs (got `{entry}`)"
        );
    };
    match (
        part(org),
        part(project),
        part(name.trim_end_matches(".git")),
    ) {
        (Some(org), Some(project), Some(name)) => Ok(Repo { org, project, name }),
        _ => bail!(
            "credentials.azure_devops: repos are `org/project/repo` or clone URLs (got `{entry}`)"
        ),
    }
}

/// `url.<base>.insteadOf` pairs that send the organization's legacy and `org@` HTTPS URLs to
/// `https://dev.azure.com/<org>/`.
fn https_rewrites(org: &str) -> Vec<(String, String)> {
    let base = format!("https://{HOST}/{org}/");
    vec![
        (base.clone(), format!("https://{org}.visualstudio.com/")),
        (
            base.clone(),
            format!("https://{org}.visualstudio.com/DefaultCollection/"),
        ),
        (base, format!("https://{org}@{HOST}/{org}/")),
    ]
}

/// The organization's SSH remote prefixes (`…v3/<org>/`), scp-like and `ssh://`: the legacy
/// host and the `aliases` (organization as the remote writes it, alias), and with `standard`
/// `ssh.dev.azure.com` too.
fn ssh_prefixes(org: &str, aliases: &[(String, String)], standard: bool) -> Vec<String> {
    let mut hosts: Vec<(String, String)> = vec![(
        format!("{org}@{LEGACY_SSH_HOST}:"),
        format!("ssh://{org}@{LEGACY_SSH_HOST}/"),
    )];
    if standard {
        hosts.push((format!("git@{SSH_HOST}:"), format!("ssh://git@{SSH_HOST}/")));
    }
    let mut out: Vec<String> = hosts
        .iter()
        .flat_map(|(scp, ssh)| [format!("{scp}v3/{org}/"), format!("{ssh}v3/{org}/")])
        .collect();
    for (written, alias) in aliases.iter().filter(|(o, _)| o.eq_ignore_ascii_case(org)) {
        for p in ["git@", ""] {
            out.push(format!("{p}{alias}:v3/{written}/"));
        }
        out.push(format!("ssh://git@{alias}/v3/{written}/"));
    }
    out
}

/// SSH remotes to HTTPS, where the PAT logs in, per project: SSH writes
/// `v3/org/project/repo`, HTTPS `org/project/_git/repo`.
fn ssh_to_https(
    org: &str,
    projects: &[String],
    aliases: &[(String, String)],
) -> Vec<(String, String)> {
    let prefixes = ssh_prefixes(org, aliases, true);
    let mut out = Vec::new();
    for p in projects {
        let https = format!("https://{HOST}/{org}/{p}/_git/");
        for prefix in &prefixes {
            out.push((https.clone(), format!("{prefix}{p}/")));
        }
    }
    out
}

/// SSH remotes on the legacy host and on `aliases` to `ssh.dev.azure.com`, where the vault's
/// key logs in (`[credentials.ssh]`).
fn ssh_to_ssh(org: &str, aliases: &[(String, String)]) -> Vec<(String, String)> {
    let target = format!("git@{SSH_HOST}:v3/{org}/");
    ssh_prefixes(org, aliases, false)
        .into_iter()
        .map(|from| (target.clone(), from))
        .collect()
}

/// The env's git remote rewrites for Azure DevOps, as `url.<base>.insteadOf` pairs: each
/// organization of `repos` gets its legacy URLs sent to `https://dev.azure.com`, and its SSH
/// remotes (`aliases` among them) too unless the vault's key logs in over SSH (`over_ssh`).
/// With that key, SSH remotes on the legacy host and on `aliases` go to `ssh.dev.azure.com`.
pub fn rewrites(
    repos: &[Repo],
    aliases: &[(String, String)],
    over_ssh: bool,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Organizations as their repos write them, each with its projects.
    let mut orgs: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for r in repos {
        let (_, projects) = orgs
            .entry(r.org.to_ascii_lowercase())
            .or_insert_with(|| (r.org.clone(), Vec::new()));
        extend_unique(projects, [r.project.clone()]);
    }
    for (org, projects) in orgs.values() {
        out.extend(https_rewrites(org));
        if !over_ssh {
            out.extend(ssh_to_https(org, projects, aliases));
        }
    }
    if over_ssh {
        let mut orgs: Vec<&str> = aliases
            .iter()
            .map(|(o, _)| o.as_str())
            .chain(repos.iter().map(|r| r.org.as_str()))
            .collect();
        orgs.sort_by_key(|o| o.to_ascii_lowercase());
        orgs.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        for org in orgs {
            out.extend(ssh_to_ssh(org, aliases));
        }
    }
    out
}

/// SSH host aliases from `~/.ssh/config` that the project's own remotes use for Azure DevOps
/// (`git@my-azure:v3/org/…`), as (organization as the remote writes it, alias): read from the
/// `.git/config` and `.gitmodules` of the folder and its repos' folders, and from the remotes
/// its repos clone. The env has no SSH config, so these are rewritten like the standard hosts.
pub fn aliases(workspace: &crate::config::Workspace) -> Vec<(String, String)> {
    let mut urls: Vec<String> = workspace
        .repos
        .values()
        .filter_map(|r| r.url.clone())
        .collect();
    let folders = workspace
        .dir
        .iter()
        .chain(workspace.repos.values().filter_map(|r| r.dir.as_ref()));
    for dir in folders {
        let dir = std::path::Path::new(dir);
        for f in [dir.join(".git").join("config"), dir.join(".gitmodules")] {
            let Ok(text) = std::fs::read_to_string(f) else {
                continue;
            };
            urls.extend(text.lines().filter_map(|l| {
                let v = l.trim().strip_prefix("url")?.trim_start();
                Some(v.strip_prefix('=')?.trim().to_string())
            }));
        }
    }
    let mut out: Vec<(String, String)> = urls
        .iter()
        .filter_map(|u| {
            let (r, alias) = parse_url(u)?;
            Some((r.org, alias?))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A URL path segment as people read it (`Data%20Platform` → `Data Platform`).
pub fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok());
        match (b[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(v)) => {
                out.push(v);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(org: &str, project: &str, name: &str) -> Repo {
        Repo {
            org: org.into(),
            project: project.into(),
            name: name.into(),
        }
    }

    #[test]
    fn remote_urls_in_every_form_name_the_repo() {
        let r = repo("invinite", "AppServices", "pseudo-registry");
        for url in [
            "https://dev.azure.com/invinite/AppServices/_git/pseudo-registry",
            "https://invinite@dev.azure.com/invinite/AppServices/_git/pseudo-registry",
            "https://invinite.visualstudio.com/AppServices/_git/pseudo-registry",
            "https://invinite.visualstudio.com/DefaultCollection/AppServices/_git/pseudo-registry",
            "git@ssh.dev.azure.com:v3/invinite/AppServices/pseudo-registry",
            "ssh://git@ssh.dev.azure.com/v3/invinite/AppServices/pseudo-registry",
            "invinite@vs-ssh.visualstudio.com:v3/invinite/AppServices/pseudo-registry",
        ] {
            assert_eq!(parse_url(url), Some((r.clone(), None)), "{url}");
        }
        assert_eq!(
            parse_url("git@azure-invinite:v3/invinite/AppServices/pseudo-registry"),
            Some((r.clone(), Some("azure-invinite".into()))),
            "an alias from ~/.ssh/config"
        );
        assert_eq!(
            parse_url("https://dev.azure.com/invinite/_git/AppServices").map(|(r, _)| r),
            Some(repo("invinite", "AppServices", "AppServices"))
        );
        assert_eq!(parse_url("git@github.com:eetu/luoto.git"), None);
        assert_eq!(parse_url("https://github.com/eetu/luoto"), None);
    }

    #[test]
    fn repos_are_org_project_repo_or_a_clone_url() {
        assert_eq!(
            parse_repo("invinite/Data Platform/dbt-core").unwrap(),
            repo("invinite", "Data%20Platform", "dbt-core")
        );
        assert_eq!(
            parse_repo("https://invinite@dev.azure.com/invinite/Data%20Platform/_git/dbt-core")
                .unwrap(),
            repo("invinite", "Data%20Platform", "dbt-core")
        );
        assert_eq!(
            parse_repo("invinite/Data%20Platform/dbt-core.git").unwrap(),
            repo("invinite", "Data%20Platform", "dbt-core"),
            "already encoded stays as it is"
        );
        assert!(parse_repo("project/repo").is_err());
        assert!(parse_repo("a/b/c/d").is_err());
        assert!(parse_repo("a//c").is_err());
    }

    /// Where git sends `url` with these rewrites: the longest matching prefix.
    fn rewritten(pairs: &[(String, String)], url: &str) -> Option<String> {
        pairs
            .iter()
            .filter(|(_, f)| url.starts_with(f.as_str()))
            .max_by_key(|(_, f)| f.len())
            .map(|(base, f)| format!("{base}{}", &url[f.len()..]))
    }

    #[test]
    fn ssh_remotes_go_to_https_per_project_with_the_git_segment_added() {
        let aliases = [("invinite".to_string(), "azure-invinite".to_string())];
        let mut pairs = https_rewrites("invinite");
        pairs.extend(ssh_to_https("invinite", &["AppServices".into()], &aliases));
        let https = "https://dev.azure.com/invinite/AppServices/_git/pseudo-registry";
        for url in [
            "git@ssh.dev.azure.com:v3/invinite/AppServices/pseudo-registry",
            "git@azure-invinite:v3/invinite/AppServices/pseudo-registry",
            "invinite@vs-ssh.visualstudio.com:v3/invinite/AppServices/pseudo-registry",
        ] {
            assert_eq!(rewritten(&pairs, url).as_deref(), Some(https), "{url}");
        }
        assert_eq!(
            rewritten(
                &pairs,
                "https://invinite.visualstudio.com/DefaultCollection/AppServices/_git/x"
            )
            .as_deref(),
            Some("https://dev.azure.com/invinite/AppServices/_git/x")
        );
    }

    #[test]
    fn with_an_ssh_key_aliases_go_to_the_real_host_and_stay_ssh() {
        let aliases = [("invinite".to_string(), "azure-invinite".to_string())];
        let pairs = ssh_to_ssh("invinite", &aliases);
        assert_eq!(
            rewritten(&pairs, "git@azure-invinite:v3/invinite/AppServices/r").as_deref(),
            Some("git@ssh.dev.azure.com:v3/invinite/AppServices/r")
        );
        assert_eq!(
            rewritten(&pairs, "git@ssh.dev.azure.com:v3/invinite/AppServices/r"),
            None,
            "already the real host"
        );
    }

    #[test]
    fn aliases_come_from_the_folders_remotes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(
            dir.path().join(".git/config"),
            "[remote \"origin\"]\n\turl = git@azure-invinite:v3/invinite/AppServices/pseudo-registry\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".gitmodules"),
            "[submodule \"x\"]\n\turl = git@ssh.dev.azure.com:v3/other/P/r\n",
        )
        .unwrap();
        let ws = crate::config::Workspace {
            dir: Some(dir.path().display().to_string()),
            ..Default::default()
        };
        assert_eq!(
            aliases(&ws),
            [("invinite".to_string(), "azure-invinite".to_string())]
        );
    }

    #[test]
    fn paths_cover_both_url_forms() {
        let p = repo("o", "Proj", "proj").git_paths(true);
        assert!(p.contains(&"/o/Proj/_git/proj/info/refs".to_string()));
        assert!(p.contains(&"/o/_git/proj.git/git-receive-pack".to_string()));
        assert_eq!(repo("o", "P", "r").git_paths(true).len(), 12);
        assert!(
            !repo("o", "P", "r")
                .git_paths(false)
                .iter()
                .any(|p| p.ends_with("receive-pack"))
        );
    }
}
