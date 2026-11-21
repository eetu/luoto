//! Package feeds: which service a feed's URL names, and the entry its credential's `feeds`
//! keeps: an Azure DevOps feed (`[credentials.azure_devops]`), a GitHub owner's packages
//! (`[[credentials.github]]`), or a feed of a Gitea, Forgejo or GitLab instance
//! (`[[credentials.git]]` of its host). The service is told from the URL alone: by host for
//! the hosted ones, by path for self-hosted instances, whose hosts are their own.

use anyhow::{Result, bail};

use crate::azure;

/// GitHub Packages' registries, each with the one host its downloads redirect to (signed
/// URLs, no login).
pub const GITHUB_REGISTRIES: [(&str, &str); 4] = [
    ("npm.pkg.github.com", "pkg-npm.githubusercontent.com"),
    (
        "maven.pkg.github.com",
        "github-registry-files.githubusercontent.com",
    ),
    (
        "nuget.pkg.github.com",
        "nugetregistryv2prod.blob.core.windows.net",
    ),
    (
        "rubygems.pkg.github.com",
        "rubygemsregistryv2prod.blob.core.windows.net",
    ),
];

/// A feed, as a URL names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feed {
    Azure(azure::Feed),
    /// An owner's GitHub Packages (every registry of theirs).
    Github {
        owner: String,
    },
    /// A feed on a self-hosted forge: its host (`host` or `host:port`) and where its packages
    /// are.
    Forge {
        host: String,
        scope: Scope,
    },
}

/// Where a self-hosted forge keeps a feed's packages: a path prefix (the instance's own,
/// empty unless it is served under a path) and the feed in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Gitea or Forgejo: an owner's packages, `<prefix>/api/packages/<owner>`.
    Gitea { prefix: String, owner: String },
    /// GitLab: a project's, by its numeric ID.
    GitlabProject { prefix: String, id: String },
    /// GitLab: a group's (its packages link to their projects' paths).
    GitlabGroup { prefix: String, group: String },
    /// GitLab: the instance's npm and Maven endpoints (they link to projects' paths).
    GitlabInstance { prefix: String },
}

impl Scope {
    /// The entry `[[credentials.git]] feeds` keeps: the path the packages are under.
    pub fn entry(&self) -> String {
        match self {
            Scope::Gitea { prefix, owner } => format!("{prefix}/api/packages/{owner}"),
            Scope::GitlabProject { prefix, id } => format!("{prefix}/api/v4/projects/{id}"),
            Scope::GitlabGroup { prefix, group } => format!("{prefix}/api/v4/groups/{group}"),
            Scope::GitlabInstance { prefix } => format!("{prefix}/api/v4/packages"),
        }
    }

    /// The service, as people name it.
    pub fn service(&self) -> &'static str {
        match self {
            Scope::Gitea { .. } => "Gitea or Forgejo",
            _ => "GitLab",
        }
    }

    /// The paths the feed's packages and downloads are under: a GitLab project's packages,
    /// never the rest of its API. A group's or the instance's endpoints link files to their
    /// projects, by ID: every project's packages.
    pub fn paths(&self) -> Vec<String> {
        match self {
            Scope::Gitea { .. } => vec![format!("{}/**", self.entry())],
            Scope::GitlabProject { .. } => vec![format!("{}/packages/**", self.entry())],
            Scope::GitlabGroup { prefix, group } => vec![
                format!("{prefix}/api/v4/groups/{group}/-/packages/**"),
                // Composer's group endpoint is `group`, singular.
                format!("{prefix}/api/v4/group/{group}/-/packages/**"),
                format!("{prefix}/api/v4/projects/*/packages/**"),
            ],
            Scope::GitlabInstance { prefix } => vec![
                format!("{prefix}/api/v4/packages/**"),
                format!("{prefix}/api/v4/projects/*/packages/**"),
            ],
        }
    }

    /// What the token reaches there, for the closing summary.
    pub fn reaches(&self) -> String {
        match self {
            Scope::Gitea { owner, .. } => format!("{owner}'s packages, to install"),
            Scope::GitlabProject { id, .. } => format!("project {id}'s packages, to install"),
            Scope::GitlabGroup { group, .. } => {
                format!("group {group}'s packages and every project's it links to, to install")
            }
            Scope::GitlabInstance { .. } => "every project's packages, to install".into(),
        }
    }
}

impl Feed {
    /// The feed as `luoto feed list` shows it: its service's own short name.
    pub fn label(&self) -> String {
        match self {
            Feed::Azure(f) => f.entry(),
            Feed::Github { owner } => format!("github.com/{owner}"),
            Feed::Forge { host, scope } => format!("{host}{}", scope.entry()),
        }
    }

    /// The service, as people name it.
    pub fn service(&self) -> &'static str {
        match self {
            Feed::Azure(_) => "Azure DevOps",
            Feed::Github { .. } => "GitHub Packages",
            Feed::Forge { scope, .. } => scope.service(),
        }
    }
}

fn unknown(entry: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "`{}` is no feed luoto knows: give the URL your package manager's settings have, of \
         Azure DevOps (`…/_packaging/<feed>/…`), GitHub Packages \
         (`https://npm.pkg.github.com/<owner>`, …), Gitea or Forgejo \
         (`…/api/packages/<owner>/…`) or GitLab (`…/api/v4/projects/<ID>/packages/…`)",
        crate::text::display(entry)
    )
}

/// A name a URL's path segment may be: plain characters, never a dot segment.
fn plain(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// The feed a URL names, as package managers' settings write it: a feed or index URL
/// (credentials in it are dropped), an `.npmrc` key (`//host/path`), or an `.npmrc` scope
/// line (`@owner:registry=https://…`); and `org/project/feed` or `org/feed` for Azure DevOps.
pub fn parse(entry: &str) -> Result<Feed> {
    let e = entry.trim();
    // `@acme:registry=https://npm.pkg.github.com`: the scope names the owner where the URL
    // has none.
    let (scope, e) = match e.split_once(":registry=") {
        Some((s, url)) if s.starts_with('@') => (Some(s.trim_start_matches('@')), url.trim()),
        _ => (None, e),
    };
    // cargo writes a sparse registry's index as `sparse+https://…`.
    let e = e.strip_prefix("sparse+").unwrap_or(e);
    let Some(rest) = e
        .strip_prefix("https://")
        .or_else(|| e.strip_prefix("http://"))
        .or_else(|| e.strip_prefix("//"))
    else {
        if e.contains("://") {
            return Err(unknown(entry));
        }
        // What `luoto feed list` shows: `github.com/<owner>`, `<host>/<feed path>`.
        if let Some(owner) = e.strip_prefix("github.com/") {
            return Ok(Feed::Github {
                owner: github_entry(owner.trim_end_matches('/'))?,
            });
        }
        if e.contains("/api/") {
            return parse(&format!("https://{e}"));
        }
        return azure::parse_feed(e)
            .map(Feed::Azure)
            .map_err(|_| unknown(entry));
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = authority.to_ascii_lowercase();
    let name = host.split(':').next().unwrap_or(&host);
    if azure::is_feed_host(name) {
        return azure::parse_feed(&format!("https://{name}/{path}")).map(Feed::Azure);
    }
    let path = path.split(['?', '#']).next().unwrap_or("");
    let seg: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if GITHUB_REGISTRIES.iter().any(|(h, _)| *h == name) {
        let owner = seg
            .first()
            .map(|o| o.trim_start_matches('@').trim_start_matches("%40"))
            .or(scope)
            .filter(|o| plain(o));
        let Some(owner) = owner else {
            bail!(
                "a GitHub Packages URL names its owner: `https://{name}/<owner>`, or the \
                 `.npmrc` line `@<owner>:registry=https://npm.pkg.github.com`"
            );
        };
        return Ok(Feed::Github {
            owner: owner.to_ascii_lowercase(),
        });
    }
    if crate::text::display(&host) != host || !host_ok(&host) {
        return Err(unknown(entry));
    }
    let scope = forge_scope(&seg).ok_or_else(|| unknown(entry))??;
    Ok(Feed::Forge { host, scope })
}

/// `host` or `host:port`, plain.
fn host_ok(host: &str) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (host, None),
    };
    !name.is_empty()
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.".contains(&b))
        && port.is_none_or(|p| p.parse::<u16>().is_ok())
}

/// A self-hosted forge's feed in a URL's path segments, by where its API puts packages;
/// `None` when the path is none of theirs.
fn forge_scope(seg: &[&str]) -> Option<Result<Scope>> {
    let prefix = |at: usize| -> Option<String> {
        seg[..at]
            .iter()
            .all(|s| plain(s))
            .then(|| seg[..at].iter().map(|s| format!("/{s}")).collect())
    };
    for (at, w) in seg.windows(3).enumerate() {
        if let ["api", "packages", owner] = w {
            let p = prefix(at)?;
            return Some(if plain(owner) {
                Ok(Scope::Gitea {
                    prefix: p,
                    owner: owner.to_ascii_lowercase(),
                })
            } else {
                Err(anyhow::anyhow!("`{owner}` is not an owner's name"))
            });
        }
        if let ["api", "v4", kind] = w {
            let p = prefix(at)?;
            let next = seg.get(at + 3).copied();
            return Some(match (*kind, next) {
                ("packages", _) => Ok(Scope::GitlabInstance { prefix: p }),
                ("projects", Some(id)) if id.bytes().all(|b| b.is_ascii_digit()) => {
                    Ok(Scope::GitlabProject {
                        prefix: p,
                        id: id.to_string(),
                    })
                }
                ("projects", Some(_)) => Err(anyhow::anyhow!(
                    "name a GitLab project by its ID (on its page, under the name), not its \
                     path: `…/api/v4/projects/<ID>/packages/…`"
                )),
                ("groups" | "group", Some(g)) if plain(g) => Ok(Scope::GitlabGroup {
                    prefix: p,
                    group: g.to_ascii_lowercase(),
                }),
                ("groups" | "group", Some(_)) => Err(anyhow::anyhow!(
                    "name a GitLab subgroup by its ID, not its path: \
                     `…/api/v4/groups/<ID>/-/packages/…`"
                )),
                _ => return None,
            });
        }
    }
    None
}

/// The service of a private feed a request to `host` at `path` went to, if it was one: for
/// the hint on its denials.
pub fn service_of(host: &str, path: Option<&str>) -> Option<&'static str> {
    let host = host.to_ascii_lowercase();
    if azure::is_feed_host(&host) {
        return Some("Azure DevOps");
    }
    if GITHUB_REGISTRIES.iter().any(|(h, _)| *h == host) {
        return Some("GitHub Packages");
    }
    let seg: Vec<&str> = path?.split('/').filter(|s| !s.is_empty()).collect();
    match forge_scope(&seg)? {
        Ok(s) => Some(s.service()),
        Err(_) => Some("GitLab"),
    }
}

/// A `[[credentials.git]] feeds` entry, the path its packages are under.
pub fn forge_entry(entry: &str) -> Result<Scope> {
    let seg: Vec<&str> = entry.split('/').filter(|s| !s.is_empty()).collect();
    forge_scope(&seg).unwrap_or_else(|| {
        bail!(
            "`{}` is no feed path: `/api/packages/<owner>` (Gitea, Forgejo), \
             `/api/v4/projects/<ID>`, `/api/v4/groups/<ID>` or `/api/v4/packages` (GitLab)",
            crate::text::display(entry)
        )
    })
}

/// A `[[credentials.github]] feeds` entry, an owner.
pub fn github_entry(entry: &str) -> Result<String> {
    let o = entry.trim().trim_start_matches('@');
    if !plain(o) {
        bail!(
            "credentials.github: feeds are owners (`acme`), not `{}`",
            crate::text::display(entry)
        );
    }
    Ok(o.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forge(url: &str) -> (String, String) {
        match parse(url).unwrap() {
            Feed::Forge { host, scope } => (host, scope.entry()),
            other => panic!("{url}: {other:?}"),
        }
    }

    #[test]
    fn a_feed_url_tells_its_service() {
        for url in [
            "https://pkgs.dev.azure.com/acme/web/_packaging/main/pypi/simple/",
            "acme/web/main",
        ] {
            assert!(matches!(parse(url).unwrap(), Feed::Azure(_)), "{url}");
        }
        for url in [
            "https://npm.pkg.github.com/acme",
            "https://npm.pkg.github.com/@acme",
            "@acme:registry=https://npm.pkg.github.com",
            "@acme:registry=https://npm.pkg.github.com/",
            "https://maven.pkg.github.com/Acme/web",
            "https://nuget.pkg.github.com/acme/index.json",
            "https://rubygems.pkg.github.com/acme",
            "//npm.pkg.github.com/acme/",
        ] {
            assert_eq!(
                parse(url).unwrap(),
                Feed::Github {
                    owner: "acme".into()
                },
                "{url}"
            );
        }
        assert!(parse("https://npm.pkg.github.com").is_err());
        // What `luoto feed list` shows reads back as the same feed.
        for url in [
            "https://npm.pkg.github.com/acme",
            "https://git.acme.internal:3443/api/packages/acme/npm/",
            "https://gitlab.acme.internal/api/v4/projects/12/packages/pypi/simple",
            "https://pkgs.dev.azure.com/acme/web/_packaging/main/pypi/simple/",
        ] {
            let feed = parse(url).unwrap();
            assert_eq!(parse(&feed.label()).unwrap(), feed, "{url}");
        }
        assert_eq!(
            forge("https://git.acme.internal/api/packages/Acme/pypi/simple"),
            ("git.acme.internal".into(), "/api/packages/acme".into())
        );
        assert_eq!(
            forge("@acme:registry=https://code.acme.internal:3000/api/packages/acme/npm/"),
            (
                "code.acme.internal:3000".into(),
                "/api/packages/acme".into()
            )
        );
        assert_eq!(
            forge("https://user:tok@gitlab.acme.internal/api/v4/projects/12/packages/pypi/simple"),
            ("gitlab.acme.internal".into(), "/api/v4/projects/12".into())
        );
        assert_eq!(
            forge("//gitlab.acme.internal/gitlab/api/v4/groups/7/-/packages/npm/"),
            (
                "gitlab.acme.internal".into(),
                "/gitlab/api/v4/groups/7".into()
            )
        );
        assert_eq!(
            forge("https://gitlab.acme.internal/api/v4/packages/npm/"),
            ("gitlab.acme.internal".into(), "/api/v4/packages".into())
        );
        assert_eq!(
            forge("https://gitlab.acme.internal/api/v4/group/7/-/packages/composer/packages.json"),
            ("gitlab.acme.internal".into(), "/api/v4/groups/7".into())
        );
        assert_eq!(
            forge("sparse+https://git.acme.internal/api/packages/acme/cargo/"),
            ("git.acme.internal".into(), "/api/packages/acme".into())
        );
        for bad in [
            "https://gitlab.acme.internal/api/v4/projects/acme%2Fweb/packages/npm/",
            "https://repo.acme.internal/pypi/simple",
            "ftp://x/api/packages/acme",
            "https://x/a/../api/packages/acme",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_forge_feed_reaches_its_packages_and_what_they_link_to() {
        let s = forge_entry("/api/v4/groups/7").unwrap();
        assert_eq!(
            s.paths(),
            [
                "/api/v4/groups/7/-/packages/**",
                "/api/v4/group/7/-/packages/**",
                "/api/v4/projects/*/packages/**"
            ]
        );
        assert_eq!(
            forge_entry("/api/packages/acme").unwrap().paths(),
            ["/api/packages/acme/**"]
        );
        assert_eq!(
            forge_entry("/api/v4/projects/12").unwrap().paths(),
            ["/api/v4/projects/12/packages/**"]
        );
        assert!(forge_entry("/api/v3/x").is_err());
        assert_eq!(github_entry("@Acme").unwrap(), "acme");
        assert!(github_entry("acme/web").is_err());
    }
}
