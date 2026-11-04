//! Git write guard-rails: inspect the ref updates at the start of a git push (GitHub and
//! Azure DevOps), and refuse GitHub GraphQL documents that mutate outside an allowlist.
//! Server-side rulesets remain the real enforcement; these keep a compromised sandbox from
//! the obvious moves.

use graphql_parser::query::{Definition, OperationDefinition, Selection};
use luoto_shared::policy::{AzureGuard, GithubGuard};

/// What a push may update, from either host's guard.
#[derive(Debug, Clone, Copy)]
pub struct PushRules<'a> {
    pub protected_branches: &'a [String],
    pub allow_tags: bool,
    pub allow_branch_delete: bool,
}

impl<'a> From<&'a GithubGuard> for PushRules<'a> {
    fn from(g: &'a GithubGuard) -> Self {
        PushRules {
            protected_branches: &g.protected_branches,
            allow_tags: g.allow_tags,
            allow_branch_delete: g.allow_branch_delete,
        }
    }
}

impl<'a> From<&'a AzureGuard> for PushRules<'a> {
    fn from(g: &'a AzureGuard) -> Self {
        PushRules {
            protected_branches: &g.protected_branches,
            allow_tags: g.allow_tags,
            allow_branch_delete: g.allow_branch_delete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parse {
    NeedMore,
    Invalid(String),
}

/// `owner/repo` (lowercase, no `.git`) from a smart-HTTP path.
pub fn repo_of(path: &str) -> Option<String> {
    let mut it = path.trim_start_matches('/').split('/');
    let owner = it.next()?;
    let repo = it.next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!(
        "{}/{}",
        owner.to_ascii_lowercase(),
        repo.to_ascii_lowercase()
    ))
}

/// `org/project/repo` (lowercase, no `.git`) from an Azure DevOps smart-HTTP path:
/// `/org/project/_git/repo/…`, or `/org/_git/repo/…` for a project's repo of the same name.
pub fn azure_repo_of(path: &str) -> Option<String> {
    let seg: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (org, project, repo) = match seg.as_slice() {
        [org, "_git", repo, ..] => (*org, *repo, *repo),
        [org, project, "_git", repo, ..] => (*org, *project, *repo),
        _ => return None,
    };
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let project = project.strip_suffix(".git").unwrap_or(project);
    if org.is_empty() || project.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{org}/{project}/{repo}").to_ascii_lowercase())
}

/// Parse the pkt-line command list that opens a receive-pack request, up to the flush
/// packet. Returns the updates once the flush has been seen.
pub fn parse_ref_updates(buf: &[u8]) -> Result<Vec<RefUpdate>, Parse> {
    let mut updates = Vec::new();
    let mut pos = 0;
    loop {
        if buf.len() < pos + 4 {
            return Err(Parse::NeedMore);
        }
        let len_hex = std::str::from_utf8(&buf[pos..pos + 4])
            .map_err(|_| Parse::Invalid("bad pkt-line length".into()))?;
        let len = usize::from_str_radix(len_hex, 16)
            .map_err(|_| Parse::Invalid("bad pkt-line length".into()))?;
        if len == 0 {
            return if updates.is_empty() {
                Err(Parse::Invalid("push without ref updates".into()))
            } else {
                Ok(updates)
            };
        }
        if len < 4 {
            return Err(Parse::Invalid("bad pkt-line length".into()));
        }
        if buf.len() < pos + len {
            return Err(Parse::NeedMore);
        }
        let line = &buf[pos + 4..pos + len];
        let line = line.split(|b| *b == 0).next().unwrap_or(line);
        let line = std::str::from_utf8(line)
            .map_err(|_| Parse::Invalid("non-UTF-8 ref update".into()))?
            .trim_end_matches('\n');
        if line.starts_with("shallow ") || line.starts_with("push-cert") {
            pos += len;
            continue;
        }
        let mut parts = line.split(' ');
        let (Some(old), Some(new), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(Parse::Invalid(format!("unexpected push command `{line}`")));
        };
        updates.push(RefUpdate {
            old: old.to_string(),
            new: new.to_string(),
            name: name.to_string(),
        });
        pos += len;
    }
}

fn is_zero(oid: &str) -> bool {
    !oid.is_empty() && oid.bytes().all(|b| b == b'0')
}

pub fn check_updates(guard: PushRules<'_>, updates: &[RefUpdate]) -> Result<(), String> {
    for u in updates {
        if is_zero(&u.new) && !guard.allow_branch_delete {
            return Err(format!(
                "deleting `{}` is not allowed from the sandbox",
                u.name
            ));
        }
        if let Some(tag) = u.name.strip_prefix("refs/tags/") {
            if !guard.allow_tags {
                return Err(format!(
                    "pushing tag `{tag}` is not allowed from the sandbox"
                ));
            }
            continue;
        }
        let Some(branch) = u.name.strip_prefix("refs/heads/") else {
            return Err(format!(
                "pushing `{}` is not allowed (branches only)",
                u.name
            ));
        };
        if guard.protected_branches.iter().any(|p| p == branch) {
            return Err(format!(
                "`{branch}` is protected: push a feature branch and open a pull request"
            ));
        }
    }
    Ok(())
}

pub fn check_graphql(guard: &GithubGuard, body: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "GraphQL body is not JSON".to_string())?;
    if value.is_array() {
        return Err("batched GraphQL requests are not allowed".into());
    }
    let query = value
        .get("query")
        .and_then(|q| q.as_str())
        .ok_or_else(|| "GraphQL body has no query".to_string())?;
    let doc = graphql_parser::parse_query::<&str>(query)
        .map_err(|_| "GraphQL query does not parse".to_string())?;
    for def in &doc.definitions {
        let Definition::Operation(op) = def else {
            continue;
        };
        match op {
            OperationDefinition::SelectionSet(_) | OperationDefinition::Query(_) => {}
            OperationDefinition::Subscription(_) => {
                return Err("GraphQL subscriptions are not allowed".into());
            }
            OperationDefinition::Mutation(m) => {
                for sel in &m.selection_set.items {
                    match sel {
                        Selection::Field(f) => {
                            if !guard.graphql_mutations.iter().any(|a| a == f.name) {
                                return Err(format!(
                                    "GraphQL mutation `{}` is not allowed from the sandbox",
                                    f.name
                                ));
                            }
                        }
                        _ => return Err("fragments at the mutation root are not allowed".into()),
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_paths_name_organization_project_and_repo() {
        assert_eq!(
            azure_repo_of("/Invinite/AppServices/_git/Pseudo-Registry/git-receive-pack").as_deref(),
            Some("invinite/appservices/pseudo-registry")
        );
        assert_eq!(
            azure_repo_of("/o/_git/r.git/git-receive-pack").as_deref(),
            Some("o/r/r")
        );
        assert_eq!(azure_repo_of("/o/p/r/git-receive-pack"), None);
        assert_eq!(azure_repo_of("/o/p/_git//git-receive-pack"), None);
    }

    fn pkt(s: &str) -> String {
        format!("{:04x}{s}", s.len() + 4)
    }

    fn guard() -> GithubGuard {
        GithubGuard {
            repos: vec!["eetu/foo".into()],
            protected_branches: vec!["main".into()],
            graphql_mutations: vec!["createPullRequest".into()],
            ..Default::default()
        }
    }

    const Z: &str = "0000000000000000000000000000000000000000";
    const A: &str = "1111111111111111111111111111111111111111";

    #[test]
    fn parses_and_checks_pushes() {
        let body = format!(
            "{}{}0000PACK",
            pkt(&format!(
                "{Z} {A} refs/heads/feature\0 report-status side-band-64k\n"
            )),
            pkt(&format!("{A} {A} refs/heads/other\n"))
        );
        let ups = parse_ref_updates(body.as_bytes()).unwrap();
        assert_eq!(ups.len(), 2);
        assert!(check_updates((&guard()).into(), &ups).is_ok());

        let main = format!("{}0000", pkt(&format!("{A} {A} refs/heads/main\0caps\n")));
        let ups = parse_ref_updates(main.as_bytes()).unwrap();
        assert!(
            check_updates((&guard()).into(), &ups)
                .unwrap_err()
                .contains("protected")
        );

        let del = format!(
            "{}0000",
            pkt(&format!("{A} {Z} refs/heads/feature\0caps\n"))
        );
        assert!(
            check_updates(
                (&guard()).into(),
                &parse_ref_updates(del.as_bytes()).unwrap()
            )
            .is_err()
        );

        let tag = format!("{}0000", pkt(&format!("{Z} {A} refs/tags/v1\0caps\n")));
        assert!(
            check_updates(
                (&guard()).into(),
                &parse_ref_updates(tag.as_bytes()).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn partial_push_needs_more() {
        let body = pkt(&format!("{Z} {A} refs/heads/feature\0caps\n"));
        assert_eq!(
            parse_ref_updates(&body.as_bytes()[..10]),
            Err(Parse::NeedMore)
        );
        assert_eq!(parse_ref_updates(body.as_bytes()), Err(Parse::NeedMore));
    }

    #[test]
    fn graphql_queries_pass_mutations_filtered() {
        let g = guard();
        assert!(check_graphql(&g, br#"{"query":"query { viewer { login } }"}"#).is_ok());
        assert!(check_graphql(&g, br#"{"query":"{ viewer { login } }"}"#).is_ok());
        assert!(
            check_graphql(
                &g,
                br#"{"query":"mutation { createPullRequest(input:{}) { clientMutationId } }"}"#
            )
            .is_ok()
        );
        assert!(
            check_graphql(
                &g,
                br#"{"query":"mutation { createCommitOnBranch(input:{}) { clientMutationId } }"}"#
            )
            .is_err()
        );
        assert!(
            check_graphql(&g, br#"{"query":"mutation { a: createPullRequest(input:{}) { x } b: addComment(input:{}) { x } }"}"#)
                .is_err()
        );
        assert!(check_graphql(&g, br#"[{"query":"{ viewer { login } }"}]"#).is_err());
        assert!(
            check_graphql(&g, br#"{"query":"mutation { ...F } fragment F on Mutation { addComment(input:{}) { x } }"}"#)
                .is_err()
        );
    }

    #[test]
    fn repo_from_path() {
        assert_eq!(
            repo_of("/Eetu/Foo.git/git-receive-pack").as_deref(),
            Some("eetu/foo")
        );
        assert_eq!(repo_of("/eetu/foo/info/refs").as_deref(), Some("eetu/foo"));
        assert_eq!(repo_of("/"), None);
    }
}
