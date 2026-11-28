//! Guards that read a request body: forge write guard-rails (the ref updates at the start of
//! a git push to GitHub, Azure DevOps or any `[[credentials.git]]` host, GitHub GraphQL
//! documents that mutate outside an allowlist) and model API requests that ask the provider to
//! reach the network. Server-side rulesets remain the real enforcement for forges; these keep
//! a compromised sandbox from the obvious moves.

use bytes::BytesMut;
use graphql_parser::query::{Definition, OperationDefinition, Selection};
use http::HeaderMap;
use http::header::CONTENT_ENCODING;
use http_body_util::BodyExt;
use luoto_shared::forges;
use luoto_shared::policy::{AzureGuard, BodyDeny, GitGuard, GithubGuard, JsonBody, Policy};

use crate::body::{Body, collect_limited, full, prefixed};

/// The most of a body a guard reads before it decides.
const MAX_READ: usize = 1 << 20;
/// The most of a model API request the gate reads to check it: the most the APIs take.
const MAX_JSON: usize = 32 << 20;

/// Run the guards that apply to a request, and hand back the body to forward: what a guard
/// read of it, then the rest.
pub async fn check(
    policy: &Policy,
    host: &str,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Result<Body, String> {
    let denies: Vec<&BodyDeny> = policy
        .body_denies
        .iter()
        .filter(|d| d.applies(host, method, path))
        .collect();
    if !denies.is_empty() {
        return check_json(&denies, headers, body).await;
    }
    if method != "POST" {
        return Ok(body);
    }
    // Git hosts route paths without regard to case, as their rules match them.
    if path.to_ascii_lowercase().ends_with("/git-receive-pack") {
        let push = if host == forges::GITHUB
            && let Some(g) = &policy.github
        {
            Some((
                repo_of(path).is_some_and(|r| g.repos.contains(&r)),
                PushRules::from(g),
            ))
        } else if host == forges::AZURE_DEVOPS
            && let Some(g) = &policy.azure_devops
        {
            Some((
                azure_repo_of(path).is_some_and(|r| g.repos.contains(&r)),
                PushRules::from(g),
            ))
        } else {
            policy
                .git
                .iter()
                .find(|g| g.host.eq_ignore_ascii_case(host))
                .map(|g| {
                    (
                        git_repo_of(path).is_some_and(|r| g.repos.contains(&r)),
                        PushRules::from(g),
                    )
                })
        };
        if let Some((granted, rules)) = push {
            return guard_push(headers, body, granted, rules).await;
        }
    }
    if host == forges::GITHUB_API
        && path.eq_ignore_ascii_case("/graphql")
        && let Some(g) = &policy.github
    {
        let bytes = collect_limited(body, MAX_READ)
            .await
            .map_err(|_| "GraphQL body too large".to_string())?;
        check_graphql(g, &bytes)?;
        return Ok(full(bytes));
    }
    Ok(body)
}

/// A request whose body may ask for what the env doesn't allow (a model API reaching the
/// network, a pull request completed): read whole (a body the check can't read is refused)
/// and forwarded unless it asks.
async fn check_json(denies: &[&BodyDeny], headers: &HeaderMap, body: Body) -> Result<Body, String> {
    if headers
        .get(CONTENT_ENCODING)
        .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err("a compressed request body to this API can't be checked".into());
    }
    let bytes = collect_limited(body, MAX_JSON).await.map_err(|_| {
        format!(
            "a request body over {} MiB to this API can't be checked",
            MAX_JSON >> 20
        )
    })?;
    let json = JsonBody::parse(&bytes)
        .ok_or("the request body is not a JSON object the gate can check (each key once)")?;
    if let Some(d) = denies.iter().find(|d| d.asks(&json)) {
        return Err(d.reason.clone());
    }
    Ok(full(bytes))
}

/// A push to a guarded git host: only to the env's granted repositories, uncompressed, and
/// with every ref update allowed.
async fn guard_push(
    headers: &HeaderMap,
    body: Body,
    granted: bool,
    rules: PushRules<'_>,
) -> Result<Body, String> {
    if !granted {
        return Err("pushes are only allowed to the env's granted repositories".into());
    }
    if headers.contains_key(CONTENT_ENCODING) {
        return Err("compressed pushes cannot be inspected".into());
    }
    inspect_push(body, rules).await
}

/// Read the ref-update commands at the front of a push, check them, and hand back a body
/// that replays what was read followed by the rest of the stream.
async fn inspect_push(mut body: Body, rules: PushRules<'_>) -> Result<Body, String> {
    let mut buf = BytesMut::new();
    loop {
        match parse_ref_updates(&buf) {
            Ok(updates) => {
                check_updates(rules, &updates)?;
                break;
            }
            Err(Parse::FlushOnly) => return probe(buf, body).await,
            Err(Parse::Invalid(e)) => return Err(e),
            Err(Parse::NeedMore) => {}
        }
        if buf.len() > MAX_READ {
            return Err("push command list too large".into());
        }
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    buf.extend_from_slice(&data);
                }
            }
            Some(Err(e)) => return Err(format!("reading push: {e}")),
            None => return Err("truncated push".into()),
        }
    }
    Ok(prefixed(buf.freeze(), body))
}

/// git's probe before a push larger than its `http.postBuffer`: a body of one flush packet,
/// which updates nothing. Anything after the flush makes it a push without ref updates.
async fn probe(buf: BytesMut, mut body: Body) -> Result<Body, String> {
    let mut len = buf.len();
    while len <= FLUSH.len() {
        match body.frame().await {
            Some(Ok(frame)) => len += frame.into_data().map_or(0, |d| d.len()),
            Some(Err(e)) => return Err(format!("reading push: {e}")),
            None => return Ok(full(buf.freeze())),
        }
    }
    Err("push without ref updates".into())
}

const FLUSH: &[u8] = b"0000";

/// What a push may update, from either host's guard. Deleting a ref is never allowed.
#[derive(Debug, Clone, Copy)]
struct PushRules<'a> {
    protected_branches: &'a [String],
    allow_tags: bool,
}

impl<'a> From<&'a GithubGuard> for PushRules<'a> {
    fn from(g: &'a GithubGuard) -> Self {
        PushRules {
            protected_branches: &g.protected_branches,
            allow_tags: g.allow_tags,
        }
    }
}

impl<'a> From<&'a GitGuard> for PushRules<'a> {
    fn from(g: &'a GitGuard) -> Self {
        PushRules {
            protected_branches: &g.protected_branches,
            allow_tags: g.allow_tags,
        }
    }
}

impl<'a> From<&'a AzureGuard> for PushRules<'a> {
    fn from(g: &'a AzureGuard) -> Self {
        PushRules {
            protected_branches: &g.protected_branches,
            allow_tags: g.allow_tags,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RefUpdate {
    old: String,
    new: String,
    name: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Parse {
    NeedMore,
    /// A flush packet first: no commands at all.
    FlushOnly,
    Invalid(String),
}

/// Whether capability list `caps` asks for `feature` as git's receive-pack reads it
/// (`parse_feature_request`): at its start or after any whitespace, and followed by its end,
/// whitespace or `=value`.
fn asks_for(caps: &[u8], feature: &[u8]) -> bool {
    let space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    caps.windows(feature.len()).enumerate().any(|(i, w)| {
        w == feature
            && (i == 0 || space(&caps[i - 1]))
            && caps
                .get(i + feature.len())
                .is_none_or(|b| space(b) || *b == b'=')
    })
}

/// `owner/repo` (lowercase, no `.git`) from a smart-HTTP path.
fn repo_of(path: &str) -> Option<String> {
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

/// The repository path (lowercase, no `.git`) of a push on any git host: what comes before
/// `/git-receive-pack`, as deep as the forge nests groups (`group/sub/repo`).
fn git_repo_of(path: &str) -> Option<String> {
    let lower = path.trim_start_matches('/').to_ascii_lowercase();
    let repo = lower.strip_suffix("/git-receive-pack")?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    let plain = !repo.is_empty()
        && !repo
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..");
    plain.then(|| repo.to_string())
}

/// `org/project/repo` (lowercase, no `.git`) from an Azure DevOps smart-HTTP path:
/// `/org/project/_git/repo/…`, or `/org/_git/repo/…` for a project's repo of the same name.
fn azure_repo_of(path: &str) -> Option<String> {
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
fn parse_ref_updates(buf: &[u8]) -> Result<Vec<RefUpdate>, Parse> {
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
            return if pos == 0 {
                Err(Parse::FlushOnly)
            } else if updates.is_empty() {
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
        let raw = &buf[pos + 4..pos + len];
        let mut fields = raw.split(|b| *b == 0);
        let line = fields.next().unwrap_or(raw);
        // Push options reach the forge's own handlers past the ref checks: on GitLab they open
        // and merge merge requests, set CI variables and skip secret scanning.
        if fields.any(|caps| asks_for(caps, b"push-options")) {
            return Err(Parse::Invalid(
                "push options are not allowed from the sandbox".into(),
            ));
        }
        let line = std::str::from_utf8(line)
            .map_err(|_| Parse::Invalid("non-UTF-8 ref update".into()))?
            .trim_end_matches('\n');
        if line.starts_with("shallow ") {
            pos += len;
            continue;
        }
        // git runs the commands inside a certificate, which this parser would not see.
        if line.starts_with("push-cert") {
            return Err(Parse::Invalid(
                "signed pushes are not allowed from the sandbox".into(),
            ));
        }
        let parts: Vec<&str> = line.split(' ').collect();
        let [old, new, name] = parts[..] else {
            return Err(Parse::Invalid(format!(
                "unexpected push command `{}`",
                line.escape_debug()
            )));
        };
        if !is_oid(old) || !is_oid(new) || !is_ref_name(name) {
            return Err(Parse::Invalid(format!(
                "unexpected push command `{}`",
                line.escape_debug()
            )));
        }
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

/// A SHA-1 or SHA-256 object ID.
fn is_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A ref name git's `check-ref-format` would take: one the guard and git read alike.
fn is_ref_name(s: &str) -> bool {
    s.starts_with("refs/")
        && !s.ends_with(['/', '.'])
        && !s.ends_with(".lock")
        && !s.contains("..")
        && !s.contains("//")
        && !s.contains("/.")
        && !s.contains("@{")
        && !s
            .bytes()
            .any(|b| b < 0x20 || b == 0x7f || b" ~^:?*[\\".contains(&b))
}

/// `name` without `prefix`, compared without case: refs on a case-insensitive store (macOS,
/// Windows, Azure DevOps) are one ref in any case.
fn strip_prefix_ci<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let head = name.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &name[prefix.len()..])
}

fn check_updates(guard: PushRules<'_>, updates: &[RefUpdate]) -> Result<(), String> {
    for u in updates {
        if is_zero(&u.new) {
            return Err(format!(
                "deleting `{}` is not allowed from the sandbox",
                u.name
            ));
        }
        if let Some(tag) = strip_prefix_ci(&u.name, "refs/tags/") {
            if !guard.allow_tags {
                return Err(format!(
                    "pushing tag `{tag}` is not allowed from the sandbox"
                ));
            }
            continue;
        }
        let Some(branch) = strip_prefix_ci(&u.name, "refs/heads/") else {
            return Err(format!(
                "pushing `{}` is not allowed (branches only)",
                u.name
            ));
        };
        if guard
            .protected_branches
            .iter()
            .any(|p| p.eq_ignore_ascii_case(branch))
        {
            return Err(format!(
                "`{branch}` is protected: push a feature branch and open a pull request"
            ));
        }
    }
    Ok(())
}

fn check_graphql(guard: &GithubGuard, body: &[u8]) -> Result<(), String> {
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
                                    "GraphQL mutation `{}` is not allowed from the sandbox: \
                                     on a repository the env may write, use the REST API \
                                     (`gh api repos/<owner>/<repo>/…`), or the user adds it \
                                     to `graphql_mutations` of the env's GitHub credential",
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
    fn any_git_host_names_its_repo_before_receive_pack() {
        assert_eq!(
            git_repo_of("/Group/Sub/Repo.git/git-receive-pack").as_deref(),
            Some("group/sub/repo")
        );
        assert_eq!(git_repo_of("/o/r/git-receive-pack").as_deref(), Some("o/r"));
        assert_eq!(git_repo_of("/o/../r/git-receive-pack"), None);
        assert_eq!(git_repo_of("/git-receive-pack"), None);
        assert_eq!(git_repo_of("/o/r/info/refs"), None);
    }

    #[test]
    fn azure_paths_name_organization_project_and_repo() {
        assert_eq!(
            azure_repo_of("/Fabrikam/Apps/_git/Web-Api/git-receive-pack").as_deref(),
            Some("fabrikam/apps/web-api")
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
            repos: vec!["octo/foo".into()],
            protected_branches: vec!["main".into()],
            graphql_mutations: vec!["createPullRequest".into()],
            ..Default::default()
        }
    }

    const Z: &str = "0000000000000000000000000000000000000000";
    const A: &str = "1111111111111111111111111111111111111111";

    #[test]
    fn push_options_are_refused_however_git_would_read_them() {
        for caps in [
            "report-status push-options side-band-64k\n",
            "push-options",
            "report-status\tpush-options",
            "report-status\rpush-options\n",
            "report-status push-options=1",
            "report-status\x0bpush-options",
        ] {
            let body = format!(
                "{}0000",
                pkt(&format!("{Z} {A} refs/heads/feature\0{caps}"))
            );
            assert!(
                matches!(
                    parse_ref_updates(body.as_bytes()),
                    Err(Parse::Invalid(m)) if m.contains("push options")
                ),
                "{caps:?}"
            );
        }
        // Another feature that merely contains the name is no request for it.
        let other = format!(
            "{}0000",
            pkt(&format!(
                "{Z} {A} refs/heads/feature\0report-status no-push-optionsx\n"
            ))
        );
        assert!(parse_ref_updates(other.as_bytes()).is_ok());
    }

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
    fn signed_pushes_and_smuggled_commands_are_refused() {
        // git runs the commands after the certificate's blank line.
        let cert = format!(
            "{}{}{}0000",
            pkt("push-cert\0report-status\n"),
            pkt(&format!(
                "{A} {A} refs/heads/ok\n\n{A} {Z} refs/heads/main\n"
            )),
            pkt("push-cert-end\n")
        );
        assert!(matches!(
            parse_ref_updates(cert.as_bytes()),
            Err(Parse::Invalid(m)) if m.contains("signed pushes")
        ));
        for line in [
            format!("{A} {A} refs/heads/ok\n\n{A} {Z} refs/heads/main\n"),
            format!("{A} {A} refs/heads/ok extra\n"),
            format!("{A} {A}\n"),
            format!("{A} xyz refs/heads/ok\n"),
            format!("{A} {A} heads/ok\n"),
            format!("{A} {A} refs/heads/a..b\n"),
            format!("{A} {A} refs/heads/a\tb\n"),
            format!("{A} {A} refs/heads/x.lock\n"),
        ] {
            let body = format!("{}0000", pkt(&line));
            assert!(
                matches!(parse_ref_updates(body.as_bytes()), Err(Parse::Invalid(_))),
                "{line:?}"
            );
        }
        let sha256 = "a".repeat(64);
        let ok = format!("{}0000", pkt(&format!("{sha256} {sha256} refs/heads/x\n")));
        assert!(parse_ref_updates(ok.as_bytes()).is_ok());
    }

    #[test]
    fn protected_branches_and_tags_match_without_case() {
        for name in ["refs/heads/MAIN", "refs/HEADS/Main", "refs/Heads/main"] {
            let body = format!("{}0000", pkt(&format!("{A} {A} {name}\n")));
            let ups = parse_ref_updates(body.as_bytes()).unwrap();
            assert!(
                check_updates((&guard()).into(), &ups)
                    .unwrap_err()
                    .contains("protected"),
                "{name}"
            );
        }
        let tag = format!("{}0000", pkt(&format!("{Z} {A} refs/TAGS/v1\n")));
        let ups = parse_ref_updates(tag.as_bytes()).unwrap();
        assert!(
            check_updates((&guard()).into(), &ups)
                .unwrap_err()
                .contains("tag")
        );
    }

    #[tokio::test]
    async fn gits_probe_before_a_large_push_passes_and_nothing_after_it() {
        let g = guard();
        let rules = PushRules::from(&g);
        let body = inspect_push(full(&b"0000"[..]), rules).await.unwrap();
        assert_eq!(&body.collect().await.unwrap().to_bytes()[..], b"0000");
        for after in [&b"0000PACK"[..], b"00000000"] {
            let err = inspect_push(full(after), rules).await.err().unwrap();
            assert!(err.contains("without ref updates"), "{err}");
        }
        let shallow = format!("{}0000", pkt(&format!("shallow {A}\n")));
        assert_eq!(
            parse_ref_updates(shallow.as_bytes()),
            Err(Parse::Invalid("push without ref updates".into()))
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
            repo_of("/Octo/Foo.git/git-receive-pack").as_deref(),
            Some("octo/foo")
        );
        assert_eq!(repo_of("/octo/foo/info/refs").as_deref(), Some("octo/foo"));
        assert_eq!(repo_of("/"), None);
    }
}
