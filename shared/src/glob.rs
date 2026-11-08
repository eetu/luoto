//! Path globs for policy rules: `*` matches within one segment, `**` across segments.
//! Matching is a linear-space DP, so an attacker-chosen path cannot make it blow up.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Lit(u8),
    Star,
    DoubleStar,
}

fn tokenize(pattern: &str) -> Vec<Tok> {
    let b = pattern.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'*' {
            if b.get(i + 1) == Some(&b'*') {
                out.push(Tok::DoubleStar);
                i += 2;
            } else {
                out.push(Tok::Star);
                i += 1;
            }
        } else {
            out.push(Tok::Lit(b[i]));
            i += 1;
        }
    }
    out
}

/// Does `path` match one of `patterns`? No patterns match every path. `ignore_case` is for
/// hosts whose paths are case-insensitive.
pub fn matches_any(patterns: &[String], ignore_case: bool, path: &str) -> bool {
    patterns.is_empty()
        || patterns.iter().any(|p| {
            if ignore_case {
                glob_match_any_case(p, path)
            } else {
                glob_match(p, path)
            }
        })
}

/// [`glob_match`] without regard to ASCII case.
pub fn glob_match_any_case(pattern: &str, path: &str) -> bool {
    glob_match(&pattern.to_ascii_lowercase(), &path.to_ascii_lowercase())
}

/// Whole-path match of `path` (no query string) against `pattern`. A pattern ending in `/**`
/// also matches the path it is under (`/serde/**` matches `/serde`): registries serve a
/// package's metadata there and its files below, and a rule for one is meant for both.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    pattern
        .strip_suffix("/**")
        .is_some_and(|dir| !dir.is_empty() && dp_match(dir, path))
        || dp_match(pattern, path)
}

/// Does `outer` match every path `inner` matches? A `true` is always right; a `false` may only
/// mean the containment could not be shown, which is the safe answer for a grant that must stay
/// within what was asked.
pub fn covers(outer: &str, inner: &str) -> bool {
    // What `glob_match` matches: the pattern itself, and for `dir/**` also `dir`.
    let parts = |p: &str| {
        let dir = p.strip_suffix("/**").filter(|d| !d.is_empty());
        std::iter::once(tokenize(p))
            .chain(dir.map(tokenize))
            .collect::<Vec<_>>()
    };
    let outer = parts(outer);
    parts(inner)
        .iter()
        .all(|i| outer.iter().any(|o| tokens_cover(o, i)))
}

/// Every token of `inner` taken whole by a token of `outer`: a literal by the same literal, a
/// run of `*` and literals other than `/` by `*`, any run by `**`.
fn tokens_cover(outer: &[Tok], inner: &[Tok]) -> bool {
    // prev[j]: outer's tokens so far cover inner[..j]
    let mut prev = vec![false; inner.len() + 1];
    prev[0] = true;
    for tok in outer {
        let mut cur = vec![false; inner.len() + 1];
        cur[0] = prev[0] && !matches!(tok, Tok::Lit(_));
        for j in 1..=inner.len() {
            let t = &inner[j - 1];
            cur[j] = match tok {
                Tok::Lit(_) => prev[j - 1] && t == tok,
                Tok::Star => {
                    prev[j]
                        || (cur[j - 1]
                            && (*t == Tok::Star || matches!(t, Tok::Lit(c) if *c != b'/')))
                }
                Tok::DoubleStar => prev[j] || cur[j - 1],
            };
        }
        prev = cur;
    }
    prev[inner.len()]
}

fn dp_match(pattern: &str, path: &str) -> bool {
    let toks = tokenize(pattern);
    let s = path.as_bytes();
    // prev[j]: tokens[..i] match s[..j]
    let mut prev = vec![false; s.len() + 1];
    prev[0] = true;
    for tok in &toks {
        let mut cur = vec![false; s.len() + 1];
        match tok {
            Tok::Lit(c) => {
                for j in 1..=s.len() {
                    cur[j] = prev[j - 1] && s[j - 1] == *c;
                }
            }
            Tok::Star => {
                cur[0] = prev[0];
                for j in 1..=s.len() {
                    cur[j] = prev[j] || (cur[j - 1] && s[j - 1] != b'/');
                }
            }
            Tok::DoubleStar => {
                cur[0] = prev[0];
                for j in 1..=s.len() {
                    cur[j] = prev[j] || cur[j - 1];
                }
            }
        }
        prev = cur;
    }
    prev[s.len()]
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn literal_and_wildcards() {
        assert!(glob_match("/v1/messages", "/v1/messages"));
        assert!(!glob_match("/v1/messages", "/v1/messages/batches"));
        assert!(glob_match("/repos/*/foo", "/repos/eetu/foo"));
        assert!(!glob_match("/repos/*/foo", "/repos/a/b/foo"));
        assert!(glob_match("/repos/eetu/foo/**", "/repos/eetu/foo/pulls/1"));
        assert!(glob_match("/repos/eetu/foo/**", "/repos/eetu/foo/"));
        assert!(!glob_match(
            "/repos/eetu/foo/**",
            "/repos/eetu/foobar/pulls"
        ));
        assert!(glob_match(
            "/**/git-upload-pack",
            "/eetu/foo.git/git-upload-pack"
        ));
        assert!(glob_match("**", "/anything/at/all"));
    }

    #[test]
    fn a_trailing_double_star_covers_its_directory() {
        assert!(glob_match("/basedpyright/**", "/basedpyright"));
        assert!(glob_match(
            "/basedpyright/**",
            "/basedpyright/-/basedpyright-1.0.0.tgz"
        ));
        assert!(!glob_match("/basedpyright/**", "/basedpyright-x"));
        assert!(!glob_match("/basedpyright/**", "/based"));
        assert!(glob_match("/repos/*/**", "/repos/eetu"));
        assert!(!glob_match("/**", ""));
    }

    #[test]
    fn covers_only_what_the_outer_pattern_matches() {
        use super::covers;
        for (outer, inner) in [
            ("/a/**", "/a/b/**"),
            ("/a/**", "/a/b"),
            ("/a/**", "/a"),
            ("/a/**", "/a/*/c"),
            ("/a/*", "/a/b"),
            ("/a/*", "/a/b*"),
            ("/v1/*/x", "/v1/foo/x"),
            ("**", "/anything/**"),
            ("/a/b", "/a/b"),
        ] {
            assert!(covers(outer, inner), "{outer} covers {inner}");
        }
        for (outer, inner) in [
            ("/a/*", "/a/**"),
            ("/a/*", "/a/b/c"),
            ("/a/b", "/a/*"),
            ("/a/**", "/ab"),
            ("/a/**", "**"),
            ("/a/**", "/b/**"),
            ("/a/*/c", "/a/**/c"),
            ("/a", "/a/**"),
        ] {
            assert!(!covers(outer, inner), "{outer} doesn't cover {inner}");
        }
    }

    #[test]
    fn adversarial_path_is_linear() {
        let path = format!("/{}", "a/".repeat(5000));
        assert!(!glob_match("/**/**/**/**/**/b", &path));
    }
}
