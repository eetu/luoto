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

/// Whole-path match of `path` (no query string) against `pattern`.
pub fn glob_match(pattern: &str, path: &str) -> bool {
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
    fn adversarial_path_is_linear() {
        let path = format!("/{}", "a/".repeat(5000));
        assert!(!glob_match("/**/**/**/**/**/b", &path));
    }
}
