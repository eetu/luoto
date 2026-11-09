//! Built-in egress presets, shipped as TOML data so adding an ecosystem is a file, not code.

use serde::Deserialize;

use crate::policy::Rule;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    #[serde(skip)]
    pub name: String,
    pub description: String,
    /// Files whose presence in a project folder suggests this preset at `luoto init`.
    #[serde(default)]
    pub detect: Vec<String>,
    /// mise tools whose installs need these hosts: a tool name (`node`), a backend
    /// (`npm:*`) or `*` for any. Granted while an install runs if the env lacks the preset.
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    /// Environment for the env's shells, as agents set theirs: what turns a tool's update
    /// checks and telemetry off.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
}

impl Preset {
    /// Whether installing mise tool `tool` (`node`, `npm:typescript`) needs this preset.
    pub fn serves_tool(&self, tool: &str) -> bool {
        let backend = tool.split_once(':').map(|(b, _)| b);
        self.tools.iter().any(|t| match t.strip_suffix(":*") {
            _ if t == "*" => true,
            Some(b) => backend == Some(b),
            None => t == tool,
        })
    }
}

const PRESETS: &[(&str, &str)] = crate::embed!(
    "presets";
    "debian",
    "ubuntu",
    "alpine",
    "npm",
    "pypi",
    "crates",
    "go",
    "github",
    "github-releases",
    "toolchains",
    "vscode",
    "docs",
    "maven",
    "gradle",
    "rubygems",
    "composer",
    "terraform",
    "opentofu",
);

pub fn names() -> impl Iterator<Item = &'static str> {
    PRESETS.iter().map(|(n, _)| *n)
}

pub fn get(name: &str) -> Option<Preset> {
    crate::load(PRESETS, name, |p: &mut Preset| &mut p.name)
}

pub fn all() -> Vec<Preset> {
    names().filter_map(get).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{WildcardRisk, wildcard_risk};
    use crate::policy::{CompiledRule, Decision, DenyReason, Policy, RequestInfo};
    use chrono::Utc;

    /// The policy of an env that selects `names`.
    fn policy_of(names: &[&str]) -> Policy {
        let rules = names
            .iter()
            .flat_map(|n| {
                get(n)
                    .unwrap()
                    .rules
                    .into_iter()
                    .enumerate()
                    .map(move |(i, rule)| CompiledRule {
                        id: format!("{n}-{i}"),
                        origin: format!("preset:{n}"),
                        rule,
                    })
            })
            .collect();
        Policy {
            rules,
            ..Default::default()
        }
    }

    fn decide(p: &Policy, host: &str, path: &str) -> Decision {
        let req = RequestInfo {
            host,
            port: 443,
            method: "GET",
            path,
            websocket: false,
            content_length: None,
        };
        p.decide(&req, Utc::now())
    }

    #[test]
    fn go_modules_only_from_known_hosts() {
        let p = policy_of(&["go"]);
        for (host, path) in [
            ("proxy.golang.org", "/github.com/!burnt!sushi/toml/@v/list"),
            ("proxy.golang.org", "/golang.org/x/net/@v/v0.30.0.zip"),
            (
                "proxy.golang.org",
                "/golang.org/toolchain/@v/v0.0.1-go1.23.0.linux-amd64.zip",
            ),
            ("proxy.golang.org", "/gopkg.in/yaml.v3/@latest"),
            // A 403 here would stop the go command; the proxy's 404 sends it to sum.golang.org.
            ("proxy.golang.org", "/sumdb/sum.golang.org/supported"),
            (
                "proxy.golang.org",
                "/sumdb/sum.golang.org/lookup/go.uber.org/zap@v1.27.0",
            ),
            ("sum.golang.org", "/lookup/k8s.io/client-go@v0.31.0"),
            ("sum.golang.org", "/tile/8/0/x123/456"),
            ("sum.golang.org", "/latest"),
        ] {
            assert!(
                matches!(decide(&p, host, path), Decision::Allow { .. }),
                "{host}{path}"
            );
        }
        for (host, path) in [
            ("proxy.golang.org", "/filippo.io/edwards25519/@v/list"),
            ("proxy.golang.org", "/github.com.evil.example/x/@v/list"),
            ("proxy.golang.org", "/evil.example/github.com/x/@v/list"),
            (
                "proxy.golang.org",
                "/sumdb/sum.golang.org/lookup/evil.example/x@v1.0.0",
            ),
            ("sum.golang.org", "/lookup/evil.example/x@v1.0.0"),
        ] {
            assert_eq!(
                decide(&p, host, path),
                Decision::Deny(DenyReason::PathNotAllowed),
                "{host}{path}"
            );
        }
    }

    #[test]
    fn github_release_files_only_with_the_presets_that_need_them() {
        let asset = "/github-production-release-asset/1/x";
        let download = "/hetznercloud/terraform-provider-hcloud/releases/download/v1.49.1/x.zip";
        let p = policy_of(&["github", "toolchains"]);
        for host in [
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
        ] {
            assert_eq!(decide(&p, host, asset), Decision::Deny(DenyReason::NoRule));
        }
        // The redirect to the file still answers; the file doesn't.
        assert!(matches!(
            decide(&p, "github.com", download),
            Decision::Allow { .. }
        ));
        for n in ["github-releases", "terraform", "opentofu"] {
            let p = policy_of(&[n]);
            assert!(
                matches!(
                    decide(&p, "release-assets.githubusercontent.com", asset),
                    Decision::Allow { .. }
                ),
                "{n}"
            );
            assert!(
                matches!(decide(&p, "github.com", download), Decision::Allow { .. }),
                "{n}"
            );
        }
        // Every install opens them while it runs.
        let releases = get("github-releases").unwrap();
        assert!(releases.serves_tool("python") && releases.serves_tool("aqua:cli/cli"));
    }

    #[test]
    fn every_preset_parses_and_uses_safe_hosts() {
        for p in all() {
            assert!(!p.rules.is_empty(), "{} has rules", p.name);
            for r in &p.rules {
                let risk = wildcard_risk(&r.host);
                assert!(
                    matches!(risk, WildcardRisk::None),
                    "preset {} host {} is a risky wildcard ({risk:?})",
                    p.name,
                    r.host
                );
            }
        }
    }

    #[test]
    fn tool_patterns() {
        let npm = get("npm").unwrap();
        assert!(npm.serves_tool("npm:typescript"));
        assert!(npm.serves_tool("yarn"));
        assert!(!npm.serves_tool("node"));
        assert!(get("toolchains").unwrap().serves_tool("java"));
    }
}
