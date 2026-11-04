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

macro_rules! presets {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_str!(concat!("../presets/", $name, ".toml")))),*]
    };
}

const PRESETS: &[(&str, &str)] = presets!(
    "debian",
    "ubuntu",
    "alpine",
    "npm",
    "pypi",
    "crates",
    "go",
    "github",
    "toolchains",
    "vscode",
    "docs",
    "maven",
    "gradle",
    "rubygems",
    "composer",
);

pub fn names() -> impl Iterator<Item = &'static str> {
    PRESETS.iter().map(|(n, _)| *n)
}

pub fn get(name: &str) -> Option<Preset> {
    let (n, src) = PRESETS.iter().find(|(n, _)| *n == name)?;
    let mut p: Preset = toml::from_str(src).expect("built-in preset parses");
    p.name = (*n).to_string();
    Some(p)
}

pub fn all() -> Vec<Preset> {
    names().filter_map(get).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{WildcardRisk, wildcard_risk};

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
