//! Shell completion candidates. The shell calls `COMPLETE=<shell> luoto …` while completing,
//! so env names and profiles come from the current config and data, not a generated script.

use clap_complete::engine::CompletionCandidate;
use luoto_shared::{presets, profiles};

use crate::{config, paths::Paths};

pub fn envs() -> Vec<CompletionCandidate> {
    Paths::get()
        .ok()
        .and_then(|p| config::list_envs(&p).ok())
        .unwrap_or_default()
        .into_iter()
        .map(CompletionCandidate::new)
        .collect()
}

pub fn agents() -> Vec<CompletionCandidate> {
    profiles::agent_names()
        .map(|n| described(n, profiles::agent(n).map(|a| a.description)))
        .collect()
}

pub fn editors() -> Vec<CompletionCandidate> {
    profiles::editor_names()
        .map(|n| described(n, profiles::editor(n).map(|e| e.description)))
        .collect()
}

pub fn presets() -> Vec<CompletionCandidate> {
    presets::names()
        .map(|n| described(n, presets::get(n).map(|p| p.description)))
        .collect()
}

fn described(name: &str, description: Option<String>) -> CompletionCandidate {
    CompletionCandidate::new(name).help(description.map(Into::into))
}
