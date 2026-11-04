//! The images a release binary runs, pinned by digest. The release workflow builds and signs
//! the images first and compiles their references (its `images.json`) into the binary through
//! `LUOTO_IMAGES`, so `luoto setup` pulls exactly the images that were released with it; a value
//! `parse` would refuse fails the build (build.rs). A binary built from source has none and runs
//! images built locally (`luoto setup --build`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::names;

pub const COMPONENTS: [&str; 4] = ["gate", "vault", "tools", "base"];

#[derive(Deserialize)]
struct Pins {
    images: BTreeMap<String, String>,
}

/// build.rs checks the same rules at compile time; keep the two in step.
fn parse(json: &str) -> Option<BTreeMap<String, String>> {
    let pins: Pins = serde_json::from_str(json).ok()?;
    // Only digest references: a tag could be moved after the release.
    let ok = COMPONENTS
        .iter()
        .all(|c| pins.images.get(*c).is_some_and(|r| r.contains("@sha256:")));
    ok.then_some(pins.images)
}

fn pins() -> Option<&'static BTreeMap<String, String>> {
    static PINS: OnceLock<Option<BTreeMap<String, String>>> = OnceLock::new();
    PINS.get_or_init(|| option_env!("LUOTO_IMAGES").and_then(parse))
        .as_ref()
}

/// Whether this binary carries released image references.
pub fn pinned() -> bool {
    pins().is_some()
}

/// The image for `component`: locally built ones with tag `local` when set (`images` in
/// config.toml), else the release's pinned image, else the `dev` build.
pub fn image(local: Option<&str>, component: &str) -> String {
    match (local, pins().and_then(|p| p.get(component))) {
        (None, Some(r)) => r.clone(),
        (tag, _) => names::image(component, tag.unwrap_or("dev")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_pins_must_be_digests_for_every_component() {
        let full = r#"{"version":"0.1.0","images":{
            "gate":"ghcr.io/eetu/luoto-gate@sha256:aa","vault":"ghcr.io/eetu/luoto-vault@sha256:bb",
            "tools":"ghcr.io/eetu/luoto-tools@sha256:cc","base":"ghcr.io/eetu/luoto-base@sha256:dd"}}"#;
        assert_eq!(
            parse(full).unwrap()["gate"],
            "ghcr.io/eetu/luoto-gate@sha256:aa"
        );
        assert!(parse(&full.replace("@sha256:aa", ":0.1.0")).is_none());
        assert!(parse(r#"{"images":{"gate":"x@sha256:aa"}}"#).is_none());
    }
}
