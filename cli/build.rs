fn main() {
    // Re-embed the UI bundle whenever the frontend is rebuilt (rust-embed cannot see new files).
    println!("cargo:rerun-if-changed=../frontend/dist");
    // A release compiles its image pins in (release.rs); a value that doesn't pin every image
    // by digest fails the build rather than ship a binary that falls back to unpinned images.
    println!("cargo:rerun-if-env-changed=LUOTO_IMAGES");
    if let Ok(json) = std::env::var("LUOTO_IMAGES")
        && let Err(e) = check(&json)
    {
        panic!("LUOTO_IMAGES is not a valid images.json: {e}");
    }
}

/// release.rs `parse`'s rules: `images` maps every component to a digest reference, and every
/// value in it is a string. Keep the two in step.
fn check(json: &str) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let images = v
        .get("images")
        .and_then(|i| i.as_object())
        .ok_or("no `images` object")?;
    if images.values().any(|r| !r.is_string()) {
        return Err("every image reference is a string".into());
    }
    for c in ["gate", "vault", "tools", "base"] {
        match images.get(c).and_then(|r| r.as_str()) {
            Some(r) if r.contains("@sha256:") => {}
            _ => return Err(format!("`{c}` is not pinned by digest")),
        }
    }
    Ok(())
}
