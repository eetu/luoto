//! `luoto upgrade`: put the latest release where this binary lives. Script and tarball installs
//! run the installer built into this binary (the same install.sh as `curl … | sh`), so the
//! only download is the release itself, checked as the script checks it; Homebrew, Scoop and
//! source builds are pointed at their own update.

use std::io::Write;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};

const INSTALLER: &str = include_str!("../../install.sh");
const REPO: &str = "eetu/luoto";

/// The latest release's version, from GitHub's redirect to its tag; None before the first
/// release. An error means GitHub couldn't be asked.
pub fn latest() -> Result<Option<String>> {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let out = Command::new("curl")
        .args([
            "-fsSLI",
            "--max-time",
            "10",
            "-o",
            null,
            "-w",
            "%{url_effective}",
        ])
        .arg(format!("https://github.com/{REPO}/releases/latest"))
        .stderr(Stdio::null())
        .output()
        .context("run curl")?;
    if !out.status.success() {
        bail!("cannot reach GitHub");
    }
    let url = String::from_utf8_lossy(&out.stdout).into_owned();
    let Some((_, v)) = url.split_once("/tag/v") else {
        return Ok(None);
    };
    let ok = !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'));
    Ok(ok.then(|| v.to_string()))
}

/// Whether `candidate` is a later version than `current` (dotted numbers; a pre-release part
/// such as `-beta.1` counts as older than the release itself).
pub fn newer(candidate: &str, current: &str) -> bool {
    let key = |v: &str| {
        let (main, pre) = v.split_once('-').map_or((v, None), |(m, p)| (m, Some(p)));
        let nums: Vec<u64> = main.split('.').map(|n| n.parse().unwrap_or(0)).collect();
        (nums, pre.is_none(), pre.map(str::to_string))
    };
    key(candidate) > key(current)
}

pub fn upgrade() -> Result<ExitCode> {
    let current = luoto_shared::VERSION;
    let Some(latest) = latest()? else {
        println!("no luoto release is published yet");
        return Ok(ExitCode::SUCCESS);
    };
    if !newer(&latest, current) {
        println!("luoto {current} is the latest release");
        return Ok(ExitCode::SUCCESS);
    }
    let exe = std::env::current_exe()?.canonicalize()?;
    let path = exe.display().to_string();
    let lower = path.to_lowercase();
    let managed = if lower.contains("/cellar/") || lower.contains("brew/") {
        Some("installed with Homebrew: `brew upgrade luoto`")
    } else if lower.contains("\\scoop\\") {
        Some("installed with Scoop: `scoop update luoto`")
    } else if lower.contains("/target/") || lower.contains("/.cargo/bin/") {
        Some("built from source: pull, then `just install-cli`")
    } else if cfg!(windows) {
        Some("download it from the GitHub releases page")
    } else {
        None
    };
    if let Some(how) = managed {
        println!("luoto {latest} is out ({current} here); {how}");
        return Ok(ExitCode::SUCCESS);
    }
    let dir = exe.parent().context("the binary's directory")?;
    let mut child = Command::new("sh")
        .arg("-s")
        .env("LUOTO_VERSION", &latest)
        .env("LUOTO_INSTALL_DIR", dir)
        .stdin(Stdio::piped())
        .spawn()
        .context("run the installer")?;
    child
        .stdin
        .take()
        .context("installer stdin")?
        .write_all(INSTALLER.as_bytes())?;
    if !child.wait()?.success() {
        bail!("the upgrade failed; luoto {current} is unchanged");
    }
    println!(
        "next: `luoto setup` gets this version's images, then `luoto up --recreate` moves each \
         env onto them (its volumes are kept)"
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_order_numerically_and_pre_releases_first() {
        assert!(newer("0.10.0", "0.9.3"));
        assert!(newer("0.2.0", "0.2.0-beta.1"));
        assert!(!newer("0.2.0-beta.1", "0.2.0"));
        assert!(!newer("0.1.0", "0.1.0"));
    }
}
