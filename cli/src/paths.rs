//! Where luoto keeps things on the host. macOS and Linux use XDG-style dot directories
//! (`~/.config/luoto`, `~/.local/share/luoto`) so they are easy to find and edit;
//! Windows uses the platform's roaming/local app data. A source build uses `luoto-dev` for
//! `luoto` (`names::instance`). `LUOTO_HOME` overrides both (tests).

use std::path::PathBuf;

use anyhow::{Context, Result};

pub struct Paths {
    pub config: PathBuf,
    pub data: PathBuf,
}

impl Paths {
    pub fn get() -> Result<Self> {
        if let Ok(home) = std::env::var("LUOTO_HOME") {
            let base = PathBuf::from(home);
            return Ok(Paths {
                config: base.join("config"),
                data: base.join("data"),
            });
        }
        #[cfg(windows)]
        {
            let dirs = directories::ProjectDirs::from("", "", crate::names::instance())
                .context("cannot determine the user profile directory")?;
            Ok(Paths {
                config: dirs.config_dir().to_path_buf(),
                data: dirs.data_local_dir().to_path_buf(),
            })
        }
        #[cfg(not(windows))]
        {
            let home = directories::BaseDirs::new()
                .context("cannot determine the home directory")?
                .home_dir()
                .to_path_buf();
            let config = std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"))
                .join(crate::names::instance());
            let data = std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".local/share"))
                .join(crate::names::instance());
            Ok(Paths { config, data })
        }
    }

    pub fn global_config(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    /// Files copied into every env's home on `up` (dotfiles, editor and shell config).
    pub fn home_files(&self) -> PathBuf {
        self.config.join("home")
    }

    pub fn envs_dir(&self) -> PathBuf {
        self.config.join("envs")
    }

    pub fn env_config(&self, name: &str) -> PathBuf {
        self.envs_dir().join(format!("{name}.toml"))
    }

    pub fn env_state(&self, name: &str) -> PathBuf {
        self.data.join("envs").join(name)
    }

    pub fn events_db(&self) -> PathBuf {
        self.data.join("events.db")
    }
}

/// Write a file readable only by the current user.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.write_all(data)?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
