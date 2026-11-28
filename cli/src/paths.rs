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
        let paths = if let Ok(home) = std::env::var("LUOTO_HOME") {
            let base = PathBuf::from(home);
            Paths {
                config: base.join("config"),
                data: base.join("data"),
            }
        } else {
            Self::of(crate::names::instance())?
        };
        paths.keep_private();
        Ok(paths)
    }

    /// Both folders readable by this user alone: they hold the env's egress history, its
    /// configs and logs, which no other user of this machine reads (luoto's runtimes run as
    /// this user, and what a VM mounts lives elsewhere).
    fn keep_private(&self) {
        #[cfg(unix)]
        for dir in [&self.config, &self.data] {
            use std::os::unix::fs::PermissionsExt;
            let open = std::fs::metadata(dir).map(|m| m.permissions().mode() & 0o077 != 0);
            if open.unwrap_or(false) {
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
    }

    /// Where instance `inst` keeps things, `LUOTO_HOME` aside.
    pub fn of(inst: &str) -> Result<Self> {
        #[cfg(windows)]
        {
            let dirs = directories::ProjectDirs::from("", "", inst)
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
                .join(inst);
            let data = std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".local/share"))
                .join(inst);
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

    /// The background watcher's log (`watch.rs`), one for every env.
    pub fn watch_log(&self) -> PathBuf {
        self.data.join("watch.log")
    }

    /// What the env's installs printed (`logs::InstallLog`).
    pub fn install_log(&self, env: &str) -> PathBuf {
        self.env_state(env).join("install.log")
    }
}

/// Write a file readable only by the current user.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    // This process's own: the watcher and a command can write the same file at once.
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
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

#[cfg(all(test, unix))]
mod tests {
    use super::Paths;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn its_folders_are_this_users_alone() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config: dir.path().join("config"),
            data: dir.path().join("data"),
        };
        for d in [&paths.config, &paths.data] {
            std::fs::create_dir(d).unwrap();
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        paths.keep_private();
        for d in [&paths.config, &paths.data] {
            let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", d.display());
        }
    }
}
