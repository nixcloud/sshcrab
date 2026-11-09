//! `~/.sshcrab` on the client (spec §8).

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use uuid::Uuid;

pub fn dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let dir = PathBuf::from(home).join(".sshcrab");
    if !dir.is_dir() {
        std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(dir)
}

/// `~/.sshcrab/config.toml` (spec §8). Missing file = defaults.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// DHT bootstrap nodes for `.p2p` hosts; empty = the built-in list.
    #[serde(rename = "P2PBootstrap")]
    pub p2p_bootstrap: Vec<String>,
}

impl Config {
    pub fn load() -> Result<Config, String> {
        let path = dir()?.join("config.toml");
        match std::fs::read_to_string(&path) {
            Ok(s) => toml::from_str(&s).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// `--bootstrap` wins over the file, the file over the built-in list.
    pub fn bootstrap(&self, flags: &[String]) -> Vec<String> {
        if !flags.is_empty() {
            flags.to_vec()
        } else if !self.p2p_bootstrap.is_empty() {
            self.p2p_bootstrap.clone()
        } else {
            sshcrab_proto::p2p::DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()).collect()
        }
    }
}

/// `~/.sshcrab/sessions/<PID>/session` while this client is attached.
pub struct SessionFile {
    dir: PathBuf,
}

impl SessionFile {
    pub fn create(id: Uuid) -> Option<SessionFile> {
        let sessions = dir().ok()?.join("sessions");
        let dir = sessions.join(std::process::id().to_string());
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).ok()?;
        std::fs::write(dir.join("session"), format!("{id}\n")).ok()?;
        Some(SessionFile { dir })
    }

    /// Normal exit only; Ctrl+C while disconnected keeps the file (spec §4.7).
    pub fn remove(self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Remove session directories of dead clients older than a week.
pub fn gc() {
    let Ok(sessions) = dir().map(|d| d.join("sessions")) else { return };
    let Ok(entries) = std::fs::read_dir(&sessions) else { return };
    let week = Duration::from_secs(7 * 86400);
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        // Only real directories, never through a symlink.
        let Ok(meta) = std::fs::symlink_metadata(e.path()) else { continue };
        if !meta.is_dir() || std::path::Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        let old = meta.modified().ok().and_then(|m| SystemTime::now().duration_since(m).ok()).is_some_and(|age| age > week);
        if old {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}
