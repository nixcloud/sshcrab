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
