//! Linux account checks without PAM (spec §7.5). Blocking; run via `spawn_blocking`.

use std::ffi::CString;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::{Gid, Group, Uid, User};
use sshcrab_proto::keys;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub home: PathBuf,
    pub shell: PathBuf,
}

impl Account {
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }
}

/// `Err(None)` = generic failure, `Err(Some(text))` = `/etc/nologin` contents.
pub fn authorize(cfg: &Config, username: &str, key: &[u8; 32]) -> Result<Account, Option<String>> {
    let deny = |why: &str| {
        log::info!("auth refused for {username:?}: {why}");
        Err(None)
    };
    let Some(mut user) = User::from_name(username).ok().flatten() else { return deny("no such user") };
    let privileged = Uid::effective().is_root();
    if !privileged {
        if user.uid != Uid::effective() {
            return deny("daemon not running as root; only its own user may log in");
        }
        // Test mode only: a non-root daemon serves just its own account, so
        // these cannot grant anything the daemon's user does not already have.
        if let Some(home) = std::env::var_os("SSHCRABD_HOME") {
            user.dir = home.into();
        }
        if let Some(shell) = std::env::var_os("SSHCRABD_SHELL") {
            user.shell = shell.into();
        }
    }
    if user.uid.is_root() && !cfg.permit_root_login {
        return deny("PermitRootLogin = false");
    }
    if !cfg.allow_users.is_empty() && !cfg.allow_users.iter().any(|u| u == username) {
        return deny("not in AllowUsers");
    }
    let cname = CString::new(username).map_err(|_| None)?;
    let groups: Vec<u32> = nix::unistd::getgrouplist(&cname, user.gid)
        .map(|g| g.into_iter().map(Gid::as_raw).collect())
        .unwrap_or_else(|_| vec![user.gid.as_raw()]);
    if !cfg.allow_groups.is_empty() {
        let allowed = cfg.allow_groups.iter().any(|g| {
            Group::from_name(g).ok().flatten().is_some_and(|g| groups.contains(&g.gid.as_raw()))
        });
        if !allowed {
            return deny("not in AllowGroups");
        }
    }
    if account_expired(username) {
        return deny("account expired");
    }
    if !key_authorized(cfg, &user, key) {
        return deny("key not in authorized_keys");
    }
    // Only now, after the key matched, may the client learn the nologin text.
    if !user.uid.is_root() {
        if let Ok(text) = std::fs::read_to_string("/etc/nologin") {
            log::info!("auth refused for {username:?}: /etc/nologin");
            let text: String = text.chars().take(1024).collect();
            return Err(Some(text));
        }
    }
    let shell = if user.shell.as_os_str().is_empty() { PathBuf::from("/bin/sh") } else { user.shell };
    Ok(Account { name: user.name, uid: user.uid.as_raw(), gid: user.gid.as_raw(), groups, home: user.dir, shell })
}

/// shadow field 8: account expiration in days since the epoch.
fn account_expired(username: &str) -> bool {
    let Ok(shadow) = std::fs::read_to_string("/etc/shadow") else { return false };
    let today = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() / 86400).unwrap_or(0);
    shadow
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.first() == Some(&username))
        .and_then(|f| f.get(7).and_then(|e| e.parse::<u64>().ok()))
        .is_some_and(|expire| expire <= today)
}

/// StrictModes: `~`, `~/.sshcrab` and the file must be owned by the user or root
/// and not writable by group/others; `.sshcrab` and the file must not be symlinks.
fn strict_ok(path: &Path, uid: u32, allow_symlink: bool) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return false };
    if meta.file_type().is_symlink() && !allow_symlink {
        log::info!("{}: is a symlink", path.display());
        return false;
    }
    let meta = if meta.file_type().is_symlink() {
        match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return false,
        }
    } else {
        meta
    };
    let ok = (meta.uid() == uid || meta.uid() == 0) && meta.mode() & 0o022 == 0;
    if !ok {
        log::info!("{}: bad ownership or modes (StrictModes)", path.display());
    }
    ok
}

fn key_authorized(cfg: &Config, user: &User, key: &[u8; 32]) -> bool {
    let matches = |contents: &str| {
        contents
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(keys::parse_public_openssh)
            .any(|k| &k == key)
    };
    // Root-managed keys first (`AuthorizedKeysDir`, e.g. from the NixOS module):
    // the directory and the file must belong to root.
    if !cfg.authorized_keys_dir.is_empty() && !user.name.starts_with('.') {
        let dir = Path::new(&cfg.authorized_keys_dir);
        let file = dir.join(&user.name);
        if file.exists() && strict_ok(dir, 0, true) && strict_ok(&file, 0, true) {
            if let Some(contents) = read_limited(&file) {
                if matches(&contents) {
                    return true;
                }
            }
        }
    }
    let uid = user.uid.as_raw();
    let dir = user.dir.join(".sshcrab");
    let file = dir.join("authorized_keys");
    if !(strict_ok(&user.dir, uid, true) && strict_ok(&dir, uid, false) && strict_ok(&file, uid, false)) {
        return false;
    }
    let Some(contents) = read_as_user(&file, uid) else { return false };
    matches(&contents)
}

fn read_limited(path: &Path) -> Option<String> {
    let mut s = String::new();
    std::fs::File::open(path).ok()?.take(256 * 1024).read_to_string(&mut s).ok()?;
    Some(s)
}

/// Read with the user's filesystem uid so root privileges cannot be abused
/// through the user's files. `setfsuid` is per-thread, and this runs on a
/// blocking-pool thread that restores it before returning.
fn read_as_user(path: &Path, uid: u32) -> Option<String> {
    let privileged = Uid::effective().is_root();
    if privileged {
        nix::unistd::setfsuid(Uid::from_raw(uid));
    }
    let res = (|| {
        let mut f = std::fs::OpenOptions::new().read(true).custom_flags(0o400000).open(path).ok()?;
        let mut s = String::new();
        f.by_ref().take(256 * 1024).read_to_string(&mut s).ok()?;
        Some(s)
    })();
    if privileged {
        nix::unistd::setfsuid(Uid::from_raw(0));
    }
    res
}
