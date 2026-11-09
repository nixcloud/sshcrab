//! Ed25519 keys in OpenSSH format (spec §2a, §3, §7.8).
//!
//! Keys are always unencrypted. Files are created with `O_CREAT|O_EXCL` and
//! `O_NOFOLLOW`, and loading refuses keys whose mode is not 0600.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// `O_NOFOLLOW` (Linux).
const O_NOFOLLOW: i32 = 0o400000;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("{path}: {err}")]
    Io { path: String, err: std::io::Error },
    #[error("{0} already exists, not overwriting")]
    Exists(String),
    #[error("{path} permissions are {mode:04o}, expected 0600. Fix with: chmod 600 {path}")]
    Permissions { path: String, mode: u32 },
    #[error("{0}: not an OpenSSH private key")]
    Format(String),
    #[error("{0}: key is encrypted; sshcrab only supports unencrypted keys")]
    Encrypted(String),
    #[error("{0}: not an ed25519 key")]
    NotEd25519(String),
}

fn io(path: &Path, err: std::io::Error) -> KeyError {
    KeyError::Io { path: path.display().to_string(), err }
}

/// An Ed25519 key pair.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// A fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).expect("OS random number generator");
        Identity { signing: SigningKey::from_bytes(&seed) }
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// Seed of the P2P key (spec §13.2): derived, so the host key itself never
    /// reaches the P2P stack, and stable for as long as the host key is.
    pub fn p2p_seed(&self) -> Zeroizing<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(crate::p2p::SEED_LABEL);
        h.update(self.signing.to_bytes());
        Zeroizing::new(h.finalize().into())
    }

    fn to_ssh(&self, comment: &str) -> PrivateKey {
        let keypair = Ed25519Keypair::from_seed(&self.signing.to_bytes());
        PrivateKey::new(KeypairData::Ed25519(keypair), comment).expect("ed25519 key")
    }

    /// Load an unencrypted OpenSSH ed25519 private key with mode 0600.
    pub fn load(path: &Path) -> Result<Identity, KeyError> {
        let p = path.display().to_string();
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
            .map_err(|e| io(path, e))?;
        let mode = file.metadata().map_err(|e| io(path, e))?.mode() & 0o7777;
        if mode != 0o600 {
            return Err(KeyError::Permissions { path: p, mode });
        }
        let mut pem = Zeroizing::new(String::new());
        file.read_to_string(&mut pem).map_err(|e| io(path, e))?;
        let key = PrivateKey::from_openssh(pem.as_bytes()).map_err(|_| KeyError::Format(p.clone()))?;
        if key.is_encrypted() {
            return Err(KeyError::Encrypted(p));
        }
        match key.key_data() {
            KeypairData::Ed25519(kp) => {
                let seed = Zeroizing::new(kp.private.to_bytes());
                Ok(Identity { signing: SigningKey::from_bytes(&seed) })
            }
            _ => Err(KeyError::NotEd25519(p)),
        }
    }

    /// Write `path` (0600) and `path.pub` (0644). Never overwrites, never follows symlinks.
    pub fn save(&self, path: &Path, comment: &str) -> Result<(), KeyError> {
        let pub_path = path.with_file_name(format!(
            "{}.pub",
            path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
        ));
        for p in [path, pub_path.as_path()] {
            if p.symlink_metadata().is_ok() {
                return Err(KeyError::Exists(p.display().to_string()));
            }
        }
        let pem = self.to_ssh(comment).to_openssh(LineEnding::LF).map_err(|_| KeyError::Format(path.display().to_string()))?;
        write_new(path, 0o600, pem.as_bytes())?;
        let line = format!("{}\n", self.public_openssh(comment));
        write_new(&pub_path, 0o644, line.as_bytes())?;
        Ok(())
    }

    /// `ssh-ed25519 AAAA… comment`
    pub fn public_openssh(&self, comment: &str) -> String {
        public_openssh(&self.public(), comment)
    }
}

fn write_new(path: &Path, mode: u32, data: &[u8]) -> Result<(), KeyError> {
    let mut f: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => KeyError::Exists(path.display().to_string()),
            _ => io(path, e),
        })?;
    // The umask may have narrowed the mode; make it exact.
    f.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|e| io(path, e))?;
    f.write_all(data).map_err(|e| io(path, e))?;
    f.sync_all().map_err(|e| io(path, e))
}

pub fn public_openssh(key: &[u8; 32], comment: &str) -> String {
    let data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(*key));
    PublicKey::new(data, comment).to_openssh().expect("ed25519 public key")
}

/// Parse `ssh-ed25519 AAAA… [comment]`.
pub fn parse_public_openssh(line: &str) -> Option<[u8; 32]> {
    match PublicKey::from_openssh(line.trim()).ok()?.key_data() {
        KeyData::Ed25519(k) => Some(k.0),
        _ => None,
    }
}

/// `SHA256:…` fingerprint as printed by OpenSSH.
pub fn fingerprint(key: &[u8; 32]) -> String {
    let data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(*key));
    PublicKey::new(data, "").fingerprint(HashAlg::Sha256).to_string()
}

pub fn verify(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(key), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&key) else { return false };
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip_and_refusals() {
        let dir = std::env::temp_dir().join(format!("sshcrab-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("mykey");

        let id = Identity::generate();
        id.save(&path, "user@host").unwrap();
        assert!(matches!(id.save(&path, "x"), Err(KeyError::Exists(_))));

        let loaded = Identity::load(&path).unwrap();
        assert_eq!(loaded.public(), id.public());
        let pub_line = std::fs::read_to_string(dir.join("mykey.pub")).unwrap();
        assert_eq!(parse_public_openssh(&pub_line), Some(id.public()));
        assert!(pub_line.trim_end().ends_with("user@host"));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Identity::load(&path).err().unwrap().to_string();
        assert!(err.contains("permissions are 0644, expected 0600. Fix with: chmod 600"), "{err}");

        let sig = id.sign(b"msg");
        assert!(verify(&id.public(), b"msg", &sig));
        assert!(!verify(&id.public(), b"msh", &sig));
        assert!(fingerprint(&id.public()).starts_with("SHA256:"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
