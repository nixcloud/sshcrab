//! `sshcrab-keygen-ed25519 <keyfile>` (spec §2a): writes an unencrypted ed25519
//! key pair, `<keyfile>` (0600) and `<keyfile>.pub` (0644). No options, no prompts.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sshcrab_proto::keys::{self, Identity};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [path] = args.as_slice() else {
        eprintln!("usage: sshcrab-keygen-ed25519 <keyfile>");
        return ExitCode::from(2);
    };
    match run(Path::new(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sshcrab-keygen-ed25519: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &Path) -> Result<(), String> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !parent.is_dir() {
        // Only ~/.sshcrab is created on demand; any other directory must exist.
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if home.map(|h| h.join(".sshcrab")) == Some(parent.clone()) {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&parent)
                .map_err(|e| format!("{}: {e}", parent.display()))?;
        } else {
            return Err(format!("{}: directory does not exist", parent.display()));
        }
    }

    let comment = format!("{}@{}", username(), hostname());
    let id = Identity::generate();
    id.save(path, &comment).map_err(|e| e.to_string())?;

    println!("Your private key has been saved in {}", path.display());
    println!("Your public key has been saved in {}.pub", path.display());
    println!("The key fingerprint is: {} {comment}", keys::fingerprint(&id.public()));
    println!("Add this line to ~/.sshcrab/authorized_keys on the server:");
    println!("{}", id.public_openssh(&comment));
    Ok(())
}

fn username() -> String {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|u| u.name)
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "user".into())
}

fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".into())
}
