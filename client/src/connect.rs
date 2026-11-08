//! Connecting, host-key verification and authentication (spec §6.1, §7.8).

use std::cell::Cell;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use sshcrab_proto::channel::SecureConn;
use sshcrab_proto::handshake::{self, HandshakeError};
use sshcrab_proto::hostkeys::{self, Lookup};
use sshcrab_proto::keys::{self, Identity};
use sshcrab_proto::transport;

use crate::{local, ui};

#[derive(Debug, Clone)]
pub struct Target {
    pub user: String,
    pub host: String,
    pub port: u16,
}

pub enum ConnectError {
    /// Worth retrying (network).
    Transient(String),
    /// Retrying cannot help (host key, authentication).
    Fatal(String),
}

impl ConnectError {
    pub fn message(&self) -> &str {
        match self {
            ConnectError::Transient(m) | ConnectError::Fatal(m) => m,
        }
    }
}

pub struct Connector {
    pub target: Target,
    identity: Identity,
    hostkeys: PathBuf,
    accept_new: bool,
}

impl Connector {
    pub fn new(target: Target, accept_new: bool) -> Result<Connector, String> {
        let dir = local::dir()?;
        let key_path = dir.join("id_ed25519");
        if key_path.symlink_metadata().is_err() {
            return Err(format!("no key at {}; create one with: sshcrab-keygen-ed25519 {}", key_path.display(), key_path.display()));
        }
        let identity = Identity::load(&key_path).map_err(|e| e.to_string())?;
        Ok(Connector { target, identity, hostkeys: dir.join("hostkeys"), accept_new })
    }

    async fn resolve(&self) -> Result<SocketAddr, ConnectError> {
        let host = hostkeys::normalize_host(&self.target.host);
        let mut addrs = tokio::net::lookup_host((host.as_str(), self.target.port))
            .await
            .map_err(|e| ConnectError::Transient(format!("{}: {e}", self.target.host)))?;
        addrs.next().ok_or_else(|| ConnectError::Transient(format!("{}: no address", self.target.host)))
    }

    /// Connect and authenticate. An unknown host key is confirmed (or accepted
    /// with `--accept-new`), stored, and the connection retried.
    pub async fn connect(&self, interactive_prompts: bool) -> Result<SecureConn, ConnectError> {
        for _ in 0..2 {
            let addr = self.resolve().await?;
            let conn = tokio::time::timeout(Duration::from_secs(10), transport::connect(addr))
                .await
                .map_err(|_| ConnectError::Transient(format!("{addr}: timed out")))?
                .map_err(|e| ConnectError::Transient(format!("{addr}: {e}")))?;

            let contents = std::fs::read_to_string(&self.hostkeys).unwrap_or_default();
            let unknown = Cell::new(None);
            let mismatch = Cell::new(None);
            let (host, port) = (&self.target.host, self.target.port);
            let check = |key: &[u8; 32]| match hostkeys::lookup(&contents, host, port, key) {
                Lookup::Known => Ok(()),
                Lookup::Mismatch { line } => {
                    mismatch.set(Some((line, *key)));
                    Err("mismatch".into())
                }
                Lookup::Unknown => {
                    unknown.set(Some(*key));
                    Err("unknown".into())
                }
            };
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                handshake::client(conn, &self.target.user, &self.identity, check),
            )
            .await
            .map_err(|_| ConnectError::Transient("handshake timed out".into()))?;
            match result {
                Ok(sc) => return Ok(sc),
                Err(HandshakeError::HostKeyRejected(_)) => {
                    if let Some((line, key)) = mismatch.get() {
                        return Err(ConnectError::Fatal(format!(
                            "HOST KEY MISMATCH for {host} port {port}: the server presented {}, \
                             which does not match ~/.sshcrab/hostkeys:{line}\n\
                             If the host key was changed on purpose, delete that line and connect again.",
                            keys::fingerprint(&key)
                        )));
                    }
                    let key = unknown.get().expect("unknown or mismatch");
                    self.trust_new(&key, interactive_prompts)?;
                }
                Err(HandshakeError::AuthFailed { message }) => {
                    let mut msg = format!("{}@{host}: authentication failed", self.target.user);
                    if let Some(m) = message {
                        msg = format!("{msg}\n{}", ui::sanitize(&m));
                    }
                    return Err(ConnectError::Fatal(msg));
                }
                Err(HandshakeError::BadServerSignature) => {
                    return Err(ConnectError::Fatal("the server's host key signature is invalid".into()));
                }
                Err(e) => return Err(ConnectError::Transient(e.to_string())),
            }
        }
        Err(ConnectError::Transient("host key was stored, but the server key changed again".into()))
    }

    fn trust_new(&self, key: &[u8; 32], interactive_prompts: bool) -> Result<(), ConnectError> {
        let (host, port) = (&self.target.host, self.target.port);
        let fp = keys::fingerprint(key);
        if !self.accept_new {
            if !interactive_prompts || !std::io::stdin().is_terminal() {
                return Err(ConnectError::Fatal(format!(
                    "unknown host key for {host} port {port} ({fp}); use --accept-new to trust it"
                )));
            }
            let ok = ui::confirm(&format!("The host {host} port {port} is unknown. Its key fingerprint is {fp}. Trust it?"));
            if !ok {
                return Err(ConnectError::Fatal("host key not trusted".into()));
            }
        }
        hostkeys::append(&self.hostkeys, host, port, key)
            .map_err(|e| ConnectError::Fatal(format!("{}: {e}", self.hostkeys.display())))?;
        eprintln!("Added {host} port {port} ({fp}) to ~/.sshcrab/hostkeys");
        Ok(())
    }
}
