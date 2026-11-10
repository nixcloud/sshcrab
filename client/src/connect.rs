//! Connecting, host-key verification and authentication (spec §6.1, §7.8).

use std::cell::Cell;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sshcrab_proto::channel::SecureConn;
use sshcrab_proto::handshake::{self, HandshakeError};
use sshcrab_proto::hostkeys::{self, Lookup};
use sshcrab_proto::keys::{self, Identity};
use sshcrab_p2p::Stage;
use sshcrab_proto::{p2p, transport};

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

/// DHT lookup plus hole punching (up to about 40 s, spec §13).
const P2P_TIMEOUT: Duration = Duration::from_secs(45);
/// A P2P connection taking longer than this gets a status line.
const STATUS_AFTER: Duration = Duration::from_millis(300);

pub struct Connector {
    pub target: Target,
    identity: Identity,
    hostkeys: PathBuf,
    accept_new: bool,
    bootstrap: Vec<String>,
}

impl Connector {
    pub fn new(target: Target, accept_new: bool, bootstrap: Vec<String>) -> Result<Connector, String> {
        let dir = local::dir()?;
        let key_path = dir.join("id_ed25519");
        if key_path.symlink_metadata().is_err() {
            return Err(format!("no key at {}; create one with: sshcrab-keygen-ed25519 {}", key_path.display(), key_path.display()));
        }
        let identity = Identity::load(&key_path).map_err(|e| e.to_string())?;
        Ok(Connector { target, identity, hostkeys: dir.join("hostkeys"), accept_new, bootstrap })
    }

    /// A `.p2p` address has no port; hostkeys stores 0 for it.
    fn hostkey_port(&self) -> u16 {
        if p2p::parse_address(&self.target.host).is_some() { 0 } else { self.target.port }
    }

    fn label(&self) -> String {
        if p2p::parse_address(&self.target.host).is_some() {
            self.target.host.clone()
        } else {
            format!("{} port {}", self.target.host, self.target.port)
        }
    }

    async fn resolve(&self) -> Result<SocketAddr, ConnectError> {
        let host = hostkeys::normalize_host(&self.target.host);
        let mut addrs = tokio::net::lookup_host((host.as_str(), self.target.port))
            .await
            .map_err(|e| ConnectError::Transient(format!("{}: {e}", self.target.host)))?;
        addrs.next().ok_or_else(|| ConnectError::Transient(format!("{}: no address", self.target.host)))
    }

    /// Through the DHT: lookup and hole punching can take a while (spec §13),
    /// so with `show` a status line on stderr says what it waits for; it is
    /// removed once connected or failed.
    async fn connect_p2p(&self, key: [u8; 32], show: bool) -> Result<transport::Conn, ConnectError> {
        let host = &self.target.host;
        let (stage_tx, stage) = tokio::sync::watch::channel(Stage::JoiningDht);
        let connect = tokio::time::timeout(
            P2P_TIMEOUT,
            sshcrab_p2p::connect(&self.bootstrap, key, |s| {
                let _ = stage_tx.send(s);
            }),
        );
        tokio::pin!(connect);
        let start = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut shown = false;
        let result = loop {
            tokio::select! {
                r = &mut connect => break r,
                _ = tick.tick(), if show => {
                    // Quiet for fast connections, so nothing flickers.
                    if start.elapsed() < STATUS_AFTER {
                        continue;
                    }
                    let what = match *stage.borrow() {
                        Stage::JoiningDht => "joining the DHT",
                        Stage::FindingServer => "finding the server and connecting",
                    };
                    eprint!("\r\x1b[Ksshcrab: {what}… {:.1}s", start.elapsed().as_secs_f32());
                    shown = true;
                }
            }
        };
        if shown {
            eprint!("\r\x1b[K");
        }
        result
            .map_err(|_| ConnectError::Transient(format!("{host}: no connection through the DHT")))?
            .map_err(|e| ConnectError::Transient(format!("{host}: {e}")))
    }

    /// Connect and authenticate. An unknown host key is confirmed (or accepted
    /// with `--accept-new`), stored, and the connection retried.
    pub async fn connect(&self, interactive_prompts: bool) -> Result<SecureConn, ConnectError> {
        for _ in 0..2 {
            let conn = match p2p::parse_address(&self.target.host) {
                Some(key) => self.connect_p2p(key, interactive_prompts && std::io::stderr().is_terminal()).await?,
                None => {
                    let addr = self.resolve().await?;
                    tokio::time::timeout(Duration::from_secs(10), transport::connect(addr))
                        .await
                        .map_err(|_| ConnectError::Transient(format!("{addr}: timed out")))?
                        .map_err(|e| ConnectError::Transient(format!("{addr}: {e}")))?
                }
            };

            let contents = std::fs::read_to_string(&self.hostkeys).unwrap_or_default();
            let unknown = Cell::new(None);
            let mismatch = Cell::new(None);
            let (host, port, label) = (&self.target.host, self.hostkey_port(), self.label());
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
                            "HOST KEY MISMATCH for {label}: the server presented {}, \
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
        let (host, port, label) = (&self.target.host, self.hostkey_port(), self.label());
        let fp = keys::fingerprint(key);
        if !self.accept_new {
            if !interactive_prompts || !std::io::stdin().is_terminal() {
                return Err(ConnectError::Fatal(format!(
                    "unknown host key for {label} ({fp}); use --accept-new to trust it"
                )));
            }
            let ok = ui::confirm(&format!("The host {label} is unknown. Its key fingerprint is {fp}. Trust it?"));
            if !ok {
                return Err(ConnectError::Fatal("host key not trusted".into()));
            }
        }
        hostkeys::append(&self.hostkeys, host, port, key)
            .map_err(|e| ConnectError::Fatal(format!("{}: {e}", self.hostkeys.display())))?;
        eprintln!("Added {label} ({fp}) to ~/.sshcrab/hostkeys");
        Ok(())
    }
}
