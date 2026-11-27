//! P2P backend of sshcrab (spec §13), on peeroxide (a Rust HyperDHT).
//!
//! Only the client (`sshcrab`), the `sshcrabd-p2p` helper and the
//! `sshcrab-dht-node` link this crate; sshcrabd itself never does.
//!
//! Our protocol is not changed: its messages travel inside the encrypted
//! peeroxide stream, one stream message per `stream id ‖ message`
//! ([`sshcrab_proto::p2p::body`]).

use std::time::{Duration, Instant};

use bytes::Bytes;
use libudx::{UdxAsyncStream, UdxRuntime};
use peeroxide_dht::hyperdht::{self, HyperDhtConfig, HyperDhtHandle, KeyPair};
use peeroxide_dht::secret_stream::SecretStream;
use sshcrab_proto::p2p::{body, read_frame, write_frame};
use sshcrab_proto::transport::{Conn, MAX_MESSAGE, PipeEnds, Remote};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("{0}")]
    Dht(#[from] hyperdht::HyperDhtError),
    #[error("{0}")]
    Udx(#[from] libudx::UdxError),
    #[error("{0}")]
    Swarm(#[from] peeroxide::SwarmError),
    #[error("the peer presented a different key")]
    WrongPeer,
    #[error("no DHT node reachable (bootstrap: {0})")]
    NoNodes(String),
}

/// DHT settings for `bootstrap` (`host:port` or `ip@host:port`).
pub fn dht_config(bootstrap: &[String]) -> HyperDhtConfig {
    let mut cfg = HyperDhtConfig::default();
    cfg.dht.bootstrap = bootstrap.to_vec();
    cfg
}

/// A running DHT node (`sshcrab-dht-node`): not ephemeral, not firewalled,
/// so others can bootstrap from it. Runs until the returned task ends.
pub async fn run_node(
    host: &str,
    port: u16,
    bootstrap: &[String],
) -> Result<(HyperDhtHandle, tokio::task::JoinHandle<()>), P2pError> {
    let runtime = UdxRuntime::new()?;
    let mut cfg = dht_config(bootstrap);
    cfg.dht.host = host.to_string();
    cfg.dht.port = port;
    cfg.dht.ephemeral = Some(false);
    cfg.dht.firewalled = false;
    let (task, handle, mut server_rx) = hyperdht::spawn(&runtime, cfg).await?;
    let task = tokio::spawn(async move {
        let _runtime = runtime;
        // Handshake events for this node's own key: it serves nothing.
        let drain = async { while server_rx.recv().await.is_some() {} };
        tokio::select! {
            r = task => log::warn!("DHT node stopped: {r:?}"),
            _ = drain => {}
        }
    });
    Ok((handle, task))
}

/// The server side: announced under the key of `seed`, receiving connections.
pub struct Server {
    pub handle: peeroxide::SwarmHandle,
    pub connections: tokio::sync::mpsc::Receiver<peeroxide::SwarmConnection>,
    pub public_key: [u8; 32],
    _task: tokio::task::JoinHandle<()>,
}

/// Join the DHT and announce as a server (helper side).
pub async fn announce(seed: &[u8; 32], bootstrap: &[String], max_peers: usize) -> Result<Server, P2pError> {
    let key_pair = KeyPair::from_seed(*seed);
    let public_key = key_pair.public_key;
    let mut cfg = peeroxide::SwarmConfig::default();
    cfg.key_pair = Some(key_pair);
    cfg.dht = dht_config(bootstrap);
    apply_test_env(&mut cfg);
    cfg.max_peers = max_peers;
    let (task, handle, connections) = peeroxide::spawn(cfg).await?;
    // Announcing into an empty routing table "succeeds" and is only retried
    // after 10 minutes; fail instead, so the caller retries soon.
    if handle.dht().table_size().await.unwrap_or(0) == 0 {
        let _ = handle.destroy().await;
        task.abort();
        return Err(P2pError::NoNodes(bootstrap.join(", ")));
    }
    let mut opts = peeroxide::JoinOpts::default();
    opts.server = true;
    opts.client = false;
    // The topic is the key's own hash, which the swarm announces anyway:
    // no shared topic that would list every sshcrab server.
    handle.join(peeroxide::discovery_key(&public_key), opts).await?;
    handle.flush().await?;
    Ok(Server { handle, connections, public_key, _task: task })
}

/// Where [`connect`] is, for a progress display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Contacting the bootstrap nodes and filling the routing table.
    JoiningDht,
    /// Looking up the server's record, then the handshake (relayed through
    /// DHT nodes) and, behind NAT, hole punching.
    FindingServer,
}

/// Connect to the sshcrabd announced under `remote` (its P2P key). The
/// returned [`Conn`] carries our protocol; a throwaway DHT node and key pair
/// live as long as it does, so nothing about the user ends up in the DHT.
/// `progress` is called as each [`Stage`] begins. Dropping the future (a
/// timeout, Ctrl+C) shuts that DHT node down too.
pub async fn connect(bootstrap: &[String], remote: [u8; 32], progress: impl Fn(Stage)) -> Result<Conn, P2pError> {
    // Through the swarm, like the server: its socket handling (which socket a
    // firewalled node is reachable on, hole punching) is the tested path. The
    // lower-level `HyperDhtHandle::connect` failed between separate hosts.
    let mut cfg = peeroxide::SwarmConfig::default();
    cfg.key_pair = Some(KeyPair::generate());
    cfg.dht = dht_config(bootstrap);
    apply_test_env(&mut cfg);
    cfg.max_peers = 4;
    let start = Instant::now();
    progress(Stage::JoiningDht);
    let (task, handle, mut connections) = peeroxide::spawn(cfg).await?;
    let swarm = Swarm { handle, task };
    if swarm.handle.dht().table_size().await.unwrap_or(0) == 0 {
        return Err(P2pError::NoNodes(bootstrap.join(", ")));
    }
    log::debug!("joined the DHT in {:?}", start.elapsed());
    progress(Stage::FindingServer);
    // Dial the server's key itself rather than every peer announced on its
    // topic (anyone may announce there). Announcers under that target with
    // other keys get no handshakes since peeroxide-dht 1.8.2: see
    // tests/impostors.rs.
    swarm.handle.join_peer(remote).await?;
    // Only the holder of `remote` counts (Noise IK authenticated the key the
    // swarm reports); nothing else should arrive, as we announce nothing.
    let peer = loop {
        let c = connections.recv().await.ok_or(P2pError::WrongPeer)?;
        if c.remote_public_key() == &remote {
            break c;
        }
    };
    log::debug!("connected to {:?} after {:?}", peer.peer.remote_addr, start.elapsed());
    // One connection is all we want: no redialling once it closes.
    let _ = swarm.handle.leave_peer(remote).await;
    let (conn, ends) = Conn::pipe(Remote::P2p(peer.peer.remote_addr));
    tokio::spawn(async move {
        let peer = peer;
        let stream = peer.peer.stream;
        bridge_secret_stream(stream, ends).await;
        // The rest of the connection (socket, swarm) stays alive until here.
        drop(peer.peer.socket);
        drop(swarm);
    });
    Ok(conn)
}

/// A client's swarm, destroyed when dropped.
struct Swarm {
    handle: peeroxide::SwarmHandle,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Swarm {
    fn drop(&mut self) {
        let handle = self.handle.clone();
        let task = self.task.abort_handle();
        // Destroying needs the swarm task; abort it afterwards in any case.
        // Outside a runtime (process exit) there is nothing left to clean up.
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), handle.destroy()).await;
                task.abort();
            });
        } else {
            task.abort();
        }
    }
}

/// Carry a pipe [`Conn`] over a peeroxide stream until either side ends.
async fn bridge_secret_stream(stream: SecretStream<UdxAsyncStream>, ends: PipeEnds) {
    let (mut r, mut w) = stream.into_split();
    let PipeEnds { mut outgoing, incoming, mut closed } = ends;
    let reader = async move {
        while let Ok(Some(msg)) = r.read().await {
            if msg.len() > MAX_MESSAGE + 1 {
                break;
            }
            let Some((&id, data)) = msg.split_first() else { continue };
            if incoming.send((id as u16, Bytes::copy_from_slice(data))).await.is_err() {
                break;
            }
        }
    };
    let writer = async move {
        loop {
            tokio::select! {
                biased;
                msg = outgoing.recv() => match msg {
                    Some((id, data)) => {
                        if w.write(&body(id, &data)).await.is_err() {
                            return;
                        }
                    }
                    None => break,
                },
                _ = async { let _ = closed.wait_for(|c| *c).await; } => {
                    while let Ok((id, data)) = outgoing.try_recv() {
                        if w.write(&body(id, &data)).await.is_err() {
                            return;
                        }
                    }
                    break;
                }
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), w.shutdown()).await;
    };
    tokio::select! {
        _ = reader => {}
        _ = writer => {}
    }
}

/// Relay between a peeroxide stream and a framed byte stream (the helper's
/// socketpair to sshcrabd) without looking inside the messages. Once `stop`
/// becomes true (the helper shuts down), the stream is ended properly, so the
/// client starts reconnecting at once instead of after its idle timeout.
pub async fn relay<S>(stream: SecretStream<UdxAsyncStream>, local: S, mut stop: tokio::sync::watch::Receiver<bool>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut sr, mut sw) = stream.into_split();
    let (mut lr, mut lw) = tokio::io::split(local);
    let up = async move {
        // peer → sshcrabd
        while let Ok(Some(msg)) = sr.read().await {
            if msg.is_empty() || write_frame(&mut lw, &msg).await.is_err() {
                break;
            }
        }
        let _ = lw.shutdown().await;
    };
    let down = async move {
        // sshcrabd → peer
        loop {
            tokio::select! {
                msg = read_frame(&mut lr) => match msg {
                    Ok(Some(msg)) => {
                        if sw.write(&msg).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
                _ = async { let _ = stop.wait_for(|s| *s).await; } => break,
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), sw.shutdown()).await;
    };
    // The connection ends with the first direction that ends.
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
}

/// Test and diagnostic knobs for the client and the helper (not for production):
/// `SSHCRAB_P2P_BIND=<ipv4>` binds the DHT to one address, and
/// `SSHCRAB_P2P_NO_LOCAL=1` turns off peeroxide's same-network shortcut. Together
/// they let one machine play several hosts (127.0.0.2, 127.0.0.3, …).
fn apply_test_env(cfg: &mut peeroxide::SwarmConfig) {
    if let Ok(host) = std::env::var("SSHCRAB_P2P_BIND") {
        cfg.dht.dht.host = host;
    }
    if std::env::var_os("SSHCRAB_P2P_NO_LOCAL").is_some() {
        cfg.local_connection = false;
    }
}
