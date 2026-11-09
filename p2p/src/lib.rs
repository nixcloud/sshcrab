//! P2P backend of sshcrab (spec §13), on peeroxide (a Rust HyperDHT).
//!
//! Only the client (`sshcrab`), the `sshcrabd-p2p` helper and the
//! `sshcrab-dht-node` link this crate; sshcrabd itself never does.
//!
//! Our protocol is not changed: its messages travel inside the encrypted
//! peeroxide stream, one stream message per `stream id ‖ message`
//! ([`sshcrab_proto::p2p::body`]).

use std::time::Duration;

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
    cfg.max_peers = max_peers;
    let (task, handle, connections) = peeroxide::spawn(cfg).await?;
    let mut opts = peeroxide::JoinOpts::default();
    opts.server = true;
    opts.client = false;
    // The topic is the key's own hash, which the swarm announces anyway:
    // no shared topic that would list every sshcrab server.
    handle.join(peeroxide::discovery_key(&public_key), opts).await?;
    handle.flush().await?;
    Ok(Server { handle, connections, public_key, _task: task })
}

/// Connect to the sshcrabd announced under `remote` (its P2P key). The
/// returned [`Conn`] carries our protocol; a throwaway DHT node and key pair
/// live as long as it does, so nothing about the user ends up in the DHT.
pub async fn connect(bootstrap: &[String], remote: [u8; 32]) -> Result<Conn, P2pError> {
    let runtime = UdxRuntime::new()?;
    let (task, dht, _server_rx) = hyperdht::spawn(&runtime, dht_config(bootstrap)).await?;
    let result = async {
        dht.bootstrapped().await?;
        let key_pair = KeyPair::generate();
        let peer = dht.connect(&key_pair, remote, &runtime).await?;
        // Noise IK already guarantees this; checked anyway, it is the whole point.
        if peer.remote_public_key != remote {
            return Err(P2pError::WrongPeer);
        }
        Ok(peer)
    }
    .await;
    let peer = match result {
        Ok(p) => p,
        Err(e) => {
            let _ = dht.destroy().await;
            task.abort();
            return Err(e);
        }
    };
    let (conn, ends) = Conn::pipe(Remote::P2p(peer.remote_addr));
    tokio::spawn(async move {
        let peer = peer;
        let stream = peer.stream;
        bridge_secret_stream(stream, ends).await;
        // `peer.socket` and the rest of the connection stay alive until here.
        let _ = dht.destroy().await;
        task.abort();
        drop(runtime);
    });
    Ok(conn)
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
/// socketpair to sshcrabd) without looking inside the messages.
pub async fn relay<S>(stream: SecretStream<UdxAsyncStream>, local: S)
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
        while let Ok(Some(msg)) = read_frame(&mut lr).await {
            if sw.write(&msg).await.is_err() {
                break;
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
