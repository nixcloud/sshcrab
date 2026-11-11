//! A server gives a connection's `max_peers` slot back once the connection is
//! dropped (patched peeroxide, vendor/peeroxide/SSHCRAB-PATCH.md). Upstream
//! kept it, so after `max_peers` connections in total, clients included, the
//! helper accepted no more until it restarted.

use std::time::Duration;

const MAX_PEERS: usize = 2;

#[tokio::test(flavor = "multi_thread")]
async fn ended_connections_give_their_slot_back() {
    let _ = env_logger::builder().is_test(true).try_init();
    tokio::time::timeout(Duration::from_secs(120), run()).await.expect("timed out");
}

async fn run() {
    let (boot, _t1) = sshcrab_p2p::run_node("127.0.0.1", 0, &[]).await.unwrap();
    let boot_port = boot.local_port().await.unwrap();
    let bootstrap = vec![format!("127.0.0.1:{boot_port}")];
    let (_n2, _t2) = sshcrab_p2p::run_node("127.0.0.1", 0, &bootstrap).await.unwrap();

    let seed = [7u8; 32];
    let mut server = sshcrab_p2p::announce(&seed, &bootstrap, MAX_PEERS).await.unwrap();
    let key = server.public_key;
    let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(peer) = server.connections.recv().await {
            let _ = accepted_tx.send(peer);
        }
    });

    for i in 1..=MAX_PEERS + 2 {
        let conn = tokio::time::timeout(Duration::from_secs(20), sshcrab_p2p::connect(&bootstrap, key, |_| {}))
            .await
            .unwrap_or_else(|_| panic!("connection {i} was not accepted"))
            .unwrap();
        let peer = tokio::time::timeout(Duration::from_secs(5), accepted.recv()).await.unwrap().unwrap();
        // Both ends go away; the server's slot must be free again.
        drop(peer);
        drop(conn);
    }
}
