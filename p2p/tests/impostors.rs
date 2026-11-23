//! Anyone may announce under any target in the DHT. The client dials the
//! server's key itself (`join_peer`), so it must reach the real server however
//! many others announce under the server's key (`hash(key)`, also its topic).
//!
//! Ignored: peeroxide-dht 1.8.1 does not hold. A DHT node that accepts an
//! ANNOUNCE sets its handshake forwarding for that target to the announcer,
//! whoever announced (`hyperdht.rs`, the ANNOUNCE arm of the request handler),
//! so one announcer under `hash(key)` takes the handshakes meant for the
//! server and the client never connects (SPECIFICATION.md §13.8). Run with
//! `cargo test -p sshcrab-p2p --test impostors -- --ignored`.

use std::time::Duration;

use peeroxide_dht::hyperdht::KeyPair;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "peeroxide-dht forwards handshakes to whoever announced last (SPECIFICATION.md §13.8)"]
async fn announcers_under_the_key_do_not_keep_clients_away() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (boot, _t1) = sshcrab_p2p::run_node("127.0.0.1", 0, &[]).await.unwrap();
    let boot_port = boot.local_port().await.unwrap();
    let bootstrap = vec![format!("127.0.0.1:{boot_port}")];
    let (_n2, _t2) = sshcrab_p2p::run_node("127.0.0.1", 0, &bootstrap).await.unwrap();

    let mut server = sshcrab_p2p::announce(&[7u8; 32], &bootstrap, 8).await.unwrap();
    let key = server.public_key;

    // A swarm with a key of its own, announced under the server's key.
    let mut cfg = peeroxide::SwarmConfig::default();
    cfg.key_pair = Some(KeyPair::generate());
    cfg.dht = sshcrab_p2p::dht_config(&bootstrap);
    let (_task, impostor, _connections) = peeroxide::spawn(cfg).await.unwrap();
    let mut opts = peeroxide::JoinOpts::default();
    opts.server = true;
    opts.client = false;
    impostor.join(peeroxide_dht::crypto::hash(&key), opts).await.unwrap();
    impostor.flush().await.unwrap();

    let conn = tokio::time::timeout(Duration::from_secs(30), sshcrab_p2p::connect(&bootstrap, key, |_| {}))
        .await
        .expect("the real server was not reached")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), server.connections.recv()).await.unwrap().unwrap();
    drop(conn);
}
