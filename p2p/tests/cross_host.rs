//! Imperative check of peeroxide alone between "different hosts" on one
//! machine: DHT nodes on 127.0.0.1, server on 127.0.0.2, client on 127.0.0.3,
//! same-network shortcut off. No sshcrab code in the data path.
//!
//!     RUST_LOG=debug cargo test -p sshcrab-p2p --test cross_host -- --nocapture

use std::time::Duration;

use peeroxide::{JoinOpts, KeyPair, SwarmConfig, discovery_key};

async fn swarm(host: &str, bootstrap: &[String], key: KeyPair) -> (peeroxide::SwarmHandle, tokio::sync::mpsc::Receiver<peeroxide::SwarmConnection>) {
    let mut cfg = SwarmConfig::default();
    cfg.key_pair = Some(key.clone());
    cfg.dht = sshcrab_p2p::dht_config(bootstrap);
    cfg.dht.dht.host = host.to_string();
    cfg.local_connection = false;
    let (_task, handle, rx) = peeroxide::spawn(cfg).await.unwrap();
    (handle, rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn peeroxide_between_loopback_hosts() {
    let _ = env_logger::builder().is_test(true).try_init();
    tokio::time::timeout(Duration::from_secs(120), run()).await.expect("timed out");
}

async fn run() {
    // Four DHT nodes on 127.0.0.1 (NAT classification wants at least three).
    let (n0, _t0) = sshcrab_p2p::run_node("127.0.0.1", 0, &[]).await.unwrap();
    let bootstrap = vec![format!("127.0.0.1:{}", n0.local_port().await.unwrap())];
    let mut keep = vec![];
    for _ in 0..3 {
        keep.push(sshcrab_p2p::run_node("127.0.0.1", 0, &bootstrap).await.unwrap());
    }

    let server_key = KeyPair::generate();
    let topic = discovery_key(&server_key.public_key);
    let (server, mut server_rx) = swarm("127.0.0.2", &bootstrap, server_key.clone()).await;
    let mut o = JoinOpts::default();
    o.server = true;
    o.client = false;
    server.join(topic, o).await.unwrap();
    server.flush().await.unwrap();
    eprintln!("== server announced");

    let (client, mut client_rx) = swarm("127.0.0.3", &bootstrap, KeyPair::generate()).await;
    let mut o = JoinOpts::default();
    o.server = false;
    o.client = true;
    client.join(topic, o).await.unwrap();

    let server_side = tokio::spawn(async move {
        let mut c = server_rx.recv().await.expect("server connection");
        eprintln!("== server got a connection");
        let msg = c.peer.stream.read().await.unwrap().unwrap();
        c.peer.stream.write(&msg).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let mut c = client_rx.recv().await.expect("client connection");
    eprintln!("== client connected to {:?}", c.peer.remote_addr);
    assert_eq!(c.remote_public_key(), &server_key.public_key);
    c.peer.stream.write(b"ping").await.unwrap();
    let back = c.peer.stream.read().await.unwrap().unwrap();
    assert_eq!(back, b"ping");
    eprintln!("== echo ok");
    server_side.await.unwrap();
}
