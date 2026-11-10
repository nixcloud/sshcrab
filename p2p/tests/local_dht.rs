//! A whole P2P connection on 127.0.0.1: bootstrap node, announcing server,
//! connecting client, our handshake inside (spec §13, P4).

use std::time::Duration;

use sshcrab_proto::channel::Msg;
use sshcrab_proto::handshake;
use sshcrab_proto::keys::Identity;
use sshcrab_proto::transport::{Conn, Remote};
use sshcrab_proto::wire::{Data, DataStream};

#[tokio::test(flavor = "multi_thread")]
async fn connect_through_a_local_dht() {
    let _ = env_logger::builder().is_test(true).try_init();
    tokio::time::timeout(Duration::from_secs(90), run()).await.expect("timed out");
}

async fn run() {
    // Two nodes: a bootstrap and one more, so lookups have somewhere to go.
    let (boot, _t1) = sshcrab_p2p::run_node("127.0.0.1", 0, &[]).await.unwrap();
    let boot_port = boot.local_port().await.unwrap();
    let bootstrap = vec![format!("127.0.0.1:{boot_port}")];
    let (_n2, _t2) = sshcrab_p2p::run_node("127.0.0.1", 0, &bootstrap).await.unwrap();

    let host = Identity::generate();
    let user = Identity::generate();
    let (host_pub, user_pub) = (host.public(), user.public());
    let seed = host.p2p_seed();
    let mut server = sshcrab_p2p::announce(&seed, &bootstrap, 8).await.unwrap();
    assert_eq!(server.public_key, sshcrab_proto::p2p::public_key(&seed));

    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(async move {
        let peer = server.connections.recv().await.expect("a connection");
        // As the helper does: relay to a socketpair, the daemon end becomes a Conn.
        let (helper_end, daemon_end) = sshcrab_proto::seqpacket::stream_pair().unwrap();
        let helper_end = sshcrab_proto::seqpacket::into_unix_stream(helper_end).unwrap();
        let stream = peer.peer.stream;
        tokio::spawn(sshcrab_p2p::relay(stream, helper_end, stop));
        let (conn, ends) = Conn::pipe(Remote::P2p(None));
        tokio::spawn(sshcrab_proto::p2p::bridge(
            sshcrab_proto::seqpacket::into_unix_stream(daemon_end).unwrap(),
            ends,
        ));
        let (mut sc, peer) = handshake::server(conn, &host, async move |_: &str, k: &[u8; 32]| {
            if *k == user_pub { Ok(()) } else { Err(None) }
        })
        .await
        .unwrap();
        assert_eq!(peer.username, "alice");
        match sc.recv().await.unwrap() {
            Msg::Data(Data::Bytes { data, .. }) => {
                sc.send_data(&Data::Bytes { stream: DataStream::Stdout, offset: 0, data }).await.unwrap()
            }
            _ => panic!("expected data"),
        }
        // The daemon side stays up; only the helper goes away (below).
        while sc.recv().await.is_ok() {}
    });

    let conn = sshcrab_p2p::connect(&bootstrap, server_pub_key(&seed), |_| {}).await.unwrap();
    let mut sc = handshake::client(conn, "alice", &user, |k| if *k == host_pub { Ok(()) } else { Err("x".into()) })
        .await
        .unwrap();
    let payload = vec![42u8; 16 * 1024];
    sc.send_data(&Data::Bytes { stream: DataStream::Stdin, offset: 0, data: payload.clone() }).await.unwrap();
    match sc.recv().await.unwrap() {
        Msg::Data(Data::Bytes { data, .. }) => assert_eq!(data, payload),
        _ => panic!("expected the echo"),
    }
    // The helper shuts down (restart): the client learns at once, not only
    // after the idle timeout.
    let stopped = std::time::Instant::now();
    stop_tx.send(true).unwrap();
    assert!(sc.recv().await.is_err());
    assert!(stopped.elapsed() < Duration::from_secs(3), "noticed after {:?}", stopped.elapsed());
    server_task.await.unwrap();
}

fn server_pub_key(seed: &[u8; 32]) -> [u8; 32] {
    sshcrab_proto::p2p::public_key(seed)
}
