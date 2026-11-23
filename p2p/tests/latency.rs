//! Latency of the P2P data path over a link with a round trip (spec §13.8):
//! two UDX streams through a UDP proxy that delays each packet by ONE_WAY,
//! with peeroxide's SecretStream on top, written to the way our bridge does
//! (one message per write, sequentially). Loopback alone hides any per-message
//! round trip, so this is the only check that would catch one.
//!
//!     cargo test -p sshcrab-p2p --test latency -- --nocapture

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libudx::{UdxAsyncStream, UdxRuntime};
use peeroxide_dht::secret_stream::SecretStream;
use tokio::net::UdpSocket;

const ONE_WAY: Duration = Duration::from_millis(20);
const RTT: Duration = Duration::from_millis(40);

/// Forwards between `a` and `b`, delaying every packet by ONE_WAY.
/// Returns the addresses `a` and `b` must send to.
async fn delay_proxy(a: SocketAddr, b: SocketAddr) -> (SocketAddr, SocketAddr) {
    let for_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let for_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addrs = (for_a.local_addr().unwrap(), for_b.local_addr().unwrap());
    for (from, to, dest) in [(for_a.clone(), for_b.clone(), b), (for_b, for_a, a)] {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((n, _)) = from.recv_from(&mut buf).await {
                let (packet, to) = (buf[..n].to_vec(), to.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(ONE_WAY).await;
                    let _ = to.send_to(&packet, dest).await;
                });
            }
        });
    }
    addrs
}

/// A connected pair of SecretStreams over the delaying proxy.
async fn pair(rt: &UdxRuntime) -> (SecretStream<UdxAsyncStream>, SecretStream<UdxAsyncStream>, Vec<libudx::UdxSocket>) {
    let (sa, sb) = (rt.create_socket().await.unwrap(), rt.create_socket().await.unwrap());
    sa.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    sb.bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let (for_a, for_b) = delay_proxy(sa.local_addr().await.unwrap(), sb.local_addr().await.unwrap()).await;
    let (a, b) = (rt.create_stream(1).await.unwrap(), rt.create_stream(2).await.unwrap());
    a.connect(&sa, 2, for_a).await.unwrap();
    b.connect(&sb, 1, for_b).await.unwrap();
    let ka = peeroxide_dht::noise::generate_keypair();
    let kb = peeroxide_dht::noise::generate_keypair();
    let (a, b) = tokio::join!(
        SecretStream::new(true, a.into_async_stream(), ka),
        SecretStream::new(false, b.into_async_stream(), kb)
    );
    (a.unwrap(), b.unwrap(), vec![sa, sb])
}

#[tokio::test(flavor = "multi_thread")]
async fn latency_over_a_round_trip() {
    let _ = env_logger::builder().is_test(true).try_init();
    tokio::time::timeout(Duration::from_secs(60), run()).await.expect("timed out");
}

async fn run() {
    let rt = UdxRuntime::new().unwrap();
    let (a, b, _sockets) = pair(&rt).await;
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();

    // b echoes every message, like a shell echoing a keystroke.
    tokio::spawn(async move {
        while let Ok(Some(m)) = br.read().await {
            if bw.write(&m).await.is_err() {
                break;
            }
        }
    });

    // Ping-pong: one keystroke and its echo. Ideal: one round trip.
    for _ in 0..3 {
        aw.write(b"w").await.unwrap(); // warm up
        ar.read().await.unwrap().unwrap();
    }
    let rounds = 10;
    let start = Instant::now();
    for _ in 0..rounds {
        aw.write(b"k").await.unwrap();
        assert_eq!(ar.read().await.unwrap().unwrap(), b"k");
    }
    let echo = start.elapsed() / rounds;

    // Burst: a screen redraw as many small messages, until the last echo is
    // back. libudx 1.7.4 needed two round trips per message (about 4 s for 50).
    // From 1.8 a burst takes one round trip once the congestion window has
    // grown, and about two before (BBR startup), so a fresh stream gets three.
    let n = 50;
    let mut bursts = vec![];
    for _ in 0..3 {
        let start = Instant::now();
        let reader = tokio::spawn(async move {
            for i in 0..n {
                let m = ar.read().await.unwrap().unwrap();
                assert_eq!(m, format!("line {i}").as_bytes(), "order");
            }
            ar
        });
        for i in 0..n {
            aw.write(format!("line {i}").as_bytes()).await.unwrap();
        }
        ar = reader.await.unwrap();
        bursts.push(start.elapsed());
    }

    eprintln!("round trip {RTT:?}: echo {echo:?}; {n} messages there and back: {bursts:?}");
    assert!(echo < RTT * 3 / 2, "echo takes {echo:?}, over 1.5 round trips of {RTT:?}");
    for b in bursts {
        assert!(b < RTT * 3, "{n} messages take {b:?}, over 3 round trips of {RTT:?}");
    }
}

/// `shutdown()` returns once the peer acknowledged the end of the stream, so a
/// process may exit right after it (the helper does) and the peer still learns
/// the stream ended, instead of waiting for its idle timeout.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_waits_for_the_end_to_arrive() {
    let _ = env_logger::builder().is_test(true).try_init();
    tokio::time::timeout(Duration::from_secs(30), async {
        let rt = UdxRuntime::new().unwrap();
        let (a, b, _sockets) = pair(&rt).await;
        let (_ar, mut aw) = a.into_split();
        let (mut br, _bw) = b.into_split();
        let start = Instant::now();
        aw.shutdown().await.unwrap();
        let took = start.elapsed();
        assert!(took >= RTT, "shutdown returned after {took:?}, before a round trip of {RTT:?}");
        assert!(br.read().await.unwrap().is_none(), "the peer sees the end");
    })
    .await
    .expect("timed out");
}
