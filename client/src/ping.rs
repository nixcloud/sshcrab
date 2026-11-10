//! `sshcrab --ping`: round trips of Ping/Pong over an authenticated
//! connection, the path keystrokes and their echo take (transport, P2P helper,
//! sshcrabd), at typing pace. Outliers matter more than the median: a few slow
//! keystrokes make a shell feel sluggish.

use std::time::{Duration, Instant};

use sshcrab_proto::channel::{Msg, SecureConn};
use sshcrab_proto::transport::Remote;
use sshcrab_proto::wire::Ctrl;

/// A ping counts as slow above this (well above any normal round trip a
/// shell is still pleasant over).
const SLOW: Duration = Duration::from_millis(100);
/// Give up on a Pong after this (the transport retransmits until then).
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// `count` pings (0 = until Ctrl+C), one per `interval`; prints each and a summary.
pub async fn run(sc: &mut SecureConn, connected_in: Duration, count: u32, interval: Duration) -> i32 {
    let path = match sc.remote() {
        Remote::Udp(a) => format!("{a} (direct UDP)"),
        Remote::P2p(Some(a)) => format!("{a} (P2P)"),
        Remote::P2p(None) => "P2P, address unknown".into(),
    };
    println!("connected via {path} in {:.1} s", connected_in.as_secs_f32());
    let every = if count == 0 { String::new() } else { format!("{count} pings, ") };
    println!("{every}1 every {} ms (Ctrl+C to stop):", interval.as_millis());

    let mut times = vec![];
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut lost = false;
    for seq in 1.. {
        if count != 0 && seq > count {
            break;
        }
        tokio::select! {
            _ = tick.tick() => {}
            _ = &mut ctrl_c => break,
        }
        let start = Instant::now();
        let pong = tokio::select! {
            r = tokio::time::timeout(PONG_TIMEOUT, pong(sc)) => r,
            _ = &mut ctrl_c => break,
        };
        match pong {
            Ok(true) => {}
            Ok(false) => {
                println!("connection lost");
                lost = true;
                break;
            }
            Err(_) => {
                println!("seq={seq} no answer within {} s", PONG_TIMEOUT.as_secs());
                lost = true;
                break;
            }
        }
        let t = start.elapsed();
        let mark = if t > SLOW { "  <- slow" } else { "" };
        println!("seq={seq} time={:.1} ms{mark}", ms(t));
        times.push(t);
    }
    summary(&mut times);
    if !lost {
        let _ = sc.send_ctrl(&Ctrl::Close).await;
    }
    if lost || times.is_empty() { 1 } else { 0 }
}

/// Send a Ping and wait for its Pong; `false` if the connection ended.
async fn pong(sc: &mut SecureConn) -> bool {
    if sc.send_ctrl(&Ctrl::Ping).await.is_err() {
        return false;
    }
    loop {
        match sc.recv().await {
            Ok(Msg::Ctrl(Ctrl::Pong)) => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn summary(times: &mut [Duration]) {
    if times.is_empty() {
        return;
    }
    times.sort();
    let pct = |p: usize| times[((times.len() - 1) * p).div_ceil(100)];
    let mean = times.iter().sum::<Duration>() / times.len() as u32;
    let slow = times.iter().filter(|t| **t > SLOW).count();
    println!("--- {} pings", times.len());
    println!(
        "min {:.1} ms   median {:.1} ms   mean {:.1} ms   p95 {:.1} ms   p99 {:.1} ms   max {:.1} ms",
        ms(times[0]),
        ms(pct(50)),
        ms(mean),
        ms(pct(95)),
        ms(pct(99)),
        ms(times[times.len() - 1])
    );
    println!("over {} ms: {slow} ({:.1} %)", SLOW.as_millis(), slow as f64 * 100.0 / times.len() as f64);
}
