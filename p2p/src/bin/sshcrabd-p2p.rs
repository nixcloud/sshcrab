//! sshcrabd-p2p: makes sshcrabd reachable through the DHT (spec §13.4).
//!
//! Runs unprivileged (refuses root), ideally in the systemd sandbox of the
//! NixOS module. Connects to sshcrabd's control socket, receives the P2P seed
//! and bootstrap list, announces, and hands every incoming connection to
//! sshcrabd as one end of a socketpair. It never sees the host key and does
//! not parse the sshcrab protocol.

use std::os::fd::AsFd;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use sshcrab_proto::p2p::{CONTROL_VERSION, Hello, MAX_CONTROL, Peer, format_address};
use sshcrab_proto::seqpacket::{SeqPacket, into_unix_stream, stream_pair};

#[derive(Parser)]
#[command(name = "sshcrabd-p2p", version, about = "P2P (DHT) helper of sshcrabd")]
struct Args {
    /// sshcrabd's control socket (sshcrabd.toml `P2PSocket`).
    #[arg(long, default_value = "/run/sshcrab/p2p.sock")]
    socket: PathBuf,
    /// Most concurrent P2P connections.
    #[arg(long, default_value_t = 64)]
    max_peers: usize,
}

fn main() -> std::process::ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    if nix::unistd::Uid::effective().is_root() {
        eprintln!("sshcrabd-p2p: refusing to run as root; run it as the sshcrab-p2p user");
        return std::process::ExitCode::from(2);
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    match rt.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    // sshcrabd may still be starting.
    let mut warned = false;
    let ctl = loop {
        match SeqPacket::connect(&args.socket) {
            Ok(c) => break c,
            Err(e) => {
                if !warned {
                    log::warn!("{}: {e}; retrying", args.socket.display());
                    warned = true;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };
    let mut buf = vec![0u8; MAX_CONTROL];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), ctl.recv(&mut buf))
        .await
        .map_err(|_| "no hello from sshcrabd (is this the right user?)".to_string())?
        .map_err(|e| format!("control socket: {e}"))?;
    if n == 0 {
        return Err("sshcrabd closed the control socket (wrong user?)".into());
    }
    let hello: Hello = postcard::from_bytes(&buf[..n]).map_err(|_| "malformed hello")?;
    if hello.version != CONTROL_VERSION {
        return Err(format!("control protocol {} from sshcrabd, expected {CONTROL_VERSION}", hello.version));
    }
    // The network or the bootstrap nodes may not be up yet (boot, outage).
    let mut warned = false;
    let mut server = loop {
        match sshcrab_p2p::announce(&hello.seed, &hello.bootstrap, args.max_peers).await {
            Ok(s) => break s,
            Err(e) => {
                if !warned {
                    log::warn!("announcing: {e}; retrying every 5 s");
                    warned = true;
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    r = ctl.recv(&mut buf) => if matches!(r, Ok((0, _)) | Err(_)) {
                        return Err("sshcrabd went away".into());
                    },
                }
            }
        }
    };
    drop(hello);
    log::info!("announced as {}", format_address(&server.public_key));

    loop {
        tokio::select! {
            peer = server.connections.recv() => {
                let Some(peer) = peer else { return Err("the swarm stopped".into()) };
                let remote = peer.peer.remote_addr;
                let (mine, theirs) = stream_pair().map_err(|e| format!("socketpair: {e}"))?;
                let msg = postcard::to_stdvec(&Peer { remote }).expect("encodable");
                if let Err(e) = ctl.send(&msg, Some(theirs.as_fd())).await {
                    return Err(format!("handing a connection to sshcrabd: {e}"));
                }
                drop(theirs);
                let local = into_unix_stream(mine).map_err(|e| format!("socketpair: {e}"))?;
                log::debug!("connection from {}", remote.map_or("an unknown address".into(), |a| a.to_string()));
                tokio::spawn(async move {
                    let stream = peer.peer.stream;
                    sshcrab_p2p::relay(stream, local).await;
                    drop(peer.peer.socket);
                });
            }
            r = ctl.recv(&mut buf) => match r {
                Ok((0, _)) | Err(_) => return Err("sshcrabd went away".into()),
                Ok(_) => {} // nothing else is defined yet
            },
        }
    }
}
