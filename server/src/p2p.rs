//! The daemon side of the P2P backend (spec §13.4): the control socket for
//! sshcrabd-p2p. sshcrabd never links the DHT; it only accepts the helper,
//! hands it the derived P2P seed, and treats each connection the helper passes
//! like one from the UDP listener.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use sshcrab_proto::keys::Identity;
use sshcrab_proto::p2p::{self, CONTROL_VERSION, Hello, MAX_CONTROL, Peer};
use sshcrab_proto::seqpacket::{SeqListener, SeqPacket, into_unix_stream};
use sshcrab_proto::transport::{Conn, Remote};

use crate::config::Config;
use crate::session::Manager;
use crate::{PreAuth, handle};

/// Bind the control socket (startup errors are fatal) and serve it in the background.
pub fn start(cfg: Arc<Config>, host: Arc<Identity>, mgr: Arc<Manager>, preauth: Arc<PreAuth>) -> Result<(), String> {
    let path = PathBuf::from(&cfg.p2p_socket);
    let (uid, gid) = helper_ids(&cfg)?;
    let listener = SeqListener::bind(&path).map_err(|e| format!("P2PSocket {}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).map_err(|e| format!("{}: {e}", path.display()))?;
    if nix::unistd::Uid::effective().is_root() {
        nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(0)), Some(nix::unistd::Gid::from_raw(gid)))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    log::info!(
        "P2P address {} (via sshcrabd-p2p on {})",
        p2p::format_address(&p2p::public_key(&host.p2p_seed())),
        path.display()
    );
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(ctl) => {
                    tokio::spawn(helper(ctl, uid, cfg.clone(), host.clone(), mgr.clone(), preauth.clone()));
                }
                Err(e) => {
                    log::warn!("P2P control socket: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    });
    Ok(())
}

/// The uid sshcrabd-p2p must have, and the group for the socket. As a normal
/// user (test mode) sshcrabd only accepts a helper running as itself.
fn helper_ids(cfg: &Config) -> Result<(u32, u32), String> {
    if !nix::unistd::Uid::effective().is_root() {
        return Ok((nix::unistd::Uid::effective().as_raw(), nix::unistd::Gid::effective().as_raw()));
    }
    let user = nix::unistd::User::from_name(&cfg.p2p_user)
        .map_err(|e| format!("P2PUser {}: {e}", cfg.p2p_user))?
        .ok_or_else(|| format!("P2PUser {} does not exist", cfg.p2p_user))?;
    if user.uid.is_root() {
        return Err("P2PUser must not be root".into());
    }
    Ok((user.uid.as_raw(), user.gid.as_raw()))
}

async fn helper(ctl: SeqPacket, uid: u32, cfg: Arc<Config>, host: Arc<Identity>, mgr: Arc<Manager>, preauth: Arc<PreAuth>) {
    match ctl.peer_uid() {
        Ok(u) if u == uid => {}
        Ok(u) => {
            log::warn!("P2P control socket: refused a connection from uid {u}");
            return;
        }
        Err(e) => {
            log::warn!("P2P control socket: {e}");
            return;
        }
    }
    let hello = Hello { version: CONTROL_VERSION, seed: *host.p2p_seed(), bootstrap: cfg.bootstrap() };
    let msg = zeroize::Zeroizing::new(postcard::to_stdvec(&hello).expect("encodable"));
    drop(hello);
    if let Err(e) = ctl.send(&msg, None).await {
        log::warn!("P2P helper: {e}");
        return;
    }
    drop(msg);
    log::info!("P2P helper connected");
    let mut buf = vec![0u8; MAX_CONTROL];
    loop {
        let (n, fd) = match ctl.recv(&mut buf).await {
            Ok((0, _)) => break,
            Ok(r) => r,
            Err(e) => {
                log::warn!("P2P helper: {e}");
                break;
            }
        };
        let (Ok(peer), Some(fd)) = (postcard::from_bytes::<Peer>(&buf[..n]), fd) else {
            log::warn!("P2P helper sent a malformed message; disconnecting it");
            break;
        };
        let stream = match into_unix_stream(fd) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("P2P connection: {e}");
                continue;
            }
        };
        let (conn, ends) = Conn::pipe(Remote::P2p(peer.remote));
        tokio::spawn(p2p::bridge(stream, ends));
        tokio::spawn(handle(conn, cfg.clone(), host.clone(), mgr.clone(), preauth.clone()));
    }
    log::warn!("P2P helper disconnected");
}
