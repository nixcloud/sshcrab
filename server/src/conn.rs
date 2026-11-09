//! One authenticated client connection (spec §4.4–4.6).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use sshcrab_proto::channel::{ChannelError, Msg, SecureConn};
use sshcrab_proto::handshake::Peer;
use sshcrab_proto::wire::{Attach, AttachRefusal, ControlOp, Ctrl, Data, DataStream};
use tokio::sync::{mpsc, oneshot};

use crate::auth::Account;
use crate::session::{Client, Manager, NewSession, ToClient, ToSession};

static NEXT_CLIENT: AtomicU64 = AtomicU64::new(1);

/// Only these variables are taken from the client (spec §7.6).
fn sanitize_env(env: Vec<(String, String)>) -> Vec<(String, String)> {
    env.into_iter()
        .filter(|(k, v)| {
            matches!(k.as_str(), "TERM" | "LANG" | "LC_ALL")
                && !v.is_empty()
                && v.len() <= 64
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._@+-".contains(&b))
        })
        .collect()
}

pub async fn serve(mut sc: SecureConn, peer: Peer<Account>, mgr: Arc<Manager>) {
    let user = peer.account.name.clone();
    let is_root = peer.account.is_root();
    log::info!("{user} authenticated from {} (key {})", sc.remote(), sshcrab_proto::keys::fingerprint(&peer.key));

    // Selection phase: list, control, or attach.
    let (session, client_rx, client_id, kick) = loop {
        let msg = match sc.recv().await {
            Ok(Msg::Ctrl(c)) => c,
            Ok(Msg::Data(_)) | Err(_) => return,
        };
        let reply = match msg {
            Ctrl::Ping => Ctrl::Pong,
            Ctrl::ListSessions => Ctrl::Sessions(mgr.list(Some(&user))),
            Ctrl::Control(op) => control(&mgr, &user, is_root, op).await,
            Ctrl::Attach(attach) => {
                let (tx, rx) = mpsc::channel(32);
                let client_id = NEXT_CLIENT.fetch_add(1, Ordering::Relaxed);
                let (kick_tx, kick_rx) = oneshot::channel();
                let client = Client { id: client_id, tx, kick: kick_tx };
                match attach_session(&mgr, &peer.account, attach, client).await {
                    Ok((session, attached)) => {
                        let ok = Ctrl::Attached {
                            id: attached.id,
                            replay: attached.replay,
                            lost_bytes: attached.lost_bytes,
                            terminal: attached.terminal,
                        };
                        if sc.send_ctrl(&ok).await.is_err() {
                            let _ = session.send(ToSession::Detached { client_id }).await;
                            return;
                        }
                        break (session, rx, client_id, kick_rx);
                    }
                    Err(reason) => Ctrl::AttachRefused { reason },
                }
            }
            Ctrl::Close => return,
            _ => return,
        };
        if sc.send_ctrl(&reply).await.is_err() {
            return;
        }
    };

    let _live = Live::enter();
    let end = attached(&mut sc, &session, client_rx, kick).await;
    match end {
        End::Lost | End::Kicked => {
            let _ = session.send(ToSession::Detached { client_id }).await;
        }
        End::Closed => {}
    }
    sc.close();
}

enum End {
    /// Connection lost: the session stays.
    Lost,
    /// The client said goodbye (session removed).
    Closed,
    Kicked,
}

async fn attached(
    sc: &mut SecureConn,
    session: &mpsc::Sender<ToSession>,
    mut from_session: mpsc::Receiver<ToClient>,
    mut kick: oneshot::Receiver<String>,
) -> End {
    let mut kick_done = false;
    loop {
        tokio::select! {
            msg = sc.recv() => {
                let to_session = match msg {
                    Ok(Msg::Data(Data::Bytes { stream: DataStream::Stdin, offset, data })) => ToSession::Stdin { offset, data },
                    Ok(Msg::Data(Data::Ack { stream, offset })) => ToSession::Ack { stream, offset },
                    Ok(Msg::Data(_)) => return End::Lost,
                    Ok(Msg::Ctrl(Ctrl::Ping)) => {
                        if sc.send_ctrl(&Ctrl::Pong).await.is_err() {
                            return End::Lost;
                        }
                        continue;
                    }
                    Ok(Msg::Ctrl(Ctrl::Pong)) => continue,
                    Ok(Msg::Ctrl(Ctrl::WindowSize { cols, rows })) => ToSession::Window { cols, rows },
                    Ok(Msg::Ctrl(Ctrl::Signal(sig))) => ToSession::Signal(sig),
                    Ok(Msg::Ctrl(Ctrl::StdinEof { offset })) => ToSession::StdinEof { offset },
                    Ok(Msg::Ctrl(Ctrl::Close)) => {
                        let _ = session.send(ToSession::Close).await;
                        return End::Closed;
                    }
                    Ok(Msg::Ctrl(_)) => return End::Lost,
                    Err(ChannelError::Closed) | Err(_) => return End::Lost,
                };
                if session.send(to_session).await.is_err() {
                    return End::Closed;
                }
            }
            msg = from_session.recv() => {
                let res = match msg {
                    Some(ToClient::Data(d)) => sc.send_data(&d).await,
                    Some(ToClient::Ctrl(c)) => sc.send_ctrl(&c).await,
                    // A kick drops the client right after; the reason may be waiting.
                    None => return match kick.try_recv() {
                        Ok(reason) => kicked(sc, reason).await,
                        Err(_) => End::Closed,
                    },
                };
                if res.is_err() {
                    return End::Lost;
                }
            }
            reason = &mut kick, if !kick_done => {
                kick_done = true;
                // An error means the session dropped this client; `from_session` ends too.
                if let Ok(reason) = reason {
                    return kicked(sc, reason).await;
                }
            }
        }
    }
}

async fn kicked(sc: &mut SecureConn, reason: String) -> End {
    log::info!("{}: disconnecting the client: {reason}", sc.remote());
    if sc.send_ctrl(&Ctrl::Kicked { reason }).await.is_ok() {
        // The client answers `Kicked` with `Close`, which shows the reason arrived.
        let _ = tokio::time::timeout(KICK_LINGER, async {
            while let Ok(msg) = sc.recv().await {
                if matches!(msg, Msg::Ctrl(Ctrl::Close)) {
                    break;
                }
            }
        })
        .await;
    }
    End::Kicked
}

/// How long a kicked client gets to receive the reason and hang up.
const KICK_LINGER: Duration = Duration::from_secs(2);

/// Connections attached to a session, so shutdown can wait for their `Kicked`.
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Live;

impl Live {
    fn enter() -> Live {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Live
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Daemon shutdown: wait (at most `limit`) until every attached connection is gone.
pub async fn wait_detached(limit: Duration) {
    let until = tokio::time::Instant::now() + limit;
    while LIVE.load(Ordering::SeqCst) > 0 && tokio::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn attach_session(
    mgr: &Arc<Manager>,
    account: &Account,
    attach: Attach,
    client: Client,
) -> Result<(mpsc::Sender<ToSession>, crate::session::Attached), AttachRefusal> {
    let (session, received, window, takeover) = match attach {
        Attach::New { command, env, window } => {
            let spec = NewSession { account, command, env: sanitize_env(env), window };
            let (_, tx) = mgr.create(spec)?;
            (tx, Default::default(), window, false)
        }
        // Resuming is owner-only, root included (spec §4.6).
        Attach::Resume { id, takeover, received, window } => {
            let tx = mgr.get(&id, Some(&account.name)).ok_or(AttachRefusal::NotFound)?;
            (tx, received, window, takeover)
        }
    };
    let (reply, rx) = oneshot::channel();
    session
        .send(ToSession::Attach { client, received, window, takeover, reply })
        .await
        .map_err(|_| AttachRefusal::NotFound)?;
    let attached = rx.await.map_err(|_| AttachRefusal::NotFound)??;
    Ok((session, attached))
}

async fn control(mgr: &Arc<Manager>, user: &str, is_root: bool, op: ControlOp) -> Ctrl {
    // root may manage every session, others only their own.
    let scope = if is_root { None } else { Some(user) };
    match op {
        ControlOp::List => Ctrl::Sessions(mgr.list(scope)),
        ControlOp::Detach(id) => match mgr.get(&id, scope) {
            Some(tx) => {
                let _ = tx.send(ToSession::Kick { reason: "you have been detached".into() }).await;
                log::info!("{user} detached session {id}");
                Ctrl::Feedback { text: format!("session {id} detached") }
            }
            None => Ctrl::Feedback { text: format!("session {id} not found") },
        },
        ControlOp::Remove(id) => match mgr.get(&id, scope) {
            Some(tx) => {
                let _ = tx.send(ToSession::Remove).await;
                log::info!("{user} removed session {id}");
                Ctrl::Feedback { text: format!("session {id} removed") }
            }
            None => Ctrl::Feedback { text: format!("session {id} not found") },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_allowlist() {
        let env = vec![
            ("TERM".into(), "xterm-256color".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
            ("LC_ALL".into(), "../../etc".into()),
            ("LD_PRELOAD".into(), "x.so".into()),
            ("TERM".into(), "a".repeat(65)),
        ];
        assert_eq!(
            sanitize_env(env),
            vec![("TERM".into(), "xterm-256color".into()), ("LANG".into(), "en_US.UTF-8".into())]
        );
    }
}
