//! Key agreement and authentication (spec §6.1).
//!
//! `Noise_NN_25519_ChaChaPoly_SHA256` with prologue [`PROTOCOL`] gives an
//! encrypted channel and a handshake hash `h`. Identities are bound to it by
//! Ed25519 signatures sent as the first encrypted messages, SIGMA-style:
//!
//! ```text
//! C → S  e
//! S → C  e, ee
//! S → C  ServerAuth { host_key, Sig_host(SERVER_LABEL ‖ h) }
//!        client checks host_key against hostkeys before revealing anything
//! C → S  ClientAuth { username, user_key, Sig_user(CLIENT_LABEL ‖ h ‖ len ‖ username ‖ host_key) }
//! S → C  AuthOk | AuthFail
//! ```

use std::time::Duration;

use bytes::Bytes;

use crate::channel::{ChannelError, Msg, SecureConn};
use crate::keys::{self, Identity};
use crate::transport::{Conn, STREAM_CTRL};
use crate::wire::{Ctrl, PROTOCOL};

const NOISE: &str = "Noise_NN_25519_ChaChaPoly_SHA256";
const SERVER_LABEL: &[u8] = b"sshcrab-server-auth-v1";
const CLIENT_LABEL: &[u8] = b"sshcrab-client-auth-v1";
/// Pre-authentication deadline on the server (spec §6.1).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const NOISE_E: usize = 32;
const TAG: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("connection closed during handshake")]
    Closed,
    #[error("handshake timed out")]
    Timeout,
    #[error("protocol error during handshake")]
    Protocol,
    #[error("server signature invalid")]
    BadServerSignature,
    #[error("host key rejected: {0}")]
    HostKeyRejected(String),
    #[error("authentication failed")]
    AuthFailed { message: Option<String> },
    #[error(transparent)]
    Channel(#[from] ChannelError),
}

fn server_signed(h: &[u8]) -> Vec<u8> {
    [SERVER_LABEL, h].concat()
}

fn client_signed(h: &[u8], username: &str, host_key: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(CLIENT_LABEL.len() + h.len() + 4 + username.len() + host_key.len());
    m.extend_from_slice(CLIENT_LABEL);
    m.extend_from_slice(h);
    m.extend_from_slice(&(username.len() as u32).to_be_bytes());
    m.extend_from_slice(username.as_bytes());
    m.extend_from_slice(host_key);
    m
}

fn builder() -> snow::Builder<'static> {
    snow::Builder::new(NOISE.parse().expect("valid noise params"))
        .prologue(PROTOCOL)
        .expect("prologue")
}

async fn recv_raw(conn: &mut Conn, len: usize) -> Result<Bytes, HandshakeError> {
    match conn.recv().await {
        Some((STREAM_CTRL, msg)) if msg.len() == len => Ok(msg),
        Some(_) => Err(HandshakeError::Protocol),
        None => Err(HandshakeError::Closed),
    }
}

async fn recv_ctrl(sc: &mut SecureConn) -> Result<Ctrl, HandshakeError> {
    match sc.recv().await {
        Ok(Msg::Ctrl(c)) => Ok(c),
        Ok(Msg::Data(_)) => Err(HandshakeError::Protocol),
        Err(ChannelError::Closed) => Err(HandshakeError::Closed),
        Err(e) => Err(e.into()),
    }
}

/// Usernames accepted on the wire: portable POSIX names (no leading `-`), ≤ 32 bytes.
pub fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// Client side. `check_host` decides about the server's host key (hostkeys file,
/// spec §7.8) before the username or user key are sent.
pub async fn client(
    mut conn: Conn,
    username: &str,
    identity: &Identity,
    check_host: impl FnOnce(&[u8; 32]) -> Result<(), String>,
) -> Result<SecureConn, HandshakeError> {
    let mut hs = builder().build_initiator().map_err(|_| HandshakeError::Protocol)?;
    let mut buf = [0u8; 128];
    let n = hs.write_message(&[], &mut buf).map_err(|_| HandshakeError::Protocol)?;
    conn.send(STREAM_CTRL, Bytes::copy_from_slice(&buf[..n])).await.map_err(|_| HandshakeError::Closed)?;
    let msg2 = recv_raw(&mut conn, NOISE_E + TAG).await?;
    hs.read_message(&msg2, &mut buf).map_err(|_| HandshakeError::Protocol)?;
    let h = hs.get_handshake_hash().to_vec();
    let noise = hs.into_stateless_transport_mode().map_err(|_| HandshakeError::Protocol)?;
    let mut sc = SecureConn::new(conn, noise);

    let Ctrl::ServerAuth { host_key, sig } = recv_ctrl(&mut sc).await? else {
        return Err(HandshakeError::Protocol);
    };
    if !keys::verify(&host_key, &server_signed(&h), &sig) {
        return Err(HandshakeError::BadServerSignature);
    }
    let host_key: [u8; 32] = host_key.try_into().map_err(|_| HandshakeError::Protocol)?;
    check_host(&host_key).map_err(HandshakeError::HostKeyRejected)?;

    let sig = identity.sign(&client_signed(&h, username, &host_key));
    sc.send_ctrl(&Ctrl::ClientAuth { username: username.to_string(), user_key: identity.public().to_vec(), sig: sig.to_vec() })
        .await?;
    match recv_ctrl(&mut sc).await? {
        Ctrl::AuthOk => {
            sc.accept_compressed();
            Ok(sc)
        }
        Ctrl::AuthFail { message } => Err(HandshakeError::AuthFailed { message }),
        _ => Err(HandshakeError::Protocol),
    }
}

/// An authenticated peer.
#[derive(Debug, Clone)]
pub struct Peer<T> {
    pub username: String,
    pub key: [u8; 32],
    /// Whatever `authorize` returned (e.g. the passwd entry).
    pub account: T,
}

/// Server side. `authorize(username, key)` is called only after the client's
/// signature has verified; it returns the account or the failure message.
/// The caller applies [`HANDSHAKE_TIMEOUT`].
pub async fn server<T>(
    mut conn: Conn,
    host: &Identity,
    authorize: impl AsyncFnOnce(&str, &[u8; 32]) -> Result<T, Option<String>>,
) -> Result<(SecureConn, Peer<T>), HandshakeError> {
    let mut hs = builder().build_responder().map_err(|_| HandshakeError::Protocol)?;
    let mut buf = [0u8; 128];
    let msg1 = recv_raw(&mut conn, NOISE_E).await?;
    hs.read_message(&msg1, &mut buf).map_err(|_| HandshakeError::Protocol)?;
    let n = hs.write_message(&[], &mut buf).map_err(|_| HandshakeError::Protocol)?;
    conn.send(STREAM_CTRL, Bytes::copy_from_slice(&buf[..n])).await.map_err(|_| HandshakeError::Closed)?;
    let h = hs.get_handshake_hash().to_vec();
    let noise = hs.into_stateless_transport_mode().map_err(|_| HandshakeError::Protocol)?;
    let mut sc = SecureConn::new(conn, noise);

    let host_key = host.public();
    sc.send_ctrl(&Ctrl::ServerAuth { host_key: host_key.to_vec(), sig: host.sign(&server_signed(&h)).to_vec() })
        .await?;

    let Ctrl::ClientAuth { username, user_key, sig } = recv_ctrl(&mut sc).await? else {
        return Err(HandshakeError::Protocol);
    };
    let fail = |message| HandshakeError::AuthFailed { message };
    // Signature first: it proves possession of the key without touching any
    // account data, and every failure below looks the same to the client.
    let verified = valid_username(&username) && keys::verify(&user_key, &client_signed(&h, &username, &host_key), &sig);
    let key: Option<[u8; 32]> = user_key.try_into().ok();
    let result = match (verified, key) {
        (true, Some(key)) => authorize(&username, &key).await.map(|account| (key, account)),
        _ => Err(None),
    };
    match result {
        Ok((key, account)) => {
            sc.send_ctrl(&Ctrl::AuthOk).await?;
            sc.enable_compression();
            Ok((sc, Peer { username, key, account }))
        }
        Err(message) => {
            let _ = sc.send_ctrl(&Ctrl::AuthFail { message: message.clone() }).await;
            Err(fail(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Msg;
    use crate::transport::{Limits, Listener, connect};
    use crate::wire::{Data, DataStream};

    async fn pair(
        user_ok: bool,
        host_ok: bool,
    ) -> (Result<SecureConn, HandshakeError>, Result<(SecureConn, Peer<u32>), HandshakeError>, [u8; 32]) {
        let host = Identity::generate();
        let user = Identity::generate();
        let user_pub = user.public();
        let host_pub = host.public();
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Limits::default()).await.unwrap();
        let addr = listener.local_addr();
        let server = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap();
            server(conn, &host, async move |name: &str, key: &[u8; 32]| {
                if user_ok && name == "alice" && *key == user_pub { Ok(1000u32) } else { Err(None) }
            })
            .await
        });
        let conn = connect(addr).await.unwrap();
        let client = client(conn, "alice", &user, |k| {
            if host_ok && *k == host_pub { Ok(()) } else { Err("mismatch".into()) }
        })
        .await;
        (client, server.await.unwrap(), user_pub)
    }

    #[tokio::test]
    async fn authenticates_and_exchanges_messages() {
        let (client, server, user_pub) = pair(true, true).await;
        let mut c = client.unwrap();
        let (mut s, peer) = server.unwrap();
        assert_eq!(peer.username, "alice");
        assert_eq!(peer.key, user_pub);
        assert_eq!(peer.account, 1000);

        c.send_ctrl(&Ctrl::Ping).await.unwrap();
        let big = vec![b'x'; 16 * 1024];
        s.send_data(&Data::Bytes { stream: DataStream::Stdout, offset: 0, data: big.clone() }).await.unwrap();
        assert!(matches!(s.recv().await.unwrap(), Msg::Ctrl(Ctrl::Ping)));
        match c.recv().await.unwrap() {
            Msg::Data(Data::Bytes { data, .. }) => assert_eq!(data, big),
            _ => panic!("expected data"),
        }
    }

    /// The same handshake and channel over two pipe connections bridged through
    /// a byte stream, as the P2P backend carries them (spec §13.1).
    #[tokio::test]
    async fn works_over_a_bridged_pipe() {
        use crate::transport::{Conn, Remote};
        let (a, b) = tokio::io::duplex(1 << 20);
        let (client_conn, client_ends) = Conn::pipe(Remote::P2p(None));
        let (server_conn, server_ends) = Conn::pipe(Remote::P2p(None));
        tokio::spawn(crate::p2p::bridge(a, client_ends));
        tokio::spawn(crate::p2p::bridge(b, server_ends));

        let host = Identity::generate();
        let user = Identity::generate();
        let (host_pub, user_pub) = (host.public(), user.public());
        let server = tokio::spawn(async move {
            server(server_conn, &host, async move |_: &str, key: &[u8; 32]| {
                if *key == user_pub { Ok(()) } else { Err(None) }
            })
            .await
        });
        let mut c = client(client_conn, "alice", &user, |k| if *k == host_pub { Ok(()) } else { Err("x".into()) })
            .await
            .unwrap();
        let (mut s, _) = server.await.unwrap().unwrap();
        for i in 0..100u64 {
            let data = vec![i as u8; 16 * 1024];
            c.send_data(&Data::Bytes { stream: DataStream::Stdin, offset: i, data: data.clone() }).await.unwrap();
            c.send_ctrl(&Ctrl::Ping).await.unwrap();
            assert!(matches!(s.recv().await.unwrap(), Msg::Data(Data::Bytes { data: d, .. }) if d == data));
            assert!(matches!(s.recv().await.unwrap(), Msg::Ctrl(Ctrl::Ping)));
        }
        // Closing delivers what is queued, then the other side sees the end.
        s.send_ctrl(&Ctrl::Pong).await.unwrap();
        s.close();
        assert!(matches!(c.recv().await.unwrap(), Msg::Ctrl(Ctrl::Pong)));
        assert!(c.recv().await.is_err());
    }

    /// Only the client decompresses; the server never runs the decoder.
    #[tokio::test]
    async fn the_server_refuses_compressed_data() {
        let (client, server, _) = pair(true, true).await;
        let (mut c, (mut s, _)) = (client.unwrap(), server.unwrap());
        c.enable_compression();
        let big = vec![b'x'; 16 * 1024];
        c.send_data(&Data::Bytes { stream: DataStream::Stdout, offset: 0, data: big }).await.unwrap();
        assert!(matches!(s.recv().await, Err(ChannelError::Malformed)));
    }

    #[tokio::test]
    async fn unknown_key_is_rejected() {
        let (client, server, _) = pair(false, true).await;
        assert!(matches!(client, Err(HandshakeError::AuthFailed { message: None })), "{:?}", client.err());
        assert!(matches!(server, Err(HandshakeError::AuthFailed { .. })));
    }

    #[tokio::test]
    async fn host_mismatch_reveals_no_identity() {
        let (client, server, _) = pair(true, false).await;
        assert!(matches!(client, Err(HandshakeError::HostKeyRejected(_))));
        // The client hung up before sending ClientAuth.
        assert!(matches!(server, Err(HandshakeError::Closed)));
    }

    #[test]
    fn usernames() {
        assert!(valid_username("alice"));
        assert!(valid_username("build_1.x-y"));
        assert!(!valid_username(""));
        assert!(!valid_username("-rf"));
        assert!(!valid_username("a b"));
        assert!(!valid_username("../etc"));
        assert!(!valid_username(&"a".repeat(33)));
    }
}
