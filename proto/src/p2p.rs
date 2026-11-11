//! P2P backend, the parts both sides share (spec §13). The DHT itself lives
//! in the `sshcrab-p2p` crate so that sshcrabd never links it.
//!
//! - Addresses: `<z-base-32 of the P2P public key>.p2p`.
//! - The control protocol between sshcrabd and the sshcrabd-p2p helper, over a
//!   Unix `SOCK_SEQPACKET` socket: sshcrabd sends [`Hello`]; the helper then
//!   sends one [`Peer`] per incoming connection, with one end of a fresh
//!   `SOCK_STREAM` socketpair attached (`SCM_RIGHTS`).
//! - The framing on such a socketpair, [`read_frame`]/[`write_frame`]:
//!   `u32` big-endian length, then the stream id byte and the message. The
//!   same body (`stream id ‖ message`) is one message on the DHT stream.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use bytes::Bytes;

use crate::transport::{MAX_MESSAGE, PipeEnds};

pub const SUFFIX: &str = ".p2p";
pub(crate) const SEED_LABEL: &[u8] = b"sshcrab-p2p-v1";

/// Used when neither the config nor the command line names bootstrap nodes:
/// the public HyperDHT nodes (spec §13.6).
pub const DEFAULT_BOOTSTRAP: &[&str] = &[
    "88.99.3.86@node1.hyperdht.org:49737",
    "142.93.90.113@node2.hyperdht.org:49737",
    "138.68.147.8@node3.hyperdht.org:49737",
];
pub const DHT_NODE_PORT: u16 = 49737;

/// Version of the control protocol; sshcrabd and sshcrabd-p2p must agree.
pub const CONTROL_VERSION: u32 = 1;
/// Largest control message (a `Hello` with a long bootstrap list).
pub const MAX_CONTROL: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub seed: [u8; 32],
    pub bootstrap: Vec<String>,
}

impl Drop for Hello {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.seed);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Peer {
    /// Not known on the server side for hole-punched connections.
    pub remote: Option<std::net::SocketAddr>,
}

/// The P2P public key (= address) for a seed; the same key peeroxide derives.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// z-base-32 (as used by HyperDHT tools): 52 characters for a 32-byte key.
pub fn encode(key: &[u8; 32]) -> String {
    let mut out = String::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in key {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn decode(s: &str) -> Option<[u8; 32]> {
    if s.len() != 52 {
        return None;
    }
    let mut out = Vec::with_capacity(33);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = ALPHABET.iter().position(|&a| a == c.to_ascii_lowercase())? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // 52 × 5 = 260 bits: the last 4 must be zero, or two spellings would name one key.
    if acc != 0 {
        return None;
    }
    out.try_into().ok()
}

/// `<key>.p2p`.
pub fn format_address(key: &[u8; 32]) -> String {
    format!("{}{SUFFIX}", encode(key))
}

/// The P2P key a host name stands for, if it is a `.p2p` address.
pub fn parse_address(host: &str) -> Option<[u8; 32]> {
    let name = host.strip_suffix(SUFFIX).or_else(|| host.strip_suffix(".P2P"))?;
    decode(name)
}

/// One framed message from a byte stream; `None` at a clean end.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE + 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad frame length"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> std::io::Result<()> {
    if body.is_empty() || body.len() > MAX_MESSAGE + 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad frame length"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await
}

/// Carry a pipe [`Conn`](crate::transport::Conn) over a framed byte stream
/// until either side ends.
pub async fn bridge<S>(stream: S, ends: PipeEnds)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let PipeEnds { mut outgoing, incoming, mut closed } = ends;
    let reader = async move {
        while let Ok(Some(frame)) = read_frame(&mut r).await {
            let (&id, msg) = frame.split_first().expect("frames are never empty");
            if incoming.send((id as u16, Bytes::copy_from_slice(msg))).await.is_err() {
                break;
            }
        }
    };
    let writer = async move {
        loop {
            tokio::select! {
                biased;
                msg = outgoing.recv() => match msg {
                    Some((id, data)) => {
                        if write_frame(&mut w, &body(id, &data)).await.is_err() {
                            return;
                        }
                    }
                    None => break,
                },
                _ = async { let _ = closed.wait_for(|c| *c).await; } => {
                    while let Ok((id, data)) = outgoing.try_recv() {
                        if write_frame(&mut w, &body(id, &data)).await.is_err() {
                            return;
                        }
                    }
                    break;
                }
            }
        }
        let _ = w.shutdown().await;
    };
    tokio::select! {
        _ = reader => {}
        _ = writer => {}
    }
}

/// `stream id ‖ message`, the unit both the socketpair framing and the DHT stream carry.
pub fn body(id: u16, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(data.len() + 1);
    b.push(id as u8);
    b.extend_from_slice(data);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrip() {
        let key = public_key(&[7u8; 32]);
        let addr = format_address(&key);
        assert_eq!(addr.len(), 52 + 4);
        assert_eq!(parse_address(&addr), Some(key));
        assert_eq!(parse_address(&addr.to_uppercase().replace(".P2P", ".p2p")), Some(key));
        assert_eq!(parse_address("example.org"), None);
        assert_eq!(parse_address(&format!("{}x.p2p", &addr[..51])), None);
        // Known vector: 32 zero bytes.
        assert_eq!(encode(&[0u8; 32]), "y".repeat(52));
    }

    #[test]
    fn non_canonical_spelling_is_rejected() {
        let mut s = encode(&[0u8; 32]);
        s.pop();
        s.push('b'); // sets one of the 4 padding bits
        assert_eq!(decode(&s), None);
    }

    #[tokio::test]
    async fn frames() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        write_frame(&mut a, b"\x01hello").await.unwrap();
        assert!(write_frame(&mut a, &vec![0u8; MAX_MESSAGE + 2]).await.is_err());
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"\x01hello");
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }
}
