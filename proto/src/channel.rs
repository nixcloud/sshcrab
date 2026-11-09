//! Encrypted channel over a transport [`Conn`] (spec §6.2, §6.6).
//!
//! Noise `StatelessTransportState` with explicit nonces: SCTP orders each stream
//! independently, so each stream has its own nonce range
//! (`stream << 56 | counter`) and its own strictly increasing counter. Because
//! SCTP delivers every stream reliably and in order, the counter is implicit:
//! a lost, replayed or reordered message fails authentication and ends the channel.
//!
//! Plaintext frame: one flag byte (bit 0 = zstd-compressed) + postcard body.

use std::io::Read;

use bytes::Bytes;
use serde::Serialize;
use serde::de::DeserializeOwned;
use snow::StatelessTransportState;

use crate::transport::{Conn, MAX_MESSAGE, STREAM_CTRL, STREAM_DATA};
use crate::wire::{Ctrl, Data, MAX_CHUNK};

const AEAD_TAG: usize = 16;
const FLAG_COMPRESSED: u8 = 1;
/// Decompressed frames may not exceed this (bomb protection).
const MAX_PLAINTEXT: usize = MAX_CHUNK + 1024;
/// Data smaller than this is never compressed (keystrokes, spec §6.6).
const COMPRESS_MIN: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("connection closed")]
    Closed,
    #[error("transport: {0}")]
    Transport(#[from] crate::transport::TransportError),
    #[error("decryption failed")]
    Decrypt,
    #[error("malformed message")]
    Malformed,
    #[error("message too large")]
    TooLarge,
    #[error("nonce space exhausted")]
    NonceExhausted,
}

pub enum Msg {
    Ctrl(Ctrl),
    Data(Data),
}

pub struct SecureConn {
    conn: Conn,
    noise: StatelessTransportState,
    send_ctr: [u64; 2],
    recv_ctr: [u64; 2],
    compress: bool,
}

fn nonce(stream: u16, ctr: u64) -> Result<u64, ChannelError> {
    if ctr >= 1 << 56 {
        return Err(ChannelError::NonceExhausted);
    }
    Ok((stream as u64) << 56 | ctr)
}

impl SecureConn {
    pub(crate) fn new(conn: Conn, noise: StatelessTransportState) -> Self {
        SecureConn { conn, noise, send_ctr: [0; 2], recv_ctr: [0; 2], compress: false }
    }

    pub fn remote(&self) -> crate::transport::Remote {
        self.conn.remote()
    }

    /// Turn on compression of outgoing `Data` (only after authentication, spec §6.6).
    pub fn enable_compression(&mut self) {
        self.compress = true;
    }

    pub async fn send_ctrl(&mut self, msg: &Ctrl) -> Result<(), ChannelError> {
        self.send(STREAM_CTRL, msg, false).await
    }

    pub async fn send_data(&mut self, msg: &Data) -> Result<(), ChannelError> {
        let compress = self.compress
            && matches!(msg, Data::Bytes { stream, data, .. }
                if *stream != crate::wire::DataStream::Stdin && data.len() >= COMPRESS_MIN);
        self.send(STREAM_DATA, msg, compress).await
    }

    async fn send<T: Serialize>(&mut self, stream: u16, msg: &T, compress: bool) -> Result<(), ChannelError> {
        let body = postcard::to_stdvec(msg).map_err(|_| ChannelError::Malformed)?;
        let mut plain = Vec::with_capacity(body.len() + 1);
        if compress {
            let packed = ruzstd::encoding::compress_to_vec(&body[..], ruzstd::encoding::CompressionLevel::Fastest);
            if packed.len() < body.len() {
                plain.push(FLAG_COMPRESSED);
                plain.extend_from_slice(&packed);
            } else {
                plain.push(0);
                plain.extend_from_slice(&body);
            }
        } else {
            plain.push(0);
            plain.extend_from_slice(&body);
        }
        // Noise caps a message at 65535 bytes.
        if plain.len() + AEAD_TAG > MAX_MESSAGE.min(65535) {
            return Err(ChannelError::TooLarge);
        }
        let idx = stream as usize;
        let n = nonce(stream, self.send_ctr[idx])?;
        self.send_ctr[idx] += 1;
        let mut out = vec![0u8; plain.len() + AEAD_TAG];
        let len = self.noise.write_message(n, &plain, &mut out).map_err(|_| ChannelError::Malformed)?;
        out.truncate(len);
        self.conn.send(stream, Bytes::from(out)).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Msg, ChannelError> {
        let (stream, ct) = self.conn.recv().await.ok_or(ChannelError::Closed)?;
        if stream != STREAM_CTRL && stream != STREAM_DATA {
            return Err(ChannelError::Malformed);
        }
        if ct.len() < AEAD_TAG + 1 {
            return Err(ChannelError::Malformed);
        }
        let idx = stream as usize;
        let n = nonce(stream, self.recv_ctr[idx])?;
        let mut plain = vec![0u8; ct.len()];
        let len = self.noise.read_message(n, &ct, &mut plain).map_err(|_| ChannelError::Decrypt)?;
        self.recv_ctr[idx] += 1;
        plain.truncate(len);
        let (&flags, body) = plain.split_first().ok_or(ChannelError::Malformed)?;
        let body = match flags {
            0 => body.to_vec(),
            FLAG_COMPRESSED if stream == STREAM_DATA => decompress(body)?,
            _ => return Err(ChannelError::Malformed),
        };
        Ok(if stream == STREAM_CTRL { Msg::Ctrl(decode(&body)?) } else { Msg::Data(decode(&body)?) })
    }

    pub fn close(self) {
        self.conn.close();
    }
}

fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ChannelError> {
    postcard::from_bytes(body).map_err(|_| ChannelError::Malformed)
}

fn decompress(body: &[u8]) -> Result<Vec<u8>, ChannelError> {
    let decoder = ruzstd::decoding::StreamingDecoder::new(body).map_err(|_| ChannelError::Malformed)?;
    let mut out = Vec::new();
    decoder
        .take(MAX_PLAINTEXT as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| ChannelError::Malformed)?;
    if out.len() > MAX_PLAINTEXT {
        return Err(ChannelError::TooLarge);
    }
    Ok(out)
}
