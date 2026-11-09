use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

use crate::error::Result as UdxResult;
use super::header::{Header, FLAG_END};
use super::stream::{StreamEvent, StreamInner, DEFAULT_RWND, build_data_packet};

/// Unacknowledged bytes a writer may have outstanding before `poll_write`
/// waits (backpressure). Packets are paced by the congestion controller
/// regardless; this only bounds the memory held for retransmission.
///
/// sshcrab patch: upstream 1.7.4 allowed a single outstanding write, so every
/// write and every flush waited a full round trip for its ACK.
pub const MAX_UNACKED_BYTES: usize = 1 << 20;

/// Adapter that implements [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`]
/// over a [`super::stream::UdxStream`].
///
/// Created via [`super::stream::UdxStream::into_async_stream`]. Higher layers
/// (e.g. SecretStream) wrap this for encrypted I/O.
pub struct UdxAsyncStream {
    inner: Arc<Mutex<StreamInner>>,
    read_rx: mpsc::UnboundedReceiver<StreamEvent>,
    read_buf: Vec<u8>,
    read_pos: usize,
    read_eof: bool,
    /// Writes sent but not yet acknowledged, oldest first, with their sizes.
    /// ACKs are cumulative, so they complete in this order.
    pending_acks: VecDeque<(oneshot::Receiver<UdxResult<()>>, usize)>,
    unacked_bytes: usize,
    processor: Option<tokio::task::JoinHandle<()>>,
    fin_queued: bool,
}

impl UdxAsyncStream {
    pub(crate) fn new(
        inner: Arc<Mutex<StreamInner>>,
        read_rx: mpsc::UnboundedReceiver<StreamEvent>,
        processor: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self {
            inner,
            read_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            read_eof: false,
            pending_acks: VecDeque::new(),
            unacked_bytes: 0,
            processor,
            fin_queued: false,
        }
    }

    /// Reap completed ACKs; `Pending` (with the oldest ACK's waker registered)
    /// while more than `limit` bytes stay unacknowledged. An error if a write
    /// failed or the stream closed with writes outstanding.
    fn poll_acks(&mut self, cx: &mut Context<'_>, limit: usize) -> Poll<io::Result<()>> {
        while let Some((ack_rx, len)) = self.pending_acks.front_mut() {
            let len = *len;
            match Pin::new(ack_rx).poll(cx) {
                Poll::Ready(result) => {
                    self.pending_acks.pop_front();
                    self.unacked_bytes -= len;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
                        Err(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "UDX stream closed",
                            )));
                        }
                    }
                }
                Poll::Pending if self.unacked_bytes > limit => return Poll::Pending,
                Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for UdxAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }

        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.read_pos += n;
            if self.read_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::Data(data))) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(StreamEvent::End)) | Poll::Ready(None) => {
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdxAsyncStream {
    /// Queues `buf` and returns at once; earlier writes hold it back only
    /// while more than [`MAX_UNACKED_BYTES`] would be unacknowledged.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_acks(cx, MAX_UNACKED_BYTES.saturating_sub(buf.len())))?;

        let (prep, max_payload) = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ack_rx) = inner.coalesce_write(buf) {
                drop(inner);
                self.pending_acks.push_back((ack_rx, buf.len()));
                self.unacked_bytes += buf.len();
                return Poll::Ready(Ok(buf.len()));
            }
            let p = inner
                .prepare_write(buf.len())
                .map_err(|e| io::Error::other(e.to_string()))?;
            let mp = inner.max_payload();
            (p, mp)
        };

        let len = buf.len();
        let remote_addr = prep.remote_addr;
        let remote_id = prep.remote_id;
        let first_seq = prep.first_seq;
        let current_ack = prep.current_ack;

        let chunks: Vec<&[u8]> = if buf.is_empty() {
            vec![&[]]
        } else {
            buf.chunks(max_payload).collect()
        };

        let packets: Vec<(u32, Vec<u8>)> = chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                let seq = first_seq + i as u32;
                (seq, build_data_packet(remote_id, seq, current_ack, chunk))
            })
            .collect();

        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.send_idle() {
                guard.congestion.on_transmit_start(std::time::Instant::now());
            }
            guard.queue_for_send(packets, remote_addr);
        }

        self.pending_acks.push_back((prep.ack_rx, len));
        self.unacked_bytes += len;
        Poll::Ready(Ok(len))
    }

    /// Ready once the data is handed to the stream, which sends it as the
    /// congestion window allows (like TCP); reports earlier failed writes.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_acks(cx, usize::MAX)
    }

    /// Queues FIN behind all written data and resolves once everything, FIN
    /// included, is acknowledged.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.fin_queued {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !inner.connected {
                return Poll::Ready(Ok(()));
            }
            let Some(addr) = inner.remote_addr else {
                return Poll::Ready(Ok(()));
            };
            let remote_id = inner.remote_id;
            let seq = inner.next_seq;
            inner.next_seq = seq + 1;
            let ack = inner.next_remote_seq;

            let header = Header {
                type_flags: FLAG_END,
                data_offset: 0,
                remote_id,
                recv_window: DEFAULT_RWND,
                seq,
                ack,
            };
            let packet = header.encode().to_vec();

            let (ack_tx, ack_rx) = oneshot::channel();
            inner.pending_writes.push(super::stream::PendingWrite {
                ack_threshold: seq + 1,
                tx: Some(ack_tx),
            });

            inner.queue_for_send(vec![(seq, packet)], addr);
            drop(inner);

            self.fin_queued = true;
            self.pending_acks.push_back((ack_rx, 0));
        }
        match self.poll_acks(cx, 0) {
            // Closed under us (as upstream): nothing left to shut down.
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

impl Unpin for UdxAsyncStream {}

impl Drop for UdxAsyncStream {
    fn drop(&mut self) {
        let _ = self.processor.take();
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref tx) = guard.notify_tx {
            let _ = tx.send(super::stream::StreamNotify::Shutdown);
        }
    }
}
