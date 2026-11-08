//! SCTP over UDP (spec §5).
//!
//! One driver task per UDP socket owns the sans-IO `sctp_proto::Endpoint` and all of
//! its associations. Applications talk to an association through a [`Conn`]:
//! messages on stream [`STREAM_CTRL`] or [`STREAM_DATA`], and `recv()` returning
//! `None` once the association is gone.
//!
//! sctp-proto keeps full state from the first INIT on and never sends heartbeats,
//! so this module adds the protections spec §7.2 asks for: a pre-filter that caps
//! pending (not yet established) associations globally and per source, an INIT
//! rate limit against reflection, a handshake deadline, an idle timeout so
//! dead peers are detected (the session layer pings every [`KEEPALIVE`]), and
//! panic isolation.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use log::{debug, warn};
use sctp_proto::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig,
    EndpointEvent, Event, Payload, PayloadProtocolIdentifier, ServerConfig, StreamEvent, TransportConfig,
};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

pub const STREAM_CTRL: u16 = 0;
pub const STREAM_DATA: u16 = 1;

/// Port inside the SCTP common header. The UDP port is what addresses the daemon,
/// so both sides use a fixed value here.
const SCTP_PORT: u16 = 22;
/// Largest message accepted on any stream (frames are ≤ 16 KiB plaintext, §5).
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Bytes an application may have queued in sctp-proto per association.
const SEND_WINDOW: usize = 1 << 20;
/// Messages buffered towards the application before SCTP back-pressure kicks in.
const RECV_QUEUE: usize = 64;
/// SCTP-level handshake (INIT … COOKIE-ACK) deadline.
const SCTP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// An established association with no packet from the peer for this long is
/// dead. sctp-proto never reports exhausted DATA retransmits (T3-rtx "will not
/// fail by design", inherited from WebRTC), so this is the only detection.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the session layer must send something (a ping) on an idle association.
pub const KEEPALIVE: Duration = Duration::from_secs(5);
const UDP_BUF: usize = 65536;
/// How long a closed association may linger to deliver queued data.
const CLOSE_LINGER: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Limits {
    /// Associations that are not yet established, across all sources.
    pub max_pending: usize,
    /// Associations that are not yet established, per IPv4 address / IPv6 /64.
    pub max_pending_per_source: usize,
    /// New INITs accepted per second (token bucket), bounds INIT-ACK reflection.
    pub init_rate: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_pending: 64, max_pending_per_source: 8, init_rate: 200 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("association failed: {0}")]
    Failed(String),
    #[error("association closed")]
    Closed,
    #[error("message too large ({0} bytes)")]
    TooLarge(usize),
}

fn transport_config() -> TransportConfig {
    // A low RTO ceiling keeps retransmits frequent enough for a quick recovery
    // after short outages; dead paths are detected by `IDLE_TIMEOUT` instead of
    // retransmit limits, which sctp-proto ignores for DATA.
    TransportConfig::default()
        .with_max_send_message_size(MAX_MESSAGE as u32)
        .with_max_receive_message_size(MAX_MESSAGE as u32)
        .with_max_receive_buffer_size(4 * 1024 * 1024)
        .with_max_num_inbound_streams(2)
        .with_max_num_outbound_streams(2)
        .with_max_init_retransmits(Some(4))
        .with_max_data_retransmits(None)
        .with_rto_initial_ms(1000)
        .with_rto_min_ms(500)
        .with_rto_max_ms(4000)
        .with_local_port(SCTP_PORT)
        .with_remote_port(SCTP_PORT)
}

/// An established association.
pub struct Conn {
    remote: SocketAddr,
    handle: AssociationHandle,
    cmd: mpsc::UnboundedSender<Cmd>,
    window: Arc<Semaphore>,
    rx: mpsc::Receiver<(u16, Bytes)>,
    kick: Arc<Notify>,
}

impl Conn {
    pub fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// Queue one message. Waits while more than the send window is unacknowledged.
    pub async fn send(&self, stream: u16, data: Bytes) -> Result<(), TransportError> {
        if data.len() > MAX_MESSAGE {
            return Err(TransportError::TooLarge(data.len()));
        }
        let permits = data.len().max(1) as u32;
        self.window.acquire_many(permits).await.map_err(|_| TransportError::Closed)?.forget();
        self.cmd
            .send(Cmd::Send { handle: self.handle, stream, data, permits })
            .map_err(|_| TransportError::Closed)?;
        self.kick.notify_one();
        Ok(())
    }

    /// Next message, or `None` once the association is lost or closed.
    pub async fn recv(&mut self) -> Option<(u16, Bytes)> {
        let msg = self.rx.recv().await;
        // Room in the queue again: let the driver read more from SCTP.
        self.kick.notify_one();
        msg
    }

    /// Graceful SCTP shutdown (after queued data is delivered).
    pub fn close(&self) {
        let _ = self.cmd.send(Cmd::Close(self.handle));
        self.kick.notify_one();
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.close();
    }
}

enum Cmd {
    Send { handle: AssociationHandle, stream: u16, data: Bytes, permits: u32 },
    Close(AssociationHandle),
}

struct Assoc {
    a: Association,
    remote: SocketAddr,
    source: SourceKey,
    created: Instant,
    last_rx: Instant,
    established: bool,
    /// Present until the association is handed to the application.
    on_connected: Option<oneshot::Sender<Result<Conn, TransportError>>>,
    conn_rx: Option<mpsc::Receiver<(u16, Bytes)>>,
    tx: mpsc::Sender<(u16, Bytes)>,
    window: Arc<Semaphore>,
    /// Bytes the application has handed over that sctp-proto has not yet released.
    inflight: usize,
    dead: bool,
    /// The endpoint already forgot this association (it emitted `Drained`).
    drained: bool,
    /// Close requested: shut down once all sent data is acknowledged, or at this deadline.
    close_by: Option<Instant>,
}

/// IPv4 address or IPv6 /64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SourceKey {
    V4([u8; 4]),
    V6([u8; 8]),
}

impl SourceKey {
    fn of(addr: &SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(v4) => SourceKey::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => SourceKey::V4(v4.octets()),
                None => {
                    let o = v6.octets();
                    SourceKey::V6(o[..8].try_into().unwrap())
                }
            },
        }
    }
}

struct TokenBucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        TokenBucket { rate: rate as f64, tokens: rate as f64, last: Instant::now() }
    }
    fn take(&mut self, now: Instant) -> bool {
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.rate);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Driver {
    socket: Arc<UdpSocket>,
    endpoint: Endpoint,
    assocs: HashMap<AssociationHandle, Assoc>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    kick: Arc<Notify>,
    accept_tx: Option<mpsc::Sender<Conn>>,
    limits: Limits,
    init_bucket: TokenBucket,
}

/// Server side: accepts associations on one UDP socket.
pub struct Listener {
    local: SocketAddr,
    rx: mpsc::Receiver<Conn>,
}

impl Listener {
    pub async fn bind(addr: SocketAddr, limits: Limits) -> Result<Listener, TransportError> {
        let socket = bind_socket(addr)?;
        let local = socket.local_addr()?;
        let mut server = ServerConfig::new();
        server.transport = Arc::new(transport_config());
        let endpoint = Endpoint::new(Arc::new(EndpointConfig::new()), Some(Arc::new(server)));
        let (accept_tx, rx) = mpsc::channel(16);
        let driver = Driver::new(socket, endpoint, Some(accept_tx), limits);
        tokio::spawn(driver.run());
        Ok(Listener { local, rx })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub async fn accept(&mut self) -> Option<Conn> {
        self.rx.recv().await
    }
}

/// Client side: one fresh UDP socket (and driver) per association, so every
/// reconnect starts from a new source port.
pub async fn connect(remote: SocketAddr) -> Result<Conn, TransportError> {
    let bind: SocketAddr = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let socket = bind_socket(bind)?;
    // A client endpoint must still carry a server config: sctp-proto unwraps it
    // when an INIT arrives. New associations are rejected explicitly instead.
    let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::new()), Some(Arc::new(ServerConfig::new())));
    endpoint.reject_new_associations();
    let mut client = ClientConfig::new();
    client.transport = Arc::new(transport_config());
    let (handle, a) = endpoint
        .connect(client, remote)
        .map_err(|e| TransportError::Failed(e.to_string()))?;

    let (done_tx, done_rx) = oneshot::channel();
    let mut driver = Driver::new(socket, endpoint, None, Limits::default());
    driver.insert(handle, a, remote, Some(done_tx));
    tokio::spawn(driver.run());
    done_rx.await.map_err(|_| TransportError::Closed)?
}

fn bind_socket(addr: SocketAddr) -> Result<Arc<UdpSocket>, TransportError> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        // Separate IPv4 and IPv6 sockets (spec §5): [::] must not also take IPv4.
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(Arc::new(UdpSocket::from_std(socket.into())?))
}

impl Driver {
    fn new(
        socket: Arc<UdpSocket>,
        endpoint: Endpoint,
        accept_tx: Option<mpsc::Sender<Conn>>,
        limits: Limits,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let init_bucket = TokenBucket::new(limits.init_rate);
        Driver {
            socket,
            endpoint,
            assocs: HashMap::new(),
            cmd_tx,
            cmd_rx,
            kick: Arc::new(Notify::new()),
            accept_tx,
            limits,
            init_bucket,
        }
    }

    fn insert(
        &mut self,
        handle: AssociationHandle,
        a: Association,
        remote: SocketAddr,
        on_connected: Option<oneshot::Sender<Result<Conn, TransportError>>>,
    ) {
        let (tx, rx) = mpsc::channel(RECV_QUEUE);
        self.assocs.insert(
            handle,
            Assoc {
                a,
                remote,
                source: SourceKey::of(&remote),
                created: Instant::now(),
                last_rx: Instant::now(),
                established: false,
                on_connected,
                conn_rx: Some(rx),
                tx,
                window: Arc::new(Semaphore::new(SEND_WINDOW)),
                inflight: 0,
                dead: false,
                drained: false,
                close_by: None,
            },
        );
    }

    async fn run(mut self) {
        let mut buf = vec![0u8; UDP_BUF];
        // A client driver starts with an association whose INIT is already queued.
        self.process(Instant::now()).await;
        loop {
            let deadline = self.next_deadline();
            let socket = self.socket.clone();
            let kick = self.kick.clone();
            tokio::select! {
                r = socket.recv_from(&mut buf) => match r {
                    Ok((n, from)) => self.on_datagram(from, Bytes::copy_from_slice(&buf[..n])),
                    Err(e) => debug!("udp recv: {e}"),
                },
                Some(cmd) = self.cmd_rx.recv() => {
                    self.on_cmd(cmd);
                    while let Ok(cmd) = self.cmd_rx.try_recv() {
                        self.on_cmd(cmd);
                    }
                }
                _ = kick.notified() => {}
                _ = sleep_until(deadline) => {}
            }
            self.process(Instant::now()).await;

            // A client driver ends with its only association.
            if self.accept_tx.is_none() && self.assocs.is_empty() {
                return;
            }
            if self.accept_tx.as_ref().is_some_and(|t| t.is_closed()) && self.assocs.is_empty() {
                return;
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.assocs
            .values()
            .flat_map(|s| {
                let hs = if s.established { s.last_rx + IDLE_TIMEOUT } else { s.created + SCTP_HANDSHAKE_TIMEOUT };
                let hs = s.close_by.map_or(hs, |c| c.min(hs));
                [s.a.poll_timeout(), Some(hs)]
            })
            .flatten()
            .min()
    }

    fn on_datagram(&mut self, from: SocketAddr, data: Bytes) {
        let now = Instant::now();
        // Pre-filter (spec §7.2): a packet with verification tag 0 must be an
        // INIT, which makes sctp-proto allocate a full association.
        if data.len() < 16 {
            return;
        }
        let vtag = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if vtag == 0 && !self.admit_init(from, now) {
            return;
        }
        log::trace!("datagram from {from}: {} bytes vtag={vtag:#x}", data.len());
        let res = catch_unwind(AssertUnwindSafe(|| self.endpoint.handle(now, from, None, None, data)));
        match res {
            Ok(Some((handle, DatagramEvent::NewAssociation(a)))) => {
                debug!("new association from {from}");
                self.insert(handle, a, from, None);
            }
            Ok(Some((handle, DatagramEvent::AssociationEvent(ev)))) => {
                if let Some(s) = self.assocs.get_mut(&handle) {
                    s.last_rx = now;
                    if catch_unwind(AssertUnwindSafe(|| s.a.handle_event(ev))).is_err() {
                        warn!("sctp association from {} panicked; dropped", s.remote);
                        s.dead = true;
                    }
                }
            }
            Ok(None) => {}
            Err(_) => warn!("sctp endpoint panicked on a datagram from {from}; packet dropped"),
        }
    }

    fn admit_init(&mut self, from: SocketAddr, now: Instant) -> bool {
        if self.accept_tx.is_none() {
            return false;
        }
        let source = SourceKey::of(&from);
        let pending = self.assocs.values().filter(|s| !s.established);
        let (mut total, mut same) = (0, 0);
        for s in pending {
            total += 1;
            if s.source == source {
                same += 1;
            }
        }
        if total >= self.limits.max_pending || same >= self.limits.max_pending_per_source {
            debug!("INIT from {from} refused: pending limit");
            return false;
        }
        if !self.init_bucket.take(now) {
            debug!("INIT from {from} refused: rate limit");
            return false;
        }
        true
    }

    fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Send { handle, stream, data, permits } => {
                let Some(s) = self.assocs.get_mut(&handle) else { return };
                s.inflight += permits as usize;
                let res = match s.a.stream(stream) {
                    Ok(mut st) => st.write(&data),
                    Err(_) => s
                        .a
                        .open_stream(stream, PayloadProtocolIdentifier::Binary)
                        .and_then(|mut st| st.write(&data)),
                };
                if let Err(e) = res {
                    debug!("write to {}: {e}", s.remote);
                    s.dead = true;
                }
            }
            Cmd::Close(handle) => {
                if let Some(s) = self.assocs.get_mut(&handle) {
                    // sctp-proto sends SHUTDOWN at once if nothing is in flight yet,
                    // dropping data that is only queued, so wait for the acks first.
                    s.close_by.get_or_insert(Instant::now() + CLOSE_LINGER);
                }
            }
        }
    }

    async fn process(&mut self, now: Instant) {
        let mut endpoint_events = Vec::new();
        let mut transmits = Vec::new();
        let mut accepted = Vec::new();

        for (&handle, s) in self.assocs.iter_mut() {
            let r = catch_unwind(AssertUnwindSafe(|| {
                if s.a.poll_timeout().is_some_and(|t| t <= now) {
                    s.a.handle_timeout(now);
                }
                if s.established && now.duration_since(s.last_rx) >= IDLE_TIMEOUT {
                    debug!("association with {} idle for {IDLE_TIMEOUT:?}; dead", s.remote);
                    s.dead = true;
                }
                if !s.established && now.duration_since(s.created) >= SCTP_HANDSHAKE_TIMEOUT {
                    s.dead = true;
                }
                while let Some(ev) = s.a.poll() {
                    match ev {
                        Event::Connected => {
                            s.established = true;
                            let conn = Conn {
                                remote: s.remote,
                                handle,
                                cmd: self.cmd_tx.clone(),
                                window: s.window.clone(),
                                rx: s.conn_rx.take().expect("connected once"),
                                kick: self.kick.clone(),
                            };
                            match s.on_connected.take() {
                                Some(done) => {
                                    let _ = done.send(Ok(conn));
                                }
                                None => accepted.push(conn),
                            }
                        }
                        Event::HandshakeFailed { reason } | Event::AssociationLost { reason } => {
                            debug!("association with {} ended: {reason}", s.remote);
                            if let Some(done) = s.on_connected.take() {
                                let _ = done.send(Err(TransportError::Failed(reason.to_string())));
                            }
                            s.dead = true;
                        }
                        Event::Stream(StreamEvent::Opened { .. } | StreamEvent::Readable { .. }) => {}
                        _ => {}
                    }
                }
                while s.a.accept_stream().is_some() {}

                // Deliver complete messages while the application has room.
                if s.established && !s.dead {
                    'streams: for id in [STREAM_CTRL, STREAM_DATA] {
                        loop {
                            let Ok(permit) = s.tx.try_reserve() else { break 'streams };
                            let Ok(mut st) = s.a.stream(id) else { continue 'streams };
                            match st.read() {
                                Ok(Some(chunks)) => {
                                    let mut msg = BytesMut::zeroed(chunks.len());
                                    if chunks.read(&mut msg).is_ok() {
                                        permit.send((id, msg.freeze()));
                                    }
                                }
                                _ => continue 'streams,
                            }
                        }
                    }
                }

                // Release send window for data sctp-proto has let go of.
                let buffered: usize = [STREAM_CTRL, STREAM_DATA]
                    .iter()
                    .filter_map(|&id| s.a.stream(id).ok().and_then(|st| st.buffered_amount().ok()))
                    .sum();
                if buffered < s.inflight {
                    s.window.add_permits(s.inflight - buffered);
                    s.inflight = buffered;
                }
                if let Some(by) = s.close_by {
                    if !s.established || buffered == 0 || now >= by {
                        // The SHUTDOWN chunk goes out below, before removal.
                        if s.a.shutdown().is_err() {
                            let _ = s.a.close();
                        }
                        s.dead = true;
                    }
                }

                while let Some(ev) = s.a.poll_endpoint_event() {
                    endpoint_events.push((handle, ev));
                }
                while let Some(t) = s.a.poll_transmit(now) {
                    transmits.push(t);
                }
                // A server association stays in `Closed` until COOKIE-ECHO arrives.
                // A peer SHUTDOWN leaves us `closing`; the SHUTDOWN-ACK was just
                // queued above, and nothing more will arrive.
                if s.established && (s.a.is_closed() || s.a.is_closing()) {
                    s.dead = true;
                }
            }));
            if r.is_err() {
                warn!("sctp association with {} panicked; dropped", s.remote);
                s.dead = true;
            }
        }

        for (handle, ev) in endpoint_events {
            if ev.is_drained() {
                // The endpoint panics on a second `Drained` for the same handle.
                match self.assocs.get_mut(&handle) {
                    Some(s) if !s.drained => s.drained = true,
                    _ => continue,
                }
            }
            if let Ok(Some(back)) = catch_unwind(AssertUnwindSafe(|| self.endpoint.handle_event(handle, ev))) {
                if let Some(s) = self.assocs.get_mut(&handle) {
                    s.a.handle_event(back);
                }
            }
        }
        while let Some(t) = self.endpoint.poll_transmit() {
            transmits.push(t);
        }

        for t in transmits {
            if let Payload::RawEncode(datagrams) = t.payload {
                for d in datagrams {
                    if let Err(e) = self.socket.send_to(&d, t.remote).await {
                        debug!("udp send to {}: {e}", t.remote);
                    }
                }
            }
        }

        if let Some(accept_tx) = &self.accept_tx {
            for conn in accepted {
                if accept_tx.try_send(conn).is_err() {
                    warn!("accept queue full; association dropped");
                }
            }
        }

        let endpoint = &mut self.endpoint;
        self.assocs.retain(|&handle, s| {
            if s.dead {
                // Free the endpoint's routing entry too, or every spoofed INIT
                // that never completes would leak one slab slot.
                if !s.drained {
                    let drained = EndpointEvent::drained();
                    let _ = catch_unwind(AssertUnwindSafe(|| endpoint.handle_event(handle, drained)));
                }
                s.window.close();
                if let Some(done) = s.on_connected.take() {
                    let _ = done.send(Err(TransportError::Failed("association failed".into())));
                }
            }
            !s.dead
        });
    }
}

fn sleep_until(deadline: Option<Instant>) -> impl Future<Output = ()> {
    async move {
        match deadline {
            Some(d) => tokio::time::sleep_until(d.into()).await,
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn echo_roundtrip() {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Limits::default()).await.unwrap();
        let addr = listener.local_addr();
        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            while let Some((stream, msg)) = conn.recv().await {
                conn.send(stream, msg).await.unwrap();
            }
        });

        let mut conn = connect(addr).await.unwrap();
        for i in 0..200u32 {
            let stream = if i % 2 == 0 { STREAM_CTRL } else { STREAM_DATA };
            let msg = Bytes::from(vec![(i % 251) as u8; 1 + (i as usize * 97) % 16000]);
            conn.send(stream, msg.clone()).await.unwrap();
            let (s, back) = conn.recv().await.unwrap();
            assert_eq!(s, stream);
            assert_eq!(back, msg);
        }
        drop(conn);
        tokio::time::timeout(Duration::from_secs(30), server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bulk_transfer_with_backpressure() {
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Limits::default()).await.unwrap();
        let addr = listener.local_addr();
        const N: usize = 2000;
        tokio::spawn(async move {
            let conn = listener.accept().await.unwrap();
            for i in 0..N {
                conn.send(STREAM_DATA, Bytes::from(vec![(i % 256) as u8; 16384])).await.unwrap();
            }
            // keep the association open until the client is done
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let mut conn = connect(addr).await.unwrap();
        for i in 0..N {
            let (_, msg) = conn.recv().await.unwrap();
            assert_eq!(msg.len(), 16384);
            assert_eq!(msg[0], (i % 256) as u8);
        }
    }

    /// UDP relay between a client and `server` that can be switched to drop
    /// everything, simulating a dead path. Returns its address, the drop switch
    /// and a log of (direction, datagram size) for the first packets.
    async fn relay(
        server: SocketAddr,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicBool>, Arc<std::sync::Mutex<Vec<(bool, usize)>>>) {
        use std::sync::atomic::{AtomicBool, Ordering};
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let blackhole = Arc::new(AtomicBool::new(false));
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (bh, lg) = (blackhole.clone(), log.clone());
        tokio::spawn(async move {
            let mut client = None;
            let (mut b1, mut b2) = (vec![0u8; UDP_BUF], vec![0u8; UDP_BUF]);
            loop {
                tokio::select! {
                    Ok((n, from)) = front.recv_from(&mut b1) => {
                        client = Some(from);
                        lg.lock().unwrap().push((true, n));
                        if !bh.load(Ordering::Relaxed) {
                            let _ = back.send_to(&b1[..n], server).await;
                        }
                    }
                    Ok((n, _)) = back.recv_from(&mut b2) => {
                        lg.lock().unwrap().push((false, n));
                        if let (Some(c), false) = (client, bh.load(Ordering::Relaxed)) {
                            let _ = front.send_to(&b2[..n], c).await;
                        }
                    }
                }
            }
        });
        (addr, blackhole, log)
    }

    /// M0 measurements: INIT/INIT-ACK size ratio and dead-path detection time.
    #[tokio::test]
    async fn dead_path_is_detected() {
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Limits::default()).await.unwrap();
        let (addr, blackhole, log) = relay(listener.local_addr()).await;
        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            let start = Instant::now();
            while conn.recv().await.is_some() {}
            start
        });

        let mut conn = connect(addr).await.unwrap();
        {
            let log = log.lock().unwrap();
            let init = log.iter().find(|(c2s, _)| *c2s).unwrap().1;
            let init_ack = log.iter().find(|(c2s, _)| !*c2s).unwrap().1;
            println!("INIT {init} bytes, INIT-ACK {init_ack} bytes, ratio {:.2}", init_ack as f64 / init as f64);
            assert!(init_ack <= 2 * init, "INIT-ACK amplification above 2x");
        }

        blackhole.store(true, std::sync::atomic::Ordering::Relaxed);
        let cut = Instant::now();
        // Application keepalive: one small message per second, as the session layer does.
        let detected = loop {
            tokio::select! {
                r = conn.recv() => if r.is_none() { break cut.elapsed() },
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    if conn.send(STREAM_CTRL, Bytes::from_static(b"ping")).await.is_err() {
                        break cut.elapsed();
                    }
                }
            }
        };
        println!("client detected dead path after {detected:?}");
        assert!(detected >= IDLE_TIMEOUT && detected < IDLE_TIMEOUT + Duration::from_secs(2));
        let _ = server; // the server side has no keepalive of its own in this test
    }

    #[tokio::test]
    async fn init_flood_is_capped() {
        let mut listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Limits::default()).await.unwrap();
        let addr = listener.local_addr();
        // INITs that never complete the handshake, all from one source.
        let flooder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut answered = 0;
        let mut buf = [0u8; 2048];
        for i in 0..50u32 {
            flooder.send_to(&raw_init(0x1000 + i), addr).await.unwrap();
            if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(50), flooder.recv_from(&mut buf)).await {
                answered += 1;
            }
        }
        println!("{answered} of 50 INITs answered");
        assert_eq!(answered, Limits::default().max_pending_per_source);
        // A legitimate client from the same address is still refused while the
        // pending slots are taken, but the daemon keeps serving others.
        drop(listener.rx.try_recv());
    }

    /// A minimal SCTP packet carrying one INIT chunk (RFC 9260 §3.3.2).
    fn raw_init(tag: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&SCTP_PORT.to_be_bytes());
        p.extend_from_slice(&SCTP_PORT.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // verification tag
        p.extend_from_slice(&0u32.to_be_bytes()); // checksum, filled below
        p.extend_from_slice(&[1, 0]); // type INIT, flags
        p.extend_from_slice(&20u16.to_be_bytes());
        p.extend_from_slice(&tag.to_be_bytes()); // initiate tag
        p.extend_from_slice(&131072u32.to_be_bytes()); // a_rwnd
        p.extend_from_slice(&2u16.to_be_bytes()); // outbound streams
        p.extend_from_slice(&2u16.to_be_bytes()); // inbound streams
        p.extend_from_slice(&1u32.to_be_bytes()); // initial TSN
        let crc = crc32c(&p);
        p[8..12].copy_from_slice(&crc.to_le_bytes());
        p
    }

    fn crc32c(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
            }
        }
        !crc
    }
}
