//! Sessions (spec §4): one task per session owns the child process and its
//! output buffers; connections attach to it through channels.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sshcrab_proto::wire::{
    AttachRefusal, Ctrl, Data, DataStream, ExitStatus, MAX_CHUNK, Offsets, SessionInfo,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::auth::Account;
use crate::sys::{self, ChildIo};

/// Messages from a connection to its session.
pub enum ToSession {
    Attach {
        client: Client,
        received: Offsets,
        window: Option<(u16, u16)>,
        takeover: bool,
        reply: oneshot::Sender<Result<Attached, AttachRefusal>>,
    },
    /// The connection of `client_id` is gone.
    Detached { client_id: u64 },
    Stdin { offset: u64, data: Vec<u8> },
    StdinEof { offset: u64 },
    Ack { stream: DataStream, offset: u64 },
    Window { cols: u16, rows: u16 },
    Signal(i32),
    /// Normal client exit: remove the session.
    Close,
    /// `-C` detach: kick the attached client, keep the session.
    Kick { reason: String },
    /// `-C` remove.
    Remove,
}

/// Messages from a session to the attached connection.
pub enum ToClient {
    Data(Data),
    Ctrl(Ctrl),
    /// Send `Kicked` and disconnect.
    Kicked(String),
}

pub struct Client {
    pub id: u64,
    pub tx: mpsc::Sender<ToClient>,
}

pub struct Attached {
    pub id: Uuid,
    pub replay: Offsets,
    pub lost_bytes: u64,
}

#[derive(Clone)]
struct Entry {
    owner: String,
    interactive: bool,
    created: Instant,
    /// `None` while a client is attached.
    disconnected: Option<Instant>,
    pid: u32,
    tx: mpsc::Sender<ToSession>,
}

pub struct Manager {
    sessions: Mutex<HashMap<Uuid, Entry>>,
    pub buffer_bytes: usize,
    pub timeout: Duration,
    pub max_per_user: usize,
}

pub struct NewSession<'a> {
    pub account: &'a Account,
    pub command: Option<String>,
    pub env: Vec<(String, String)>,
    pub window: Option<(u16, u16)>,
}

impl Manager {
    pub fn new(buffer_bytes: usize, timeout: Duration, max_per_user: usize) -> Arc<Self> {
        Arc::new(Manager { sessions: Mutex::new(HashMap::new()), buffer_bytes, timeout, max_per_user })
    }

    /// Sessions of `owner`, or all sessions for `None` (root in control mode).
    pub fn list(&self, owner: Option<&str>) -> Vec<SessionInfo> {
        let now = Instant::now();
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| owner.is_none_or(|o| e.owner == o))
            .map(|(id, e)| SessionInfo {
                id: *id,
                owner: e.owner.clone(),
                interactive: e.interactive,
                connected: e.disconnected.is_none(),
                age_secs: now.duration_since(e.created).as_secs(),
                idle_secs: e.disconnected.map(|d| now.duration_since(d).as_secs()),
            })
            .collect()
    }

    /// The session's channel, if it exists and `owner` may use it.
    pub fn get(&self, id: &Uuid, owner: Option<&str>) -> Option<mpsc::Sender<ToSession>> {
        let s = self.sessions.lock().unwrap();
        s.get(id).filter(|e| owner.is_none_or(|o| e.owner == o)).map(|e| e.tx.clone())
    }

    fn set_disconnected(&self, id: &Uuid, at: Option<Instant>) {
        if let Some(e) = self.sessions.lock().unwrap().get_mut(id) {
            e.disconnected = at;
        }
    }

    fn remove(&self, id: &Uuid) {
        if let Some(e) = self.sessions.lock().unwrap().remove(id) {
            log::info!("session {id} of {} removed", e.owner);
        }
    }

    /// Start a session process. The caller attaches to the returned channel.
    pub fn create(self: &Arc<Self>, spec: NewSession<'_>) -> Result<(Uuid, mpsc::Sender<ToSession>), AttachRefusal> {
        let id = Uuid::new_v4();
        let owner = spec.account.name.clone();
        {
            let s = self.sessions.lock().unwrap();
            let count = s.values().filter(|e| e.owner == owner).count();
            if self.max_per_user != 0 && count >= self.max_per_user {
                log::info!("{owner}: MaxSessionsPerUser reached");
                return Err(AttachRefusal::TooManySessions);
            }
        }
        let mut env = base_env(spec.account);
        env.extend(spec.env);
        env.push(("SSHCRAB_SESSION_ID".into(), id.to_string()));
        let interactive = spec.command.is_none();
        let (child, io) = sys::spawn(sys::Spawn {
            account: spec.account,
            command: spec.command.as_deref(),
            env,
            window: spec.window,
        })
        .map_err(|e| {
            log::warn!("spawn for {owner} failed: {e}");
            AttachRefusal::Failed
        })?;
        let pid = child.id().unwrap_or(0);
        let (tx, rx) = mpsc::channel(64);
        self.sessions.lock().unwrap().insert(
            id,
            Entry { owner: owner.clone(), interactive, created: Instant::now(), disconnected: Some(Instant::now()), pid, tx: tx.clone() },
        );
        log::info!("session {id} created for {owner} (pid {pid}, {})", if interactive { "interactive" } else { "command" });
        let actor = Actor::new(self.clone(), id, interactive, pid, self.buffer_bytes);
        tokio::spawn(actor.run(child, io, rx));
        Ok((id, tx))
    }

    /// Daemon shutdown: end all session processes.
    pub fn kill_all(&self) {
        for e in self.sessions.lock().unwrap().values() {
            sys::kill_group(e.pid, libc::SIGHUP);
        }
    }
}

fn base_env(acc: &Account) -> Vec<(String, String)> {
    let home = acc.home.display().to_string();
    let path = format!(
        "/run/wrappers/bin:{home}/.nix-profile/bin:/nix/profile/bin:/etc/profiles/per-user/{u}/bin:\
         /nix/var/nix/profiles/default/bin:/run/current-system/sw/bin:/usr/local/bin:/usr/bin:/bin",
        u = acc.name
    );
    vec![
        ("HOME".into(), home),
        ("USER".into(), acc.name.clone()),
        ("LOGNAME".into(), acc.name.clone()),
        ("SHELL".into(), acc.shell.display().to_string()),
        ("PATH".into(), path),
    ]
}

/// Unacknowledged output of one stream, addressed by absolute byte offset.
struct OutBuf {
    /// Offset of `buf[0]`.
    start: u64,
    buf: VecDeque<u8>,
    /// Next offset to send to the attached client.
    sent: u64,
    eof: bool,
}

impl OutBuf {
    fn new() -> Self {
        OutBuf { start: 0, buf: VecDeque::new(), sent: 0, eof: false }
    }
    fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }
    fn ack(&mut self, offset: u64) {
        let offset = offset.min(self.sent);
        if offset > self.start {
            self.buf.drain(..(offset - self.start) as usize);
            self.start = offset;
        }
    }
    /// Ring-buffer mode (interactive): drop the oldest bytes beyond `cap`.
    fn push_ring(&mut self, data: &[u8], cap: usize) {
        self.buf.extend(data);
        if self.buf.len() > cap {
            let drop = self.buf.len() - cap;
            self.buf.drain(..drop);
            self.start += drop as u64;
            self.sent = self.sent.max(self.start);
        }
    }
    fn unsent(&self) -> bool {
        self.sent < self.end()
    }
    fn next_chunk(&mut self) -> Option<(u64, Vec<u8>)> {
        if !self.unsent() {
            return None;
        }
        let from = (self.sent - self.start) as usize;
        let n = (self.buf.len() - from).min(MAX_CHUNK);
        let chunk: Vec<u8> = self.buf.range(from..from + n).copied().collect();
        let offset = self.sent;
        self.sent += n as u64;
        Some((offset, chunk))
    }
}

struct Actor {
    mgr: Arc<Manager>,
    id: Uuid,
    interactive: bool,
    pid: u32,
    cap: usize,
    out: OutBuf,
    err: OutBuf,
    stdin_offset: u64,
    /// Client-announced end of stdin; EOF is passed on once all of it arrived.
    stdin_eof_at: Option<u64>,
    exit: Option<ExitStatus>,
    exit_sent: bool,
    client: Option<Client>,
    disconnected: Option<Instant>,
}

enum Input {
    Data(Vec<u8>),
    Eof,
}

impl Actor {
    fn new(mgr: Arc<Manager>, id: Uuid, interactive: bool, pid: u32, cap: usize) -> Self {
        Actor {
            mgr,
            id,
            interactive,
            pid,
            cap,
            out: OutBuf::new(),
            err: OutBuf::new(),
            stdin_offset: 0,
            stdin_eof_at: None,
            exit: None,
            exit_sent: false,
            client: None,
            disconnected: Some(Instant::now()),
        }
    }

    async fn run(mut self, mut child: tokio::process::Child, io: ChildIo, mut rx: mpsc::Receiver<ToSession>) {
        // Output readers feed `out_rx`; stdin goes through a writer task so a
        // child that does not read its input cannot stall the session.
        let (out_tx, mut out_rx) = mpsc::channel::<(DataStream, Option<Vec<u8>>)>(4);
        let (in_tx, in_rx) = mpsc::channel::<Input>(256);
        let pty = match io {
            ChildIo::Pty(master) => {
                let master = Arc::new(master);
                spawn_pty_reader(master.clone(), out_tx.clone());
                spawn_pty_writer(master.clone(), in_rx);
                Some(master)
            }
            ChildIo::Pipes { stdin, stdout, stderr } => {
                spawn_pipe_reader(stdout, DataStream::Stdout, out_tx.clone());
                spawn_pipe_reader(stderr, DataStream::Stderr, out_tx.clone());
                spawn_pipe_writer(stdin, in_rx);
                self.err.eof = false;
                None
            }
        };
        if pty.is_some() {
            self.err.eof = true;
        }
        drop(out_tx);
        let mut in_tx = Some(in_tx);
        let mut child_done = false;

        loop {
            self.maybe_send_exit().await;
            let timeout_at = self.disconnected.map(|d| d + self.mgr.timeout);
            let unsent = self.client.is_some() && (self.out.unsent() || self.err.unsent());
            // Non-interactive: stop reading while the buffers are full (back-pressure).
            let room = self.interactive || (self.out.buf.len() < self.cap && self.err.buf.len() < self.cap);
            let reserve_tx = self.client.as_ref().filter(|_| unsent).map(|c| c.tx.clone());
            let reserve = async move {
                match reserve_tx {
                    Some(tx) => tx.reserve_owned().await.ok(),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                msg = rx.recv() => match msg {
                    Some(m) => {
                        if self.handle(m, pty.as_deref(), &mut in_tx).await {
                            break;
                        }
                    }
                    None => break,
                },
                Some((stream, data)) = out_rx.recv(), if room => {
                    let buf = if stream == DataStream::Stderr { &mut self.err } else { &mut self.out };
                    match data {
                        Some(d) if self.interactive => buf.push_ring(&d, self.cap),
                        Some(d) => buf.buf.extend(d),
                        None => buf.eof = true,
                    }
                }
                status = child.wait(), if !child_done => {
                    child_done = true;
                    self.exit = Some(match status {
                        Ok(s) => match (s.code(), std::os::unix::process::ExitStatusExt::signal(&s)) {
                            (Some(c), _) => ExitStatus::Code(c),
                            (None, Some(sig)) => ExitStatus::Signal(sig),
                            _ => ExitStatus::Code(255),
                        },
                        Err(_) => ExitStatus::Code(255),
                    });
                    log::info!("session {}: process exited ({:?})", self.id, self.exit);
                    // A PTY stays readable while background jobs hold it; the
                    // session ends with the shell, like sshd.
                    if pty.is_some() {
                        self.drain_pty_output(&mut out_rx).await;
                        self.out.eof = true;
                    }
                }
                Some(permit) = reserve => {
                    let msg = if self.out.unsent() {
                        self.out.next_chunk().map(|(o, d)| (DataStream::Stdout, o, d))
                    } else {
                        self.err.next_chunk().map(|(o, d)| (DataStream::Stderr, o, d))
                    };
                    if let Some((stream, offset, data)) = msg {
                        permit.send(ToClient::Data(Data::Bytes { stream, offset, data }));
                    }
                }
                _ = sleep_until(timeout_at) => {
                    log::info!("session {}: disconnected timeout reached", self.id);
                    break;
                }
            }
        }

        if !child_done {
            sys::kill_group(self.pid, libc::SIGHUP);
            let pid = self.pid;
            tokio::spawn(async move {
                tokio::select! {
                    _ = child.wait() => {}
                    _ = tokio::time::sleep(Duration::from_secs(5)) => sys::kill_group(pid, libc::SIGKILL),
                }
                let _ = child.wait().await;
            });
        }
        self.mgr.remove(&self.id);
    }

    async fn drain_pty_output(&mut self, out_rx: &mut mpsc::Receiver<(DataStream, Option<Vec<u8>>)>) {
        while let Ok(Some((_, Some(d)))) = tokio::time::timeout(Duration::from_millis(50), out_rx.recv()).await {
            self.out.push_ring(&d, self.cap);
        }
    }

    async fn maybe_send_exit(&mut self) {
        let Some(exit) = self.exit else { return };
        if self.exit_sent || !self.out.eof || !self.err.eof || self.out.unsent() || self.err.unsent() {
            return;
        }
        if let Some(c) = &self.client {
            let end = Offsets { stdin: self.stdin_offset, stdout: self.out.end(), stderr: self.err.end() };
            if c.tx.send(ToClient::Ctrl(Ctrl::Exit { status: exit, end })).await.is_ok() {
                self.exit_sent = true;
            }
        }
    }

    async fn maybe_stdin_eof(&mut self, in_tx: &mut Option<mpsc::Sender<Input>>) {
        if self.stdin_eof_at.is_some_and(|at| self.stdin_offset >= at) {
            if let Some(tx) = in_tx.take() {
                let _ = tx.send(Input::Eof).await;
            }
        }
    }

    fn detach(&mut self) {
        self.client = None;
        self.exit_sent = false;
        let now = Instant::now();
        self.disconnected = Some(now);
        self.mgr.set_disconnected(&self.id, Some(now));
        log::info!("session {} detached", self.id);
    }

    /// Returns true when the session ends.
    async fn handle(&mut self, msg: ToSession, pty: Option<&sys::PtyMaster>, in_tx: &mut Option<mpsc::Sender<Input>>) -> bool {
        match msg {
            ToSession::Attach { client, received, window, takeover, reply } => {
                if let Some(old) = &self.client {
                    if !takeover {
                        let _ = reply.send(Err(AttachRefusal::AttachedElsewhere));
                        return false;
                    }
                    let _ = old.tx.try_send(ToClient::Kicked("your session has been taken over by a different user".into()));
                    log::info!("session {} taken over", self.id);
                }
                let mut lost = 0;
                for (buf, got) in [(&mut self.out, received.stdout), (&mut self.err, received.stderr)] {
                    // Never trust client offsets beyond what exists.
                    let got = got.min(buf.end());
                    if got < buf.start {
                        lost += buf.start - got;
                    }
                    buf.sent = got.max(buf.start);
                    buf.ack(buf.sent);
                }
                if let (Some(p), Some((c, r))) = (pty, window) {
                    p.set_size(c, r);
                }
                let replay = Offsets { stdin: self.stdin_offset, stdout: self.out.sent, stderr: self.err.sent };
                self.client = Some(client);
                self.exit_sent = false;
                self.disconnected = None;
                self.mgr.set_disconnected(&self.id, None);
                let _ = reply.send(Ok(Attached { id: self.id, replay, lost_bytes: lost }));
            }
            ToSession::Detached { client_id } => {
                if self.client.as_ref().is_some_and(|c| c.id == client_id) {
                    self.detach();
                }
            }
            ToSession::Stdin { offset, data } => {
                let end = offset + data.len() as u64;
                if offset <= self.stdin_offset && end > self.stdin_offset {
                    let skip = (self.stdin_offset - offset) as usize;
                    if let Some(tx) = in_tx {
                        let _ = tx.send(Input::Data(data[skip..].to_vec())).await;
                    }
                    self.stdin_offset = end;
                }
                if let Some(c) = &self.client {
                    let _ = c.tx.try_send(ToClient::Data(Data::Ack { stream: DataStream::Stdin, offset: self.stdin_offset }));
                }
                self.maybe_stdin_eof(in_tx).await;
            }
            ToSession::StdinEof { offset } => {
                self.stdin_eof_at = Some(offset);
                self.maybe_stdin_eof(in_tx).await;
            }
            ToSession::Ack { stream, offset } => match stream {
                DataStream::Stdout => self.out.ack(offset),
                DataStream::Stderr => self.err.ack(offset),
                DataStream::Stdin => {}
            },
            ToSession::Window { cols, rows } => {
                if let Some(p) = pty {
                    p.set_size(cols, rows);
                }
            }
            ToSession::Signal(sig) => {
                if matches!(sig, libc::SIGINT | libc::SIGTERM | libc::SIGHUP | libc::SIGQUIT | libc::SIGKILL | libc::SIGUSR1 | libc::SIGUSR2) {
                    sys::kill_group(self.pid, sig);
                }
            }
            ToSession::Close | ToSession::Remove => return true,
            ToSession::Kick { reason } => {
                if let Some(c) = self.client.take() {
                    let _ = c.tx.try_send(ToClient::Kicked(reason));
                    self.client = Some(c);
                    self.detach();
                }
            }
        }
        false
    }
}

fn spawn_pty_reader(master: Arc<sys::PtyMaster>, tx: mpsc::Sender<(DataStream, Option<Vec<u8>>)>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_CHUNK];
        loop {
            match master.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = tx.send((DataStream::Stdout, None)).await;
                    return;
                }
                Ok(n) => {
                    if tx.send((DataStream::Stdout, Some(buf[..n].to_vec()))).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
}

fn spawn_pty_writer(master: Arc<sys::PtyMaster>, mut rx: mpsc::Receiver<Input>) {
    tokio::spawn(async move {
        while let Some(input) = rx.recv().await {
            match input {
                Input::Data(d) => {
                    if master.write_all(&d).await.is_err() {
                        return;
                    }
                }
                // ^D: what a terminal sends for end of input.
                Input::Eof => {
                    let _ = master.write_all(&[4]).await;
                }
            }
        }
    });
}

fn spawn_pipe_reader<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut r: R,
    stream: DataStream,
    tx: mpsc::Sender<(DataStream, Option<Vec<u8>>)>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_CHUNK];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = tx.send((stream, None)).await;
                    return;
                }
                Ok(n) => {
                    if tx.send((stream, Some(buf[..n].to_vec()))).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
}

fn spawn_pipe_writer(mut stdin: tokio::process::ChildStdin, mut rx: mpsc::Receiver<Input>) {
    tokio::spawn(async move {
        while let Some(input) = rx.recv().await {
            match input {
                Input::Data(d) => {
                    if stdin.write_all(&d).await.is_err() {
                        return;
                    }
                }
                Input::Eof => return, // dropping stdin closes the pipe
            }
        }
    });
}

async fn sleep_until(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t.into()).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbuf_ack_and_ring() {
        let mut b = OutBuf::new();
        b.buf.extend(b"hello world");
        let (o, d) = b.next_chunk().unwrap();
        assert_eq!((o, d.as_slice()), (0, &b"hello world"[..]));
        b.ack(6);
        assert_eq!(b.start, 6);
        b.ack(100); // beyond what was sent: clamped
        assert_eq!(b.start, 11);
        b.push_ring(b"0123456789", 4);
        assert_eq!(b.start, 17);
        assert_eq!(b.sent, 17);
        assert_eq!(b.next_chunk().unwrap(), (17, b"6789".to_vec()));
    }
}
