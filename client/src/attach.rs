//! An attached session: I/O forwarding, keepalive, reconnect (spec §4.3, §4.7).

use std::collections::VecDeque;
use std::io::Write;
use std::time::{Duration, Instant};

use sshcrab_proto::channel::{Msg, SecureConn};
use sshcrab_proto::transport::KEEPALIVE;
use sshcrab_proto::wire::{Attach, AttachRefusal, Ctrl, Data, DataStream, MAX_CHUNK, Offsets};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::connect::{ConnectError, Connector};
use crate::{term, ui};

const BACKOFF: [u64; 4] = [2, 4, 8, 16];
const CTRL_C: u8 = 3;

pub enum Outcome {
    Exit(i32),
    Kicked(String),
    Gone,
    /// Ctrl+C while disconnected.
    Aborted,
}

pub struct Session {
    pub id: Uuid,
    pub interactive: bool,
    /// Output bytes written locally, per stream.
    received: Offsets,
    /// Stdin bytes from `stdin_acked` on, not yet acknowledged by the server.
    stdin_buf: VecDeque<u8>,
    stdin_acked: u64,
    stdin_eof: bool,
    /// Visible characters since the last newline, to put the cursor back after
    /// the reconnect status line.
    col: usize,
}

impl Session {
    pub fn new(id: Uuid, interactive: bool) -> Self {
        Session { id, interactive, received: Offsets::default(), stdin_buf: VecDeque::new(), stdin_acked: 0, stdin_eof: false, col: 0 }
    }

    fn track_column(&mut self, data: &[u8]) {
        let mut in_escape = false;
        for &b in data {
            match b {
                b'\n' | b'\r' => self.col = 0,
                0x1b => in_escape = true,
                b if in_escape => {
                    if b.is_ascii_alphabetic() {
                        in_escape = false;
                    }
                }
                b if b >= 0x20 && b & 0xC0 != 0x80 => self.col += 1,
                _ => {}
            }
        }
    }
}

/// Stdin, read on a plain thread (blocking reads); `None` = EOF.
pub fn stdin_reader() -> mpsc::Receiver<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = vec![0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.blocking_send(None);
                    return;
                }
                Ok(n) => {
                    if tx.blocking_send(Some(buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
            }
        }
    });
    rx
}

enum End {
    Exit(i32),
    Kicked(String),
    Lost,
}

pub struct Runner<'a> {
    pub connector: &'a Connector,
    pub session: Session,
    pub stdin: mpsc::Receiver<Option<Vec<u8>>>,
    /// Printed on Ctrl+C while disconnected.
    pub resume_command: String,
}

impl Runner<'_> {
    pub async fn run(mut self, mut sc: SecureConn, mut replay: Offsets) -> Outcome {
        loop {
            match self.attached(&mut sc, replay).await {
                End::Exit(code) => {
                    // Say goodbye, then wait until the server hangs up so the
                    // Close is delivered before this process exits.
                    let _ = sc.send_ctrl(&Ctrl::Close).await;
                    let _ = tokio::time::timeout(Duration::from_secs(3), async { while sc.recv().await.is_ok() {} }).await;
                    return Outcome::Exit(code);
                }
                End::Kicked(reason) => return Outcome::Kicked(reason),
                End::Lost => match self.reconnect().await {
                    Ok((new, r)) => {
                        sc = new;
                        replay = r;
                    }
                    Err(outcome) => return outcome,
                },
            }
        }
    }

    async fn send_stdin(&mut self, sc: &mut SecureConn, from: u64) -> bool {
        let end = self.session.stdin_acked + self.session.stdin_buf.len() as u64;
        let mut offset = from.max(self.session.stdin_acked);
        while offset < end {
            let start = (offset - self.session.stdin_acked) as usize;
            let n = (self.session.stdin_buf.len() - start).min(MAX_CHUNK);
            let data: Vec<u8> = self.session.stdin_buf.range(start..start + n).copied().collect();
            if sc.send_data(&Data::Bytes { stream: DataStream::Stdin, offset, data }).await.is_err() {
                return false;
            }
            offset += n as u64;
        }
        true
    }

    fn stdin_end(&self) -> u64 {
        self.session.stdin_acked + self.session.stdin_buf.len() as u64
    }

    fn has_all(&self, end: &Offsets) -> bool {
        self.session.received.stdout >= end.stdout && self.session.received.stderr >= end.stderr
    }

    fn ack_stdin(&mut self, offset: u64) {
        let end = self.session.stdin_acked + self.session.stdin_buf.len() as u64;
        let offset = offset.min(end);
        if offset > self.session.stdin_acked {
            self.session.stdin_buf.drain(..(offset - self.session.stdin_acked) as usize);
            self.session.stdin_acked = offset;
        }
    }

    async fn attached(&mut self, sc: &mut SecureConn, replay: Offsets) -> End {
        // Output before `replay` was acknowledged by an earlier client (or lost
        // from an interactive ring buffer); the stream continues from there.
        let rx = &mut self.session.received;
        rx.stdout = rx.stdout.max(replay.stdout);
        rx.stderr = rx.stderr.max(replay.stderr);
        // A client resuming someone else's stream continues at the server's offset.
        if replay.stdin > self.stdin_end() {
            self.session.stdin_buf.clear();
            self.session.stdin_acked = replay.stdin;
        }
        // What the server already has is acknowledged; resend the rest.
        self.ack_stdin(replay.stdin);
        if !self.send_stdin(sc, self.session.stdin_acked).await {
            return End::Lost;
        }
        if self.session.stdin_eof && sc.send_ctrl(&Ctrl::StdinEof { offset: self.stdin_end() }).await.is_err() {
            return End::Lost;
        }
        if self.session.interactive {
            // Also makes full-screen programs redraw after a resume.
            if let Some((cols, rows)) = term::window_size() {
                if sc.send_ctrl(&Ctrl::WindowSize { cols, rows }).await.is_err() {
                    return End::Lost;
                }
            }
        }
        let mut winch = signal(SignalKind::window_change()).expect("SIGWINCH handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut ping = tokio::time::interval(KEEPALIVE);
        ping.tick().await;
        // Exit arrives on the control stream and may overtake the last output.
        let mut exit: Option<(i32, Offsets)> = None;

        loop {
            tokio::select! {
                msg = sc.recv() => match msg {
                    Ok(Msg::Data(Data::Bytes { stream, offset, data })) => {
                        let got = match stream {
                            DataStream::Stdout => &mut self.session.received.stdout,
                            DataStream::Stderr => &mut self.session.received.stderr,
                            DataStream::Stdin => return End::Lost,
                        };
                        let end = offset + data.len() as u64;
                        if offset > *got || end <= *got {
                            continue; // gap or duplicate
                        }
                        let new = &data[(*got - offset) as usize..];
                        *got = end;
                        if stream == DataStream::Stdout {
                            let mut out = std::io::stdout().lock();
                            let _ = out.write_all(new);
                            let _ = out.flush();
                        } else {
                            let _ = std::io::stderr().lock().write_all(new);
                        }
                        self.session.track_column(new);
                        if sc.send_data(&Data::Ack { stream, offset: end }).await.is_err() {
                            return End::Lost;
                        }
                        if let Some((code, end)) = exit {
                            if self.has_all(&end) {
                                return End::Exit(code);
                            }
                        }
                    }
                    Ok(Msg::Data(Data::Ack { stream: DataStream::Stdin, offset })) => self.ack_stdin(offset),
                    Ok(Msg::Data(_)) => {}
                    Ok(Msg::Ctrl(Ctrl::Exit { status, end })) => {
                        if self.has_all(&end) {
                            return End::Exit(status.code());
                        }
                        exit = Some((status.code(), end));
                    }
                    Ok(Msg::Ctrl(Ctrl::Kicked { reason })) => return End::Kicked(ui::sanitize(&reason)),
                    Ok(Msg::Ctrl(Ctrl::Ping)) => {
                        if sc.send_ctrl(&Ctrl::Pong).await.is_err() {
                            return End::Lost;
                        }
                    }
                    Ok(Msg::Ctrl(_)) => {}
                    Err(_) => return End::Lost,
                },
                input = self.stdin.recv(), if !self.session.stdin_eof => match input {
                    Some(Some(data)) => {
                        let from = self.session.stdin_acked + self.session.stdin_buf.len() as u64;
                        self.session.stdin_buf.extend(&data);
                        if !self.send_stdin(sc, from).await {
                            return End::Lost;
                        }
                    }
                    _ => {
                        self.session.stdin_eof = true;
                        if sc.send_ctrl(&Ctrl::StdinEof { offset: self.stdin_end() }).await.is_err() {
                            return End::Lost;
                        }
                    }
                },
                _ = winch.recv() => {
                    if let Some((cols, rows)) = term::window_size() {
                        if sc.send_ctrl(&Ctrl::WindowSize { cols, rows }).await.is_err() {
                            return End::Lost;
                        }
                    }
                }
                // Without a PTY, Ctrl+C arrives as SIGINT; it goes to the remote side.
                _ = sigint.recv() => {
                    if sc.send_ctrl(&Ctrl::Signal(libc::SIGINT)).await.is_err() {
                        return End::Lost;
                    }
                }
                _ = ping.tick() => {
                    if sc.send_ctrl(&Ctrl::Ping).await.is_err() {
                        return End::Lost;
                    }
                }
            }
        }
    }

    fn status(&self, first: bool, elapsed: Duration, next: u64) {
        let text = format!("reconnecting… (elapsed {}s, next in {next}s)", elapsed.as_secs());
        let mut err = std::io::stderr().lock();
        if first {
            let _ = write!(err, "\r\n{text}");
        } else {
            let _ = write!(err, "\r\x1b[K{text}");
        }
        let _ = err.flush();
    }

    /// Remove the status line and put the cursor back where output left it.
    fn clear_status(&self) {
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r\x1b[K\x1b[1A");
        if self.session.col > 0 {
            let _ = write!(err, "\x1b[{}C", self.session.col);
        }
        let _ = err.flush();
    }

    async fn reconnect(&mut self) -> Result<(SecureConn, Offsets), Outcome> {
        let since = Instant::now();
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        for attempt in 0usize.. {
            let delay = BACKOFF[attempt.min(BACKOFF.len() - 1)];
            self.status(attempt == 0, since.elapsed(), delay);
            let wait = tokio::time::sleep(Duration::from_secs(delay));
            tokio::pin!(wait);
            // Wait, watching for Ctrl+C; other keystrokes are kept for later.
            loop {
                tokio::select! {
                    _ = &mut wait => break,
                    _ = sigint.recv() => return Err(self.abort()),
                    input = self.stdin.recv(), if !self.session.stdin_eof => match input {
                        Some(Some(data)) if self.session.interactive && data.contains(&CTRL_C) => return Err(self.abort()),
                        Some(Some(data)) => self.session.stdin_buf.extend(&data),
                        _ => self.session.stdin_eof = true,
                    },
                }
            }
            match self.try_resume().await {
                Ok(r) => {
                    self.clear_status();
                    return Ok(r);
                }
                Err(Some(outcome)) => {
                    self.clear_status();
                    return Err(outcome);
                }
                Err(None) => {}
            }
        }
        unreachable!()
    }

    /// `Err(None)`: try again later.
    async fn try_resume(&mut self) -> Result<(SecureConn, Offsets), Option<Outcome>> {
        let mut sc = match self.connector.connect(false).await {
            Ok(sc) => sc,
            Err(ConnectError::Transient(_)) => return Err(None),
            Err(ConnectError::Fatal(msg)) => {
                term::restore();
                eprintln!("\r\nsshcrab: {msg}");
                return Err(Some(Outcome::Exit(255)));
            }
        };
        let window = if self.session.interactive { term::window_size() } else { None };
        let attach = Attach::Resume { id: self.session.id, takeover: true, received: self.session.received, window };
        if sc.send_ctrl(&Ctrl::Attach(attach)).await.is_err() {
            return Err(None);
        }
        loop {
            match sc.recv().await {
                Ok(Msg::Ctrl(Ctrl::Attached { replay, lost_bytes, .. })) => {
                    if lost_bytes > 0 {
                        eprint!("\r\n[sshcrab: {lost_bytes} bytes of output were lost while disconnected]\r\n");
                    }
                    return Ok((sc, replay));
                }
                Ok(Msg::Ctrl(Ctrl::AttachRefused { reason: AttachRefusal::NotFound })) => return Err(Some(Outcome::Gone)),
                Ok(Msg::Ctrl(Ctrl::Pong)) => continue,
                _ => return Err(None),
            }
        }
    }

    fn abort(&self) -> Outcome {
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r\x1b[K");
        let _ = err.flush();
        term::restore();
        eprintln!("\nresume with: {}", self.resume_command);
        Outcome::Aborted
    }
}
