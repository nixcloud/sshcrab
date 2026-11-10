//! An attached session: I/O forwarding, keepalive, reconnect (spec §4.3, §4.7).

use std::collections::VecDeque;
use std::io::Write;
use std::time::{Duration, Instant};

use sshcrab_proto::channel::{Msg, SecureConn};
use sshcrab_proto::transport::KEEPALIVE;
use sshcrab_proto::vt::Modes;
use sshcrab_proto::wire::{Attach, AttachRefusal, Ctrl, Data, DataStream, MAX_CHUNK, Offsets};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::connect::{ConnectError, Connector, Report};
use crate::outage::Dialog;
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
    /// the reconnect dialog.
    col: usize,
    /// Terminal modes the session's output switched on, to undo when leaving.
    modes: Modes,
}

impl Session {
    pub fn new(id: Uuid, interactive: bool) -> Self {
        Session {
            id,
            interactive,
            received: Offsets::default(),
            stdin_buf: VecDeque::new(),
            stdin_acked: 0,
            stdin_eof: false,
            col: 0,
            modes: Modes::default(),
        }
    }

    /// Put the local terminal into the modes the server says the program uses.
    pub fn enter_terminal(&mut self, seq: &[u8]) {
        if self.interactive && !seq.is_empty() {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(seq);
            let _ = out.flush();
            self.modes.feed(seq);
        }
    }

    /// Undo those modes (alternate screen, mouse reporting, …) before leaving
    /// the session for good, so the local shell works normally again.
    fn leave_terminal(&mut self) {
        let seq = std::mem::take(&mut self.modes).reset();
        if !seq.is_empty() {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(&seq);
            let _ = out.flush();
        }
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

/// Say goodbye, then wait until the server hangs up so the Close is delivered
/// before this process exits.
async fn goodbye(sc: &mut SecureConn) {
    let _ = sc.send_ctrl(&Ctrl::Close).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), async { while sc.recv().await.is_ok() {} }).await;
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
                    goodbye(&mut sc).await;
                    self.session.leave_terminal();
                    return Outcome::Exit(code);
                }
                End::Kicked(reason) => {
                    goodbye(&mut sc).await;
                    self.session.leave_terminal();
                    if self.session.col > 0 {
                        eprint!("\r\n");
                    }
                    return Outcome::Kicked(reason);
                }
                End::Lost => match self.reconnect().await {
                    Ok((new, r)) => {
                        sc = new;
                        replay = r;
                    }
                    Err(outcome) => {
                        self.session.leave_terminal();
                        return outcome;
                    }
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
                            if self.session.interactive {
                                self.session.modes.feed(new);
                            }
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

    /// Reconnect with backoff, showing the outage dialog. Ctrl+C leaves at any
    /// moment, also in the middle of an attempt; other keystrokes are kept and
    /// sent once the session is back.
    async fn reconnect(&mut self) -> Result<(SecureConn, Offsets), Outcome> {
        let since = Instant::now();
        let target = &self.connector.target;
        let mut dialog = Dialog::new(format!("connection to {}@{} lost", target.user, target.host), self.session.col);
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        for attempt in 1usize.. {
            let delay = Duration::from_secs(BACKOFF[(attempt - 1).min(BACKOFF.len() - 1)]);
            let next = tokio::time::Instant::now() + delay;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(next) => break,
                    _ = tick.tick() => {
                        let left = next.saturating_duration_since(tokio::time::Instant::now());
                        let left = left.as_secs_f32().ceil() as u64;
                        dialog.update(&format!("reconnecting… (elapsed {}s, next in {left}s)", since.elapsed().as_secs()));
                    }
                    _ = sigint.recv() => return Err(self.abort(dialog, since)),
                    input = self.stdin.recv(), if !self.session.stdin_eof => if self.keep_input(input) {
                        return Err(self.abort(dialog, since));
                    },
                }
            }
            let (report, stage) = tokio::sync::watch::channel("connecting");
            let s = &self.session;
            let window = if s.interactive { term::window_size() } else { None };
            let attach = Attach::Resume { id: s.id, takeover: true, received: s.received, window };
            let resume = try_resume(self.connector, attach, &report);
            tokio::pin!(resume);
            let result = loop {
                tokio::select! {
                    r = &mut resume => break r,
                    _ = tick.tick() => dialog.update(&format!(
                        "reconnecting… (elapsed {}s, attempt {attempt}: {})",
                        since.elapsed().as_secs(),
                        *stage.borrow(),
                    )),
                    _ = sigint.recv() => return Err(self.abort(dialog, since)),
                    input = self.stdin.recv(), if !self.session.stdin_eof => if self.keep_input(input) {
                        return Err(self.abort(dialog, since));
                    },
                }
            };
            match result {
                Ok(Resumed { sc, replay, lost_bytes, terminal }) => {
                    dialog.close();
                    self.session.enter_terminal(&terminal);
                    if lost_bytes > 0 {
                        eprint!("\r\n[sshcrab: {lost_bytes} bytes of output were lost while disconnected]\r\n");
                    }
                    return Ok((sc, replay));
                }
                Err(Failed::Retry) => {}
                Err(Failed::Gone) => {
                    dialog.close();
                    return Err(Outcome::Gone);
                }
                Err(Failed::Fatal(msg)) => {
                    dialog.close();
                    self.session.leave_terminal();
                    term::restore();
                    eprintln!("\r\nsshcrab: {msg}");
                    return Err(Outcome::Exit(255));
                }
            }
        }
        unreachable!()
    }

    /// Keep keystrokes typed while disconnected; `true` on Ctrl+C.
    fn keep_input(&mut self, input: Option<Option<Vec<u8>>>) -> bool {
        match input {
            Some(Some(data)) if self.session.interactive && data.contains(&CTRL_C) => true,
            Some(Some(data)) => {
                self.session.stdin_buf.extend(&data);
                false
            }
            _ => {
                self.session.stdin_eof = true;
                false
            }
        }
    }

    fn abort(&mut self, dialog: Dialog, since: Instant) -> Outcome {
        self.session.leave_terminal();
        dialog.cancel(
            &format!("reconnect cancelled after {}s; the session keeps running", since.elapsed().as_secs()),
            &format!("resume with: {}", self.resume_command),
        );
        term::restore();
        Outcome::Aborted
    }
}

struct Resumed {
    sc: SecureConn,
    replay: Offsets,
    lost_bytes: u64,
    terminal: Vec<u8>,
}

enum Failed {
    /// Try again later.
    Retry,
    /// The session no longer exists.
    Gone,
    /// Retrying cannot help (host key, authentication).
    Fatal(String),
}

/// One attempt: connect, authenticate, attach to the session again. Borrows
/// nothing of the session, so the caller can keep reading the keyboard meanwhile.
async fn try_resume(connector: &Connector, attach: Attach, report: &Report) -> Result<Resumed, Failed> {
    let mut sc = match connector.reconnect(report).await {
        Ok(sc) => sc,
        Err(ConnectError::Transient(_)) => return Err(Failed::Retry),
        Err(ConnectError::Fatal(msg)) => return Err(Failed::Fatal(msg)),
    };
    report.send_replace("resuming the session");
    if sc.send_ctrl(&Ctrl::Attach(attach)).await.is_err() {
        return Err(Failed::Retry);
    }
    loop {
        match sc.recv().await {
            Ok(Msg::Ctrl(Ctrl::Attached { replay, lost_bytes, terminal, .. })) => {
                return Ok(Resumed { sc, replay, lost_bytes, terminal });
            }
            Ok(Msg::Ctrl(Ctrl::AttachRefused { reason: AttachRefusal::NotFound })) => return Err(Failed::Gone),
            Ok(Msg::Ctrl(Ctrl::Pong)) => continue,
            _ => return Err(Failed::Retry),
        }
    }
}
