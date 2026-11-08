//! Message types (spec §6.3–6.5), postcard-encoded inside the encrypted channel.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protocol identifier, part of the Noise prologue so a version mismatch fails the handshake.
pub const PROTOCOL: &[u8] = b"sshcrab/1";

/// Largest plaintext payload of one `Data` message (spec §5).
pub const MAX_CHUNK: usize = 16 * 1024;

/// Messages on the control stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ctrl {
    // --- authentication (spec §6.1), the first transport messages ---
    ServerAuth { host_key: Vec<u8>, sig: Vec<u8> },
    ClientAuth { username: String, user_key: Vec<u8>, sig: Vec<u8> },
    AuthOk,
    /// Same for every failure reason (no user enumeration), except an
    /// `/etc/nologin` text, which is only sent after successful key auth.
    AuthFail { message: Option<String> },

    // --- liveness (spec §5) ---
    Ping,
    Pong,

    // --- session selection (spec §4.4) ---
    ListSessions,
    Sessions(Vec<SessionInfo>),
    Attach(Attach),
    Attached { id: Uuid, replay: Offsets, lost_bytes: u64 },
    /// The requested session needs a decision (it is attached elsewhere).
    AttachRefused { reason: AttachRefusal },

    // --- attached session ---
    WindowSize { cols: u16, rows: u16 },
    Signal(i32),
    /// End of input after `offset` stdin bytes. The control and data streams
    /// are not ordered against each other, so the end offset travels along.
    StdinEof { offset: u64 },
    /// The process ended; `end` = total output, sent before this on the data stream.
    Exit { status: ExitStatus, end: Offsets },
    /// Normal client exit: remove the session (spec §4.2).
    Close,
    /// Sent to a client before it is disconnected by takeover or `-C` detach.
    Kicked { reason: String },

    // --- control mode (spec §4.6) ---
    Control(ControlOp),
    Feedback { text: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Attach {
    New {
        /// `None` = interactive shell on a PTY.
        command: Option<String>,
        env: Vec<(String, String)>,
        window: Option<(u16, u16)>,
    },
    Resume {
        id: Uuid,
        /// Take over even if another client is attached.
        takeover: bool,
        /// What this client has already received.
        received: Offsets,
        window: Option<(u16, u16)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachRefusal {
    NotFound,
    AttachedElsewhere,
    TooManySessions,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlOp {
    List,
    Detach(Uuid),
    Remove(Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub owner: String,
    pub interactive: bool,
    pub connected: bool,
    /// Seconds since creation.
    pub age_secs: u64,
    /// Seconds since the last client disconnected (`None` while connected).
    pub idle_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
}

impl ExitStatus {
    /// Client process exit code (spec §2: 128 + N for a signal).
    pub fn code(self) -> i32 {
        match self {
            ExitStatus::Code(c) => c,
            ExitStatus::Signal(s) => 128 + s,
        }
    }
}

/// Byte offsets per data stream (spec §4.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offsets {
    pub stdin: u64,
    pub stdout: u64,
    pub stderr: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataStream {
    Stdin,
    Stdout,
    Stderr,
}

/// Messages on the data stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Data {
    Bytes { stream: DataStream, offset: u64, data: Vec<u8> },
    Ack { stream: DataStream, offset: u64 },
}
