# sshcrab — Specification

This is the single source of truth for sshcrab: requirements, protocol, security
model and implementation plan. Decisions that refine or deviate from the original
draft are marked **[decision]**.

## 1. Overview

Minimal SSH-like remote shell / command execution tool implemented in pure Rust (Linux only for now).

- Client (`sshcrab`) and server (`sshcrabd`)
- Ed25519 authentication only (host key + user key)
- Transport: pure user-space SCTP over UDP (default port 22)
- Application-level encryption: X25519 key agreement + ChaCha20-Poly1305 AEAD (Noise framework, see §6)
- Strict host-key verification with line-based hostkeys file
- Compression enabled by default (zstd via pure-Rust `ruzstd`, "Fastest" ≈ level 1) for output data, after authentication only (see §6.6)
- Sessions kept in memory only (lost on daemon restart)
- Both interactive PTY shell (with immediate window-size updates) and non-interactive command execution (realtime streaming)
- Single data stream + control stream in v1
- No port forwarding or other advanced features (no agent forwarding, no X11, no SFTP/SCP, no PAM)
- Long-running daemon supporting multiple concurrent users/sessions
- For now the daemon always runs as root; session processes run as the authenticated user **[decision]**

### Non-goals (v1)

Port/agent/X11 forwarding, file transfer, password/keyboard-interactive auth, PAM,
certificates, ssh-agent, non-Linux platforms, OpenSSH wire compatibility.

## 2. Client CLI

```
sshcrab [user@]host [-p port] [-N|--new] [-R|--resume [<UUID>]] [-L] [-C] [--accept-new] [--] [command…]
```

- Syntax similar to OpenSSH. User falls back to `$USER`; if empty the client aborts with an error.
- Presence of a remote command ⇒ non-interactive; absence ⇒ interactive (PTY), exactly like OpenSSH.
- `-N` / `--new` forces a new session. `-R` / `--resume` forces resume (or lists when no UUID is given). Passing both `-N` and `-R` is an error.
- `-L user@host` — list sessions (see §4.5).
- `-C user@host` — control mode (see §4.6).
- `--accept-new` — accept an *unknown* host key without prompting (never overrides a mismatch) **[decision]**.
- Client exit code matches the remote command's exit code; remote death by signal N ⇒ exit `128+N` **[decision]**.

## 2a. Key generation tool: `sshcrab-keygen-ed25519`

```
sshcrab-keygen-ed25519 <keyfile>        e.g. sshcrab-keygen-ed25519 /home/user/.sshcrab/mykey
```

- Separate binary, similar to `ssh-keygen -t ed25519`. The only argument is the path of the private key; there are
  no options. Missing or extra arguments ⇒ usage message, exit 2.
- Writes `<keyfile>` (OpenSSH private key format, mode 0600) and `<keyfile>.pub` (OpenSSH one-line public key,
  mode 0644) whose comment is `user@hostname`.
- Never prompts: the private key is always written unencrypted (no passphrase). Protection relies on file mode
  0600 and the 0700 `~/.sshcrab` directory **[decision]**.
- Refuses to overwrite an existing `<keyfile>` or `<keyfile>.pub`. Files are created with `O_CREAT|O_EXCL`, never
  through a symlink. The parent directory must exist, except `~/.sshcrab`, which is created with mode 0700.
- Prints the SHA256 fingerprint and the public-key line to paste into the server's `~/.sshcrab/authorized_keys`.
- Keys come from the OS CSPRNG (`getrandom`), and private key material is zeroized after writing.
- The client uses `~/.sshcrab/id_ed25519` by default, so `sshcrab-keygen-ed25519 ~/.sshcrab/id_ed25519` creates the default key.

## 3. Daemon CLI / configuration

- Binary: `sshcrabd`. CLI: `sshcrabd -p 20202` overrides the port on all addresses.
- Workdir = directory the daemon was started in (PWD). It holds `host_key` and `sshcrabd.toml`.
- `host_key` is generated on first start if missing (mode 0600); print `Generated new host key in <workdir>/host_key`.
  Permissions are checked on every start; refuse to start if not 0600 and print the expected mode and a fix, e.g.
  `host_key permissions are 0644, expected 0600. Fix with: chmod 600 host_key`.
  Additionally refuse to start if `host_key`, `sshcrabd.toml` or the workdir are not owned by root, or the workdir/config are group/world-writable **[decision]**.
- `sshcrabd.toml` is optional; built-in defaults are used if absent:

```toml
ListenAddress        = ["0.0.0.0:22", "[::]:22"]  # separate sockets for IPv4 and IPv6
PermitRootLogin      = true      # key-only, so OpenSSH's prohibit-password equivalent
AllowUsers           = []        # empty = everyone with a valid account and key
AllowGroups          = []        # empty = no group restriction
MaxSessionsPerUser   = 32        # [decision] spec draft said unlimited; 0 = unlimited
MaxUnauthenticated   = 64        # global pre-auth associations
MaxUnauthPerSource   = 8         # per IPv4 address / IPv6 /64
SessionBufferBytes   = 1048576   # per-session replay buffer
DisconnectedTimeout  = "24h"     # configurable mainly for tests
P2P                  = false     # reachable through the DHT via sshcrabd-p2p (§13)
P2PSocket            = "/run/sshcrab/p2p.sock"
P2PUser              = "sshcrab-p2p" # the only uid allowed on P2PSocket (as root)
P2PBootstrap         = []        # empty = built-in list (§13.6)
MaxUnauthP2P         = 16        # pre-auth P2P connections (one shared bucket)
```

- NixOS module `services.sshcrab` (options: `enable`, `port`, `listenAddresses`, `openFirewall`, `settings`,
  `p2p.*`, `dhtNode.*` — §13.5) runs
  it with `StateDirectory=sshcrab` as workdir; host key generated by the daemon on first start.
- Logging: `log` + `env_logger` to stderr (journald). See §7.9 for what must be logged.
- **Test mode [decision]:** when not running as root, the daemon serves only its own account and honours
  `SSHCRABD_HOME` (where `.sshcrab/authorized_keys` is read and the session starts) and `SSHCRABD_SHELL`. Both are
  ignored as root, so they cannot widen access. Used by `tests/e2e.sh`.

## 4. Session model

### 4.1 Basics

- Server generates a 128-bit random UUID (v4, from the OS CSPRNG) as the session ID.
- The session ID is an *identifier, not a capability*: every attach/resume/control operation requires a fresh,
  fully authenticated connection whose user owns the session (or is root for `-C` operations). **[decision]**
- Sessions live only in server memory.
- Interactive sessions run the user's login shell on a PTY; non-interactive sessions run `<login shell> -c <command>`
  with stdout/stderr on pipes, stdin on a pipe (EOF propagated). **[decision]**
- Environment: start from a clean environment (`HOME`, `USER`, `LOGNAME`, `SHELL`, `PATH` default), then pass through
  `TERM`, `LANG`, `LC_ALL` if set by the client (validated, §7.6); always set `SSHCRAB_SESSION_ID` to the full UUID
  (also for non-interactive).

### 4.2 Lifetime

- When a session's SCTP association disconnects, the session is preserved.
- A session is removed when:
  - it is attached and the remote side closes it (interactive: shell exits, e.g. `exit`; non-interactive: program finished
    and all output delivered and acknowledged), or
  - the client exits normally and explicitly tells the server to remove it, or
  - it is removed via `-C`, or
  - the hard timeout expires.
- On abrupt client crash, or if the client is killed by a signal other than Ctrl+C while connected, the session is preserved.
- Hard timeout (default 24 h) starts when the server stops receiving any data from the client (SCTP heartbeats,
  keepalive, window-size updates or any other message) and applies only while the session is disconnected. While a
  client is connected the timeout is not counted down. On expiry: SIGHUP to the process group, SIGKILL after 5 s.
- A process that exits while disconnected keeps its exit status and unread output until reattach or timeout.
- Daemon restart terminates all sessions (they live in the service's cgroup). Attached clients are first sent
  `Kicked{"sshcrabd is shutting down…"}` so they exit instead of reconnecting to sessions that no longer exist.

### 4.3 Output buffering and replay **[decision]**

Both directions carry byte offsets on the data stream and are acknowledged at the application level.

- Server keeps unacknowledged stdout/stderr in a per-session buffer (`SessionBufferBytes`).
  - Non-interactive: when the buffer is full the server stops reading from the child (back-pressure, no data loss).
  - Interactive: ring buffer, oldest output dropped; on resume the client is told how many bytes were lost.
    **Fresh client** (`-R`, takeover; it has received nothing of this session). Found with htop in Windows Terminal:
    - The server follows the DEC private modes the program set in its output (alternate screen, cursor keys, cursor
      visibility, mouse reporting, focus events, bracketed paste; `proto/src/vt.rs`) and sends the sequences that
      recreate them in `Attached.terminal`; the client writes them before any output. Without this a full-screen
      program draws on the normal screen, which terminals with reflow (Windows Terminal) mangle on resize.
    - Shell (no alternate screen): the last 64 KiB stay buffered even once acknowledged and are replayed from the
      first full line, so the recent screen appears instead of an empty one. The foreground process group gets
      SIGWINCH (readline does not redraw on it at an unchanged size, hence the replay).
    - Full-screen program: no replay (old frames of another size would only scroll by); instead the PTY is shrunk by
      one row and restored 100 ms later, a real size change, so curses programs repaint everything rather than only
      what they think changed.
    - A client leaving the session (kicked, aborted, lost for good, exit) resets the modes it followed, so the local
      shell is usable again.
- Client keeps unacknowledged stdin and re-sends from the server's acknowledged offset after resume.
- `Attach` response carries `replay_from` offsets; offsets outside the buffer are rejected/clamped, never trusted.

### 4.4 Attaching: default decision table

Interactive invocation without `-N`/`-R`:

| Preserved sessions of user | Action |
|---|---|
| 0 | create new |
| 1, no client attached | resume it |
| 1, client attached | `cliclack` prompt: create new / take over |
| >1 | session menu as for `-R` **[decision]** |

- A remote command always creates a new session (`sshcrab host ls` must never attach to a shell) **[decision]**.
- `-N` always creates a new session.
- `sshcrab -R <UUID> user@host` / `--resume <UUID>` always takes over an already-active session (no prompt).
- `sshcrab -R user@host` (no UUID): server sends all of the user's sessions; client shows a `cliclack` single-select
  numbered menu, both interactive and non-interactive sessions, sorted:
  1. disconnected sessions first, then connected ones;
  2. within each group: by disconnection time ascending (oldest disconnect first), then creation time, then UUID.
- Each entry shows the UUID; disconnected sessions also show idle duration in full format omitting zero components
  (`45s`, `2m15s`, `1h5m30s`, `2h15m`, `3d2h`). Connected sessions show no timer.
- Ctrl+C on the session list prints `aborted` to stderr, exits 0 and leaves local state untouched.
- On takeover the previous client receives `your session has been taken over by a different user` and is disconnected.
- Non-interactive sessions can be resumed by the original client reconnecting automatically or by an explicit `-R <UUID>`.

### 4.5 `-L` list mode

Prints all of the user's sessions, sorted as in §4.4, one per line: UUID plus `[interactive]`/`[non-interactive]`
and `[disconnected]`/`[connected]`. Intended for copying UUIDs. Connected sessions are distinguished by order only.

### 4.6 `-C` control mode

Full `cliclack` workflow:
- **detach** — kick the currently attached client but keep the session; the kicked client receives `you have been detached`.
- **remove** — delete the session entirely (process group SIGHUP → SIGKILL).
- Same Ed25519 authentication. A normal user manages only their own sessions; `root` can manage (list/detach/remove)
  any session but cannot *attach* to another user's session **[decision]**.
- The controlling client receives feedback messages for every operation.

### 4.7 Reconnect behaviour (interactive and non-interactive)

- On detected disconnect the client reconnects indefinitely with backoff 2 s → 4 s → 8 s → 16 s, then 16 s.
- Every reconnect performs a full handshake including host-key verification (no cached trust).
- The client pings every 2 s while attached (more often than `KEEPALIVE` requires). After 5 s without any message the
  dialog below already appears: `waiting… (no answer for Ns, reconnecting after 15s)`; it goes away (screen restored)
  when the server answers again, or turns into the reconnect dialog once the connection counts as dead. This covers a
  P2P helper that died without ending its streams (killed, crashed): nothing reports that before the 15 s rule.
- While disconnected, a dialog in cliclack's style below the existing output (`client/src/outage.rs`), redrawn every
  second: `reconnecting… (elapsed Ns, next in Ms)` while waiting, `reconnecting… (elapsed Ns, attempt K: <stage>)`
  during an attempt (joining the DHT, finding the server, authenticating, resuming). Drawn by hand: cliclack's prompts
  read the keyboard themselves and its spinner draws from another thread. Completely removed on success (cursor back
  to where the output left it). Without a terminal on stderr: one line when the connection is lost, one on success.
- Interactive sessions: the client keeps a model of the screen (`vt100` crate, fed with all output). While
  disconnected, the screen is shown in barely visible grey behind the dialog (context, but clearly not live). A shell's
  screen is greyed on the alternate screen, so the terminal itself restores the real one on reconnect and a wrong model
  can only spoil the grey copy. A full-screen program is already on the alternate screen: the copy is drawn over it and
  the model's contents put back on reconnect, before the program repaints (§4.3).
- A single Ctrl+C while disconnected, also in the middle of an attempt, does **not** alter local or remote sessions; it
  shows the dialog as cancelled with a resume command that replicates the original invocation (UUID + host + port and
  other original flags, not the remote command; shell-quoted) and exits. The local `sessions/<PID>/session` file is
  left in place. In interactive raw mode Ctrl+C is detected as byte `0x03` on stdin.
- While connected, Ctrl+C is sent to the remote host and ignored locally: interactive — as the byte in the PTY stream;
  non-interactive — as a `Signal(SIGINT)` control message delivered to the remote process group **[decision]**.

## 5. Transport

- Pure user-space SCTP over UDP using `sctp-proto` (Sans-IO), driven by `tokio::net::UdpSocket`.
- Keepalive: an encrypted `Ping` on the control stream every 5 s; an association with no packet from the peer for
  15 s is dead. **[decision]** This replaces "SCTP heartbeats only": M0 showed that `sctp-proto` answers heartbeats
  but never sends them, and never fails an association on exhausted DATA retransmits. The application-level ping
  is also authenticated, which SCTP heartbeats are not. Measured detection time: 15.0 s.
- RTO: initial 1 s, min 0.5 s, max 4 s, so retransmits recover quickly after short outages.
- Stream 0 = control, stream 1 = data. Ordered, reliable on each stream.
- SCTP association death never destroys a session.
- Listens on all interfaces by default (IPv4 + IPv6, separate sockets), UDP port 22, configurable via `ListenAddress`; `-p` overrides the port of every address.
- Application messages are ≤ 16 KiB plaintext before framing.

- **[decision]** SCTP is final; QUIC/TLS were considered and rejected. Because SCTP has no built-in client address
  validation or amplification limit, the pre-auth hardening in §7.2 is mandatory work, not optional.

## 6. Protocol

### 6.1 Handshake **[decision]**

Use the Noise framework (`snow`) for key agreement instead of an ad-hoc construction:
`Noise_NN_25519_ChaChaPoly_SHA256`, prologue = `"sshcrab/2"` (the protocol version).
Identity is bound with Ed25519 signatures over the final Noise handshake hash `h` (SIGMA-style, as SSH signs its
exchange hash). `h` is only final after msg2, so the signatures travel as the first encrypted messages
(implemented in `proto/src/handshake.rs`):

```
C → S  : Noise NN msg1 (e)                                   32 bytes, plaintext
S → C  : Noise NN msg2 (e, ee)                               48 bytes, plaintext
S → C  : enc{ ServerAuth { host_pubkey, Sig_host("sshcrab-server-auth-v1" || h) } }
         client verifies the signature and the host key against ~/.sshcrab/hostkeys BEFORE sending anything identifying
C → S  : enc{ ClientAuth { username, user_pubkey,
              Sig_user("sshcrab-client-auth-v1" || h || u32 len || username || host_pubkey) } }
S → C  : enc{ AuthOk | AuthFail { message } }   identical for unknown user / unknown key / bad signature;
         `message` is only set for /etc/nologin, after the key matched
```

- The server verifies the client's signature before it touches any account data (`authorize` runs only for a
  proven key).

- Server authenticates first ⇒ client username and key are never sent to an unverified server.
- Domain-separation labels prevent signature reuse across roles/protocols; `h` binds to fresh ephemerals ⇒ no replay.
- Protocol version is in the prologue ⇒ downgrade is detected.
- Handshake must complete within 10 s or the association is aborted.

### 6.2 Transport encryption

- After the handshake, `snow::StatelessTransportState` with explicit nonces. Because SCTP streams are ordered
  independently, the 64-bit nonce space is partitioned per stream: `nonce = stream_id << 56 | counter`. Each receiver
  requires strictly increasing counters per stream (replay/reorder ⇒ drop association).
  SCTP delivers each stream reliably and in order, so the counter is implicit (not sent).
- Counter exhaustion (2^56 per stream) ⇒ tear down (practically unreachable).
- **[decision]** No in-session rekey: a direction's key is shared by both streams, which are not ordered against
  each other, so the two sides cannot agree on a switch-over point without extra protocol. Every reconnect = new
  handshake = new keys (forward secrecy across reconnects). Revisit if long-lived associations need forward secrecy.

### 6.3 Framing

`postcard`-encoded enums inside AEAD ciphertext; outer length-prefix with hard maximum (decoder rejects before
allocating). Unknown variants ⇒ protocol error.

### 6.4 Control stream messages

Defined in `proto/src/wire.rs`: `ServerAuth`, `ClientAuth`, `AuthOk`, `AuthFail{message}`, `Ping`, `Pong`,
`ListSessions`, `Sessions(list)`, `Attach{ New{command, env, window} | Resume{id, takeover, received, window} }`,
`Attached{id, replay, lost_bytes}`, `AttachRefused{NotFound | AttachedElsewhere | TooManySessions | Failed}`,
`WindowSize`, `Signal`, `StdinEof{offset}`, `Exit{status, end}`, `Close` (normal client exit → remove),
`Kicked{reason}`, `Control{List | Detach(id) | Remove(id)}`, `Feedback{text}`.

**Cross-stream ordering [decision]:** the control and data streams are not ordered against each other (found in
testing: `Exit` overtook the last output chunks, and `StdinEof` the last input). Every control message that ends a
data stream therefore carries the final offsets: the client exits only once it has written all output up to
`Exit.end`, and the server closes the child's stdin only once it has received input up to `StdinEof.offset`.

`Attached.replay` tells a resuming client where each stream continues. A client that resumes a session whose
earlier output another client already acknowledged starts at those offsets (and its stdin continues at the
server's stdin offset).

### 6.5 Data stream messages

`Bytes{ stream: Stdin|Stdout|Stderr, offset, data }`, `Ack{ stream, offset }`. Compression is a flag byte in the
encrypted frame (§6.6). The client acknowledges every output chunk; the server acknowledges stdin.

### 6.6 Compression

- Enabled only after successful authentication (no decompressor reachable pre-auth): the client accepts compressed
  frames only after `AuthOk`; the server never does.
- Per-message, independent contexts (no shared streaming dictionary) to limit CRIME-style cross-message leakage.
- Applied to server→client output only; client stdin (keystrokes, typed passwords) is never compressed.
- Decompression output is capped at the frame maximum (bomb protection), and a frame may declare a window of at most
  128 KiB, the one our compressor uses (ruzstd would otherwise reserve up to 128 MiB up front).
- Crate: `ruzstd` (pure Rust, "Fastest" ≈ level 1) **[decision]**. The C-based `zstd` crate is not used.

## 7. Security analysis

### 7.1 Threat model

| Attacker | Capabilities | Must not achieve |
|---|---|---|
| Internet, unauthenticated | send arbitrary UDP to port 22, spoof source addresses | code execution, memory/CPU exhaustion, amplification, user enumeration, crash of the daemon |
| Network MITM (on-path) | read/modify/drop/inject packets | read or alter session data, impersonate server or user, hijack sessions; *can* cause disconnects (accepted, sessions survive) |
| Authenticated user | valid key for own account | access to other users' sessions, privilege escalation via the daemon, DoS of other users beyond configured limits |
| Malicious server | client connects to it (e.g. TOFU or compromised host) | code execution on client, terminal injection via sshcrab's own UI, key theft |
| Local user on client | read files in other homes | read private key / session files (permissions) |

Highest-impact risks, in order: (1) bug in the root daemon reachable pre-auth, (2) home-grown crypto mistakes,
(3) local privilege escalation via process spawning, (4) session hijack via resume logic, (5) DoS/amplification.

### 7.2 Pre-authentication attack surface

The daemon is internet-facing on a well-known port; everything here is parsed from attacker-controlled bytes.

- **sctp-proto is unaudited input-parsing code running as root.** Memory safety comes from Rust, but panics, unbounded
  allocations and state bugs remain. Requirements:
  - fuzz `Endpoint::handle` with arbitrary datagrams (`cargo-fuzz`) in CI;
  - build with `panic = "unwind"` and isolate each association so a panic kills one association, not the daemon;
  - after privsep (§7.4) this code runs unprivileged.
- **State exhaustion (INIT flood).** M0 result: `sctp-proto` 0.10.8 allocates a full association on the first INIT
  (its own code says `TODO: improve INIT handling for DoS attack`). The transport therefore pre-filters every packet
  with verification tag 0 (an INIT): at most 64 pending associations in total and 8 per IPv4 address / IPv6 /64, a
  global INIT token bucket (200/s), and a 10 s deadline for the SCTP handshake. Removed associations are also
  removed from the endpoint's tables (otherwise each spoofed INIT leaks a slot). Covered by the `init_flood_is_capped` test.
- **UDP amplification.** M0 result: INIT 40 bytes → INIT-ACK 76 bytes, a 1.9x ratio, bounded by the INIT token bucket.
  The test `dead_path_is_detected` fails if the ratio exceeds 2x.
- **Library quirks found in M0** (all handled in `proto/src/transport.rs`): a client endpoint without a server config
  panics when it receives an INIT (it gets one and rejects new associations); a server association reports `Closed`
  until COOKIE-ECHO arrives; `shutdown()` drops the endpoint routing immediately.
- **Handshake DoS.** X25519 + Ed25519 verify are cheap but nonzero: 10 s handshake timeout, per-source auth-failure
  backoff, global concurrency cap.
- **Decoder hardening.** Maximum frame length checked before allocation; postcard decode of bounded types only; no
  compression pre-auth.

### 7.3 Cryptography

- Use Noise (`snow`) instead of designing key exchange by hand; only the signature binding (§6.1) is ours, and it
  follows the SSH/SIGMA pattern.
- Per-stream nonce partitioning is mandatory — a single counter across two independently ordered SCTP streams would
  either break or invite nonce reuse.
- Constant-time comparisons for keys/tags (`subtle`); `zeroize` for private keys and session keys; RNG = `getrandom`/`OsRng`.
- SCTP headers/chunks are not authenticated: an on-path attacker can inject ABORT and kill an association. Accepted —
  same as TCP RST against OpenSSH — because sessions survive and the client reconnects.
- Residual leaks: packet sizes and keystroke timing are visible (OpenSSH ≥ 9.5 added keystroke-timing obfuscation;
  candidate for v2). Compression lengths leak information about output; mitigated by §6.6.
- Test vectors for handshake and transport; property test that encrypt→decrypt round-trips and that any bit flip fails.

### 7.4 Privilege separation **[decision]**

A single root process that parses network input is the classic way to end up on Twitter. Target architecture:

- `sshcrabd` (root **monitor**): holds the host key, reads `authorized_keys`, spawns session processes, owns nothing
  network-facing. Tiny IPC interface over a `socketpair`.
- `sshcrabd --net` (unprivileged **network worker**, user `sshcrab`): SCTP, Noise, framing, compression, session buffers.
  Self-sandboxed with `no_new_privs`, seccomp (allowlist), Landlock (no filesystem access), bounded `RLIMIT_NOFILE`, `RLIMIT_NPROC` = 0.
- Monitor operations: `sign_host(h)` (only for handshake hashes, with label), `verify_user(username, pubkey, sig, h, nonce)`
  where the monitor injects a fresh nonce into the signed data so a compromised worker cannot replay signatures,
  `spawn(session params) → PTY master / pipe fds via SCM_RIGHTS`, `signal`, `kill`.
- Systemd hardening cannot be applied to the unit as a whole, because user shells are children of the service and
  would inherit it (e.g. `NoNewPrivileges=yes` breaks `sudo`). Hence the worker sandboxes itself.

Phasing: M1–M7 keep this boundary as a Rust trait inside one process; **M9 splits it into two processes and is a
release blocker for exposure to untrusted networks.**

### 7.5 User authentication

- `authorized_keys`: `~<user>/.sshcrab/authorized_keys`, OpenSSH one-key-per-line format, Ed25519 only **[decision]**.
- StrictModes equivalent: the file, `~/.sshcrab` and `~` must be owned by the user (or root) and not group/world-writable;
  open with `O_NOFOLLOW`; read with the user's filesystem identity (`setfsuid` in a helper) so a symlink to
  `/etc/shadow` cannot be abused; never log file contents.
- Username: validated against a conservative charset/length, resolved via `getpwnam`; unknown user, unknown key and bad
  signature produce the same `AuthFail` with the same work done (no enumeration).
- Linux accounts are checked natively, without PAM **[decision]**. A login is accepted only if all of these pass:
  1. the user exists (NSS `getpwnam`, so LDAP/sssd via NSS work too);
  2. the account is not expired (shadow `sp_expire`, via `getspnam`);
  3. `/etc/nologin` does not exist, unless the user is root (its contents are shown to the client);
  4. `PermitRootLogin` allows it;
  5. the user matches `AllowUsers` / `AllowGroups` if those are set;
  6. the presented key is in `authorized_keys` and the signature verifies.
- A `!` or `*` password marker in shadow does **not** block key login (like OpenSSH with PAM, which is how NixOS runs
  it; NixOS users without a password may carry such a marker). Lock someone out by expiring the account or removing
  their `authorized_keys`.
- Accounts whose shell is `nologin`/`false` get that shell executed (it prints its message and exits).
- After a successful login the session process writes its uid to `/proc/self/loginuid` (audit trail).
- Not provided without PAM: logind session (no `XDG_RUNTIME_DIR`, no `systemctl --user`), `limits.conf`,
  `pam_access`/`pam_time`, motd/lastlog. PAM account+session support may be added later as an optional feature.
- `PermitRootLogin` configurable.
- Key revocation: removing a key from `authorized_keys` takes effect on the next handshake; since every resume needs a
  fresh handshake, a revoked key cannot resume existing sessions. Running processes continue until removed (`-C` as root).

### 7.6 Session spawning (local privilege escalation surface)

- Compute everything that is not async-signal-safe *before* fork: passwd entry, supplementary groups (`getgrouplist`),
  argv, envp. In `pre_exec` only: `setsid`, `TIOCSCTTY`, `setgroups`, `setgid`, `setuid`, `chdir`, signal reset.
  Never call `initgroups`/NSS after fork in a multithreaded process.
- After `setuid`, assert `setuid(0)` fails.
- All daemon fds are `O_CLOEXEC`; additionally `close_range(3, ~0)` in the child. Reset signal mask and dispositions.
- Clean environment, never inherited from the daemon (no `LD_PRELOAD`, `RUST_LOG`, …).
- Client-supplied env: only `TERM`, `LANG`, `LC_ALL`; values ≤ 64 bytes, charset `[A-Za-z0-9._@+-]` (no `/`, so
  terminfo path tricks are impossible).
- PTY: allocate via `openpt`/`grantpt` semantics, slave chowned to the user, group `tty`, mode 0620; master never
  reaches the child.
- Resource limits: `MaxSessionsPerUser` and per-session buffer caps (spec draft said unlimited sessions — that lets one
  user exhaust daemon memory with disconnected sessions).
- Auditing: write utmp/wtmp entries for interactive sessions (v1 nice-to-have, v2 required).

### 7.7 Session hijacking / authorization

- Resume, takeover, list, detach and remove check `session.owner == authenticated_user` (root: list/detach/remove only).
- UUIDs come from the CSPRNG but are never sufficient on their own; they appear in `SSHCRAB_SESSION_ID`, shell
  history, terminal scrollback and process listings, so they must be treated as public.
- Offsets from clients are bounds-checked.
- The "taken over" message is sent before disconnecting the old client so that a user notices unexpected takeovers.

### 7.8 Client-side security

- Strict host-key checking: mismatch is fatal, reports `~/.sshcrab/hostkeys:<line>`, and has no override flag.
- Unknown host: `cliclack` confirmation showing the SHA256 fingerprint; `--accept-new` for scripts; non-TTY without
  `--accept-new` ⇒ fail.
- Hostkeys line format `hostname port keytype base64key` (`keytype` = `ssh-ed25519`); hostname lower-cased, IPv6 without
  brackets; written atomically (temp file + rename); parser is fuzzed.
- `~/.sshcrab` created 0700; `id_ed25519` must be 0600 or the client refuses (with `chmod` hint). Keys are
  unencrypted only; an encrypted key is rejected with a clear error (no passphrase prompts, which also keeps automatic
  reconnects non-interactive).
- Residual risk: anyone who can read the key file (root, backups, a stolen disk without full-disk encryption) can
  authenticate as the user. Accepted; documented in §7.11.
- All server-provided text (`Feedback`, `Kicked` reasons, error strings) is stripped of control characters before
  printing in sshcrab's own UI. UUIDs are rendered from parsed `Uuid` values only.
- Remote output itself is passed to the terminal unchanged (same as OpenSSH; terminal escape risk is inherent).
- Session-dir GC only touches entries named by a decimal PID that are real directories (`symlink_metadata`), whose PID
  is not alive and whose mtime is > 7 days.
- The printed resume command is shell-quoted.

### 7.9 Logging & operations

- Log: auth success/failure (source address, sanitized username, key SHA256 fingerprint), session create/attach/
  takeover/detach/remove/timeout, limit hits. Never log key material, plaintext data or env values.
- Sanitize usernames and other client strings before logging (log injection).
- Port 22/UDP will be scanned constantly; logs must be rate-limited for pre-auth noise.

### 7.10 Supply chain & process

- `Cargo.lock` committed; Nix fetches crates by checksum; `cargo deny` (advisories, licenses, duplicate crates) and
  `cargo audit` in CI.
- Minimal dependency set; prefer RustCrypto / dalek / snow crates.
- `#![forbid(unsafe_code)]` everywhere except one small `sys` module (fork/exec, PTY, setuid, sandbox) that gets
  focused review.
- Fuzz targets: SCTP datagram input, frame decoder, handshake state machine, hostkeys and authorized_keys parsers,
  config parser.
- Before announcing publicly: external review of `proto/handshake.rs`, `sys`, and the privsep IPC.

### 7.11 Residual risks (accepted for v1)

On-path DoS via injected SCTP chunks; traffic analysis (sizes/timing); TOFU on first connect; unencrypted private keys at rest; no PAM (no logind
session, no `limits.conf`, no `pam_access`); `sctp-proto` maturity; daemon restart kills all sessions.

## 8. Client storage

- `~/.sshcrab/hostkeys` — line-based (`hostname port keytype base64key`); `.p2p` addresses with port 0 (§13.3).
- `~/.sshcrab/config.toml` — optional; `P2PBootstrap = [...]` (§13.6).
- `~/.sshcrab/id_ed25519`, `~/.sshcrab/id_ed25519.pub` — default user key (created with `sshcrab-keygen-ed25519`).
- `~/.sshcrab/sessions/` — directory:
  - an active client creates `sessions/<PID>/session` containing only the UUID;
  - deleted when the client exits normally;
  - on client start, garbage-collect disconnected session directories older than 1 week (§7.8);
  - Ctrl+C on the session list exits 0, prints `aborted` to stderr and does not touch local state;
  - Ctrl+C while disconnected leaves the local session file in place.

Server side: `~<user>/.sshcrab/authorized_keys`.

## 9. Architecture

Cargo workspace:

```
Cargo.toml          workspace
proto/              sshcrab-proto (library)
  transport.rs      tokio UdpSocket + sctp-proto Endpoint driver → async Association { ctrl, data, events }
  handshake.rs      Noise NN + Ed25519 binding (§6.1)
  channel.rs        stateless transport, per-stream nonces, compression
  wire.rs           postcard message enums
  keys.rs           key load/generate, permission checks
  hostkeys.rs       parse / lookup / append, file:line reporting
client/             bin sshcrab: state machine Connecting → Handshake → Select → Attached ⇄ Reconnecting → Done
  src/bin/sshcrab-keygen-ed25519.rs   key generation tool (§2a)
server/             bin sshcrabd
  manager.rs        SessionManager (Arc<Mutex<HashMap<Uuid, Session>>>), reaper task
  session.rs        buffers, offsets, attach/takeover
  monitor.rs        privileged operations (trait; separate process from M9)
  sys.rs            the only unsafe code: fork/exec, PTY, setuid, sandbox
```

Crates: `sctp-proto`, `tokio`, `snow`, `ed25519-dalek`, `x25519-dalek` (via snow), `ssh-key`, `chacha20poly1305` (via
snow), `sha2`, `subtle`, `zeroize`, `postcard`, `serde`, `ruzstd`, `nix`, `clap`, `cliclack`, `toml`, `uuid`,
`getrandom`, `log`, `env_logger`.

## 10. Build & toolchain

- Toolchain: `nixcloud/cargo` (libnix) 1.99.0+v4 with rustc 1.99.0, both provided by the flake through `libfenix`
  (`lf.rust-1_99.minimalToolchain`). No rustup; no other toolchain.
- Development happens inside `nix develop`, which provides the toolchain and sets `CARGO_BACKEND=nix`; plain
  `cargo build` / `cargo test` work there.
- Nix builds: the flake reads `Cargo.lock`, fetches every crates.io dependency by checksum, then runs
  `cargo build --release --offline write-nix-buildsystem` to generate the Nix build system and builds the binaries
  from it. `Cargo.lock` must therefore always be committed and current.
- Pure-Rust dependency set (no `-sys` crates, no C compiler or `pkg-config` in the build); this is also why `ruzstd`
  is used instead of `zstd`.
- Flake outputs: `packages.sshcrab` (`sshcrab` + `sshcrab-keygen-ed25519`), `packages.sshcrabd`, `packages.default`,
  `devShells.default`, `nixosModules.sshcrab` (`services.sshcrab`), `checks` (unit tests and the NixOS VM test).

## 11. Milestones

- **M0 — Bootstrap & transport spike.** Workspace, `Cargo.lock`, rewrite `flake.nix` for sshcrab (§10; remove the
  leftover pankat parts) and check that `nix develop` and `nix build` work with nixcloud/cargo 1.99 v3. `sctp-proto` echo spike over UDP: heartbeat tuning and failure-detection time,
  max message size, INIT state behaviour, INIT-ACK amplification ratio. *Go/no-go for SCTP.*
- **M1 — Transport crate.** Async association wrapper, two streams, death events; pre-auth limits.
- **M2 — Crypto.** Handshake, transport encryption, framing, compression (`ruzstd`); hostkeys; `sshcrab-keygen-ed25519`; test vectors; fuzz targets.
- **M3 — Non-interactive exec.** Spawn as user (§7.6), realtime streaming, stdin/EOF, exit codes, env.
- **M4 — Interactive PTY.** Raw mode, SIGWINCH → `WindowSize`, Ctrl+C passthrough.
- **M5 — Persistence.** Disconnect survival, offsets/replay, reconnect backoff + status line, Ctrl+C-while-disconnected
  resume command, normal-exit removal, timeout reaper, takeover, local session files + GC.
- **M6 — Session UX.** `-R` (menu + sorting + duration format), decision table, `-L`, `-C`, root semantics, `-N`/`-R` conflict.
- **M7 — Daemon ops.** `sshcrabd.toml`, `-p`, host key generation/permission/ownership checks, NixOS module, logging.
- **M8 — Tests.** Unit (parsers, sorting, durations, backoff, handshake), integration (daemon on high port in temp dir,
  non-root test mode serving only the invoking user), NixOS VM test with two nodes and nftables UDP drops for
  reconnect/replay/takeover/timeout.
- **M9 — Privilege separation & sandbox (release blocker).** Split monitor/worker, seccomp + Landlock, IPC fuzzing,
  external review.

## 12. Implementation status (2026-11-08)

| Milestone | State |
|---|---|
| M0 bootstrap & SCTP spike | done — `nix develop` / `nix build` work; findings in §5 and §7.2 |
| M1 transport | done — `proto/src/transport.rs`, 4 tests (echo, 32 MB bulk, INIT flood cap, dead-path detection) |
| M2 crypto | done — handshake, channel, `ruzstd`, hostkeys, key files, `sshcrab-keygen-ed25519`; fuzz targets still missing |
| M3 non-interactive exec | done — privilege drop, env allowlist, exit codes, stdin/stdout/stderr streaming |
| M4 interactive PTY | done — raw mode, SIGWINCH, Ctrl+C passthrough; not yet tried from a real terminal |
| M5 persistence | done — offsets/replay, reconnect with backoff and status line, takeover, timeout, session files + GC |
| M6 session UX | implemented — `-R` menu, decision table, `-L`, `-C`; the `cliclack` prompts need a manual test on a TTY |
| M7 daemon ops | mostly — config, `-p`, host key checks, NixOS module; module not yet tested in a VM |
| M8 tests | partial — 18 unit tests + `tests/e2e.sh` (16 checks incl. a 20 s outage); NixOS VM test missing |
| M9 privilege separation | not started — release blocker |
| P2P backend (§13) | implemented; hole punching works between distinct addresses on one host (e2e) and through a Linux NAT router (`checks.p2p-nat-containers`); real-internet NATs not yet verified (§13.8) |

Known gaps: never run as root yet (setuid path, PTY chown, `/proc/self/loginuid`, `setfsuid`); output throughput
is ~2.5 MB/s on loopback in a debug build (one ack per 16 KiB chunk, compression of incompressible data); no
fuzzing; no `cargo deny`/`cargo audit` in CI.

## 13. P2P backend (hosts behind NAT) **[decision]**

Background and requirements: `P2P.md` (registry, hole punching, threat analysis). This section is what sshcrab
implements and where it deviates. Built on **peeroxide 1.8.3** (Rust HyperDHT), unpatched and pinned exactly.

```
sshcrab ──DHT lookup + hole punch──► sshcrabd-p2p (sandboxed, user sshcrab-p2p) ──socketpair fd──► sshcrabd (root)
 our protocol inside peeroxide's        relays messages, never parses them          over /run/sshcrab/p2p.sock (SCM_RIGHTS)
 encrypted stream (Noise IK + UDX)                                                    normal pre-auth limits, handshake, sessions
```

### 13.1 Transport
- peeroxide hands out an encrypted, reliable, ordered *message* stream (UDX + SecretStream), not the punched UDP
  socket (taking that over would steal the library's own receive path). Our protocol runs inside it unchanged:
  each message is `stream id (1 byte) ‖ message`. `Conn` (`proto/src/transport.rs`) has two backends: the SCTP
  association, and a *pipe* that a bridge task feeds (`Conn::pipe`, `proto/src/p2p.rs` `bridge`). Pipes apply the same
  15 s idle rule as SCTP, as a deadline that restarting `recv()` does not reset; the client still pings every 5 s.
  When the helper stops (restart, SIGTERM, sshcrabd gone), it ends every stream properly, so clients notice at once
  instead of after 15 s.
- Costs: double encryption (peeroxide's and ours), and control and data share one ordered stream.

### 13.2 Keys and addresses
- P2P key: `seed = SHA-256("sshcrab-p2p-v1" ‖ host_key_seed)`; peeroxide's Ed25519 key pair from that seed is the
  DHT identity, its record signer and its Noise static key. The host key itself never enters peeroxide.
- Address: `<z-base-32 of the P2P public key, 52 chars>.p2p`; sshcrabd logs it at startup (`P2P address …`).
  `sshcrab alice@<address>.p2p`.
- The client uses a fresh random P2P key pair and a throwaway DHT node per connection (nothing about the user in the DHT).
- Announcement: the swarm joins the topic `BLAKE2b(P2P public key)` as server only, which it announces anyway; there
  is no shared topic that would list all sshcrab servers.

### 13.3 Trust
- Noise IK means only the holder of the P2P key can answer at an address, and the client checks the key it got.
- The host key is still verified as for every host: stored in `~/.sshcrab/hostkeys` as `<address> 0 ssh-ed25519 …`,
  first use asks (or `--accept-new`), a change is a fatal mismatch. **Deviation from the plan:** the address does not
  replace that first-use check, because whoever holds the P2P key (for example someone who took over the helper)
  can answer at the address and present a host key of their own; the P2P key cannot be checked against the host key
  (it is a hash of the secret). Clients that already know the host key detect such an attacker as a mismatch.

### 13.4 Daemon ↔ helper
- sshcrabd (`P2P = true`) binds `P2PSocket` (`SOCK_SEQPACKET`, mode 0660, group of `P2PUser`) and accepts only the uid
  of `P2PUser` (`SO_PEERCRED`; as a normal user: its own uid). It sends `Hello{version, seed, bootstrap}`
  (postcard; the seed is zeroized after use, never written to disk).
- The helper announces, and for each incoming connection creates a `SOCK_STREAM` socketpair, sends
  `Peer{remote}` with one end attached (`SCM_RIGHTS`) and relays between the peeroxide stream and its end
  (length-prefixed frames). sshcrabd wraps the received end as a pipe `Conn` and calls the same `handle()` as for UDP.
- Pre-auth: all P2P connections share one bucket (`MaxUnauthP2P`, default 16) inside the global `MaxUnauthenticated`;
  their addresses are unknown on the server side.
- The helper refuses to run as root. It retries connecting to the socket; if sshcrabd goes away it exits (systemd
  restarts it). sshcrabd survives helper restarts; the address stays the same.
- sshcrabd does not link peeroxide (`tests/e2e-p2p.sh` checks this).

### 13.5 Deployment (NixOS module)
- `services.sshcrab.p2p.enable` (+ `bootstrap`, `maxPeers`): sets `P2P`/`P2PSocket`/`P2PUser`/`P2PBootstrap`,
  creates the system user `sshcrab-p2p` (fixed, not `DynamicUser`: sshcrabd checks its uid) and `sshcrabd-p2p.service`:
  `BindsTo=`/`WantedBy=` sshcrabd, no capabilities, `ProtectSystem=strict`, `ProtectHome`, `ProtectProc=invisible`,
  `TemporaryFileSystem=/run` with only `/run/sshcrab` and the resolver sockets bound read-only,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, `SystemCallFilter=@system-service ~@privileged`,
  `MemoryDenyWriteExecute`, `MemoryMax=256M`, `TasksMax=64`. sshcrabd gets `RuntimeDirectory=sshcrab`.
- Without systemd: `sshcrabd-p2p --socket <path>` by hand (no sandbox), as `P2PUser`, or as the daemon's own user in
  test mode.

### 13.6 Bootstrap nodes
- Default list (`proto::p2p::DEFAULT_BOOTSTRAP`): the three public HyperDHT nodes
  (`node1`–`node3.hyperdht.org`): sshcrab joins the *public* HyperDHT network. An own node (below) is one more
  entry point. A private DHT is only a config change (list only own nodes; run at least three then).
- Server: `P2PBootstrap` in `sshcrabd.toml`. Client: `P2PBootstrap` in `~/.sshcrab/config.toml`, overridden by
  `--bootstrap HOST:PORT` (repeatable). peeroxide resolves host names itself.
- `sshcrab-dht-node [--host 0.0.0.0] [--port 49737] [--public] [--bootstrap …]`: a non-ephemeral, non-firewalled node;
  `services.sshcrab.dhtNode.enable` (+ `port`, `public` = true, `bootstrap`, `openFirewall` = true) runs it sandboxed
  as a `DynamicUser`. A node bound to a wildcard address learns its DHT id (derived from its public address) from
  the nodes it joins; a first node without any must bind its public IPv4 (enforced by the binary and the module).
  An own node needs a host with a static public IPv4 and UDP 49737 open. The blind relay
  stays off (bandwidth, abuse).

### 13.7 Deviations from P2P.md
1. The DHT key is derived from the host key, not the host key itself (FR-2, §8.2).
2. Our protocol runs over peeroxide's encrypted stream, not over the raw punched UDP path (FR-12, §10).
3. The record is peeroxide's signed announce, no own `SignedEndpointRecord` (§8.1).
4. IPv4 only: peeroxide binds and announces IPv4 only (FR-8).
5. The address does not replace host-key TOFU (§13.3; SR-5 holds only for clients that know the host key).

### 13.8 Status and open points
- Done: `proto` (addresses, seed, control messages, framing, `SOCK_SEQPACKET` fd passing, pipe `Conn`),
  `sshcrab-p2p` crate (client connector, `sshcrabd-p2p`, `sshcrab-dht-node`), sshcrabd control socket, client
  `.p2p` hosts with `--bootstrap` and `config.toml`, NixOS options, flake package `sshcrab-p2p`.
- Tests: `p2p/tests/local_dht.rs` (bootstrap node, announce, connect, relay, handshake on 127.0.0.1),
  `tests/e2e-p2p.sh` (16 checks, three simulated hosts: address, TOFU, commands, 2 MB both ways, PTY, hole-punch path, helper restart, mismatch,
  sshcrabd not linking peeroxide), handshake over a bridged pipe, address and fd-passing unit tests.
- NixOS tests (`nix/test-p2p.nix`): `checks.p2p` runs the sandboxed module stack
  (root sshcrabd, `sshcrab-p2p` user, `AuthorizedKeysDir`, announce retry, data both ways, helper restart) between
  hosts without firewalls. `checks.p2p-nat` puts the server behind a NAT router. Both as QEMU VMs (KVM) or as
  systemd-nspawn containers (`checks.p2p-containers`, `checks.p2p-nat-containers`, no KVM, about 2 minutes each).
- **Hole punching: works in the host tests and through a Linux NAT router (container tests, 2026-11-27); not yet
  verified across real-internet NATs.** Findings:
  1. Signalling works through the NAT: the client finds the record, and PEER_HANDSHAKE is relayed via a DHT node in
     both directions.
  2. A server announcing before any DHT node is reachable "succeeds" and is only retried after 10 minutes; fixed:
     `announce` fails on an empty routing table and the helper retries every 5 s.
  3. A DHT node bound to `0.0.0.0` without others to join gets no valid node id (it derives from its public
     address); fixed: refused by `sshcrab-dht-node` and asserted in the module (§13.6).
  4. NAT classification needs replies from at least three DHT nodes; with fewer the server reports `UNKNOWN` and
     never offers hole punching (on the internet there are enough nodes).
  5. In the VMs both sides then ran peeroxide's hole punch and timed out; also without NAT and without firewalls.
     **Cause (found 2026-11-27): our test configuration, not peeroxide.** The test framework gives every machine
     `192.168.<vlan>.<node number>` besides the addresses the test sets, so the client's 192.168.1.3 was also the
     server's, and the server's punch went to itself. With only the test's addresses (`mkForce`) both tests pass,
     NAT included. A second fault showed up behind it: the test driver runs commands with `set -e`, so the first
     check's `sshcrab …; grep` stopped at the expected refusal (exit 1).
  6. **Host test (`p2p/tests/cross_host.rs`, `tests/e2e-p2p.sh`): it works.** One machine plays three hosts
     (DHT nodes on 127.0.0.1, server on 127.0.0.2, client on 127.0.0.3, peeroxide's same-network shortcut off via
     `SSHCRAB_P2P_BIND`/`SSHCRAB_P2P_NO_LOCAL`). Signalling, NAT classification, hole punch ("passive holepunch
     landed") and the full sshcrab session pass: 16/16 e2e checks, the punch path is asserted. An earlier
     conclusion that peeroxide's server side is broken between hosts was wrong.
  7. **Latency (first real-internet test, 40 ms ping):** the shell answered after about 200 ms. Cause in libudx
     1.7.4: `UdxAsyncStream` allowed one outstanding write and its `poll_flush` waited for the ACK, and
     SecretStream writes every message as header + body + flush, so each message cost two round trips, one at a
     time. sshcrab carried a patched copy until upstream fixed it in libudx 1.8.0, whose writes no longer wait for
     acknowledgements (README.md section 7). `p2p/tests/latency.rs` (40 ms simulated round trip): echo 132 ms
     (1.7.4) → 43 ms (1.8.1); 50 messages there and back 4.4 s → about two round trips on a fresh stream, one
     once its congestion window has grown.
  Open: NATs other than Linux masquerading (home routers, symmetric NATs, which need the relay) are untested.
- **Connection slots (fixed in peeroxide 1.8.0, GHSA-48wj-x5q3-ggfq):** 1.7.4 gave a connection's `max_peers` slot
  back only when setting it up failed, so after 64 connections in total (every client uses a fresh key) the
  helper accepted none until it restarted. Test `p2p/tests/slots.rs`.
- **Denial of service, from a review (2026-11-11):** fixed in peeroxide 1.8.0: a lookup reply with a huge count
  aborted the client (GHSA-4jh8-33j3-h73j), SecretStream allocated a frame of up to 16 MiB before authenticating
  it (GHSA-pchg-rmv6-56f4).
- **Anyone could make a P2P server unreachable**, fixed in peeroxide-dht 1.8.2 (reported by us, upstream #69). A
  DHT node that accepted an ANNOUNCE set its handshake forwarding for that target to the announcer's address,
  whoever announced. So one swarm announcing with a key of its own under `hash(server key)` (also the server's
  topic: `peeroxide::discovery_key` is `hash`) took the handshakes meant for the server, and clients never
  connected, whether they dialled the key through `join_peer` or found it through the topic. Likewise another
  key's UNANNOUNCE removed the server's record. Since 1.8.2 only `hash(announcer) == target` sets or clears the
  forwarding, as in Node's HyperDHT. Test `p2p/tests/impostors.rs`.
- Not yet: the relay for symmetric NATs, IPv6, a fuzz target for the frame decoder.
- A client that refuses the host key exits before its bridge has closed the peeroxide stream; sshcrabd notices only
  at the 10 s handshake timeout (one pre-auth slot meanwhile), as with any client that vanishes.
