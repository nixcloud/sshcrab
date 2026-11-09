# libudx 1.7.4, patched for sshcrab

An unmodified copy of [libudx 1.7.4](https://crates.io/crates/libudx/1.7.4) (MIT OR Apache-2.0, from the
peeroxide project) plus one change, used through `[patch.crates-io]` in the workspace `Cargo.toml`. The full
diff against upstream is `sshcrab.patch`. Drop this directory once upstream has an equivalent fix.

## The problem

`UdxAsyncStream`, the `AsyncRead`/`AsyncWrite` adapter that peeroxide's SecretStream runs over, let only one
write be outstanding:

- `poll_write` returned `Pending` until the previous write was acknowledged by the peer;
- `poll_flush` returned `Pending` until the last write was acknowledged.

SecretStream sends each message as `write_all(3-byte header)`, `write_all(body)`, `flush()`. So every message
cost two full round trips, and messages could not overlap. At a 40 ms ping an interactive shell took about
200 ms to echo a key, and a screen redraw of many small messages took seconds. On loopback the round trip is
close to zero, so the problem cannot be seen there.

## The change

`src/native/async_stream.rs`:

- `poll_write` queues the packets and returns at once. Outstanding ACKs are kept in a queue (they complete in
  order, ACKs being cumulative). It waits only while more than `MAX_UNACKED_BYTES` (1 MiB) would be unacknowledged
  (backpressure; the congestion controller paces the actual sending as before).
- `poll_flush` no longer waits for ACKs (TCP semantics: data handed to the stream is "flushed"); it still reports a
  failed earlier write.
- `poll_shutdown` queues FIN behind all data and resolves once everything, FIN included, is acknowledged.

`src/native/stream.rs`: `StreamInner::coalesce_write` appends a small write to the newest queued, not yet sent
DATA packet if it fits (like TCP's send buffer), so writes waiting behind a full congestion window leave as a
few full packets instead of one tiny packet each. Without it, a 3-byte SecretStream header and a short body were
two packets, and 50 short messages needed about four round trips with the initial 10-packet window.

Wire format and the `UdxStream` message API are unchanged.

## Verification

- `p2p/tests/latency.rs` in sshcrab (UDP proxy, 20 ms each way, SecretStream on top):

  | | upstream 1.7.4 | patched |
  |---|---|---|
  | one message there and back (echo) | 132 ms | 45 ms |
  | 50 messages there and back | 4.4 s | 56 ms |

- libudx's own test suite passes (lifecycle, errors, loss/delay/reorder simulation, MTU probing, throughput,
  relay). The Node.js interop tests (`stream_interop`, `udx_interop`, `wire_compat`) need scripts not shipped in
  the crate and fail identically without the patch.
- sshcrab: `cargo test`, `tests/e2e.sh`, `tests/e2e-p2p.sh` (2 MB in both directions, byte-exact).

## Upstream report (draft)

> **UdxAsyncStream: one round trip per write and per flush**
>
> `UdxAsyncStream::poll_write` waits for the previous write's ACK, and `poll_flush` waits for the last write's ACK.
> SecretStream writes header, body and flushes per message, so every message costs two RTTs and messages never
> overlap: over a 40 ms link an echo takes ~130 ms, and 50 small messages take ~4.4 s. Proposed: keep a queue of
> outstanding ACKs, apply backpressure only above a byte limit, make `poll_flush` not wait for ACKs, make
> `poll_shutdown` wait for all of them; optionally coalesce small writes into the newest unsent packet. Patch and a
> test with a delaying proxy attached (echo 132 ms → 45 ms, 50 messages 4.4 s → 56 ms).
