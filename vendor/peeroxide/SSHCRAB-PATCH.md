# peeroxide 1.7.4, patched for sshcrab

An unmodified copy of [peeroxide 1.7.4](https://crates.io/crates/peeroxide/1.7.4) (MIT OR Apache-2.0) plus one
change, used through `[patch.crates-io]` in the workspace `Cargo.toml`. The full diff against upstream is
`sshcrab.patch`. Drop this directory once upstream has an equivalent fix.

## The problem

A swarm counts its connections against `max_peers` (the helper uses 64). A slot was taken when a connection was
set up and given back only if setting it up failed (or on deduplication). Closing or dropping an established
`SwarmConnection` never gave it back.

Every sshcrab client connects with a fresh key pair, so every connection (reconnects included) used up one slot
for good. After 64 connections in total, `sshcrabd-p2p` silently ignored every handshake until it was restarted.
Anyone could get there in seconds with 64 throwaway key pairs.

## The change

`src/swarm.rs`, `src/connection_set.rs`:

- A slot is taken through `take_slot`, which returns a `Slot` guard. Each `SwarmConnection` holds its guard;
  dropping the connection (or the guard, when setting it up fails) sends the slot back to the swarm task over
  the channel upstream already used for failed setups.
- Slots carry an id, and only the slot with that id is released: a dropped old connection of a key does not free
  the slot of a newer connection with the same key (deduplication).

Test: `p2p/tests/slots.rs` (a server with `max_peers = 2` accepts a 3rd and 4th connection after the first ones
ended; upstream refuses the 3rd).
