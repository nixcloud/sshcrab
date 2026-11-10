#!/usr/bin/env bash
# End-to-end test of the P2P backend on 127.0.0.1 (spec §13, P4): a local
# sshcrab-dht-node as the only bootstrap node, sshcrabd with P2P = true, the
# sshcrabd-p2p helper (unsandboxed, as the same user) and the client
# connecting to the .p2p address. One machine plays three hosts: DHT nodes on
# 127.0.0.1, the helper on 127.0.0.2, the client on 127.0.0.3, peeroxide's
# same-network shortcut off, so the hole-punch path runs. Needs target/debug binaries.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=$ROOT/target/debug
T=$(mktemp -d)
PORT=${SSHCRAB_E2E_PORT:-$((23000 + RANDOM % 2000))}
DHT=$((PORT + 1))
PASS=0
FAIL=0
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$T"' EXIT

ok() { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkdir -m 755 "$T/srv" "$T/home" "$T/client" "$T/home/.sshcrab" "$T/run"
export HOME=$T/client USER=$(id -un)
"$B/sshcrab-keygen-ed25519" "$T/client/.sshcrab/id_ed25519" >/dev/null
install -m 644 "$T/client/.sshcrab/id_ed25519.pub" "$T/home/.sshcrab/authorized_keys"
cat > "$T/srv/sshcrabd.toml" <<EOF
ListenAddress = ["127.0.0.1:22"]
P2P = true
P2PSocket = "$T/run/p2p.sock"
P2PBootstrap = ["127.0.0.1:$DHT"]
EOF
chmod 644 "$T/srv/sshcrabd.toml"

"$B/sshcrab-dht-node" --host 127.0.0.1 --port $DHT > "$T/dht.log" 2>&1 &
PIDS+=($!)
sleep 0.5
# NAT classification needs replies from at least three nodes.
for p in 1 2 3; do
    "$B/sshcrab-dht-node" --host 127.0.0.1 --port $((DHT + 1 + p)) --bootstrap 127.0.0.1:$DHT >> "$T/dht.log" 2>&1 &
    PIDS+=($!)
done
PIDS+=($!)
sleep 0.5
(cd "$T/srv" && exec env SSHCRABD_HOME="$T/home" SSHCRABD_SHELL="$(command -v bash)" "$B/sshcrabd" -p $PORT) > "$T/daemon.log" 2>&1 &
PIDS+=($!)
sleep 1
RUST_LOG=info,peeroxide::swarm=debug SSHCRAB_P2P_BIND=127.0.0.2 SSHCRAB_P2P_NO_LOCAL=1 "$B/sshcrabd-p2p" --socket "$T/run/p2p.sock" > "$T/helper.log" 2>&1 &
HELPER=$!
PIDS+=($HELPER)
for _ in $(seq 1 30); do grep -q 'announced as' "$T/helper.log" && break; sleep 0.5; done

ADDR=$(grep -o '[a-z0-9]\{52\}\.p2p' "$T/daemon.log" | head -1)
check "sshcrabd logs its P2P address" "[ -n '$ADDR' ]"
check "the helper announces that address" "grep -q 'announced as $ADDR' '$T/helper.log'"
check "the control socket is mode 0660" "[ \$(stat -c %a '$T/run/p2p.sock') = 660 ]"

c() { SSHCRAB_P2P_BIND=127.0.0.3 SSHCRAB_P2P_NO_LOCAL=1 timeout 90 "$B/sshcrab" --bootstrap 127.0.0.1:$DHT "$@"; }
c "$ADDR" true </dev/null 2>"$T/err"
check "unknown host key on a .p2p address is refused without --accept-new" "grep -q 'unknown host key for $ADDR' '$T/err'"
c --accept-new "$ADDR" true </dev/null 2>/dev/null
check "--accept-new stores the host key under the address" "grep -q '^$ADDR 0 ssh-ed25519 ' '$T/client/.sshcrab/hostkeys'"

out=$(c "$ADDR" 'echo out; echo err >&2; exit 7' </dev/null 2>"$T/err"); code=$?
check "command over P2P: exit code" "[ $code = 7 ]"
check "command over P2P: stdout and stderr" "[ '$out' = out ] && grep -qx err '$T/err'"

head -c 2000000 /dev/urandom > "$T/blob"
want=$(sha256sum < "$T/blob" | cut -d' ' -f1)
got=$(c "$ADDR" "export PATH=$PATH; sha256sum" < "$T/blob" | cut -d' ' -f1)
check "2 MB stdin over P2P arrives intact" "[ '$got' = '$want' ]"
got=$(c "$ADDR" "export PATH=$PATH; cat '$T/blob'" </dev/null | sha256sum | cut -d' ' -f1)
check "2 MB stdout over P2P arrives intact" "[ '$got' = '$want' ]"

out=$(c --ping --ping-count 5 --ping-interval 20 "$ADDR" </dev/null 2>&1); code=$?
check "--ping measures round trips over P2P" "[ $code = 0 ] && grep -q '(P2P)' <<<\"\$out\" && grep -q '^--- 5 pings' <<<\"\$out\""

out=$(printf 'export PATH=%s; tty; exit 5\n' "$PATH" | TERM=xterm-256color c "$ADDR" 2>&1); code=$?
check "interactive session over P2P runs on a PTY" "grep -q /dev/pts/ <<<\"\$out\" && [ $code = 5 ]"

# The helper restarts (as systemd would) and the address stays the same.
kill $HELPER; wait $HELPER 2>/dev/null
check "sshcrabd notices the helper leaving" "sleep 0.5; grep -q 'P2P helper disconnected' '$T/daemon.log'"
SSHCRAB_P2P_BIND=127.0.0.2 SSHCRAB_P2P_NO_LOCAL=1 "$B/sshcrabd-p2p" --socket "$T/run/p2p.sock" > "$T/helper2.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do grep -q 'announced as' "$T/helper2.log" && break; sleep 0.5; done
check "a restarted helper announces the same address" "grep -q 'announced as $ADDR' '$T/helper2.log'"
out=$(c "$ADDR" 'echo again' </dev/null 2>/dev/null)
check "connections work after a helper restart" "[ '$out' = again ]"

check "connections took the hole-punch path (not a same-host shortcut)" "grep -q 'passive holepunch landed' '$T/helper.log'"

# A wrong key at a known address is a mismatch, as for UDP hosts.
sed -i "s|^$ADDR 0 ssh-ed25519 .*|$ADDR 0 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDgP2oyNSbMWDPXH8G8dXFR4qiCaUvwyEDyrVMxRGrD3|" "$T/client/.sshcrab/hostkeys"
c "$ADDR" true </dev/null 2>"$T/err"
check "a changed host key at a known address is reported" "grep -q 'HOST KEY MISMATCH for $ADDR' '$T/err'"

# A helper running as a different user would be refused; we can only test the
# check for root-owned daemons in the NixOS VM test. sshcrabd never links the DHT:
check "sshcrabd does not link peeroxide" "! strings '$B/sshcrabd' | grep -q peeroxide"

echo "$PASS passed, $FAIL failed"
grep -h "timed out\|handshake failed" "$T/daemon.log" | sed "s/^/daemon: /"
[ $FAIL = 0 ] || { for f in dht daemon helper helper2; do echo "--- $f log:"; tail -15 "$T/$f.log" 2>/dev/null; done; }
[ $FAIL = 0 ]
