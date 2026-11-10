#!/usr/bin/env bash
# End-to-end test against a non-root sshcrabd on 127.0.0.1 (spec §11, M8).
# Needs: target/debug binaries (cargo build in `nix develop`), socat, sha256sum, seq.
# Usage: tests/e2e.sh [--skip-reconnect]
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=$ROOT/target/debug
T=$(mktemp -d)
PORT=${SSHCRAB_E2E_PORT:-$((21000 + RANDOM % 2000))}
RELAY=$((PORT + 1))
PASS=0
FAIL=0
trap 'kill $DAEMON 2>/dev/null; [ -n "${R:-}" ] && { pkill -P "$R"; kill "$R"; } 2>/dev/null; rm -rf "$T"' EXIT

ok() { echo "ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL - $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkdir -m 755 "$T/srv" "$T/home" "$T/client" "$T/home/.sshcrab"
export HOME=$T/client USER=$(id -un)
"$B/sshcrab-keygen-ed25519" "$T/client/.sshcrab/id_ed25519" >/dev/null
install -m 644 "$T/client/.sshcrab/id_ed25519.pub" "$T/home/.sshcrab/authorized_keys"
printf 'ListenAddress = ["127.0.0.1:22"]\n' > "$T/srv/sshcrabd.toml"
chmod 644 "$T/srv/sshcrabd.toml"
(cd "$T/srv" && exec env SSHCRABD_HOME="$T/home" SSHCRABD_SHELL="$(command -v bash)" "$B/sshcrabd" -p $PORT) > "$T/daemon.log" 2>&1 &
DAEMON=$!
sleep 1
P="export PATH=$PATH;"
c() { timeout 60 "$B/sshcrab" -p $PORT "$@"; }

c 127.0.0.1 true </dev/null 2>"$T/err"
check "unknown host key is refused without --accept-new" "grep -q 'use --accept-new' '$T/err'"
c --accept-new 127.0.0.1 true </dev/null 2>/dev/null
check "--accept-new stores the host key" "grep -q '^127.0.0.1 $PORT ssh-ed25519 ' '$T/client/.sshcrab/hostkeys'"

out=$(c 127.0.0.1 'echo out; echo err >&2; exit 7' </dev/null 2>"$T/err"); code=$?
check "exit code is passed through" "[ $code = 7 ]"
check "stdout and stderr are separate" "[ '$out' = out ] && grep -qx err '$T/err'"
c 127.0.0.1 'kill -TERM $$' </dev/null; code=$?
check "death by signal exits 128+N" "[ $code = 143 ]"
id=$(c 127.0.0.1 'echo $SSHCRAB_SESSION_ID' </dev/null)
check "SSHCRAB_SESSION_ID is a UUID" "[[ '$id' =~ ^[0-9a-f-]{36}$ ]]"

head -c 5000000 /dev/urandom > "$T/blob"
want=$(sha256sum < "$T/blob" | cut -d' ' -f1)
got=$(c 127.0.0.1 "$P sha256sum" < "$T/blob" | cut -d' ' -f1)
check "5 MB stdin arrives intact" "[ '$got' = '$want' ]"
got=$(c 127.0.0.1 "$P cat '$T/blob'" </dev/null | sha256sum | cut -d' ' -f1)
check "5 MB stdout arrives intact" "[ '$got' = '$want' ]"

out=$(c --ping --ping-count 5 --ping-interval 20 127.0.0.1 </dev/null 2>&1); code=$?
check "--ping measures round trips over UDP" "[ $code = 0 ] && grep -q '(direct UDP)' <<<\"\$out\" && grep -q '^--- 5 pings' <<<\"\$out\""

out=$(printf '%s tty; exit 5\n' "$P" | TERM=xterm-256color c 127.0.0.1 2>&1); code=$?
check "interactive session runs on a PTY" "grep -q /dev/pts/ <<<\"\$out\" && [ $code = 5 ]"

# Session survives a killed client and resumes with -R <UUID>.
# Started directly (not via c/timeout) so kill -9 hits sshcrab itself.
"$B/sshcrab" -p $PORT 127.0.0.1 "$P for i in \$(seq 1 8); do echo l\$i; sleep 1; done; exit 4" </dev/null > "$T/k.out" &
K=$!
sleep 2.5
kill -9 $K 2>/dev/null; wait $K 2>/dev/null
sid=$(cat "$T"/client/.sshcrab/sessions/*/session 2>/dev/null)
check "client writes sessions/<PID>/session" "[ -n '$sid' ]"
check "-L lists the session" "c -L 127.0.0.1 | grep -q '^$sid \[non-interactive\]'"
sleep 7
rest=$(c -R "$sid" 127.0.0.1 </dev/null); code=$?
all=$( (cat "$T/k.out"; echo "$rest") | grep -c '^l[0-9]')
check "-R <UUID> resumes with the remaining output and exit code" "[ $code = 4 ] && [ $all -ge 8 ]"
check "a finished session is removed" "[ -z \"\$(c -L 127.0.0.1)\" ]"

if [ "${1:-}" != --skip-reconnect ]; then
    relay() { socat UDP4-LISTEN:$RELAY,reuseaddr,fork UDP4:127.0.0.1:$PORT >/dev/null 2>&1 & echo $!; }
    R=$(relay)
    sleep 0.5
    timeout 120 "$B/sshcrab" --accept-new -p $RELAY 127.0.0.1 "$P for i in \$(seq 1 30); do echo \$i; sleep 1; done; exit 3" \
        </dev/null > "$T/rc.out" 2> "$T/rc.err" &
    CL=$!
    sleep 5; pkill -P "$R"; kill "$R"
    sleep 20; R=$(relay)
    wait $CL; code=$?
    check "reconnect after a 20 s outage: exit code" "[ $code = 3 ]"
    check "reconnect after a 20 s outage: output complete, no duplicates" "seq 1 30 | cmp -s - '$T/rc.out'"
    check "reconnect status line was shown" "grep -q 'reconnecting… (elapsed' '$T/rc.err'"
fi

# Last: stopping the daemon tells attached clients instead of leaving them to reconnect.
"$B/sshcrab" -p $PORT 127.0.0.1 "$P sleep 600" </dev/null 2> "$T/sd.err" &
CL=$!
sleep 1.5
kill -INT $DAEMON
timeout 10 tail --pid=$CL -f /dev/null; wait $CL; code=$?
check "daemon shutdown disconnects clients with a reason" "[ $code = 255 ] && grep -q 'shutting down' '$T/sd.err'"

echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ] || { echo "--- daemon log:"; tail -20 "$T/daemon.log"; }
[ $FAIL = 0 ]
