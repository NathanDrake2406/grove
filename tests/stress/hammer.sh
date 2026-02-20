#!/usr/bin/env bash
# Grove Load Hammer
#
# Starts a grove daemon on a test repo with 4 worktrees, then hammers
# the Unix socket with 50 parallel clients sending status/list/conflicts
# requests simultaneously. Tests:
#   - All responses are valid JSON with "ok" field
#   - High success rate under concurrent load
#   - Rapid sequential requests on one connection
#   - Concurrent connections
#   - Malformed requests mixed in (must not crash daemon)
#
# Usage: ./hammer.sh
#
set -euo pipefail

GROVE_BIN="${GROVE_BIN:-/Users/nathan/Projects/grove/target/debug/grove}"
NUM_CLIENTS="${NUM_CLIENTS:-50}"
REQUESTS_PER_CLIENT="${REQUESTS_PER_CLIENT:-5}"
NUM_WORKTREES=4

# ── helpers ───────────────────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
STEP_COUNT=0

step() {
    STEP_COUNT=$((STEP_COUNT + 1))
    echo "[STEP $STEP_COUNT] $*"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  [PASS] $*"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  [FAIL] $*"
}

die() {
    echo "FATAL: $*" >&2
    exit 1
}

# ── pre-flight ────────────────────────────────────────────────────────────────

step "Pre-flight checks"
[[ -x "$GROVE_BIN" ]] || die "Grove binary not found at $GROVE_BIN (run: cargo build)"

# Detect available socket tool (socat preferred, nc -U as fallback, python3 always works)
SOCKET_TOOL="python3"
if command -v socat &>/dev/null; then
    SOCKET_TOOL="socat"
    pass "Socket tool: socat"
elif nc -h 2>&1 | grep -q '\-U'; then
    SOCKET_TOOL="nc"
    pass "Socket tool: nc (with -U support)"
else
    pass "Socket tool: python3 (socat/nc not available)"
fi

pass "Grove binary: $GROVE_BIN"
pass "Parallel clients: $NUM_CLIENTS"
pass "Requests per client: $REQUESTS_PER_CLIENT"
pass "Total planned requests: $(( NUM_CLIENTS * REQUESTS_PER_CLIENT ))"

# ── create test repo ──────────────────────────────────────────────────────────

step "Creating test git repo with $NUM_WORKTREES worktrees"

TMPDIR_ROOT=$(mktemp -d /tmp/grove-hammer-XXXXXX)
REPO="$TMPDIR_ROOT/repo"
DAEMON_PID=""

cleanup() {
    if [[ -n "${DAEMON_PID}" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR_ROOT"
}
trap cleanup EXIT

mkdir -p "$REPO/src"
git -C "$REPO" init -b main --quiet
git -C "$REPO" config user.email "hammer@grove.test"
git -C "$REPO" config user.name "Grove Hammer"

cat > "$REPO/src/app.ts" <<'TSEOF'
export function main(): void {
  console.log("app");
}
TSEOF

cat > "$REPO/src/utils.ts" <<'TSEOF'
export function helper(x: number): number {
  return x + 1;
}
TSEOF

git -C "$REPO" add -A
git -C "$REPO" commit -m "base: hammer test repo" --quiet

# Create worktrees
WORKTREE_DIRS=()
for i in $(seq 1 "$NUM_WORKTREES"); do
    WT_DIR="$TMPDIR_ROOT/wt_${i}"
    git -C "$REPO" worktree add "$WT_DIR" -b "branch-${i}" --quiet
    git -C "$WT_DIR" config user.email "wt${i}@grove.test"
    git -C "$WT_DIR" config user.name "Worktree $i"

    echo "// wt${i} change" >> "$WT_DIR/src/app.ts"
    git -C "$WT_DIR" add -A
    git -C "$WT_DIR" commit -m "wt${i}: change" --quiet
    WORKTREE_DIRS+=("$WT_DIR")
done

pass "Test repo ready with $NUM_WORKTREES worktrees"

# ── start daemon ──────────────────────────────────────────────────────────────

step "Starting grove daemon"

SCRATCH="$TMPDIR_ROOT/scratch"
mkdir -p "$SCRATCH/.grove"
cd "$SCRATCH"

"$GROVE_BIN" daemon start >"$TMPDIR_ROOT/daemon.log" 2>&1 &
DAEMON_PID=$!

SOCKET_PATH="$SCRATCH/.grove/daemon.sock"
SOCKET_READY=0
for _attempt in $(seq 1 60); do
    if [[ -S "$SOCKET_PATH" ]]; then
        SOCKET_READY=1
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "Daemon exited prematurely. Log:" >&2
        cat "$TMPDIR_ROOT/daemon.log" >&2
        die "Daemon died before socket appeared"
    fi
    sleep 0.25
done

[[ "$SOCKET_READY" -eq 1 ]] || die "Socket did not appear after 15s"
pass "Daemon started (PID=$DAEMON_PID, socket=$SOCKET_PATH)"

# ── socket send helper ────────────────────────────────────────────────────────

# Sends a single NDJSON request and prints the response line.
# Uses the best available tool.
socket_request() {
    local sock="$1"
    local payload="$2"

    if [[ "$SOCKET_TOOL" == "socat" ]]; then
        printf '%s\n' "$payload" | socat - "UNIX-CONNECT:${sock}" 2>/dev/null
    elif [[ "$SOCKET_TOOL" == "nc" ]]; then
        printf '%s\n' "$payload" | nc -U "$sock" 2>/dev/null
    else
        python3 - "$sock" "$payload" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode())
buf = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
    if b"\n" in buf:
        break
s.close()
print(buf.split(b"\n")[0].decode())
PYEOF
    fi
}

# Sends multiple requests on a single connection
socket_multi_request() {
    local sock="$1"
    shift
    local -a payloads=("$@")
    python3 - "$sock" "${payloads[@]}" <<'PYEOF'
import socket, sys
sock_path = sys.argv[1]
payloads  = sys.argv[2:]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(15)
s.connect(sock_path)

for p in payloads:
    s.sendall((p + "\n").encode())

buf = b""
target_newlines = len(payloads)
while buf.count(b"\n") < target_newlines:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk

s.close()
lines = [l for l in buf.split(b"\n") if l.strip()]
for line in lines:
    print(line.decode())
PYEOF
}

# Sync worktrees so daemon has state to query
step "Syncing $NUM_WORKTREES worktrees with daemon"

WORKTREES_JSON="["
for i in $(seq 1 "$NUM_WORKTREES"); do
    WT_DIR="${WORKTREE_DIRS[$((i-1))]}"
    HEAD=$(git -C "$WT_DIR" rev-parse HEAD)
    if [[ "$i" -gt 1 ]]; then WORKTREES_JSON+=","; fi
    WORKTREES_JSON+="{\"name\":\"wt-${i}\",\"path\":\"${WT_DIR}\",\"branch\":\"refs/heads/branch-${i}\",\"head\":\"${HEAD}\"}"
done
WORKTREES_JSON+="]"

SYNC_RESP=$(socket_request "$SOCKET_PATH" \
    "{\"method\":\"sync_worktrees\",\"params\":{\"worktrees\":${WORKTREES_JSON}}}")

if echo "$SYNC_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok')" 2>/dev/null; then
    pass "Worktrees synced"
else
    fail "Sync failed: $SYNC_RESP"
fi

# ── test 1: rapid sequential requests on one connection ───────────────────────

step "Test 1: Rapid sequential requests on one connection"

SEQUENTIAL_REQUESTS=20
SEQ_PAYLOADS=()
for i in $(seq 1 "$SEQUENTIAL_REQUESTS"); do
    case $(( i % 3 )) in
        0) SEQ_PAYLOADS+=('{"method":"status","params":{}}') ;;
        1) SEQ_PAYLOADS+=('{"method":"list_workspaces","params":{}}') ;;
        2) SEQ_PAYLOADS+=('{"method":"get_all_analyses","params":{}}') ;;
    esac
done

SEQ_OUTPUT=$(socket_multi_request "$SOCKET_PATH" "${SEQ_PAYLOADS[@]}")
SEQ_LINES=$(echo "$SEQ_OUTPUT" | grep -c '^{' || echo "0")
SEQ_OK=$(echo "$SEQ_OUTPUT" | python3 -c "
import json, sys
ok = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
        if d.get('ok'):
            ok += 1
    except:
        pass
print(ok)
" 2>/dev/null || echo "0")

if [[ "$SEQ_LINES" -ge "$SEQUENTIAL_REQUESTS" ]] && [[ "$SEQ_OK" -ge "$SEQUENTIAL_REQUESTS" ]]; then
    pass "Sequential: $SEQ_OK/$SEQUENTIAL_REQUESTS responses OK"
else
    fail "Sequential: only $SEQ_OK/$SEQ_LINES valid responses (expected $SEQUENTIAL_REQUESTS)"
fi

# ── test 2: 50 concurrent clients ────────────────────────────────────────────

step "Test 2: $NUM_CLIENTS concurrent clients (${REQUESTS_PER_CLIENT} requests each)"

RESULTS_DIR="$TMPDIR_ROOT/results"
mkdir -p "$RESULTS_DIR"

METHODS=('{"method":"status","params":{}}' '{"method":"list_workspaces","params":{}}' '{"method":"get_all_analyses","params":{}}')
MALFORMED=('not-json-at-all' '{"method":"status"' '{}')

START_NS=$(python3 -c "import time; print(int(time.monotonic_ns()))")

# Spawn parallel clients
# Each client writes one JSON record per request to a separate file to avoid
# CSV parsing ambiguity (responses themselves contain commas).
PIDS=()
for client_id in $(seq 1 "$NUM_CLIENTS"); do
    (
        for req_idx in $(seq 1 "$REQUESTS_PER_CLIENT"); do
            # ~20% of requests are malformed (to test error path)
            if (( (client_id * req_idx) % 5 == 0 )); then
                payload="${MALFORMED[$(( (client_id + req_idx) % ${#MALFORMED[@]} ))]}"
                is_malformed=1
            else
                payload="${METHODS[$(( (client_id + req_idx) % ${#METHODS[@]} ))]}"
                is_malformed=0
            fi

            t_start=$(python3 -c "import time; print(int(time.monotonic_ns()))")
            response=$(socket_request "$SOCKET_PATH" "$payload" 2>/dev/null || echo '{"ok":false,"error":"connection_failed"}')
            t_end=$(python3 -c "import time; print(int(time.monotonic_ns()))")
            latency_ms=$(( (t_end - t_start) / 1000000 ))

            # Write a JSON record using python to handle quoting safely
            python3 -c "
import json, sys
rec = {
    'client': ${client_id},
    'req':    ${req_idx},
    'lat_ms': ${latency_ms},
    'malformed': bool(${is_malformed}),
    'response': sys.argv[1],
}
print(json.dumps(rec))
" "$response" >> "$RESULTS_DIR/client_${client_id}.jsonl"
        done
    ) &
    PIDS+=($!)
done

# Wait for all clients
for pid in "${PIDS[@]}"; do
    wait "$pid"
done

END_NS=$(python3 -c "import time; print(int(time.monotonic_ns()))")
TOTAL_MS=$(( (END_NS - START_NS) / 1000000 ))

pass "All $NUM_CLIENTS clients completed in ${TOTAL_MS}ms"

# ── test 3: analyze concurrent results ───────────────────────────────────────

step "Test 3: Analyzing results — success rate, latency, JSON validity"

python3 - "$RESULTS_DIR" "$NUM_CLIENTS" "$REQUESTS_PER_CLIENT" "$TOTAL_MS" <<'PYEOF'
import json, os, sys, glob

results_dir  = sys.argv[1]
num_clients  = int(sys.argv[2])
req_per_cli  = int(sys.argv[3])
total_ms     = int(sys.argv[4])

total_requests = 0
ok_count       = 0
fail_count     = 0
error_count    = 0
latencies      = []
# Track how many malformed requests received ok=false (correct error handling)
malformed_rejected = 0
malformed_total    = 0

for filepath in sorted(glob.glob(os.path.join(results_dir, "*.jsonl"))):
    with open(filepath) as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                rec = json.loads(raw_line)
            except json.JSONDecodeError:
                error_count += 1
                continue

            total_requests += 1
            latencies.append(rec.get("lat_ms", 0))
            is_malformed = rec.get("malformed", False)
            response_raw = rec.get("response", "")

            try:
                d = json.loads(response_raw)
                if "ok" not in d:
                    error_count += 1
                    print(f"  [WARN] Response missing 'ok' field: {response_raw[:80]}")
                elif d["ok"]:
                    ok_count += 1
                else:
                    fail_count += 1
                    if is_malformed:
                        malformed_rejected += 1
                if is_malformed:
                    malformed_total += 1
            except json.JSONDecodeError:
                error_count += 1
                print(f"  [WARN] Non-JSON response: {response_raw[:80]}")

# Summary stats
expected          = num_clients * req_per_cli
valid_requests    = total_requests - malformed_total
all_pass          = True

print(f"\n  Total requests:         {total_requests} (expected {expected})")
print(f"  Valid (non-malformed):  {valid_requests}")
print(f"  Malformed (sent):       {malformed_total}")
print(f"  ok=true:                {ok_count}")
print(f"  ok=false (daemon err):  {fail_count - malformed_rejected}")
print(f"  ok=false (malformed):   {malformed_rejected}  (expected daemon rejects)")
print(f"  Invalid JSON:           {error_count}")

if total_requests >= expected * 0.9:
    print(f"  [PASS] Request count >= 90% of expected ({expected})")
else:
    print(f"  [FAIL] Only {total_requests}/{expected} requests completed")
    all_pass = False

# Success rate over valid (non-malformed) requests only
valid_ok_count = ok_count
valid_success_rate = valid_ok_count / max(valid_requests, 1) * 100
if valid_success_rate >= 90.0:
    print(f"  [PASS] Valid request success rate {valid_success_rate:.1f}% >= 90%")
else:
    print(f"  [FAIL] Valid request success rate {valid_success_rate:.1f}% below 90%")
    all_pass = False

if malformed_total > 0 and malformed_rejected > 0:
    print(f"  [PASS] Daemon correctly rejected {malformed_rejected}/{malformed_total} malformed requests")

if error_count == 0:
    print("  [PASS] All responses are valid JSON")
else:
    print(f"  [FAIL] {error_count} non-JSON responses received")
    all_pass = False

if latencies:
    latencies.sort()
    p50  = latencies[len(latencies) // 2]
    p95  = latencies[int(len(latencies) * 0.95)]
    p99  = latencies[int(len(latencies) * 0.99)]
    pmax = latencies[-1]
    print(f"\n  Latency (ms):")
    print(f"    p50:  {p50}ms")
    print(f"    p95:  {p95}ms")
    print(f"    p99:  {p99}ms")
    print(f"    max:  {pmax}ms")

    if pmax <= 10000:
        print(f"  [PASS] Max latency {pmax}ms <= 10000ms")
    else:
        print(f"  [FAIL] Max latency {pmax}ms exceeds 10000ms")
        all_pass = False

sys.exit(0 if all_pass else 2)
PYEOF

if [[ $? -eq 0 ]]; then
    pass "Concurrent load test passed"
else
    fail "Concurrent load test failed"
fi

# ── test 4: malformed requests do not crash daemon ────────────────────────────

step "Test 4: Daemon still responds after malformed-request barrage"

# Verify daemon is still alive and responding
HEALTH_RESP=$(socket_request "$SOCKET_PATH" '{"method":"status","params":{}}' 2>/dev/null || echo '{"ok":false}')
if echo "$HEALTH_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok')" 2>/dev/null; then
    pass "Daemon healthy after load test"
else
    fail "Daemon unhealthy after load test: $HEALTH_RESP"
fi

# ── test 5: connection exhaustion tolerance ───────────────────────────────────

step "Test 5: Connection burst (100 quick connect-send-disconnect)"

BURST_RESULTS="$TMPDIR_ROOT/burst_results.txt"
> "$BURST_RESULTS"

BURST_PIDS=()
for i in $(seq 1 100); do
    (
        resp=$(socket_request "$SOCKET_PATH" '{"method":"status","params":{}}' 2>/dev/null || echo "ERROR")
        if echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok')" 2>/dev/null; then
            echo "OK" >> "$BURST_RESULTS"
        else
            echo "FAIL:${resp::60}" >> "$BURST_RESULTS"
        fi
    ) &
    BURST_PIDS+=($!)
done

for pid in "${BURST_PIDS[@]}"; do
    wait "$pid"
done

BURST_OK=$(grep -c '^OK$' "$BURST_RESULTS" || echo "0")
BURST_FAIL=$(grep -c '^FAIL' "$BURST_RESULTS" || echo "0")
BURST_TOTAL=$(wc -l < "$BURST_RESULTS" | tr -d ' ')

if [[ "$BURST_OK" -ge 85 ]]; then
    pass "Burst: $BURST_OK/100 connections succeeded (>= 85 required)"
else
    fail "Burst: only $BURST_OK/100 connections succeeded (FAIL=$BURST_FAIL, total=$BURST_TOTAL)"
fi

# ── print summary ─────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Load Hammer Results"
echo "  Total wall time: ${TOTAL_MS}ms"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "════════════════════════════════════════════════════════════════"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
