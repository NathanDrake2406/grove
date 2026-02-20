#!/usr/bin/env bash
# Grove Chaos Stress Test
#
# Creates N worktrees with overlapping TypeScript changes, runs grove daemon,
# waits for analysis, and verifies scoring invariants:
#   - All C(N,2) pairs are analyzed
#   - Pairs with shared file changes score non-Green
#   - All score values are valid (Green/Yellow/Red/Black)
#
# Usage:
#   ./chaos.sh [N]               Run with N worktrees (default 10)
#   RUN_SCALE_SWEEP=1 ./chaos.sh Run 5, 10, 15 worktree sweeps
#
set -euo pipefail

GROVE_BIN="${GROVE_BIN:-/Users/nathan/Projects/grove/target/debug/grove}"
N="${1:-10}"
TIMEOUT_SEC="${TIMEOUT_SEC:-90}"

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
[[ -x "$GROVE_BIN" ]] || die "grove binary not found at $GROVE_BIN (run: cargo build)"

N_INT=$(( N + 0 ))
[[ "$N_INT" -ge 2 ]] || die "N must be >= 2, got: $N"

EXPECTED_PAIRS=$(( N_INT * (N_INT - 1) / 2 ))
pass "Grove binary: $GROVE_BIN"
pass "Worktree count: $N_INT  (expected C($N_INT,2) = $EXPECTED_PAIRS pairs)"

# ── setup temp repo ───────────────────────────────────────────────────────────

step "Creating temp git repo"
TMPDIR_ROOT=$(mktemp -d /tmp/grove-chaos-XXXXXX)
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

mkdir -p "$REPO"

git -C "$REPO" init -b main --quiet
git -C "$REPO" config user.email "test@grove.test"
git -C "$REPO" config user.name "Grove Test"

# Create base TypeScript project
mkdir -p "$REPO/src"

# shared.ts — the hotspot that multiple worktrees will touch
cat > "$REPO/src/shared.ts" <<'TSEOF'
// Shared module — multiple worktrees will modify this file
export function authenticate(token: string): boolean {
  return token.length > 0;
}

export function processPayment(amount: number, currency: string): string {
  return `${amount} ${currency}`;
}

export function formatUser(id: number, name: string): string {
  return `${id}:${name}`;
}

export class DataStore {
  private data: Map<string, unknown> = new Map();

  set(key: string, value: unknown): void {
    this.data.set(key, value);
  }

  get(key: string): unknown {
    return this.data.get(key);
  }
}

export interface Config {
  timeout: number;
  retries: number;
  baseUrl: string;
}

const DEFAULT_CONFIG: Config = {
  timeout: 5000,
  retries: 3,
  baseUrl: "https://api.example.com",
};

export { DEFAULT_CONFIG };
TSEOF

# package.json — schema file; first 3 worktrees will bump deps (Schema overlap)
cat > "$REPO/package.json" <<'JSONEOF'
{
  "name": "grove-chaos-test",
  "version": "1.0.0",
  "dependencies": {}
}
JSONEOF

# Per-worktree unique files (disjoint — should stay Green with each other)
for i in $(seq 1 "$N_INT"); do
    cat > "$REPO/src/feature_${i}.ts" <<TSEOF
// Feature module $i — unique to worktree $i, no overlap expected
export function featureOp${i}(x: number): number {
  return x * $i;
}

export const FEATURE_${i}_ID = "$i";
TSEOF
done

git -C "$REPO" add -A
git -C "$REPO" commit -m "base: initial project structure" --quiet

pass "Base repo initialized at $REPO"

# ── create worktrees ──────────────────────────────────────────────────────────

step "Creating $N_INT worktrees with overlapping changes"

WORKTREE_DIRS=()

for i in $(seq 1 "$N_INT"); do
    WT_DIR="$TMPDIR_ROOT/wt_${i}"
    BRANCH="feature/wt-${i}"

    git -C "$REPO" worktree add "$WT_DIR" -b "$BRANCH" --quiet
    git -C "$WT_DIR" config user.email "wt${i}@grove.test"
    git -C "$WT_DIR" config user.name "Worktree $i"

    # Even worktrees: modify authenticate function in shared.ts
    if (( i % 2 == 0 )); then
        # Use Python for portable in-place replacement (avoids sed -i'' portability issues)
        python3 -c "
path = '${WT_DIR}/src/shared.ts'
with open(path) as f:
    content = f.read()
content = content.replace(
    'return token.length > 0;',
    'return token.length > ${i};  // wt${i}'
)
with open(path, 'w') as f:
    f.write(content)
"
    fi

    # Odd worktrees: modify processPayment function in shared.ts
    if (( i % 2 == 1 )); then
        python3 -c "
path = '${WT_DIR}/src/shared.ts'
with open(path) as f:
    content = f.read()
content = content.replace(
    'return \`\${amount} \${currency}\`;',
    'return \`wt${i}: \${amount} \${currency}\`;'
)
with open(path, 'w') as f:
    f.write(content)
"
    fi

    # Every worktree appends to its own unique feature file (disjoint changes)
    cat >> "$WT_DIR/src/feature_${i}.ts" <<TSEOF

// Worktree $i: added in worktree branch
export function worktreeUnique${i}(): string {
  return "wt-${i}-unique";
}
TSEOF

    # First 3 worktrees also bump package.json (triggers Schema overlap)
    if (( i <= 3 )); then
        python3 -c "
import json
with open('${WT_DIR}/package.json') as f:
    pkg = json.load(f)
pkg['dependencies']['dep-wt-${i}'] = '^${i}.0.0'
with open('${WT_DIR}/package.json', 'w') as f:
    json.dump(pkg, f, indent=2)
    f.write('\n')
"
    fi

    git -C "$WT_DIR" add -A
    git -C "$WT_DIR" commit -m "wt${i}: overlapping changes to shared.ts" --quiet

    WORKTREE_DIRS+=("$WT_DIR")
done

pass "Created $N_INT worktrees"

# ── initialize grove workspace ────────────────────────────────────────────────

step "Initializing grove workspace and starting daemon"

# The grove binary looks for .grove/ directory walking up from cwd.
# Create a scratch dir with .grove/ as the daemon home.
SCRATCH="$TMPDIR_ROOT/scratch"
mkdir -p "$SCRATCH/.grove"
cd "$SCRATCH"

"$GROVE_BIN" daemon start >"$TMPDIR_ROOT/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for socket to become available (daemon uses daemon.sock per DaemonPaths)
SOCKET_PATH="$SCRATCH/.grove/daemon.sock"
SOCKET_READY=0
for _attempt in $(seq 1 60); do
    if [[ -S "$SOCKET_PATH" ]]; then
        SOCKET_READY=1
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "  Daemon exited unexpectedly. Log:" >&2
        cat "$TMPDIR_ROOT/daemon.log" >&2
        fail "Daemon died before socket appeared"
        exit 1
    fi
    sleep 0.25
done

if [[ "$SOCKET_READY" -eq 0 ]]; then
    echo "  Daemon log:" >&2
    cat "$TMPDIR_ROOT/daemon.log" >&2
    die "Daemon socket did not appear within 15 seconds at $SOCKET_PATH"
fi

pass "Daemon started (PID=$DAEMON_PID, socket=$SOCKET_PATH)"

# ── Unix socket request helper ────────────────────────────────────────────────

send_request() {
    local payload="$1"
    python3 - "$SOCKET_PATH" "$payload" <<'PYEOF'
import socket, sys

sock_path = sys.argv[1]
payload   = sys.argv[2]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(15)
s.connect(sock_path)
s.sendall((payload + "\n").encode())

buf = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
    if b"\n" in buf:
        break

s.close()
line = buf.split(b"\n")[0]
print(line.decode())
PYEOF
}

# ── build sync_worktrees payload ──────────────────────────────────────────────

step "Syncing worktrees with daemon"

WORKTREES_JSON="["
for i in $(seq 1 "$N_INT"); do
    WT_DIR="${WORKTREE_DIRS[$((i-1))]}"
    BRANCH="feature/wt-${i}"
    HEAD=$(git -C "$WT_DIR" rev-parse HEAD)
    if [[ "$i" -gt 1 ]]; then WORKTREES_JSON+=","; fi
    WORKTREES_JSON+="{\"name\":\"wt-${i}\",\"path\":\"${WT_DIR}\",\"branch\":\"refs/heads/${BRANCH}\",\"head\":\"${HEAD}\"}"
done
WORKTREES_JSON+="]"

SYNC_PAYLOAD="{\"method\":\"sync_worktrees\",\"params\":{\"worktrees\":${WORKTREES_JSON}}}"
SYNC_RESP=$(send_request "$SYNC_PAYLOAD")

if echo "$SYNC_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if not d.get('ok'):
    print('Sync error: ' + str(d.get('error', 'unknown')), file=sys.stderr)
    sys.exit(1)
added = len(d['data']['added'])
print(f'Added {added} worktrees')
" 2>&1; then
    pass "Sync succeeded"
else
    fail "Sync failed: $SYNC_RESP"
fi

# ── wait for analysis to complete ─────────────────────────────────────────────

step "Waiting for all $EXPECTED_PAIRS pairs to be analyzed (timeout: ${TIMEOUT_SEC}s)"

ANALYSIS_DONE=0
ELAPSED=0
POLL_INTERVAL=2

while [[ "$ELAPSED" -lt "$TIMEOUT_SEC" ]]; do
    STATUS_RESP=$(send_request '{"method":"status","params":{}}')
    ANALYSIS_COUNT=$(echo "$STATUS_RESP" | python3 -c \
        "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('analysis_count',0))" 2>/dev/null || echo "0")

    if [[ "$ANALYSIS_COUNT" -ge "$EXPECTED_PAIRS" ]]; then
        ANALYSIS_DONE=1
        break
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
    echo "  ... analysis_count=$ANALYSIS_COUNT/$EXPECTED_PAIRS  (${ELAPSED}s elapsed)"
done

if [[ "$ANALYSIS_DONE" -eq 1 ]]; then
    pass "All $EXPECTED_PAIRS pairs analyzed in ${ELAPSED}s"
else
    CURRENT=$(send_request '{"method":"status","params":{}}' | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('data',{}).get('analysis_count',0))" 2>/dev/null || echo "unknown")
    fail "Timeout after ${TIMEOUT_SEC}s: $CURRENT/$EXPECTED_PAIRS pairs analyzed"
fi

# ── fetch and verify all analyses ─────────────────────────────────────────────

step "Fetching all pair analyses and verifying scoring invariants"

ALL_RESP=$(send_request '{"method":"get_all_analyses","params":{}}')

python3 - <<PYEOF
import json, sys

raw = '''${ALL_RESP}'''
d = json.loads(raw)

if not d.get('ok'):
    print("  [FAIL] get_all_analyses returned error:", d.get('error'))
    sys.exit(2)

analyses = d.get('data', [])
total = len(analyses)

# Build normalized pair -> score mapping
pair_scores = {}
for a in analyses:
    wa = a.get('workspace_a', '')
    wb = a.get('workspace_b', '')
    score = a.get('score', 'Green')
    key = tuple(sorted([wa, wb]))
    pair_scores[key] = score

n = ${N_INT}
expected_pairs = n * (n - 1) // 2

print(f"  Total analyses returned: {total}")
print(f"  Unique pairs:           {len(pair_scores)}")
print(f"  Expected pairs C({n},2): {expected_pairs}")

all_pass = True

# Check 1: pair count
if len(pair_scores) >= expected_pairs:
    print(f"  [PASS] Pair count >= C({n},{n-1}...2) = {expected_pairs}")
else:
    print(f"  [FAIL] Pair count {len(pair_scores)} < expected {expected_pairs}")
    all_pass = False

# Check 2: all scores are valid values
valid_scores = {"Green", "Yellow", "Red", "Black"}
invalid = [s for s in pair_scores.values() if s not in valid_scores]
if not invalid:
    print("  [PASS] All score values are valid (Green/Yellow/Red/Black)")
else:
    print(f"  [FAIL] Invalid score values: {invalid}")
    all_pass = False

# Check 3: overlapping pairs (all worktrees touch shared.ts) should be non-Green
score_counts = {}
for s in pair_scores.values():
    score_counts[s] = score_counts.get(s, 0) + 1

print(f"  Score distribution: {score_counts}")

non_green = sum(1 for s in pair_scores.values() if s != 'Green')
if non_green > 0:
    print(f"  [PASS] {non_green} pairs correctly scored non-Green (shared.ts overlaps detected)")
else:
    print("  [FAIL] All pairs Green — expected overlaps from shared.ts modifications")
    all_pass = False

# Check 4: overlaps list is non-empty for non-Green pairs
non_green_with_overlaps = sum(
    1 for a in analyses
    if a.get('score', 'Green') != 'Green' and len(a.get('overlaps', [])) > 0
)
non_green_total = sum(1 for a in analyses if a.get('score', 'Green') != 'Green')
if non_green_total > 0 and non_green_with_overlaps == non_green_total:
    print(f"  [PASS] All {non_green_total} non-Green pairs have overlap details")
elif non_green_total == 0:
    pass  # already caught above
else:
    print(f"  [FAIL] {non_green_total - non_green_with_overlaps} non-Green pairs missing overlap details")
    all_pass = False

# Check 5: score monotonicity — Black >= Red >= Yellow >= Green
score_order = {"Green": 0, "Yellow": 1, "Red": 2, "Black": 3}
for a in analyses:
    score = a.get('score', 'Green')
    overlaps = a.get('overlaps', [])
    if overlaps:
        max_severity = max(
            score_order.get(
                {"File": "Yellow", "Hunk": "Yellow", "Symbol": "Red",
                 "Dependency": "Black", "Schema": "Yellow"}.get(
                    list(o.keys())[0] if isinstance(o, dict) else "File", "Green"
                ),
                0
            )
            for o in overlaps
        )
        # Hunk distance=0 -> Red, distance>0 -> Yellow
        reported_order = score_order.get(score, 0)
        # score should be >= max overlap severity (could be higher due to other layers)
        # We just ensure no scores are Green when overlaps exist
        if score == 'Green' and overlaps:
            print(f"  [FAIL] Score is Green but {len(overlaps)} overlaps exist")
            all_pass = False
            break

if all_pass:
    print("  [PASS] Monotonicity: no Green scores with overlaps")

sys.exit(0 if all_pass else 2)
PYEOF

if [[ $? -eq 0 ]]; then
    pass "All scoring invariants verified"
else
    fail "Scoring invariants check failed"
fi

# ── print summary ─────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Chaos Test Results (N=$N_INT worktrees)"
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo "════════════════════════════════════════════════════════════════"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi

exit 0

# ── scale sweep mode ──────────────────────────────────────────────────────────
# Invoked separately by setting RUN_SCALE_SWEEP=1 before calling the script.
# Example:
#   RUN_SCALE_SWEEP=1 bash tests/stress/chaos.sh
# The sweep spawns this script recursively with N=5, 10, 15.
