#!/usr/bin/env bash
set -Eeuo pipefail

CORPUS_DIR="${1:-/corpus}"
STRICT="${MRTGEN_STRICT:-0}"
FAILURES=()

run_one() {
    local label="$1"
    local path="$2"
    local mode="$3"
    local out="/tmp/${label//\//_}.out"
    local err="/tmp/${label//\//_}.err"
    local rc

    set +e
    timeout 60s bgpkit-parser --records-count "$path" >"$out" 2>"$err"
    rc=$?
    set -e

    local output stderr_bytes
    output="$(tr '\n' ' ' <"$out" | sed 's/[[:space:]]*$//')"
    stderr_bytes="$(wc -c <"$err")"
    echo "$label: rc=$rc; records_count_output=${output:-<empty>}; stderr_bytes=$stderr_bytes"

    if [[ "$mode" == "valid" ]]; then
        local expected count
        expected="$(jq '.records | length' "$path.manifest.json")"
        count="$(grep -oE '[0-9]+' "$out" | tail -1 || true)"
        if [[ "$rc" -ne 0 || "$count" != "$expected" ]]; then
            FAILURES+=("bgpkit-parser valid-only count mismatch: expected $expected, got ${count:-<empty>}")
        fi
        return
    fi

    if [[ "$rc" -eq 124 ]]; then
        FAILURES+=("bgpkit-parser timed out on $label")
    elif [[ "$rc" -ge 128 ]]; then
        FAILURES+=("bgpkit-parser crashed or was killed on $label with rc=$rc")
    elif [[ "$STRICT" == "1" && "$mode" == "full" && "$rc" -ne 0 ]]; then
        FAILURES+=("bgpkit-parser returned non-zero on malformed full corpus in strict mode")
    elif [[ "$STRICT" == "1" && "$mode" == "fatal" && "$rc" -eq 0 ]]; then
        FAILURES+=("bgpkit-parser accepted fatal-tail file in strict mode: $label")
    fi
}

run_one "bgp-valid.mrt" "$CORPUS_DIR/bgp-valid.mrt" valid
run_one "bgp-corpus.mrt" "$CORPUS_DIR/bgp-corpus.mrt" full

for fatal in "$CORPUS_DIR"/bgp-fatal/*.mrt; do
    [[ -e "$fatal" ]] || continue
    run_one "bgp-fatal/$(basename "$fatal")" "$fatal" fatal
done

BASELINE=/usr/local/share/mrtgen/parser-baseline.json
mapfile -t KNOWN_STOPS < <(jq -r '."bgpkit-parser".recovery_known_stop[]' "$BASELINE")
is_known_stop() {
    local want="$1" item
    for item in "${KNOWN_STOPS[@]}"; do [[ "$item" == "$want" ]] && return 0; done
    return 1
}

for recovery in "$CORPUS_DIR"/recovery/*.mrt; do
    [[ -e "$recovery" ]] || continue
    kind="$(basename "$recovery" .mrt)"
    out="/tmp/recovery_${kind}.out"
    err="/tmp/recovery_${kind}.err"
    set +e
    timeout 30s bgpkit-parser "$recovery" >"$out" 2>"$err"
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]] && grep -q '198\.51\.100\.128/25' "$out"; then
        echo "recovery/$kind: PASS sentinel reached"
        if is_known_stop "$kind"; then
            FAILURES+=("bgpkit-parser unexpected recovery pass; remove stale baseline: $kind")
        fi
    elif is_known_stop "$kind" && [[ "$STRICT" != 1 ]]; then
        echo "recovery/$kind: KNOWN-STOP"
    else
        FAILURES+=("bgpkit-parser failed to reach recovery sentinel after $kind (rc=$rc)")
    fi
done

if ((${#FAILURES[@]})); then
    echo "failures:" >&2
    for failure in "${FAILURES[@]}"; do
        echo "  - $failure" >&2
    done
    exit 1
fi
