#!/usr/bin/env bash
set -Eeuo pipefail

CORPUS_DIR="${1:-/corpus}"
STRICT="${MRTGEN_STRICT:-0}"
FAILURES=()
KNOWN_CRASHES=()

# Upstream bgpdump bugs that abort the whole process. Matched against stderr
# when bgpdump dies on a signal: a hit is reported as a visible KNOWN-CRASH
# without failing the run; any other crash signature still fails hard.
# Keep this list tight so new crashes stay loud.
#
# bgpdump_lib.c process_one_attr() handles a duplicate single-valued
# attribute with assert() instead of RFC 7606 treat-as-withdraw; the
# skip-class record invalid_attr_duplicate_origin_len4 (duplicate ORIGIN)
# triggers SIGABRT, leaving every later record in the file unvalidated.
# Same assert family as CAIDA/bgpstream#62 (!attr->community).
KNOWN_CRASH_RE="Assertion \`attr->origin == -1' failed"

run_one() {
    local label="$1"
    local path="$2"
    local mode="$3"
    local out="/tmp/${label//\//_}.out"
    local err="/tmp/${label//\//_}.err"
    local rc

    set +e
    timeout 30s bgpdump -m "$path" >"$out" 2>"$err"
    rc=$?
    set -e

    local lines stderr_bytes
    lines="$(wc -l <"$out")"
    stderr_bytes="$(wc -c <"$err")"
    echo "$label: rc=$rc; output_lines=$lines; stderr_bytes=$stderr_bytes"

    if [[ "$mode" == "valid" ]]; then
        if [[ "$rc" -ne 0 || "$lines" -eq 0 ]]; then
            FAILURES+=("bgpdump failed to parse the valid-only corpus")
        fi
        return
    fi

    if [[ "$rc" -eq 124 ]]; then
        FAILURES+=("bgpdump timed out on $label")
    elif [[ "$rc" -ge 128 ]]; then
        if grep -qF "$KNOWN_CRASH_RE" "$err"; then
            echo "$label: KNOWN-CRASH (upstream bgpdump bug; records after the abort point are unvalidated)"
            echo "    $(grep -m1 -F "$KNOWN_CRASH_RE" "$err")"
            KNOWN_CRASHES+=("$label")
        else
            FAILURES+=("bgpdump crashed or was killed on $label with rc=$rc")
        fi
    elif [[ "$STRICT" == "1" && "$mode" == "full" && "$rc" -ne 0 ]]; then
        FAILURES+=("bgpdump returned non-zero on malformed full corpus in strict mode")
    elif [[ "$STRICT" == "1" && "$mode" == "fatal" && "$rc" -eq 0 ]]; then
        FAILURES+=("bgpdump accepted fatal-tail file in strict mode: $label")
    fi
}

run_one "bgp-valid.mrt" "$CORPUS_DIR/bgp-valid.mrt" valid
run_one "bgp-corpus.mrt" "$CORPUS_DIR/bgp-corpus.mrt" full

for fatal in "$CORPUS_DIR"/bgp-fatal/*.mrt; do
    [[ -e "$fatal" ]] || continue
    run_one "bgp-fatal/$(basename "$fatal")" "$fatal" fatal
done

# The full corpus dies at the known duplicate-ORIGIN assert, so the records
# after it only get coverage through these variants with that record removed.
if [[ -e "$CORPUS_DIR/bgpdump-corpus.mrt" ]]; then
    run_one "bgpdump-corpus.mrt" "$CORPUS_DIR/bgpdump-corpus.mrt" full
    for fatal in "$CORPUS_DIR"/bgpdump-fatal/*.mrt; do
        [[ -e "$fatal" ]] || continue
        run_one "bgpdump-fatal/$(basename "$fatal")" "$fatal" fatal
    done
else
    echo "bgpdump-corpus.mrt missing: post-abort records have no bgpdump coverage (regenerate the corpus)"
fi

if ((${#KNOWN_CRASHES[@]})); then
    echo "known upstream bgpdump crashes hit (improvement backlog, not failing the run):"
    echo "  - assert on duplicate ORIGIN attribute in process_one_attr (bgpdump_lib.c),"
    echo "    should be RFC 7606 treat-as-withdraw; files: ${KNOWN_CRASHES[*]}"
fi

if ((${#FAILURES[@]})); then
    echo "failures:" >&2
    for failure in "${FAILURES[@]}"; do
        echo "  - $failure" >&2
    done
    exit 1
fi
