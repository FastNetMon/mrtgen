#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${MRTGEN_PARSER_CORPUS_DIR:-$ROOT/target/parser-harness/corpus}"
IMAGE_PREFIX="${MRTGEN_DOCKER_IMAGE_PREFIX:-mrtgen-parser}"
STRICT=0
PARSERS=()

usage() {
    cat <<'EOF'
Usage: tests/parsers/run-docker.sh [--strict] [PARSER...]

Build isolated Docker images for external MRT parsers, generate mrtgen corpus
files under target/parser-harness/corpus, and run each parser over the mounted
read-only corpus directory.

Parsers:
  mrtparse       Python mrtparse package
  bgpdump        RIPE NCC bgpdump utility
  bgpkit-parser  Rust BGPKIT Parser CLI
  fastnetmon     FastNetMon's BGP FlowSpec decoder (pinned commit), fed the
                 manifests' flowspec NLRI bytes; reports the decoder's known
                 gaps as visible KNOWN-FAIL entries without failing the run

Options:
  --strict   Make malformed-corpus and fatal-tail parser errors fail the run.
             By default only valid-corpus failures, timeouts, and process
             crashes fail the run; malformed-corpus behavior is reported.
  -h, --help Show this help.

Environment:
  MRTGEN_PARSER_CORPUS_DIR    Override generated corpus directory.
  MRTGEN_DOCKER_IMAGE_PREFIX  Override Docker image name prefix.
  MRTGEN_APT_HTTP_PROXY       Optional APT HTTP proxy for Debian-based images,
                              e.g. http://10.255.255.10:3142
EOF
}

while (($#)); do
    case "$1" in
        --strict)
            STRICT=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            PARSERS+=("$1")
            ;;
    esac
    shift
done

if ((${#PARSERS[@]} == 0)); then
    PARSERS=(mrtparse bgpdump bgpkit-parser fastnetmon)
fi

FAILURES=()

mkdir -p "$OUT_DIR/fatal"

echo "Generating parser harness corpora in $OUT_DIR"
cargo run --quiet -- \
    --out "$OUT_DIR/valid.mrt" \
    --manifest "$OUT_DIR/valid.mrt.manifest.json" \
    --no-skip \
    --no-combo \
    --no-attr-errors
cargo run --quiet -- \
    --out "$OUT_DIR/corpus.mrt" \
    --manifest "$OUT_DIR/corpus.mrt.manifest.json" \
    --fatal-dir "$OUT_DIR/fatal"

echo "Generating route-list files (all --routes options) for field-level validation"
cargo run --quiet -- \
    --routes "$ROOT/tests/parsers/routes-all-options.json" \
    --out "$OUT_DIR/routes-td2.mrt"
cargo run --quiet -- \
    --routes "$ROOT/tests/parsers/routes-all-options.json" \
    --routes-format bgp4mp \
    --out "$OUT_DIR/routes-bgp4mp.mrt"
cargo run --quiet -- \
    --routes "$ROOT/tests/parsers/routes-flowspec.json" \
    --routes-format bgp4mp \
    --out "$OUT_DIR/routes-flowspec.mrt"
cargo run --quiet -- \
    --routes "$ROOT/tests/parsers/routes-flowspec-fnm.json" \
    --routes-format bgp4mp \
    --out "$OUT_DIR/routes-flowspec-fnm.mrt"
cargo run --quiet -- \
    --routes "$ROOT/tests/parsers/routes-flowspec-absurd.json" \
    --routes-format bgp4mp \
    --out "$OUT_DIR/routes-flowspec-absurd.mrt"

echo "Creating BGP-family subcorpora for parsers that do not support IGP MRT types"
python3 "$ROOT/tests/parsers/slice-corpus.py" \
    --types 12,13,16,17 \
    "$OUT_DIR/valid.mrt" \
    "$OUT_DIR/valid.mrt.manifest.json" \
    "$OUT_DIR/bgp-valid.mrt" \
    "$OUT_DIR/bgp-valid.mrt.manifest.json"
python3 "$ROOT/tests/parsers/slice-corpus.py" \
    --types 12,13,16,17 \
    "$OUT_DIR/corpus.mrt" \
    "$OUT_DIR/corpus.mrt.manifest.json" \
    "$OUT_DIR/bgp-corpus.mrt" \
    "$OUT_DIR/bgp-corpus.mrt.manifest.json"
mkdir -p "$OUT_DIR/bgp-fatal"
for fatal in "$OUT_DIR"/fatal/*.mrt; do
    name="$(basename "$fatal")"
    python3 "$ROOT/tests/parsers/slice-corpus.py" \
        --types 12,13,16,17 \
        "$fatal" \
        "$fatal.manifest.json" \
        "$OUT_DIR/bgp-fatal/$name" \
        "$OUT_DIR/bgp-fatal/$name.manifest.json"
done

# bgpdump aborts on the duplicate-ORIGIN record (upstream assert, reported as
# KNOWN-CRASH by its runner) and never reaches anything after it; also build
# variants without that record so the rest of the corpus keeps coverage.
python3 "$ROOT/tests/parsers/slice-corpus.py" \
    --types 12,13,16,17 \
    --drop-kinds invalid_attr_duplicate_origin_len4 \
    "$OUT_DIR/corpus.mrt" \
    "$OUT_DIR/corpus.mrt.manifest.json" \
    "$OUT_DIR/bgpdump-corpus.mrt" \
    "$OUT_DIR/bgpdump-corpus.mrt.manifest.json"
mkdir -p "$OUT_DIR/bgpdump-fatal"
for fatal in "$OUT_DIR"/fatal/*.mrt; do
    name="$(basename "$fatal")"
    python3 "$ROOT/tests/parsers/slice-corpus.py" \
        --types 12,13,16,17 \
        --drop-kinds invalid_attr_duplicate_origin_len4 \
        "$fatal" \
        "$fatal.manifest.json" \
        "$OUT_DIR/bgpdump-fatal/$name" \
        "$OUT_DIR/bgpdump-fatal/$name.manifest.json"
done

for parser in "${PARSERS[@]}"; do
    dockerfile="$ROOT/tests/parsers/docker/$parser.Dockerfile"
    if [[ ! -f "$dockerfile" ]]; then
        echo "error: unknown parser '$parser' (missing $dockerfile)" >&2
        exit 2
    fi

    image="$IMAGE_PREFIX-$parser:latest"
    echo
    echo "Building $image"
    if ! docker build \
        --build-arg "APT_HTTP_PROXY=${MRTGEN_APT_HTTP_PROXY:-}" \
        -f "$dockerfile" \
        -t "$image" \
        "$ROOT"; then
        FAILURES+=("$parser: Docker image build failed")
        continue
    fi

    echo "Running $parser against mounted corpus"
    if ! docker run --rm \
        -e "MRTGEN_STRICT=$STRICT" \
        -v "$OUT_DIR:/corpus:ro" \
        "$image" /corpus; then
        FAILURES+=("$parser: parser runner failed")
    fi
done

if ((${#FAILURES[@]})); then
    echo
    echo "parser harness failures:" >&2
    for failure in "${FAILURES[@]}"; do
        echo "  - $failure" >&2
    done
    exit 1
fi
