#!/usr/bin/env python3
import json
import os
import sys
import traceback
from pathlib import Path

from mrtparse import Reader

sys.path.insert(0, str(Path(__file__).resolve().parent))
import routes_mrtparse_check

STRICT = os.environ.get("MRTGEN_STRICT") == "1"
BASELINE_PATH = Path("/usr/local/share/mrtgen/parser-baseline.json")


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_file(path):
    count = 0
    entry_errors = 0
    try:
        for entry in Reader(str(path)):
            count += 1
            if getattr(entry, "err", None):
                entry_errors += 1
        return {
            "ok": True,
            "records_seen": count,
            "entry_errors": entry_errors,
            "exception": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "records_seen": count,
            "entry_errors": entry_errors,
            "exception": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(limit=4),
        }


def report(name, result, manifest=None):
    expected = ""
    if manifest is not None:
        counts = manifest["counts"]
        expected = f" manifest={counts['valid']} valid/{counts['skip']} skip/{counts['abort']} abort"
    status = "ok" if result["ok"] else "error"
    print(
        f"{name}: {status}; records_seen={result['records_seen']}; "
        f"entry_errors={result['entry_errors']};{expected}"
    )
    if result["exception"]:
        print(f"{name}: {result['exception']}", file=sys.stderr)


def main():
    corpus_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "/corpus")
    failures = []

    valid = corpus_dir / "bgp-valid.mrt"
    valid_manifest = load_manifest(corpus_dir / "bgp-valid.mrt.manifest.json")
    valid_result = parse_file(valid)
    report("bgp-valid.mrt", valid_result, valid_manifest)
    expected_valid = len(valid_manifest["records"])
    if not valid_result["ok"] or valid_result["records_seen"] != expected_valid or valid_result["entry_errors"]:
        failures.append(
            f"mrtparse valid-only count mismatch: expected {expected_valid}, "
            f"saw {valid_result['records_seen']} with {valid_result['entry_errors']} entry errors"
        )

    full = corpus_dir / "bgp-corpus.mrt"
    full_manifest = load_manifest(corpus_dir / "bgp-corpus.mrt.manifest.json")
    full_result = parse_file(full)
    report("bgp-corpus.mrt", full_result, full_manifest)
    if STRICT and (not full_result["ok"] or full_result["records_seen"] == 0):
        failures.append("mrtparse failed the BGP-family malformed corpus in strict mode")

    fatal_dir = corpus_dir / "bgp-fatal"
    for fatal in sorted(fatal_dir.glob("*.mrt")):
        fatal_manifest = load_manifest(fatal.with_suffix(fatal.suffix + ".manifest.json"))
        result = parse_file(fatal)
        report(f"bgp-fatal/{fatal.name}", result, fatal_manifest)
        if STRICT and result["ok"] and result["records_seen"] >= len(fatal_manifest["records"]):
            failures.append(f"mrtparse did not stop before abort tail: {fatal.name}")

    baseline = load_manifest(BASELINE_PATH) if BASELINE_PATH.exists() else {"mrtparse": {"recovery_known_stop": []}}
    known_stop = set(baseline.get("mrtparse", {}).get("recovery_known_stop", []))
    seen_known = set()
    for recovery in sorted((corpus_dir / "recovery").glob("*.mrt")):
        kind = recovery.stem
        result = parse_file(recovery)
        recovered = result["ok"] and result["records_seen"] >= 2
        if recovered:
            print(f"recovery/{kind}: PASS sentinel reached")
            if kind in known_stop:
                failures.append(f"mrtparse unexpected recovery pass; remove stale baseline: {kind}")
        elif kind in known_stop and not STRICT:
            seen_known.add(kind)
            print(f"recovery/{kind}: KNOWN-STOP records_seen={result['records_seen']}")
        else:
            failures.append(f"mrtparse failed to reach recovery sentinel after {kind}")
    stale = known_stop - seen_known
    if stale:
        failures.append(f"mrtparse stale recovery baseline entries: {sorted(stale)}")

    # Route-list mode: field-level cross-check of every --routes option.
    if (corpus_dir / "routes-td2.mrt").exists():
        failures.extend(routes_mrtparse_check.check(corpus_dir))
    else:
        print("routes-td2.mrt absent; route-list validation skipped")

    if failures:
        print("failures:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
