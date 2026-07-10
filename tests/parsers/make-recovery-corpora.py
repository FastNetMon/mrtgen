#!/usr/bin/env python3
"""Build one [skip case, valid sentinel] corpus per recoverable error."""

import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_mrt", type=Path)
    ap.add_argument("input_manifest", type=Path)
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--types", default="12,13,16,17")
    ap.add_argument("--sentinel", default="bgp4mp_message_update")
    args = ap.parse_args()

    allowed = {int(x) for x in args.types.split(",") if x}
    raw = args.input_mrt.read_bytes()
    source = json.loads(args.input_manifest.read_text(encoding="utf-8"))
    by_kind = {r["kind"]: r for r in source["records"]}
    sentinel = by_kind.get(args.sentinel)
    if sentinel is None:
        raise SystemExit(f"sentinel kind not found: {args.sentinel}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    def record_bytes(r):
        start = int(r["offset"])
        return raw[start:start + int(r["size"])]

    made = 0
    for damaged in source["records"]:
        if damaged["expect"] != "skip" or int(damaged["mrt_type"]) not in allowed:
            continue
        out = bytearray()
        records = []
        for original in (damaged, sentinel):
            item = dict(original)
            item["index"] = len(records)
            item["offset"] = len(out)
            records.append(item)
            out.extend(record_bytes(original))
        manifest = {
            "generator": source["generator"],
            "generator_version": source["generator_version"],
            "profile": source.get("profile", "standard"),
            "file_size": len(out),
            "counts": {"valid": 1, "skip": 1, "abort": 0},
            "records": records,
            "recovery": {"damaged_kind": damaged["kind"], "sentinel_kind": sentinel["kind"]},
        }
        mrt = args.output_dir / f"{damaged['kind']}.mrt"
        mrt.write_bytes(out)
        mrt.with_suffix(".mrt.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        made += 1
    print(f"wrote {made} recovery corpora to {args.output_dir}")


if __name__ == "__main__":
    main()
