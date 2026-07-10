#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def parse_types(value):
    try:
        return {int(part, 0) for part in value.split(",") if part}
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main():
    parser = argparse.ArgumentParser(description="Copy selected MRT records into a manifest-preserving subcorpus")
    parser.add_argument("--types", type=parse_types, help="comma-separated MRT type numbers to retain; default keeps all")
    parser.add_argument("--expect", choices=("valid", "skip", "abort"), help="retain only this manifest expectation")
    parser.add_argument("--only-kinds", default="", help="comma-separated manifest record kinds to retain")
    parser.add_argument("--drop-kinds", default="", help="comma-separated manifest record kinds to exclude")
    parser.add_argument("input_mrt", type=Path)
    parser.add_argument("input_manifest", type=Path)
    parser.add_argument("output_mrt", type=Path)
    parser.add_argument("output_manifest", type=Path)
    args = parser.parse_args()

    data = args.input_mrt.read_bytes()
    manifest = json.loads(args.input_manifest.read_text(encoding="utf-8"))

    out = bytearray()
    records = []
    counts = {"valid": 0, "skip": 0, "abort": 0}

    drop_kinds = {part for part in args.drop_kinds.split(",") if part}
    only_kinds = {part for part in args.only_kinds.split(",") if part}

    for record in manifest["records"]:
        if args.types is not None and int(record["mrt_type"]) not in args.types:
            continue
        if record["kind"] in drop_kinds:
            continue
        if only_kinds and record["kind"] not in only_kinds:
            continue
        if args.expect is not None and record["expect"] != args.expect:
            continue
        start = int(record["offset"])
        end = start + int(record["size"])
        new_record = dict(record)
        new_record["index"] = len(records)
        new_record["offset"] = len(out)
        records.append(new_record)
        out.extend(data[start:end])
        counts[new_record["expect"]] += 1

    manifest["file_size"] = len(out)
    manifest["counts"] = counts
    manifest["records"] = records

    args.output_mrt.parent.mkdir(parents=True, exist_ok=True)
    args.output_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.output_mrt.write_bytes(out)
    args.output_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(
        f"wrote {args.output_mrt} ({len(out)} bytes, {len(records)} records: "
        f"{counts['valid']} valid, {counts['skip']} skip, {counts['abort']} abort)"
    )


if __name__ == "__main__":
    raise SystemExit(main())
