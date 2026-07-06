#!/usr/bin/env python3
"""Cross-validate mrtgen's FlowSpec NLRI encoder against FastNetMon's decoder.

For every flowspec record in routes-flowspec-fnm.mrt.manifest.json (focused
per-feature cases) and routes-flowspec.mrt.manifest.json (broad corpus) this
feeds the manifest's nlri_hex to flow_spec_decode_nlri_value() from a pinned
FastNetMon checkout (via the fastnetmon_flowspec_shim binary) and compares
FastNetMon's decoded JSON with the rule the manifest promises.

FastNetMon's decoder covers a deliberate subset of RFC 8955 — IPv4 only,
equality operators only, no common-port/ICMP/DSCP components. Rules outside
that envelope are expected to be refused and are reported as KNOWN-FAIL: they
never fail the run, but each one is listed with its reason and tallied in a
"decoder gaps" section at the end so the upstream backlog stays visible. A
KNOWN-FAIL that suddenly decodes is reported as UNEXPECTED-PASS (FastNetMon
gained support; update the model here) and fails the run in strict mode only.
Rules FastNetMon does decode are additionally scanned for silent degradations
(e.g. dropped ece/cwr TCP flags) which are reported as notes.

Usable standalone:
    fastnetmon_flowspec_check.py <corpus-dir> [shim-path]
Environment: MRTGEN_STRICT=1, FASTNETMON_SHIM=<path>.
"""
import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

# Flag-name tables, mirroring src/flowspec.rs.
TCP_FLAG_BITS = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08,
                 "ack": 0x10, "urg": 0x20, "ece": 0x40, "cwr": 0x80}
FRAGMENT_BITS = {"dont-fragment": 0x01, "is-fragment": 0x02,
                 "first-fragment": 0x04, "last-fragment": 0x08}

# FastNetMon's rendering of decoded rules (bgp_protocol_flow_spec.cpp,
# encode_flow_spec_to_json_raw): protocol names are IANA names lowercased;
# TCP flagsets are joined "|" in the fixed order below; fragment flags are
# emitted per operator item in decoder order (last, first, is, dont).
FNM_PROTOCOL_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp"}
FNM_TCP_ORDER = [("syn", 0x02), ("ack", 0x10), ("fin", 0x01),
                 ("rst", 0x04), ("urgent", 0x20), ("push", 0x08)]
FNM_FRAG_ORDER = [("last-fragment", 0x08), ("first-fragment", 0x04),
                  ("is-fragment", 0x02), ("dont-fragment", 0x01)]
# Decode-only shim: the rule's action/uuid never travel in the NLRI.
IGNORED_KEYS = {"action_type", "action", "uuid"}

NUMERIC_KEYS = ("protocol", "port", "dst_port", "src_port", "icmp_type",
                "icmp_code", "packet_length", "dscp", "flow_label")
LABEL_ORDER = ("afi", "dst_prefix", "src_prefix", "protocol", "port",
               "dst_port", "src_port", "icmp_type", "icmp_code", "tcp_flags",
               "packet_length", "dscp", "fragment", "flow_label")


class CheckerLimitation(Exception):
    """The case is outside what this checker can model (not a decoder gap)."""


def flow_v6(flow):
    p = flow.get("dst_prefix") or flow.get("src_prefix")
    if p:
        return ":" in p
    return flow.get("afi") == "ipv6"


def num_value(item):
    """A numeric match item that FastNetMon can decode: int or {"eq": v}."""
    return item["eq"] if isinstance(item, dict) else item


def bitmask_bits(item, table):
    flags = item["flags"]
    if isinstance(flags, list):
        return sum(table[n.lower()] for n in flags)
    return flags


def classify(flow, comp_len):
    """(gates, gaps) FastNetMon@09bab48 hits on this rule.

    Gaps are refusals inside flow_spec_decode_nlri_value — the shim observes
    them directly. Gates fire earlier, in the MP_REACH attribute parser the
    shim bypasses, so for gated rules the shim's verdict is informational
    only (a bare "protocol: [17]" IPv6 rule is byte-identical to its IPv4
    twin and decodes fine; the real daemon still refuses it at the AFI check).
    """
    gates, gaps = [], []
    if flow_v6(flow):
        gates.append("IPv6 FlowSpec (RFC 8956): MP_REACH parser accepts only AFI 1 / SAFI 133")
    if comp_len >= 240:
        gates.append("2-byte NLRI length form (components >= 240 bytes): 'We do not support for 2 byte NLRI length encoding yet'")
    if flow.get("port"):
        gaps.append("common port component (type 4): 'We do not support common ports'")
    if flow.get("icmp_type") or flow.get("icmp_code"):
        gaps.append("ICMP type/code components (types 7/8): no decode branch")
    if flow.get("dscp"):
        gaps.append("DSCP component (type 11): no decode branch")
    if flow.get("flow_label"):
        gaps.append("Flow Label component (type 13): no decode branch")
    for key in NUMERIC_KEYS:
        if any(isinstance(i, dict) and set(i) != {"eq"} for i in flow.get(key) or []):
            gaps.append("comparison operators (lt/le/gt/ge/range): decoder accepts equality only")
            break
    for key in ("tcp_flags", "fragment"):
        if any(i.get("not") for i in flow.get(key) or []):
            gaps.append(f"{key} NOT bit: bitmask ops are parsed as numeric ops, so NOT (0x02) aliases greater-than and is rejected")
    if any(bitmask_bits(i, TCP_FLAG_BITS) > 0xFF for i in flow.get("tcp_flags") or []):
        gaps.append("2-byte tcp_flags bitmask: 'We do not support two byte encoded tcp fields'")
    return gates, gaps


def degradation_notes(flow):
    """Lossy-but-accepted decoder behavior on rules within the envelope."""
    notes = []
    protos = [num_value(i) for i in flow.get("protocol") or []]
    tcp_items = flow.get("tcp_flags") or []
    if tcp_items and 6 not in protos:
        notes.append("tcp_flags decoded but omitted from FastNetMon's JSON (rendered only when protocol tcp is present)")
    if any(bitmask_bits(i, TCP_FLAG_BITS) & 0xC0 for i in tcp_items):
        notes.append("ece/cwr TCP flag bits silently dropped by the decoder")
    if any(i.get("match") for i in tcp_items + (flow.get("fragment") or [])):
        notes.append("bitmask match ('m') bit accepted but its exact-match semantics are discarded")
    return notes


def expected_flow(flow):
    """FastNetMon's JSON for this rule, assuming classify() found no gaps."""
    exp = {}
    if flow.get("dst_prefix"):
        exp["destination_prefix"] = flow["dst_prefix"]
    if flow.get("src_prefix"):
        exp["source_prefix"] = flow["src_prefix"]
    protos = [num_value(i) for i in flow.get("protocol") or []]
    if protos:
        unknown = [p for p in protos if p not in FNM_PROTOCOL_NAMES]
        if unknown:
            raise CheckerLimitation(f"protocol(s) {unknown} missing from this checker's FNM_PROTOCOL_NAMES table")
        exp["protocols"] = [FNM_PROTOCOL_NAMES[p] for p in protos]
    for key, out in (("dst_port", "destination_ports"), ("src_port", "source_ports"),
                     ("packet_length", "packet_lengths")):
        values = [num_value(i) for i in flow.get(key) or []]
        if values:
            exp[out] = values
    frags = []
    for item in flow.get("fragment") or []:
        bits = bitmask_bits(item, FRAGMENT_BITS)
        if bits == 0:
            frags.append("not-a-fragment")  # ExaBGP-ism, see decoder comment
        else:
            frags += [name for name, bit in FNM_FRAG_ORDER if bits & bit]
    if frags:
        exp["fragmentation_flags"] = frags
    if 6 in protos:
        flagsets = []
        for item in flow.get("tcp_flags") or []:
            bits = bitmask_bits(item, TCP_FLAG_BITS)
            joined = "|".join(name for name, bit in FNM_TCP_ORDER if bits & bit)
            if joined:  # items reduced to nothing (ece/cwr only) are dropped
                flagsets.append(joined)
        if flagsets:
            exp["tcp_flags"] = flagsets
    return exp


def diff_flows(exp, got):
    got = {k: v for k, v in got.items() if k not in IGNORED_KEYS}
    diffs = []
    for key in sorted(set(exp) | set(got)):
        e, g = exp.get(key), got.get(key)
        if e is not None and g is not None:
            if key in ("destination_prefix", "source_prefix"):
                if ipaddress.ip_network(e, strict=False) == ipaddress.ip_network(g, strict=False):
                    continue
            elif key == "fragmentation_flags":
                if sorted(e) == sorted(g):
                    continue
        if e == g:
            continue
        diffs.append(f"{key}: expected {e!r}, got {g!r}")
    return diffs


def split_nlri(nlri):
    """Strip the RFC 8955 section 4.1 length octet(s) off an NLRI."""
    if nlri[0] >= 0xF0:
        return ((nlri[0] & 0x0F) << 8) | nlri[1], nlri[2:]
    return nlri[0], nlri[1:]


# Component type codes and the v6-only ones (RFC 8955 section 4.2 / RFC 8956).
KNOWN_TYPES = set(range(1, 14))
PREFIX_TYPES = {1, 2}
V6_ONLY_TYPES = {13: "flow_label"}


def first_violation(data, v6):
    """First RFC 8955/8956 structural violation in a component list, or None
    if it is well formed. Independent of FastNetMon: it decides what an
    RFC-compliant decoder *should* do (refuse when this returns a reason), so
    accepting such an NLRI is leniency. Types must be known, strictly
    ascending and unique; operator lists must terminate within the buffer;
    prefixes must fit their declared length; v6-only components must not
    appear in an IPv4 rule."""
    pos, last, seen = 0, 0, set()
    max_bits = 128 if v6 else 32
    while pos < len(data):
        ctype = data[pos]
        pos += 1
        if ctype not in KNOWN_TYPES:
            return f"unknown component type {ctype}"
        if ctype in seen:
            return f"duplicate component type {ctype}"
        if ctype < last:
            return f"component type {ctype} after {last} (not ascending)"
        if ctype in V6_ONLY_TYPES and not v6:
            return f"{V6_ONLY_TYPES[ctype]} (type {ctype}) in an IPv4 rule"
        seen.add(ctype)
        last = ctype
        if ctype in PREFIX_TYPES:
            if pos >= len(data):
                return f"truncated prefix (type {ctype}): no length octet"
            bits = data[pos]
            pos += 1
            if v6:
                if pos >= len(data):
                    return f"truncated prefix (type {ctype}): no offset octet"
                pos += 1  # IPv6 offset octet
            if bits > max_bits:
                return f"prefix length {bits} exceeds {max_bits} (type {ctype})"
            nbytes = (bits + 7) // 8
            if pos + nbytes > len(data):
                return f"truncated prefix address (type {ctype})"
            pos += nbytes
        else:  # numeric / bitmask operator list, end bit terminated
            while True:
                if pos >= len(data):
                    return f"truncated operator list for type {ctype}"
                op = data[pos]
                pos += 1
                vlen = 1 << ((op >> 4) & 0x3)
                if pos + vlen > len(data):
                    return f"truncated {vlen}-byte value for type {ctype}"
                pos += vlen
                if op & 0x80:  # end-of-list
                    break
    return None


def case_label(flow):
    parts = [k if k != "afi" else flow["afi"] for k in LABEL_ORDER if flow.get(k)]
    if flow.get("raw_components_hex"):
        parts.append(f"raw:{flow['raw_components_hex']}")
    return "+".join(parts) or "empty"


def stderr_tail(proc, limit=3):
    lines = [l for l in proc.stderr.splitlines() if l.strip()]
    return "; ".join(lines[-limit:])


class Report:
    def __init__(self, strict, shim):
        self.strict, self.shim = strict, shim
        self.counts = {"PASS": 0, "FAIL": 0, "KNOWN-FAIL": 0, "UNEXPECTED-PASS": 0,
                       "HOSTILE-OK": 0, "KNOWN-LENIENT": 0}
        self.failures = []          # messages that always fail the run
        self.unexpected = []        # fail the run in strict mode only
        self.gap_tally = {}         # reason -> [case refs]
        self.note_tally = {}        # note -> [case refs]
        self.hostile_tally = {}     # observation -> [case refs]
        self.lenient_tally = {}     # accepted-violation -> [case refs]

    def case(self, ref, verdict, label, detail=""):
        self.counts[verdict] += 1
        pad = {"PASS": "PASS           ", "FAIL": "FAIL           ",
               "KNOWN-FAIL": "KNOWN-FAIL     ", "UNEXPECTED-PASS": "UNEXPECTED-PASS",
               "HOSTILE-OK": "HOSTILE-OK     ", "KNOWN-LENIENT": "KNOWN-LENIENT  "}[verdict]
        print(f"  {pad} {ref} {label}{' — ' + detail if detail else ''}")

    def tally(self, bucket, reasons, ref):
        for reason in reasons:
            bucket.setdefault(reason, []).append(ref)

    def check_record(self, ref, det):
        flow = det["flowspec"]
        label = case_label(flow)
        nlri_hex = det.get("nlri_hex")
        if not nlri_hex:
            self.failures.append(f"{ref}: nlri_hex missing from manifest details")
            self.case(ref, "FAIL", label, "nlri_hex missing from manifest details")
            return
        comp_len, value = split_nlri(bytes.fromhex(nlri_hex))
        if comp_len != len(value):
            self.failures.append(f"{ref}: NLRI length octet says {comp_len}, payload is {len(value)} bytes")
            self.case(ref, "FAIL", label, "NLRI length octet vs payload mismatch")
            return

        gates, gaps = classify(flow, comp_len)
        try:
            proc = subprocess.run([self.shim, value.hex()], capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            self.failures.append(f"{ref}: decoder shim timed out")
            self.case(ref, "FAIL", label, "decoder shim timed out")
            return

        if proc.returncode not in (0, 1):
            msg = f"decoder shim crashed (rc={proc.returncode}): {stderr_tail(proc)}"
            self.failures.append(f"{ref}: {msg}")
            self.case(ref, "FAIL", label, msg)
            return

        if flow.get("raw_components_hex"):
            # Hostile NLRI: the contract is "must not crash". A structurally
            # malformed NLRI additionally *should* be refused (RFC 8955 defers
            # to RFC 7606); accepting one is leniency, reported as KNOWN-LENIENT
            # so it stays a visible upstream backlog item without failing.
            decoded = proc.returncode == 0
            warn = stderr_tail(proc, limit=1)
            violation = first_violation(value, flow_v6(flow))
            if violation is None:
                # The raw append happens to be well formed; either outcome is fine.
                outcome = "decoded" if decoded else "refused"
                self.tally(self.hostile_tally, [f"well-formed raw NLRI {outcome}"], ref)
                self.case(ref, "HOSTILE-OK", label, f"{outcome} (well-formed raw append)")
            elif not decoded:
                self.tally(self.hostile_tally, [f"refused: {violation}"], ref)
                self.case(ref, "HOSTILE-OK", label, f"refused (RFC-compliant) — {violation}")
            else:
                self.tally(self.lenient_tally, [violation], ref)
                diag = warn if warn else "no diagnostic emitted"
                self.case(ref, "KNOWN-LENIENT", label, f"accepted despite {violation} ({diag})")
            return

        if gates:
            # Refused by the MP_REACH parser before the NLRI decoder runs;
            # the shim only proves the decoder does not crash on the bytes.
            self.tally(self.gap_tally, gates + gaps, ref)
            self.case(ref, "KNOWN-FAIL", label, "; ".join(gates + gaps))
            return
        if gaps:
            self.tally(self.gap_tally, gaps, ref)
            if proc.returncode == 1:
                self.case(ref, "KNOWN-FAIL", label, "; ".join(gaps))
            else:
                msg = "decoded despite modeled gap — FastNetMon may have gained support; update classify() and the pinned commit"
                self.unexpected.append(f"{ref}: {msg} ({'; '.join(gaps)})")
                self.case(ref, "UNEXPECTED-PASS", label, msg)
            return

        # Inside the supported envelope: must decode and match field-by-field.
        if proc.returncode != 0:
            msg = f"FastNetMon refused a rule modeled as supported: {stderr_tail(proc)}"
            self.failures.append(f"{ref}: {msg}")
            self.case(ref, "FAIL", label, msg)
            return
        try:
            got = json.loads(proc.stdout)["flow"]
            exp = expected_flow(flow)
        except CheckerLimitation as e:
            self.failures.append(f"{ref}: checker limitation: {e}")
            self.case(ref, "FAIL", label, f"checker limitation: {e}")
            return
        except (json.JSONDecodeError, KeyError) as e:
            self.failures.append(f"{ref}: bad shim output: {e}: {proc.stdout!r}")
            self.case(ref, "FAIL", label, f"bad shim output: {e}")
            return
        diffs = diff_flows(exp, got)
        if diffs:
            msg = "; ".join(diffs)
            self.failures.append(f"{ref}: {msg}")
            self.case(ref, "FAIL", label, msg)
            return
        notes = degradation_notes(flow)
        self.tally(self.note_tally, notes, ref)
        self.case(ref, "PASS", label)

    def summarize(self):
        print()
        if self.gap_tally:
            print("Known FastNetMon decoder gaps hit (upstream improvement backlog):")
            for reason, refs in sorted(self.gap_tally.items(), key=lambda kv: -len(kv[1])):
                print(f"  {len(refs):2}x {reason}")
                print(f"       cases: {', '.join(refs)}")
        if self.note_tally:
            print("Silent degradations on rules FastNetMon does decode:")
            for note, refs in sorted(self.note_tally.items(), key=lambda kv: -len(kv[1])):
                print(f"  {len(refs):2}x {note}")
                print(f"       cases: {', '.join(refs)}")
        if self.lenient_tally:
            print("FastNetMon accepts these malformed NLRIs a compliant decoder would refuse (leniency backlog):")
            for violation, refs in sorted(self.lenient_tally.items(), key=lambda kv: -len(kv[1])):
                print(f"  {len(refs):2}x {violation}")
                print(f"       cases: {', '.join(refs)}")
        if self.hostile_tally:
            print("Hostile-NLRI behavior FastNetMon handles correctly (refused, or well-formed):")
            for outcome, refs in sorted(self.hostile_tally.items(), key=lambda kv: -len(kv[1])):
                print(f"  {len(refs):2}x {outcome}")
                print(f"       cases: {', '.join(refs)}")
        c = self.counts
        print(f"Summary: {c['PASS']} pass, {c['KNOWN-FAIL']} known-fail (expected decoder gaps), "
              f"{c['HOSTILE-OK']} hostile-ok, {c['KNOWN-LENIENT']} known-lenient (accepted malformed), "
              f"{c['UNEXPECTED-PASS']} unexpected-pass, {c['FAIL']} fail")
        for msg in self.failures:
            print(f"  - {msg}", file=sys.stderr)
        for msg in self.unexpected:
            print(f"  - {msg}", file=sys.stderr)
        if self.failures:
            return 1
        if self.unexpected and self.strict:
            print("strict mode: failing on UNEXPECTED-PASS", file=sys.stderr)
            return 1
        return 0


def main():
    corpus_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "/corpus")
    shim = sys.argv[2] if len(sys.argv) > 2 else os.environ.get(
        "FASTNETMON_SHIM", "/usr/local/bin/fastnetmon_flowspec_shim")
    report = Report(strict=os.environ.get("MRTGEN_STRICT") == "1", shim=shim)

    checked_any = False
    for stem, required in (("routes-flowspec-fnm", True), ("routes-flowspec", False),
                           ("routes-flowspec-absurd", False)):
        manifest_path = corpus_dir / f"{stem}.mrt.manifest.json"
        if not manifest_path.exists():
            if required:
                print(f"error: {manifest_path.name} missing (harness should generate it)", file=sys.stderr)
                return 1
            continue
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        print(f"{manifest_path.name}:")
        for rec in manifest["records"]:
            det = rec.get("details") or {}
            if det.get("flowspec") is None:
                continue
            checked_any = True
            report.check_record(f"{stem}[{rec['index']}]", det)

    if not checked_any:
        print("error: no flowspec records found in the manifests", file=sys.stderr)
        return 1
    return report.summarize()


if __name__ == "__main__":
    raise SystemExit(main())
