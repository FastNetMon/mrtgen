#!/usr/bin/env python3
"""Field-level validation of mrtgen --routes output against mrtparse.

For each record of routes-td2.mrt (TABLE_DUMP_V2) and routes-bgp4mp.mrt
(BGP4MP) this cross-checks everything the manifest's `details` promises —
prefix, next hop, AS_PATH, ORIGIN, MED, LOCAL_PREF, ATOMIC_AGGREGATE,
standard/extended/large communities and the ADD-PATH Path Identifier —
against what mrtparse actually decoded from the wire.

FlowSpec records (routes-flowspec.mrt) get extra treatment because mrtparse
skips SAFI-133 NLRI entirely: this walks the raw BGP4MP bytes itself to pull
the MP_REACH NLRI off the wire, asserts it equals the manifest's nlri_hex,
then decodes it with an independent RFC 8955/8956 decoder and compares every
component (prefixes, operator bits, values) against the JSON rule spec.

Usable standalone:  routes_mrtparse_check.py <dir-with-routes-files>
or via check(corpus_dir) from mrtparse_check.py.
"""
import copy
import ipaddress
import json
import sys
from pathlib import Path

from mrtparse import Reader


def read_all(path):
    """Decode every record's data dict. mrtparse's Reader mutates one shared
    entry object as it iterates, so each record must be copied out."""
    return [copy.deepcopy(entry.data) for entry in Reader(str(path))]

# Path attribute type codes.
ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF = 1, 2, 3, 4, 5
ATOMIC_AGGREGATE, COMMUNITY, MP_REACH, EXT_COMMUNITY, LARGE_COMMUNITY = 6, 8, 14, 16, 32
IPV6_EXT_COMMUNITY = 25
AGGREGATOR, ORIGINATOR_ID, CLUSTER_LIST, AIGP = 7, 9, 10, 26

# Names mrtparse may print instead of "asn:value" (RFC 1997/7999/8326 etc.).
COMM_NAMES = {
    "GRACEFUL_SHUTDOWN": 0xFFFF0000,
    "ACCEPT_OWN": 0xFFFF0001,
    "LLGR_STALE": 0xFFFF0006,
    "NO_LLGR": 0xFFFF0007,
    "BLACKHOLE": 0xFFFF029A,
    "NO_EXPORT": 0xFFFFFF01,
    "NO_ADVERTISE": 0xFFFFFF02,
    "NO_EXPORT_SUBCONFED": 0xFFFFFF03,
    "NO_PEER": 0xFFFFFF04,
}

# --- expected values from the manifest details (mirrors src/routes.rs) ------


def spec_std_comm(s):
    low = s.lower()
    named = {"no-export": 0xFFFFFF01, "no-advertise": 0xFFFFFF02, "no-export-subconfed": 0xFFFFFF03}
    if low in named:
        return named[low]
    if low.startswith("0x"):
        return int(low, 16)
    a, b = s.split(":")
    return (int(a) << 16) | int(b)


def spec_rd_numeric(s):
    """Encode an rd spec ("asn:number" or "a.b.c.d:number", mirroring
    src/routes.rs parse_rd) and render it the way mrtparse's val_rd does:
    numerically as "<hi32>:<lo32>"."""
    admin, number = s.split(":", 1)
    try:
        ip = ipaddress.IPv4Address(admin)
        raw = (1).to_bytes(2, "big") + ip.packed + int(number).to_bytes(2, "big")
    except ipaddress.AddressValueError:
        a = int(admin)
        if a <= 0xFFFF:
            raw = (0).to_bytes(2, "big") + a.to_bytes(2, "big") + int(number).to_bytes(4, "big")
        else:
            raw = (2).to_bytes(2, "big") + a.to_bytes(4, "big") + int(number).to_bytes(2, "big")
    u64 = int.from_bytes(raw, "big")
    return f"{u64 >> 32}:{u64 & 0xFFFFFFFF}"


def spec_ext_comm(s):
    low = s.lower()
    for prefix, subtype in (("rt:", 0x02), ("soo:", 0x03)):
        if low.startswith(prefix):
            admin, value = low[len(prefix):].split(":")
            admin, value = int(admin), int(value)
            if admin <= 0xFFFF:
                raw = bytes([0x00, subtype]) + admin.to_bytes(2, "big") + value.to_bytes(4, "big")
            else:
                raw = bytes([0x02, subtype]) + admin.to_bytes(4, "big") + value.to_bytes(2, "big")
            return int.from_bytes(raw, "big")
    return int(low.removeprefix("0x"), 16)


# --- normalizing mrtparse output ---------------------------------------------


def mrt_comm(s):
    if s in COMM_NAMES:
        return COMM_NAMES[s]
    if ":" in s:
        a, b = s.split(":")
        return (int(a) << 16) | int(b)
    return int(s, 0)


def key_of(tagged):
    """mrtparse encodes enums as {"code": "NAME"}; return the numeric code."""
    return int(next(iter(tagged)))


def attr_map(attrs):
    return {key_of(a["type"]): a for a in attrs}


def flat_as_path(attr):
    return [int(asn) for seg in attr["value"] for asn in seg["value"]]


def same_net(a, b):
    return ipaddress.ip_network(a, strict=False) == ipaddress.ip_network(b, strict=False)


def same_ip(a, b):
    return ipaddress.ip_address(a) == ipaddress.ip_address(b)


def flow_v6(flow):
    """Address family of a flowspec rule (mirrors src/flowspec.rs family())."""
    p = flow.get("dst_prefix") or flow.get("src_prefix")
    if p:
        return ":" in p
    return flow.get("afi") == "ipv6"


# --- FlowSpec NLRI: wire extraction + independent RFC 8955/8956 decode -------
#
# mrtparse decodes only the MP_REACH header for SAFI 133 and discards the
# NLRI bytes, so everything below works on the raw record instead.

TCP_FLAG_BITS = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08,
                 "ack": 0x10, "urg": 0x20, "ece": 0x40, "cwr": 0x80}
FRAGMENT_BITS = {"dont-fragment": 0x01, "is-fragment": 0x02,
                 "first-fragment": 0x04, "last-fragment": 0x08}

# spec key -> component type, in required ascending-type order.
FLOW_NUMERIC = {"protocol": 3, "port": 4, "dst_port": 5, "src_port": 6,
                "icmp_type": 7, "icmp_code": 8, "packet_length": 10,
                "dscp": 11, "flow_label": 13}
FLOW_BITMASK = {"tcp_flags": (9, TCP_FLAG_BITS), "fragment": (12, FRAGMENT_BITS)}
# Numeric comparison bits (op & 0x07): lt=4 gt=2 eq=1.
CMP = {"eq": 1, "gt": 2, "ge": 3, "lt": 4, "le": 5}


def wire_flowspec_nlri(raw, mrec):
    """Walk the raw BGP4MP_MESSAGE_AS4[_ADDPATH] record at the manifest's
    offset/size down to the MP_REACH attribute and return its NLRI bytes."""
    rec = raw[mrec["offset"]:mrec["offset"] + mrec["size"]]
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(rec):
            raise ValueError(f"truncated record at byte {pos}")
        pos += n
        return rec[pos - n:pos]

    if mrec["subtype"] not in (4, 9):  # BGP4MP_MESSAGE_AS4[_ADDPATH]
        raise ValueError(f"unexpected BGP4MP subtype {mrec['subtype']}")
    take(12)  # MRT header
    take(8 + 2)  # peer AS + local AS (AS4) + interface index
    afi = int.from_bytes(take(2), "big")
    take(2 * (4 if afi == 1 else 16))  # peer + local IP
    if take(16) != b"\xff" * 16:
        raise ValueError("bad BGP marker")
    take(2)  # BGP message length
    if take(1) != b"\x02":
        raise ValueError("not a BGP UPDATE")
    take(int.from_bytes(take(2), "big"))  # withdrawn routes
    attrs_end = int.from_bytes(take(2), "big") + pos
    while pos < attrs_end:
        flags = take(1)[0]
        code = take(1)[0]
        alen = int.from_bytes(take(2 if flags & 0x10 else 1), "big")
        value = take(alen)
        if code != 14:
            continue
        if len(value) < 5:
            raise ValueError("short MP_REACH")
        nh_len = value[3]
        return value[5 + nh_len:]  # afi(2) safi(1) nhlen(1) nh reserved(1)
    raise ValueError("no MP_REACH attribute")


def decode_flowspec_nlri(data, v6):
    """Decode a FlowSpec NLRI into canonical [(type, payload)] components.
    Payload is "addr/bits" for prefix types; a list of (and, cmp, value) for
    numeric operators; a list of (and, not, match, bits) for bitmask ones.
    Deliberately written from the RFCs, not from src/flowspec.rs, so it is an
    independent check of the encoder."""
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(data):
            raise ValueError(f"truncated NLRI at byte {pos}")
        pos += n
        return data[pos - n:pos]

    first = take(1)[0]
    length = ((first & 0x0F) << 8) | take(1)[0] if first >= 0xF0 else first
    if length != len(data) - pos:
        raise ValueError(f"NLRI length {length} != {len(data) - pos} payload bytes")

    comps = []
    last_type = 0
    while pos < len(data):
        ctype = take(1)[0]
        if ctype <= last_type:
            raise ValueError(f"component type {ctype} after {last_type}: not ascending")
        last_type = ctype
        if ctype in (1, 2):  # destination/source prefix
            bits = take(1)[0]
            offset = take(1)[0] if v6 else 0
            if offset:
                raise ValueError(f"prefix offset {offset}: mrtgen never emits one")
            pattern = bytes(take((bits - offset + 7) // 8))
            addr = ipaddress.ip_address(pattern.ljust(16 if v6 else 4, b"\0"))
            comps.append((ctype, f"{addr}/{bits}"))
        else:  # numeric or bitmask operator list, terminated by the end bit
            ops = []
            while True:
                op = take(1)[0]
                value = int.from_bytes(take(1 << ((op >> 4) & 0x3)), "big")
                if ctype in (9, 12):  # tcp_flags / fragment: not=0x02, match=0x01
                    ops.append((bool(op & 0x40), bool(op & 0x02), bool(op & 0x01), value))
                else:
                    ops.append((bool(op & 0x40), op & 0x07, value))
                if op & 0x80:
                    break
            comps.append((ctype, ops))
    return comps


def flowspec_expected(flow):
    """Canonical components the JSON rule spec promises, same shape as
    decode_flowspec_nlri output."""
    comps = []
    for key, ctype in (("dst_prefix", 1), ("src_prefix", 2)):
        if flow.get(key):
            comps.append((ctype, flow[key]))
    for key, ctype in FLOW_NUMERIC.items():
        ops = []
        for item in flow.get(key) or []:
            if isinstance(item, dict):
                (cmp_name, v), = item.items()
                if cmp_name == "range":
                    ops += [(False, CMP["ge"], v[0]), (True, CMP["le"], v[1])]
                else:
                    ops.append((False, CMP[cmp_name], v))
            else:
                ops.append((False, CMP["eq"], item))
        if ops:
            comps.append((ctype, ops))
    for key, (ctype, table) in FLOW_BITMASK.items():
        ops = []
        for item in flow.get(key) or []:
            flags = item["flags"]
            bits = sum(table[n.lower()] for n in flags) if isinstance(flags, list) else flags
            ops.append((False, bool(item.get("not")), bool(item.get("match")), bits))
        if ops:
            comps.append((ctype, ops))
    return sorted(comps)


def check_flowspec_record(det, mrec, raw, fail):
    flow = det["flowspec"]
    if not det.get("nlri_hex"):
        fail("nlri_hex missing from manifest details")
        return
    nlri = bytes.fromhex(det["nlri_hex"])

    # 1. The manifest's nlri_hex must be exactly what sits on the wire
    #    (ADD-PATH prepends the 4-byte Path Identifier inside MP_REACH).
    path_id = b"" if det["path_id"] is None else det["path_id"].to_bytes(4, "big")
    try:
        wire = wire_flowspec_nlri(raw, mrec)
    except ValueError as e:
        fail(f"flowspec wire walk: {e}")
        return
    if wire != path_id + nlri:
        fail(f"flowspec NLRI on wire: expected {(path_id + nlri).hex()}, got {wire.hex()}")

    if flow.get("raw_components_hex"):
        # Deliberately hostile NLRI (duplicate/out-of-order/unknown/truncated
        # components): the independent decoder below models a compliant
        # parser and would rightly reject it, so stop at the wire assertion.
        return

    # 2. Independent decode of the NLRI, compared against the rule spec.
    try:
        comps = decode_flowspec_nlri(nlri, flow_v6(flow))
    except ValueError as e:
        fail(f"flowspec NLRI decode: {e}")
        return
    expected = flowspec_expected(flow)
    if [t for t, _ in comps] != [t for t, _ in expected]:
        fail(f"flowspec component types: expected {[t for t, _ in expected]}, got {[t for t, _ in comps]}")
        return
    for (ctype, got), (_, want) in zip(comps, expected):
        if ctype in (1, 2):
            if not same_net(got, want):
                fail(f"flowspec component {ctype}: expected {want}, got {got}")
        elif got != want:
            fail(f"flowspec component {ctype}: expected {want}, got {got}")


# --- per-record validation ----------------------------------------------------


def check_attrs(attrs, details, v6, fmt, fail):
    """Validate the decoded path attributes against the route's details.
    Returns the MP_REACH attribute value (for the caller to dig NLRI out of)."""
    amap = attr_map(attrs)
    # VPN routes (any family) carry the next hop in MP_REACH, RD-prefixed.
    use_mp = v6 or details.get("rd") is not None

    origin = amap.get(ORIGIN)
    if origin is None or key_of(origin["value"]) != details["origin"]:
        fail(f"ORIGIN: expected {details['origin']}, got {origin and origin['value']}")

    as_path = amap.get(AS_PATH)
    if as_path is None or flat_as_path(as_path) != details["as_path"]:
        fail(f"AS_PATH: expected {details['as_path']}, got {as_path and flat_as_path(as_path)}")

    flow = details.get("flowspec")
    if flow is not None:
        # SAFI 133: mrtparse decodes only the MP_REACH header (afi, safi,
        # next_hop_length) and skips the rest — assert exactly that much.
        mp = amap.get(MP_REACH)
        v = mp and mp["value"]
        if v is None:
            fail("MP_REACH missing")
        else:
            if key_of(v["safi"]) != 133:
                fail(f"MP_REACH SAFI: expected 133, got {v['safi']}")
            if key_of(v["afi"]) != (2 if flow_v6(flow) else 1):
                fail(f"MP_REACH AFI: got {v['afi']}")
            nh_len = 0 if details["nexthop"] is None else (16 if flow_v6(flow) else 4)
            if v["next_hop_length"] != nh_len:
                fail(f"next_hop_length: expected {nh_len}, got {v['next_hop_length']}")
    elif use_mp:
        mp = amap.get(MP_REACH)
        nh = mp and mp["value"]["next_hop"][0]
        if nh is None or not same_ip(nh, details["nexthop"]):
            fail(f"MP_REACH next hop: expected {details['nexthop']}, got {nh}")
    else:
        nh = amap.get(NEXT_HOP)
        if nh is None or not same_ip(nh["value"], details["nexthop"]):
            fail(f"NEXT_HOP: expected {details['nexthop']}, got {nh and nh['value']}")

    for code, name in ((MED, "med"), (LOCAL_PREF, "local_pref")):
        got = amap.get(code)
        if details[name] is None:
            if got is not None:
                fail(f"{name}: unexpected attribute {got['value']}")
        elif got is None or got["value"] != details[name]:
            fail(f"{name}: expected {details[name]}, got {got and got['value']}")

    if details["atomic_aggregate"] != (ATOMIC_AGGREGATE in amap):
        fail(f"ATOMIC_AGGREGATE: expected present={details['atomic_aggregate']}")

    agg, want = amap.get(AGGREGATOR), details.get("aggregator")
    if want is None:
        if agg is not None:
            fail(f"AGGREGATOR: unexpected attribute {agg['value']}")
    elif agg is None or int(agg["value"]["as"]) != want["as"] or not same_ip(agg["value"]["id"], want["id"]):
        fail(f"AGGREGATOR: expected {want}, got {agg and agg['value']}")

    orig, want = amap.get(ORIGINATOR_ID), details.get("originator_id")
    if want is None:
        if orig is not None:
            fail(f"ORIGINATOR_ID: unexpected attribute {orig['value']}")
    elif orig is None or not same_ip(orig["value"], want):
        fail(f"ORIGINATOR_ID: expected {want}, got {orig and orig['value']}")

    clist, want = amap.get(CLUSTER_LIST), details.get("cluster_list") or []
    got = [] if clist is None else clist["value"]
    if len(got) != len(want) or any(not same_ip(g, w) for g, w in zip(got, want)):
        fail(f"CLUSTER_LIST: expected {want}, got {got}")

    aigp, want = amap.get(AIGP), details.get("aigp")
    if want is None:
        if aigp is not None:
            fail(f"AIGP: unexpected attribute {aigp['value']}")
    elif aigp is None or aigp["value"] != [{"type": 1, "length": 11, "value": want}]:
        fail(f"AIGP: expected metric {want}, got {aigp and aigp['value']}")

    def comm_check(code, name, expect_fn, got_fn, extra=()):
        expected = sorted([expect_fn(c) for c in details[name]] + list(extra))
        got_attr = amap.get(code)
        got = sorted(got_fn(v) for v in got_attr["value"]) if got_attr else []
        if expected != got:
            fail(f"{name}: expected {expected}, got {got}")

    # FlowSpec actions are extended communities; the manifest carries their
    # exact encodings as hex so they merge into the expectation here.
    action_comms = [int(h, 16) for h in details.get("action_ext_communities_hex") or []]
    comm_check(COMMUNITY, "standard_communities", spec_std_comm, mrt_comm)
    comm_check(EXT_COMMUNITY, "extended_communities", spec_ext_comm, int, action_comms)
    comm_check(LARGE_COMMUNITY, "large_communities", lambda s: s, str)

    # RFC 5701 IPv6 addr-specific ext communities (attr 25): mrtparse leaves
    # the attribute undecoded as space-separated hex — compare byte-exactly
    # against the encodings recorded in the manifest.
    expected_hex = "".join(details.get("ipv6_ext_communities_hex") or [])
    got25 = amap.get(IPV6_EXT_COMMUNITY)
    got_hex = got25["value"].replace(" ", "") if got25 else ""
    if expected_hex != got_hex:
        fail(f"ipv6_extended_communities: expected {expected_hex or '(absent)'}, got {got_hex or '(absent)'}")

    # Raw escape-hatch attributes: assert flags/length always, and the value
    # byte-for-byte when mrtparse left the attribute undecoded (hex string).
    for raw in details.get("raw_attributes") or []:
        got = amap.get(raw["code"])
        tag = f"raw attribute {raw['code']}"
        if got is None:
            fail(f"{tag}: missing")
            continue
        if got["flag"] != raw["flags"]:
            fail(f"{tag}: flags expected {raw['flags']}, got {got['flag']}")
        if got["length"] != len(raw["value_hex"]) // 2:
            fail(f"{tag}: length expected {len(raw['value_hex']) // 2}, got {got['length']}")
        if isinstance(got.get("value"), str):
            got_hex = got["value"].replace(" ", "")
            if got_hex != raw["value_hex"]:
                fail(f"{tag}: value expected {raw['value_hex']}, got {got_hex}")

    return amap.get(MP_REACH)


def check_td2(path, manifest):
    failures = []
    records = read_all(path)
    if len(records) != len(manifest["records"]):
        failures.append(f"{path.name}: mrtparse saw {len(records)} records, manifest has {len(manifest['records'])}")
        return failures

    peer_table = records[0]
    if key_of(peer_table["subtype"]) != 1 or peer_table["peer_count"] != 2:
        failures.append(f"{path.name}: bad PEER_INDEX_TABLE: {peer_table.get('subtype')}, peers={peer_table.get('peer_count')}")

    for d, mrec in zip(records[1:], manifest["records"][1:]):
        det = mrec["details"]
        name = f"{path.name}[{mrec['index']}] {det['prefix']}"
        fail = lambda msg, name=name: failures.append(f"{name}: {msg}")
        v6 = ":" in det["prefix"]

        if key_of(d["subtype"]) != mrec["subtype"]:
            fail(f"subtype: expected {mrec['subtype']}, got {d['subtype']}")
        if det.get("rd") is not None:
            # mrtparse cannot decode TABLE_DUMP_V2 RIB_GENERIC VPN records
            # (its TD2 path lacks SAFI-128 NLRI and RD-prefixed next-hop
            # support) — the subtype assertion above is all we can do here.
            continue
        # mrtparse stores the RIB prefix length under "length".
        if not same_net(f"{d['prefix']}/{d['length']}", det["prefix"]):
            fail(f"prefix: expected {det['prefix']}, got {d['prefix']}/{d['length']}")
        if d["entry_count"] != 1 or len(d["rib_entries"]) != 1:
            fail(f"entry_count: {d['entry_count']}")
            continue

        rib = d["rib_entries"][0]
        if rib["peer_index"] != (1 if v6 else 0):
            fail(f"peer_index: got {rib['peer_index']}")
        if rib.get("path_id") != det["path_id"]:
            fail(f"path_id: expected {det['path_id']}, got {rib.get('path_id')}")
        check_attrs(rib["path_attributes"], det, v6, "td2", fail)
    return failures


def check_bgp4mp(path, manifest):
    failures = []
    raw = path.read_bytes()
    records = read_all(path)
    if len(records) != len(manifest["records"]):
        failures.append(f"{path.name}: mrtparse saw {len(records)} records, manifest has {len(manifest['records'])}")
        return failures

    for d, mrec in zip(records, manifest["records"]):
        det = mrec["details"]
        name = f"{path.name}[{mrec['index']}] {det['prefix'] or 'flowspec'}"
        fail = lambda msg, name=name: failures.append(f"{name}: {msg}")
        v6 = ":" in det["prefix"] if det["prefix"] else flow_v6(det["flowspec"])

        if key_of(d["subtype"]) != mrec["subtype"]:
            fail(f"subtype: expected {mrec['subtype']}, got {d['subtype']}")
        expected_peer_as = det["as_path"][0] if det["as_path"] else 64500
        if int(d["peer_as"]) != expected_peer_as or int(d["local_as"]) != 64511:
            fail(f"AS: expected peer {expected_peer_as}/local 64511, got {d['peer_as']}/{d['local_as']}")

        msg = d["bgp_message"]
        if key_of(msg["type"]) != 2:
            fail(f"BGP message type: {msg['type']}")
            continue
        mp = check_attrs(msg["path_attributes"], det, v6, "bgp4mp", fail)

        if det.get("flowspec") is not None:
            # mrtparse cannot decode the FlowSpec NLRI itself — extract it
            # from the raw record and decode it independently instead.
            check_flowspec_record(det, mrec, raw, fail)
            continue

        is_vpn = det.get("rd") is not None
        nlri = mp["value"]["nlri"] if (v6 or is_vpn) else msg["nlri"]
        if not nlri:
            fail("announced NLRI missing")
            continue
        n = nlri[0]
        if is_vpn:
            # SAFI 128: NLRI is label stack + RD + prefix; mrtparse reports
            # raw 3-byte label stack entries and the RD numerically, and
            # "length" counts label (24) + RD (64) + prefix bits.
            if key_of(mp["value"]["safi"]) != 128:
                fail(f"MP_REACH SAFI: expected 128, got {mp['value']['safi']}")
            if n.get("label") != [(det["label"] << 4) | 1]:
                fail(f"NLRI label: expected {[(det['label'] << 4) | 1]}, got {n.get('label')}")
            if n.get("route_distinguisher") != spec_rd_numeric(det["rd"]):
                fail(f"NLRI rd: expected {spec_rd_numeric(det['rd'])}, got {n.get('route_distinguisher')}")
            if not same_net(f"{n['prefix']}/{n['length'] - 88}", det["prefix"]):
                fail(f"NLRI prefix: expected {det['prefix']}, got {n['prefix']}/{n['length'] - 88}")
        elif not same_net(f"{n['prefix']}/{n['length']}", det["prefix"]):
            fail(f"NLRI prefix: expected {det['prefix']}, got {n['prefix']}/{n['length']}")
        if n.get("path_id") != det["path_id"]:
            fail(f"NLRI path_id: expected {det['path_id']}, got {n.get('path_id')}")
    return failures


def check(corpus_dir):
    corpus_dir = Path(corpus_dir)
    failures = []
    for stem, checker in (("routes-td2", check_td2), ("routes-bgp4mp", check_bgp4mp),
                          ("routes-flowspec", check_bgp4mp), ("routes-flowspec-absurd", check_bgp4mp)):
        mrt = corpus_dir / f"{stem}.mrt"
        if not mrt.exists():
            failures.append(f"{mrt.name}: missing (harness should generate it)")
            continue
        with open(corpus_dir / f"{stem}.mrt.manifest.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        file_failures = checker(mrt, manifest)
        route_count = len(manifest["records"])
        status = "ok" if not file_failures else f"{len(file_failures)} mismatches"
        print(f"{mrt.name}: {status}; records checked={route_count}")
        failures.extend(file_failures)
    return failures


def main():
    failures = check(sys.argv[1] if len(sys.argv) > 1 else "/corpus")
    for f in failures:
        print(f"  - {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
