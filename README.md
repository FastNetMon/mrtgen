# mrtgen

Deterministic synthetic MRT (Multi-Threaded Routing Toolkit, RFC 6396) file
generator for CI/CD testing of MRT parsers. Usable as a Rust library and as a
CLI tool.

Development of this project is sponsored by [FastNetMon Ltd](https://fastnetmon.com).

The generated corpus contains:

* **Valid records** covering every standard MRT type and subtype:
  * `TABLE_DUMP` (AFI_IPv4, AFI_IPv6)
  * `TABLE_DUMP_V2` (PEER_INDEX_TABLE, all four AFI/SAFI RIB subtypes,
    RIB_GENERIC, and all five RFC 8050 `_ADDPATH` subtypes; RIB_GENERIC also
    carries VPNv4 and VPNv6 routes (SAFI 128, RFC 4364) whose NLRI is
    label + Route Distinguisher + prefix with an RD-prefixed next hop and a
    Route Target extended community)
  * `BGP4MP` / `BGP4MP_ET` (STATE_CHANGE, STATE_CHANGE_AS4, MESSAGE,
    MESSAGE_AS4, MESSAGE_LOCAL, MESSAGE_AS4_LOCAL, and all four RFC 8050
    `_ADDPATH` subtypes; OPEN/UPDATE/KEEPALIVE/NOTIFICATION messages; an
    UPDATE announcing a VPNv4 route via MP_REACH_NLRI (SAFI 128);
    the extended-timestamp header for `_ET`)
  * `OSPFv2`, `OSPFv3`, `OSPFv3_ET`, `ISIS`, `ISIS_ET`
* **Community × ADD-PATH combination records** — every record here carries at
  least one community attribute (standard RFC 1997, extended RFC 4360, or
  large RFC 8092) *and* an ADD-PATH element (a RIB-entry Path Identifier, or a
  RIB_GENERIC_ADDPATH / BGP4MP_MESSAGE_ADDPATH NLRI Path Identifier), in
  assorted combinations. About half are fully legal; the rest are deliberately
  *illegal but still skip-class* — the MRT Length is honest, but a BGP/ADD-PATH
  content rule is broken, so a robust parser must reject the record and keep
  loading. Illegal cases include: a Path Identifier in a non-ADD-PATH subtype,
  an ADD-PATH subtype missing its Path Identifier, community values whose
  length is not a multiple of 4/8/12, a duplicated COMMUNITY attribute, a
  BGP4MP_MESSAGE_ADDPATH whose NLRI omits the Path Identifier, and a community
  block large enough to push the BGP message past its 4096-byte maximum. One
  legal case packs ~1000 communities into a single RIB entry to exercise the
  extended-length (2-byte) attribute encoding.
* **Skip-class invalid records** — the MRT common header and its Length field
  are honest, but the content is broken. A robust parser must skip these and
  continue loading. Includes: unknown type/subtype, fixed-size BGP attribute
  TLVs encoded with the wrong length (e.g. 4-byte MED declared as 2/8 bytes,
  8-byte AS4_AGGREGATOR declared as 4/16), TLV lengths overrunning their
  container, bad BGP marker, out-of-range BGP message length, inner
  truncation, empty body, impossible NLRI prefix lengths (/33, /129), VPN
  (SAFI 128) NLRI lengths that cannot contain the mandatory label + RD or that
  exceed label + RD + a full address, and peer-count/attribute-length fields
  that overrun the record.
* **Attribute error-handling records (RFC 7606)** — honest MRT and BGP framing,
  but one path attribute breaks a per-attribute rule; these are the
  malformations that most often crash or mis-parse real implementations.
  Includes: malformed AS_PATH segments (zero-length, unknown segment type,
  count overrun, trailing underrun); a longer AS4_PATH than AS_PATH (valid per
  RFC 6793 but a classic merge-panic trigger); attribute-flags errors (ORIGIN
  marked Optional, Extended-Length bit on a short value); MP_REACH_NLRI with an
  inconsistent Next Hop Length and MP_UNREACH_NLRI shorter than 3 bytes;
  illegal zero-length ORIGIN/NEXT_HOP/COMMUNITY; ATOMIC_AGGREGATE with a
  non-zero length and AGGREGATOR with a length that is neither 6 nor 8; a RIB
  entry referencing a peer index absent from the PEER_INDEX_TABLE; an unknown
  optional-transitive attribute (which must be retained, not rejected); a
  reserved type-0 attribute; and a BGP4MP_ET record too short for its
  microsecond field.
* **Abort-class tails** (optional) — the framing itself lies: header Length
  pointing past EOF, `0xFFFFFFFF` Length, or a truncated header. There is no
  way to resync after these, so loading must stop. They are always the last
  bytes of a file; each fatal case gets its own file via `--fatal-dir`.

Generation is **byte-for-byte deterministic**: no clocks, no randomness.
Record N carries timestamp `base_timestamp + N`. The same config always
produces the identical file, so CI can pin hashes if desired.

## CLI

```console
$ cargo build --release
$ ./target/release/mrtgen --out corpus.mrt --fatal-dir fatal/
wrote corpus.mrt (15304 bytes, 86 records: 42 valid, 44 skip, 0 abort) + corpus.mrt.manifest.json
wrote fatal/fatal_length_overruns_eof.mrt ...
wrote fatal/fatal_truncated_header.mrt ...
wrote fatal/fatal_huge_length.mrt ...
```

Options: `--no-valid`, `--no-skip`, `--no-combo`, `--no-attr-errors`,
`--fatal <length-overrun|truncated-header|huge-length>` (append one fatal tail
to the main file), `--base-timestamp <N>`, `--manifest <FILE>`.

## Route-list mode

Instead of the built-in corpus, `--routes <FILE>` builds an MRT file from a
JSON array of routes you supply:

```json
[
  {
    "prefix": "1.2.3.0/24",
    "nexthop": "1.1.1.1",
    "standard_communities": ["111:222", "222:333"]
  },
  {
    "prefix": "2001:db8:64::/48",
    "nexthop": "2001:db8::9",
    "as_path": [64500, 4200000001],
    "origin": "incomplete",
    "med": 50,
    "local_pref": 150,
    "extended_communities": ["rt:64500:1"],
    "large_communities": ["64500:1:2"],
    "path_id": 9
  }
]
```

```console
$ mrtgen --routes routes.json -o routes.mrt
wrote routes.mrt (295 bytes, 4 records: 4 valid, 0 skip, 0 abort) + routes.mrt.manifest.json
$ mrtgen --routes routes.json --routes-format bgp4mp -o updates.mrt
```

Only `prefix` and `nexthop` are required; the address family is taken from
the prefix and the next hop must match it. Optional fields per route:

| field                  | format                                                              | default   |
|------------------------|---------------------------------------------------------------------|-----------|
| `as_path`              | array of AS numbers (one AS_SEQUENCE); `[]` = empty path (iBGP)     | `[64500]` |
| `origin`               | `"igp"` / `"egp"` / `"incomplete"` or `0`-`2`                        | `igp`     |
| `med`, `local_pref`    | u32                                                                 | omitted   |
| `atomic_aggregate`     | bool                                                                | `false`   |
| `aggregator`           | RFC 4271 AGGREGATOR: `"asn:a.b.c.d"` (always the 4-byte-AS form)     | omitted   |
| `originator_id`        | RFC 4456 ORIGINATOR_ID: IPv4 router id                               | omitted   |
| `cluster_list`         | RFC 4456 CLUSTER_LIST: array of IPv4 cluster ids, outermost first    | omitted   |
| `aigp`                 | RFC 7311 AIGP metric, u64 (one type-1 TLV)                           | omitted   |
| `standard_communities` | `"asn:value"`, `"no-export"`, `"no-advertise"`, `"no-export-subconfed"`, or `"0xNNNNNNNN"` | omitted |
| `extended_communities` | `"rt:admin:value"`, `"soo:admin:value"` (2- or 4-byte-AS form picked from the admin), or 16 raw hex digits | omitted |
| `ipv6_extended_communities` | RFC 5701 (attr 25): `"rt:<ipv6>:<local>"`, `"soo:<ipv6>:<local>"`, or 40 raw hex digits | omitted |
| `large_communities`    | `"global:local1:local2"`                                             | omitted   |
| `path_id`              | u32 ADD-PATH Path Identifier; selects the `_ADDPATH` subtype         | omitted   |
| `rd`                   | Route Distinguisher; presence selects MPLS VPN (SAFI 128): `"asn:number"` (type 0, or type 2 with a 4-byte ASN) or `"a.b.c.d:number"` (type 1) | omitted |
| `label`                | u32 MPLS label (< 2^20) for the VPN NLRI; requires `rd`              | `0`       |
| `flowspec`             | FlowSpec rule object (see below); replaces `prefix`                  | —         |
| `actions`              | FlowSpec traffic-filtering actions (see below); requires `flowspec`  | omitted   |
| `expect`               | manifest expectation: `"valid"` or `"skip"`; `skip` intentionally emits malformed-but-framed route records | `"valid"` |
| `raw_attributes`       | escape hatch: `[{"flags": 192 or ["optional","transitive","partial"], "code": 99, "value_hex": "deadbeef"}]`, appended after all built-in attributes with honest framing (extended-length handled automatically); duplicating a code is allowed deliberately | omitted |

Two encodings via `--routes-format`:

* `table-dump-v2` (default) — a RIB dump: one `PEER_INDEX_TABLE` followed by
  one `RIB_IPV4_UNICAST` / `RIB_IPV6_UNICAST` (or `_ADDPATH`) record per
  route, in input order. VPN routes (`rd`) become `RIB_GENERIC` /
  `RIB_GENERIC_ADDPATH` records (AFI 1/2, SAFI 128) with an RD-prefixed next
  hop.
* `bgp4mp` — a stream of announcements: one `BGP4MP_MESSAGE_AS4` (or
  `_ADDPATH`) record per route, each carrying a BGP UPDATE (IPv6, VPN and
  FlowSpec routes go via MP_REACH_NLRI).

### FlowSpec rules (RFC 8955 / RFC 8956)

A route may carry a `flowspec` object instead of a `prefix` — this encodes a
Flow Specification NLRI (AFI 1/2, SAFI 133), the announcement format used for
DDoS mitigation rules. `nexthop` becomes optional (0-length next hop when
absent). FlowSpec routes require `--routes-format bgp4mp`: they are
UPDATE-stream artifacts, and common MRT parsers cannot walk
RIB_GENERIC/SAFI-133 TABLE_DUMP_V2 records.

```json
{
  "flowspec": {
    "dst_prefix": "192.0.2.0/24", "src_prefix": "203.0.113.0/24",
    "protocol": [6], "port": [25], "dst_port": [80, {"range": [8080, 8088]}],
    "src_port": [{"ge": 1024}], "icmp_type": [8], "icmp_code": [0],
    "tcp_flags": [{"flags": ["syn"], "match": false, "not": false}],
    "packet_length": [{"range": [64, 1500]}], "dscp": [46],
    "fragment": [{"flags": ["is-fragment"]}]
  },
  "actions": {
    "rate_limit_bytes": 0, "rate_limit_packets": 1000,
    "redirect": "64500:1", "traffic_marking": 46,
    "terminal_action": true, "sample": false
  }
}
```

Numeric components take bare numbers (`== n`), `{"eq"|"lt"|"le"|"gt"|"ge": n}`
or `{"range": [a, b]}`; list items are ORed. `tcp_flags` / `fragment` take
flag names (or a raw number) with optional `match` / `not` bits. IPv6 rules
(family from the prefixes, or `"afi": "ipv6"` when there is none) additionally
support `flow_label`. `actions` encode as RFC 8955 section 7 extended
communities: traffic-rate-bytes (0x8006), traffic-rate-packets (0x800c),
traffic-action (0x8007, T/S bits), rt-redirect (0x8008/0x8108/0x8208 chosen
from the administrator form) and traffic-marking (0x8009). The manifest
records the exact NLRI bytes under `details.nlri_hex` and the action
communities under `details.action_ext_communities_hex`; the NLRI encoder is
unit-tested against the worked examples in RFC 8955 section 4.3.

Unknown JSON keys are rejected so typos fail loudly. Output is deterministic
and comes with the same manifest as corpus mode: route records default to
`expect: valid`, and `details` echoes the route's fields for CI assertions.
Valid route records reject non-canonical prefixes, FlowSpec values outside
their component domain, and AS_PATH lists that do not fit one AS_SEQUENCE.
Set `"expect": "skip"` on an individual route to intentionally emit these
malformed-but-framed encodings for parser tests; `abort` is not supported in
route-list mode. The library entry points are `routes_from_json()` and
`generate_from_routes()`.

Parser-support caveats (reflected in the harness checks): mrtparse decodes
SAFI-128 UPDATEs fully but cannot walk TABLE_DUMP_V2 RIB_GENERIC VPN records,
has no FlowSpec NLRI decoder (it skips the MP_REACH body gracefully), and
leaves attribute 25 / unknown attribute codes raw — which still allows
byte-exact validation. FastNetMon's FlowSpec decoder covers only a subset of
RFC 8955 — see the FastNetMon cross-validation section below for how the
harness keeps its gaps visible without failing on them.

## Manifest

Every `.mrt` file is accompanied by `<file>.manifest.json` describing each
record, in file order:

```json
{
  "generator": "mrtgen",
  "generator_version": "0.1.0",
  "file_size": 15304,
  "counts": { "valid": 42, "skip": 44, "abort": 0 },
  "records": [
    {
      "index": 3,
      "offset": 310,
      "size": 130,
      "mrt_type": 13,
      "subtype": 8,
      "timestamp": 1600000003,
      "kind": "rib_ipv4_unicast_addpath",
      "expect": "valid",
      "description": "TABLE_DUMP_V2 IPv4 RIB record with 2 RIB entries",
      "details": { "prefix": "10.102.0.0/16", "entry_count": 2, "path_ids": [3, 103] }
    }
  ]
}
```

`expect` is the contract with the parser under test:

| expect  | meaning                                                              |
|---------|----------------------------------------------------------------------|
| `valid` | must be fully parsed; `details` holds content facts to assert on     |
| `skip`  | record is present in the MRT file and has honest framing, but its content is intentionally broken; parser must reject/skip it and keep loading |
| `abort` | framing is broken; parser must stop loading at this point            |

`kind` is a unique, stable identifier per test case — key your CI assertions
on it. `offset`/`size` let you locate any record in the file for debugging.

A typical CI check: run the parser under test over `corpus.mrt`, assert every
`expect == "valid"` record was loaded (matching `details`), every
`expect == "skip"` record was rejected without killing the load, and that
loading each `fatal/*.mrt` file fails (while still yielding the records
before the tail, if your parser is incremental).

## Library

```rust
use mrtgen::{generate, GeneratorConfig, FatalKind, Expect};

let corpus = generate(&GeneratorConfig::default());
std::fs::write("corpus.mrt", &corpus.bytes)?;
std::fs::write("corpus.mrt.manifest.json", corpus.manifest.to_json())?;

// or compose your own records:
use mrtgen::{records, bgp, invalid, types::*};
let rec = records::bgp4mp_message(
    1_600_000_000, BGP4MP, None, BGP4MP_MESSAGE,
    64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2],
    &bgp::bgp_keepalive(),
);
let bytes = rec.encode();
```

Modules: `records` (valid builders), `invalid` (malformed builders), `bgp`
(BGP message/attribute encoding, including length-lying TLV helpers),
`writer` (MRT framing with Length override), `manifest`, `generator`.

## Standards

Copies of the implemented specifications live in `docs/`:

* RFC 6396 — MRT routing information export format
* RFC 6397 — MRT with geo-location extensions (not generated; reference only)
* RFC 8050 — MRT with BGP additional path extensions
* RFC 4271 — BGP-4
* RFC 4760 — Multiprotocol extensions for BGP-4
* RFC 1997 — BGP communities attribute
* RFC 7911 — BGP additional paths (ADD-PATH)
* RFC 4360 — BGP extended communities
* RFC 8092 — BGP large communities
* RFC 6793 — BGP support for 4-octet AS number space
* RFC 7606 — Revised error handling for BGP UPDATE messages

## Tests

`cargo test` covers determinism (double generation is byte-identical),
manifest offset/size consistency against the emitted bytes, walkability of
valid+skip corpora with a reference reader, abort behavior of each fatal
tail, and full type/subtype coverage. The corpus has additionally been
cross-validated against the independent `mrtparse` Python parser.

## External parser harness

`tests/parsers/run-docker.sh` builds selected MRT parsers in isolated Docker
images, generates corpus files under `target/parser-harness/corpus`, and
mounts that directory read-only into each container. This keeps parser builds
and package installs out of the host system. The same harness is available in
CI as the manually triggered `Parser harness` workflow
(`.github/workflows/parser-harness.yml`, run via the Actions tab or
`gh workflow run parser-harness.yml`), with the parser selection and
`--strict` flag as inputs.

```console
$ tests/parsers/run-docker.sh
```

The default run builds and executes:

* `mrtparse` from PyPI
* `bgpdump` from the Debian package archive
* `bgpkit-parser` from Cargo with its CLI feature enabled
* `fastnetmon` — FastNetMon's BGP FlowSpec decoder
  (`bgp_protocol_flow_spec.cpp`, pinned commit), compiled into a small shim

You can run one parser at a time:

```console
$ tests/parsers/run-docker.sh mrtparse
$ tests/parsers/run-docker.sh bgpdump
$ tests/parsers/run-docker.sh bgpkit-parser
$ tests/parsers/run-docker.sh fastnetmon
```

The harness generates both the complete corpus and BGP-family subcorpora for
parsers that only support the usual MRT BGP types (`TABLE_DUMP`,
`TABLE_DUMP_V2`, `BGP4MP`, `BGP4MP_ET`):

* `valid.mrt` contains only well-formed standard records and is expected to
  parse successfully in parsers that support every generated MRT type.
* `corpus.mrt` contains valid, skip-class malformed, combo, and RFC 7606
  records.
* `fatal/*.mrt` appends one abort-class tail per file.
* `bgp-valid.mrt`, `bgp-corpus.mrt`, and `bgp-fatal/*.mrt` contain only MRT
  types 12, 13, 16, and 17. The bundled parser runners use these files.
* `routes-td2.mrt` and `routes-bgp4mp.mrt` are built from
  `tests/parsers/routes-all-options.json`, a route list exercising every
  `--routes` option (both key aliases, defaults, empty AS_PATH, string and
  numeric origins, MED/LOCAL_PREF extremes, ATOMIC_AGGREGATE, every community
  syntax including well-known names and raw hex, 2- and 4-byte-AS extended
  communities, RFC 5701 IPv6 address-specific extended communities, raw
  escape-hatch attributes, VPNv4/VPNv6 routes with all three RD types and
  labels, ADD-PATH path ids, and edge prefixes `0.0.0.0/0`, `/32`, `/128`).
  `routes-flowspec.mrt` is built from `tests/parsers/routes-flowspec.json`
  (bgp4mp only) and covers every FlowSpec match component and action. The
  mrtparse runner validates these **field by field**: for each record,
  `routes_mrtparse_check.py` compares the prefix, next hop, AS_PATH, ORIGIN,
  MED, LOCAL_PREF, ATOMIC_AGGREGATE, all community families (attribute 25 and
  raw attributes byte-exactly via hex), RD/label of VPN NLRI, FlowSpec
  MP_REACH headers and action communities, and the Path Identifier that
  mrtparse decoded against the values promised by the manifest `details`.
  Where mrtparse cannot decode (TD2 RIB_GENERIC VPN records, FlowSpec NLRI
  bodies) the checker asserts structure only; the byte-level contract for
  those lives in the manifest and the Rust unit tests. It can also be run
  standalone against any directory holding the routes files:

  ```console
  $ python3 tests/parsers/runners/routes_mrtparse_check.py target/parser-harness/corpus
  routes-td2.mrt: ok; records checked=8
  routes-bgp4mp.mrt: ok; records checked=7
  ```

### FastNetMon FlowSpec cross-validation

The `fastnetmon` runner cross-validates mrtgen's FlowSpec NLRI encoder
against the decoder that actually consumes such announcements in production:
`flow_spec_decode_nlri_value()` from
[FastNetMon](https://github.com/pavel-odintsov/fastnetmon)'s
`bgp_protocol_flow_spec.cpp`, compiled at a pinned commit into
`fastnetmon_flowspec_shim`. For every flowspec record in
`routes-flowspec-fnm.mrt` (per-feature cases from
`tests/parsers/routes-flowspec-fnm.json`) and `routes-flowspec.mrt`, the
`fastnetmon_flowspec_check.py` driver feeds the manifest's `nlri_hex` to the
shim and compares FastNetMon's decoded JSON field by field with the rule the
manifest promises.

FastNetMon's decoder intentionally covers a subset of RFC 8955 (IPv4 only,
equality operators only, no common-port/ICMP/DSCP components, 1-byte NLRI
length only). Rules outside that envelope are expected to be refused and are
reported as **KNOWN-FAIL** — visible line by line, with the refusal reason,
and tallied in a "decoder gaps" section that doubles as the upstream
improvement backlog — but they never fail the run. If a KNOWN-FAIL case
suddenly decodes (FastNetMon gained support), it is flagged as
**UNEXPECTED-PASS**, which fails the run in `--strict` mode as the prompt to
re-pin the commit and update the checker's gap model. Decoded rules are also
scanned for silent degradations (dropped `ece`/`cwr` TCP flags, discarded
match-bit semantics, `tcp_flags` hidden unless protocol `tcp` is present),
reported as notes.

By default, malformed-corpus behavior is reported but not treated as a hard
failure unless the parser times out or crashes. Use strict mode when you want
CI to require clean handling of the hostile corpus and fatal tails:

```console
$ tests/parsers/run-docker.sh --strict
```

The script runs every selected parser even if one fails, then exits non-zero
after printing an aggregate failure list.

Some parser failures are useful findings, not harness bugs. For example,
Debian `bgpdump` 1.6.2 currently aborts on
`invalid_attr_duplicate_origin_len4`, a skip-class record with a valid ORIGIN
followed by a second ORIGIN encoded with length 4.

If your network provides an APT cache, pass it without making the Dockerfiles
network-specific:

```console
$ MRTGEN_APT_HTTP_PROXY=http://10.255.255.10:3142 tests/parsers/run-docker.sh bgpdump
```

When unset, Debian-based images use direct APT access. When set, the image
writes an internal apt config equivalent to:

```text
Acquire::http::Proxy "http://10.255.255.10:3142";
Acquire::https::Proxy "DIRECT";
```
