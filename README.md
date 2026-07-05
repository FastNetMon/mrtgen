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
| `standard_communities` | `"asn:value"`, `"no-export"`, `"no-advertise"`, `"no-export-subconfed"`, or `"0xNNNNNNNN"` | omitted |
| `extended_communities` | `"rt:admin:value"`, `"soo:admin:value"` (2- or 4-byte-AS form picked from the admin), or 16 raw hex digits | omitted |
| `large_communities`    | `"global:local1:local2"`                                             | omitted   |
| `path_id`              | u32 ADD-PATH Path Identifier; selects the `_ADDPATH` subtype         | omitted   |

Two encodings via `--routes-format`:

* `table-dump-v2` (default) — a RIB dump: one `PEER_INDEX_TABLE` followed by
  one `RIB_IPV4_UNICAST` / `RIB_IPV6_UNICAST` (or `_ADDPATH`) record per
  route, in input order.
* `bgp4mp` — a stream of announcements: one `BGP4MP_MESSAGE_AS4` (or
  `_ADDPATH`) record per route, each carrying a BGP UPDATE (IPv6 routes go
  via MP_REACH_NLRI).

Unknown JSON keys are rejected so typos fail loudly. Output is deterministic
and comes with the same manifest as corpus mode: every record is
`expect: valid` and `details` echoes the route's fields for CI assertions.
The library entry points are `routes_from_json()` and `generate_from_routes()`.

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
| `skip`  | record content is broken but framing is honest; parser must skip it and keep loading |
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
and package installs out of the host system.

```console
$ tests/parsers/run-docker.sh
```

The default run builds and executes:

* `mrtparse` from PyPI
* `bgpdump` from the Debian package archive
* `bgpkit-parser` from Cargo with its CLI feature enabled

You can run one parser at a time:

```console
$ tests/parsers/run-docker.sh mrtparse
$ tests/parsers/run-docker.sh bgpdump
$ tests/parsers/run-docker.sh bgpkit-parser
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
