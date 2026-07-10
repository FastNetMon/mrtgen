//! Deterministic corpus assembly.
//!
//! `generate()` always produces byte-identical output for the same
//! [`GeneratorConfig`]: no clocks, no randomness. Every field is derived
//! from the record's position in the corpus, and the accompanying
//! [`Manifest`] records offset, size and expected parser outcome for
//! each record so CI can verify a parser loaded exactly what it should.

use serde_json::json;

use crate::bgp;
use crate::invalid;
use crate::manifest::{CorpusProfile, Counts, Expect, Manifest, RecordEntry};
use crate::records::{self, Peer, RibEntry};
use crate::types::*;
use crate::writer::MrtRecord;

/// Which abort-class damage to append as the file's final bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatalKind {
    /// Header Length promises more bytes than remain before EOF.
    LengthOverrunsEof,
    /// The file ends inside an MRT common header.
    TruncatedHeader,
    /// Header Length is 0xFFFFFFFF.
    HugeLength,
}

impl FatalKind {
    pub const ALL: [FatalKind; 3] = [FatalKind::LengthOverrunsEof, FatalKind::TruncatedHeader, FatalKind::HugeLength];

    pub fn kind_name(self) -> &'static str {
        match self {
            FatalKind::LengthOverrunsEof => "fatal_length_overruns_eof",
            FatalKind::TruncatedHeader => "fatal_truncated_header",
            FatalKind::HugeLength => "fatal_huge_length",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Timestamp of the first record; record N uses `base_timestamp + N`.
    pub base_timestamp: u32,
    /// Emit the well-formed records covering all standard types/subtypes.
    pub include_valid: bool,
    /// Emit skip-class malformed records.
    pub include_skip: bool,
    /// Emit the communities × ADD-PATH combination records (both the legal
    /// combinations and the deliberately-illegal-but-skippable ones).
    pub include_combo: bool,
    /// Emit the RFC 7606 attribute error-handling records (malformed AS_PATH
    /// segments, bad attribute flags/length, MP_REACH/UNREACH damage, etc.).
    pub include_attr_errors: bool,
    /// Append one abort-class tail as the file's final bytes.
    pub fatal: Option<FatalKind>,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            base_timestamp: 1_600_000_000,
            include_valid: true,
            include_skip: true,
            include_combo: true,
            include_attr_errors: true,
            fatal: None,
        }
    }
}

/// A generated MRT file plus its manifest.
#[derive(Debug, Clone)]
pub struct Corpus {
    pub bytes: Vec<u8>,
    pub manifest: Manifest,
}

struct Builder {
    bytes: Vec<u8>,
    entries: Vec<RecordEntry>,
    counts: Counts,
    base_timestamp: u32,
    profile: CorpusProfile,
}

impl Builder {
    fn tags(&self, rec: &MrtRecord, kind: &str, expect: Expect) -> Vec<String> {
        let mut tags = vec![match expect {
            Expect::Valid => "valid",
            Expect::Skip => "skip",
            Expect::Abort => "abort",
        }.into()];
        let family = match rec.mrt_type {
            TABLE_DUMP => "table_dump",
            TABLE_DUMP_V2 => "table_dump_v2",
            BGP4MP | BGP4MP_ET => "bgp4mp",
            OSPFV2 | OSPFV3 | OSPFV3_ET => "ospf",
            ISIS | ISIS_ET => "isis",
            _ => "unknown",
        };
        tags.push(family.into());
        if kind.contains("boundary") { tags.push("boundary".into()); }
        if kind.starts_with("stress_") { tags.push("stress".into()); }
        tags
    }

    fn next_timestamp(&self) -> u32 {
        self.base_timestamp + self.entries.len() as u32
    }

    fn push(&mut self, rec: MrtRecord, kind: &str, expect: Expect, description: &str, details: serde_json::Value) {
        let offset = self.bytes.len() as u64;
        rec.encode_into(&mut self.bytes);
        match expect {
            Expect::Valid => self.counts.valid += 1,
            Expect::Skip => self.counts.skip += 1,
            Expect::Abort => self.counts.abort += 1,
        }
        let tags = self.tags(&rec, kind, expect);
        self.entries.push(RecordEntry {
            index: self.entries.len(),
            offset,
            size: rec.encoded_len() as u64,
            mrt_type: rec.mrt_type,
            subtype: rec.subtype,
            timestamp: rec.timestamp,
            kind: kind.to_string(),
            expect,
            description: description.to_string(),
            tags,
            details,
        });
    }

    fn push_raw(&mut self, raw: Vec<u8>, mrt_type: u16, subtype: u16, timestamp: u32, kind: &str, description: &str) {
        let offset = self.bytes.len() as u64;
        let size = raw.len() as u64;
        self.bytes.extend_from_slice(&raw);
        self.counts.abort += 1;
        self.entries.push(RecordEntry {
            index: self.entries.len(),
            offset,
            size,
            mrt_type,
            subtype,
            timestamp,
            kind: kind.to_string(),
            expect: Expect::Abort,
            description: description.to_string(),
            tags: vec!["abort".into(), "framing".into()],
            details: serde_json::Value::Null,
        });
    }
}

fn v6(last: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0d;
    a[3] = 0xb8;
    a[15] = last;
    a
}

/// The fixed peer table used by every TABLE_DUMP_V2 RIB record. Index:
/// 0 = IPv4 peer / 2-byte AS, 1 = IPv4 / 4-byte AS,
/// 2 = IPv6 / 4-byte AS,     3 = IPv6 / 2-byte AS.
pub fn corpus_peers() -> Vec<Peer> {
    vec![
        Peer { bgp_id: [192, 0, 2, 10], ip: vec![10, 0, 0, 1], asn: 64500, as4: false },
        Peer { bgp_id: [192, 0, 2, 11], ip: vec![10, 0, 0, 2], asn: 4_200_000_001, as4: true },
        Peer { bgp_id: [192, 0, 2, 12], ip: v6(1).to_vec(), asn: 4_200_000_002, as4: true },
        Peer { bgp_id: [192, 0, 2, 13], ip: v6(2).to_vec(), asn: 64501, as4: false },
    ]
}

/// Generate the corpus described by `cfg`.
pub fn generate(cfg: &GeneratorConfig) -> Corpus {
    generate_profile(CorpusProfile::Standard, cfg)
}

/// Generate either the compact standard corpus or the standard corpus plus
/// deterministic high-volume stress cases.
pub fn generate_profile(profile: CorpusProfile, cfg: &GeneratorConfig) -> Corpus {
    let mut b = Builder { bytes: Vec::new(), entries: Vec::new(), counts: Counts::default(), base_timestamp: cfg.base_timestamp, profile };

    if cfg.include_valid {
        emit_valid(&mut b);
    }
    if cfg.include_skip {
        emit_skip(&mut b);
    }
    if cfg.include_combo {
        emit_combo(&mut b);
    }
    if cfg.include_attr_errors {
        emit_attr_errors(&mut b);
    }
    emit_edge_cases(&mut b, cfg.include_valid, cfg.include_skip);
    if profile == CorpusProfile::Stress {
        emit_stress(&mut b, cfg.include_valid, cfg.include_skip);
    }
    if let Some(fatal) = cfg.fatal {
        emit_fatal(&mut b, fatal);
    }

    let manifest = Manifest {
        generator: "mrtgen".into(),
        generator_version: env!("CARGO_PKG_VERSION").into(),
        profile: b.profile,
        file_size: b.bytes.len() as u64,
        counts: b.counts,
        records: b.entries,
    };
    Corpus { bytes: b.bytes, manifest }
}

fn emit_stress(b: &mut Builder, include_valid: bool, include_skip: bool) {
    if include_valid {
        // High record-count stream: unique kinds retain the corpus invariant
        // and make a premature stop directly visible in the manifest.
        let keepalive = bgp::bgp_keepalive();
        for i in 0..100_000u32 {
            let ts = b.next_timestamp();
            b.push(
                records::bgp4mp_message(ts, BGP4MP, None, BGP4MP_MESSAGE_AS4, 4_200_000_001, 4_200_000_002, (i & 0xffff) as u16, &[192,0,2,1], &[192,0,2,2], &keepalive),
                &format!("stress_keepalive_{i:06}"), Expect::Valid,
                "High-volume BGP4MP KEEPALIVE stream record", json!({"ordinal":i}),
            );
        }

        // Maximum representable Peer Count, alternating all four peer-type
        // combinations without allocating per-record metadata.
        let peers: Vec<Peer> = (0..u16::MAX).map(|i| {
            let ipv6 = i & 1 != 0;
            let as4 = i & 2 != 0;
            let ip = if ipv6 {
                let mut a=v6(0); a[14..].copy_from_slice(&i.to_be_bytes()); a.to_vec()
            } else {
                vec![10, (i >> 8) as u8, i as u8, 1]
            };
            Peer { bgp_id: [10, (i >> 8) as u8, i as u8, 2], ip, asn: if as4 { 4_200_000_000 + i as u32 } else { i as u32 }, as4 }
        }).collect();
        let ts=b.next_timestamp();
        b.push(records::peer_index_table(ts,[192,0,2,100],"stress-max-peers",&peers),
               "stress_peer_count_65535",Expect::Valid,"PEER_INDEX_TABLE at the u16 peer-count limit",
               json!({"peer_count":65535,"encoded_entries":65535}));

        // Largest legal RIB entry count. Empty attributes make the case large
        // enough to exercise loops without wasting tens of megabytes.
        let entries: Vec<RibEntry> = (0..u16::MAX).map(|i| RibEntry::new(i, ts, Vec::new())).collect();
        let ts=b.next_timestamp();
        b.push(records::rib_afi_safi(ts,RIB_IPV4_UNICAST,0xffff_ffff,&bgp::nlri_v4([0,0,0,0],0),&entries),
               "stress_rib_entry_count_65535",Expect::Valid,"RIB at the u16 entry-count limit",
               json!({"entry_count":65535,"sequence":u32::MAX}));

        // Attribute Length is exactly 65535 bytes: a four-byte extended TLV
        // header plus 65531 opaque value bytes.
        let ts=b.next_timestamp();
        let attrs=bgp::attribute(FLAG_OPTIONAL|FLAG_TRANSITIVE,240,&vec![0x5a;65531]);
        debug_assert_eq!(attrs.len(),65535);
        let entry=RibEntry::new(0,ts,attrs);
        b.push(records::rib_afi_safi(ts,RIB_IPV4_UNICAST,0xffff_fffe,&bgp::nlri_v4([203,0,113,0],24),&[entry]),
               "stress_rib_attribute_length_65535",Expect::Valid,"RIB entry at the u16 Attribute Length limit",
               json!({"attribute_length":65535}));

        // AS_SEQUENCE count byte at 255, carried in TABLE_DUMP_V2's AS4 form.
        let ts=b.next_timestamp();
        let asns:Vec<u32>=(0..255).map(|i|64500+i).collect();
        let mut attrs=bgp::attr_origin(0); attrs.extend(bgp::attr_as_path_4b(&asns)); attrs.extend(bgp::attr_next_hop([192,0,2,1]));
        let entry=RibEntry::new(0,ts,attrs);
        b.push(records::rib_afi_safi(ts,RIB_IPV4_UNICAST,0xffff_fffd,&bgp::nlri_v4([198,51,100,0],24),&[entry]),
               "stress_as_sequence_count_255",Expect::Valid,"AS_SEQUENCE at its one-octet count limit",json!({"as_count":255}));
    }

    if include_skip {
        // Systematic inner-length mutations remain skip-class because MRT
        // framing is honest; each is later paired with a recovery sentinel.
        for declared in [0u16, 1, 17, 18, 20, 4095, 4097, u16::MAX] {
            let ts=b.next_timestamp();
            let msg=bgp::bgp_message_raw([0xff;16],declared,BGP_KEEPALIVE,&[]);
            b.push(records::bgp4mp_message(ts,BGP4MP,None,BGP4MP_MESSAGE_AS4,4_200_000_001,4_200_000_002,0,&[192,0,2,1],&[192,0,2,2],&msg),
                   &format!("stress_mutation_bgp_length_{declared}"),Expect::Skip,
                   "Systematic BGP Length-field mutation",json!({"declared":declared,"actual":19}));
        }
    }
}

/// Boundary and protocol-state cases are kept independent from the historic
/// sections so `--no-valid` and `--no-skip` continue to mean exactly what
/// their names say while valid edge cases are never lost from valid-only CI.
fn emit_edge_cases(b: &mut Builder, include_valid: bool, include_skip: bool) {
    let wrap_bgp = |ts: u32, msg: &[u8]| {
        records::bgp4mp_message(ts, BGP4MP, None, BGP4MP_MESSAGE_AS4, 4_200_000_001, 4_200_000_002, 0, &[192, 0, 2, 1], &[192, 0, 2, 2], msg)
    };

    if include_valid {
        // Empty structures and count boundaries.
        let ts = b.next_timestamp();
        b.push(
            records::peer_index_table(ts, [0, 0, 0, 0], "", &[]),
            "boundary_peer_index_zero", Expect::Valid,
            "PEER_INDEX_TABLE with empty view name and zero peers",
            json!({"peer_count": 0, "view_name_len": 0}),
        );
        let ts = b.next_timestamp();
        b.push(
            records::rib_afi_safi(ts, RIB_IPV4_UNICAST, 0, &bgp::nlri_v4([0, 0, 0, 0], 0), &[]),
            "boundary_rib_zero_entries", Expect::Valid,
            "RIB_IPV4_UNICAST default route with zero entries",
            json!({"prefix": "0.0.0.0/0", "entry_count": 0, "sequence": 0}),
        );

        // Non-octet-aligned prefixes on both sides of octet transitions.
        for (i, bits) in [1u8, 7, 8, 9, 31].into_iter().enumerate() {
            let ts = b.next_timestamp();
            let prefix = [0x80, 0, 0, 0];
            let entry = RibEntry::new(0, ts, records::standard_attrs_v4(i as u32 + 60));
            b.push(
                records::rib_afi_safi(ts, RIB_IPV4_UNICAST, 2_000 + i as u32, &bgp::nlri_v4(prefix, bits), &[entry]),
                &format!("boundary_rib_v4_prefix_{bits}"), Expect::Valid,
                "Valid non-octet-aligned IPv4 prefix boundary",
                json!({"bits": bits, "entry_count": 1}),
            );
        }
        let ts = b.next_timestamp();
        let mut p127 = [0u8; 16]; p127[0] = 0x20; p127[1] = 0x01; p127[2] = 0x0d; p127[3] = 0xb8; p127[15] = 0xfe;
        let entry = RibEntry::new(2, ts, records::standard_attrs_v6(60));
        b.push(
            records::rib_afi_safi(ts, RIB_IPV6_UNICAST, 2_010, &bgp::nlri_v6(p127, 127), &[entry]),
            "boundary_rib_v6_prefix_127", Expect::Valid,
            "Valid non-octet-aligned IPv6 /127 prefix", json!({"bits": 127, "entry_count": 1}),
        );

        // Empty/EOR, withdrawal-only, multi-prefix, and MP_UNREACH UPDATEs.
        let valid_updates = [
            ("boundary_bgp_empty_update", bgp::bgp_update(&[], &[], &[]), json!({"mode": "eor"})),
            ("boundary_bgp_withdraw_only", bgp::bgp_update(&bgp::nlri_v4([198, 51, 100, 0], 24), &[], &[]), json!({"withdrawn": 1})),
            ("boundary_bgp_multi_nlri", {
                let mut attrs = bgp::attr_origin(0); attrs.extend(bgp::attr_as_path_4b(&[64500])); attrs.extend(bgp::attr_next_hop([192,0,2,1]));
                let mut nlri = bgp::nlri_v4([10,0,0,0], 8); nlri.extend(bgp::nlri_v4([172,16,0,0], 12));
                bgp::bgp_update(&[], &attrs, &nlri)
            }, json!({"announced": 2})),
            ("boundary_bgp_mp_unreach_v6", {
                let attrs = bgp::attr_mp_unreach(BGP_AFI_IPV6, SAFI_UNICAST, &bgp::nlri_v6(v6(0), 64));
                bgp::bgp_update(&[], &attrs, &[])
            }, json!({"withdrawn": 1, "afi": 2})),
        ];
        for (kind, msg, details) in valid_updates {
            let ts = b.next_timestamp();
            b.push(wrap_bgp(ts, &msg), kind, Expect::Valid, "Valid BGP UPDATE boundary form", details);
        }

        // Exact maximum RFC 4271 message length (NOTIFICATION data is opaque).
        let ts = b.next_timestamp();
        let msg = bgp::bgp_notification(6, 0, &vec![0x5a; 4096 - 21]);
        debug_assert_eq!(msg.len(), 4096);
        b.push(wrap_bgp(ts, &msg), "boundary_bgp_length_4096", Expect::Valid,
               "BGP message exactly at the RFC 4271 4096-byte maximum", json!({"bgp_message_len": 4096}));

        // Attribute short/extended-length transition in TABLE_DUMP_V2, where
        // the enclosing record is not subject to BGP's 4096-byte message cap.
        for len in [255usize, 256] {
            let ts = b.next_timestamp();
            let mut attrs = records::standard_attrs_v4(70 + len as u32);
            attrs.extend(bgp::attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, 240, &vec![0xa5; len]));
            let entry = RibEntry::new(0, ts, attrs);
            b.push(records::rib_afi_safi(ts, RIB_IPV4_UNICAST, 2_100 + len as u32, &bgp::nlri_v4([203,0,113,0],24), &[entry]),
                   &format!("boundary_attr_value_{len}"), Expect::Valid,
                   "Unknown optional-transitive attribute at the one/two-octet length transition",
                   json!({"attribute_value_len": len, "extended_length": len > 255}));
        }

        // Every BGP4MP subtype under ET framing, including both state-change
        // forms. The state bodies use the same prelude encoder as messages.
        let et_subtypes = [
            BGP4MP_STATE_CHANGE, BGP4MP_MESSAGE, BGP4MP_MESSAGE_AS4,
            BGP4MP_STATE_CHANGE_AS4, BGP4MP_MESSAGE_LOCAL,
            BGP4MP_MESSAGE_AS4_LOCAL, BGP4MP_MESSAGE_ADDPATH,
            BGP4MP_MESSAGE_AS4_ADDPATH, BGP4MP_MESSAGE_LOCAL_ADDPATH,
            BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH,
        ];
        for subtype in et_subtypes {
            let ts = b.next_timestamp();
            let state = matches!(subtype, BGP4MP_STATE_CHANGE | BGP4MP_STATE_CHANGE_AS4);
            let payload = if state { vec![0, STATE_IDLE as u8, 0, STATE_ESTABLISHED as u8] } else { bgp::bgp_keepalive() };
            let as4 = matches!(subtype, BGP4MP_MESSAGE_AS4 | BGP4MP_STATE_CHANGE_AS4 | BGP4MP_MESSAGE_AS4_LOCAL | BGP4MP_MESSAGE_AS4_ADDPATH | BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH);
            let (pa, la) = if as4 { (4_200_000_001, 4_200_000_002) } else { (64500, 64501) };
            b.push(records::bgp4mp_message(ts, BGP4MP_ET, Some(if subtype == 0 { 0 } else { 999_999 }), subtype, pa, la, u16::MAX, &[192,0,2,1], &[192,0,2,2], &payload),
                   &format!("boundary_bgp4mp_et_subtype_{subtype}"), Expect::Valid,
                   "BGP4MP_ET subtype and microsecond boundary", json!({"subtype": subtype, "microsecond": if subtype == 0 {0} else {999999}}));
        }

        emit_igp_edge_cases(b, true);
    }

    if include_skip {
        // Inner BGP length and message-type failures with honest MRT framing.
        let malformed = [
            ("boundary_bgp_length_18", bgp::bgp_message_raw([0xff;16], 18, BGP_KEEPALIVE, &[]), "length_below_minimum"),
            ("boundary_bgp_length_4097", bgp::bgp_message_raw([0xff;16], 4097, BGP_NOTIFICATION, &vec![0; 4097-19]), "length_above_maximum"),
            ("boundary_bgp_unknown_message_type", bgp::bgp_message(255, &[]), "unknown_message_type"),
            ("boundary_bgp_keepalive_payload", bgp::bgp_message(BGP_KEEPALIVE, &[1]), "keepalive_nonempty"),
            ("boundary_bgp_trailing_bytes", { let mut x=bgp::bgp_keepalive(); x.extend([0xde,0xad]); x }, "bytes_after_message"),
        ];
        for (kind, msg, reason) in malformed {
            let ts = b.next_timestamp();
            b.push(wrap_bgp(ts, &msg), kind, Expect::Skip, "Malformed BGP message boundary", json!({"reason": reason}));
        }

        // Prefix truncation and non-zero padding bits.
        for (kind, nlri, reason) in [
            ("boundary_bgp_prefix_truncated", vec![24, 192, 0], "prefix_octets_truncated"),
            ("boundary_bgp_prefix_padding_bits", vec![9, 10, 0x7f], "nonzero_unused_prefix_bits"),
        ] {
            let ts = b.next_timestamp();
            let mut attrs=bgp::attr_origin(0); attrs.extend(bgp::attr_as_path_4b(&[64500])); attrs.extend(bgp::attr_next_hop([192,0,2,1]));
            let msg=bgp::bgp_update(&[], &attrs, &nlri);
            b.push(wrap_bgp(ts,&msg),kind,Expect::Skip,"Malformed NLRI prefix boundary",json!({"reason":reason}));
        }

        // Missing mandatory attributes, duplicate NEXT_HOP, wrong flags, and
        // legal-looking AS segment containers with illegal structure.
        let attr_cases = [
            ("boundary_attr_missing_origin", { let mut a=bgp::attr_as_path_4b(&[64500]); a.extend(bgp::attr_next_hop([192,0,2,1])); a }, "missing_origin"),
            ("boundary_attr_missing_as_path", { let mut a=bgp::attr_origin(0); a.extend(bgp::attr_next_hop([192,0,2,1])); a }, "missing_as_path"),
            ("boundary_attr_duplicate_nexthop", { let mut a=bgp::attr_origin(0); a.extend(bgp::attr_as_path_4b(&[64500])); a.extend(bgp::attr_next_hop([192,0,2,1])); a.extend(bgp::attr_next_hop([192,0,2,2])); a }, "duplicate_attribute"),
            ("boundary_attr_localpref_optional", { let mut a=bgp::attr_origin(0); a.extend(bgp::attr_as_path_4b(&[64500])); a.extend(bgp::attr_next_hop([192,0,2,1])); a.extend(bgp::attribute(FLAG_OPTIONAL,ATTR_LOCAL_PREF,&100u32.to_be_bytes())); a }, "wrong_flags"),
            ("boundary_attr_unknown_wellknown", { let mut a=bgp::attr_origin(0); a.extend(bgp::attr_as_path_4b(&[64500])); a.extend(bgp::attr_next_hop([192,0,2,1])); a.extend(bgp::attribute(FLAG_TRANSITIVE,241,&[1])); a }, "unknown_well_known"),
        ];
        for (kind, attrs, reason) in attr_cases {
            let ts=b.next_timestamp(); let msg=bgp::bgp_update(&[],&attrs,&bgp::nlri_v4([198,51,100,0],24));
            b.push(wrap_bgp(ts,&msg),kind,Expect::Skip,"BGP path-attribute semantic error",json!({"reason":reason}));
        }

        // TABLE_DUMP_V2 count and peer-type damage.
        let ts=b.next_timestamp();
        let mut body=vec![0,0,0,0, 0,0, 0,1]; // collector, empty view, one peer
        body.extend([0x80, 192,0,2,1, 192,0,2,2, 0xfc,0x00]);
        b.push(MrtRecord::new(ts,TABLE_DUMP_V2,PEER_INDEX_TABLE,body),"boundary_peer_reserved_type_bits",Expect::Skip,
               "PEER_INDEX_TABLE peer type uses reserved bits",json!({"reason":"reserved_peer_type_bits"}));
        let ts=b.next_timestamp();
        let mut body=Vec::new(); body.extend(7u32.to_be_bytes()); body.extend([24,203,0,113]); body.extend(2u16.to_be_bytes());
        let e=RibEntry::new(0,ts,records::standard_attrs_v4(1));
        let one=records::rib_afi_safi(ts,RIB_IPV4_UNICAST,7,&bgp::nlri_v4([203,0,113,0],24),&[e]);
        body.extend_from_slice(&one.body[10..]); // encode one entry while count claims two
        b.push(MrtRecord::new(ts,TABLE_DUMP_V2,RIB_IPV4_UNICAST,body),"boundary_rib_entry_count_plus_one",Expect::Skip,
               "RIB entry count claims one more entry than present",json!({"reason":"entry_count_overrun"}));

        // ET timestamp outside its defined microsecond range.
        let ts=b.next_timestamp();
        b.push(records::bgp4mp_message(ts,BGP4MP_ET,Some(1_000_000),BGP4MP_MESSAGE_AS4,4_200_000_001,4_200_000_002,0,&[192,0,2,1],&[192,0,2,2],&bgp::bgp_keepalive()),
               "boundary_et_microsecond_1000000",Expect::Skip,"ET microsecond timestamp outside 0..999999",json!({"reason":"microsecond_out_of_range"}));

        emit_igp_edge_cases(b, false);
    }
}

fn emit_igp_edge_cases(b: &mut Builder, valid: bool) {
    if valid {
        // Minimal fixed headers for the remaining OSPF packet types. Their
        // bodies are deliberately small but internally length-consistent.
        for ty in 2u8..=5 {
            let ts=b.next_timestamp();
            let mut pdu=vec![2,ty,0,24,192,0,2,40,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
            let pdu_len = pdu.len() as u16;
            pdu[2..4].copy_from_slice(&pdu_len.to_be_bytes());
            b.push(records::ospfv2(ts,[192,0,2,40],[192,0,2,41],&pdu),&format!("boundary_ospfv2_type_{ty}"),Expect::Valid,
                   "Length-consistent OSPFv2 packet-type sample",json!({"ospf_type":ty,"pdu_len":pdu.len()}));
        }
        for ty in 2u8..=5 {
            let ts=b.next_timestamp();
            let mut pdu=vec![3,ty,0,16,192,0,2,50,0,0,0,0,0,0,0,0];
            let pdu_len = pdu.len() as u16;
            pdu[2..4].copy_from_slice(&pdu_len.to_be_bytes());
            b.push(records::ospfv3(ts,None,v6(50),v6(51),&pdu),&format!("boundary_ospfv3_type_{ty}"),Expect::Valid,
                   "Length-consistent OSPFv3 packet-type sample",json!({"ospf_type":ty,"pdu_len":pdu.len()}));
        }
        for ty in [15u8,16,17,18,20,24,25,26,27] {
            let ts=b.next_timestamp();
            let pdu=vec![0x83,8,1,0,ty,1,0,0];
            b.push(records::isis(ts,None,&pdu),&format!("boundary_isis_pdu_{ty}"),Expect::Valid,
                   "IS-IS PDU family header sample",json!({"pdu_type":ty,"pdu_len":pdu.len()}));
        }
    } else {
        let ts=b.next_timestamp();
        let pdu=vec![2,1,0,44,0,0,0,0];
        b.push(records::ospfv2(ts,[192,0,2,1],[192,0,2,2],&pdu),"boundary_ospfv2_length_overrun",Expect::Skip,
               "OSPFv2 packet length exceeds the available PDU",json!({"reason":"pdu_length_overrun"}));
        let ts=b.next_timestamp();
        let pdu=vec![3,255,0,16,0,0,0,0,0,0,0,0,0,0,0,0];
        b.push(records::ospfv3(ts,None,v6(1),v6(2),&pdu),"boundary_ospfv3_unknown_type",Expect::Skip,
               "OSPFv3 packet has an unknown type",json!({"reason":"unknown_ospf_type"}));
        let ts=b.next_timestamp();
        b.push(records::isis(ts,None,&[0x83,27,1,0,15]),"boundary_isis_truncated_header",Expect::Skip,
               "IS-IS PDU ends inside its fixed header",json!({"reason":"truncated_pdu_header"}));
        let ts=b.next_timestamp();
        b.push(records::isis(ts,None,&[0x83,8,1,0,31,1,0,0]),"boundary_isis_unknown_pdu",Expect::Skip,
               "IS-IS PDU uses an unassigned PDU type",json!({"reason":"unknown_pdu_type"}));
    }
}

fn emit_valid(b: &mut Builder) {
    let peers = corpus_peers();

    // --- TABLE_DUMP_V2 ------------------------------------------------
    let ts = b.next_timestamp();
    b.push(
        records::peer_index_table(ts, [192, 0, 2, 100], "mrtgen-view", &peers),
        "peer_index_table",
        Expect::Valid,
        "TABLE_DUMP_V2 PEER_INDEX_TABLE with 4 peers covering all peer-type bit combinations",
        json!({
            "collector_bgp_id": "192.0.2.100",
            "view_name": "mrtgen-view",
            "peer_count": 4,
            "peers": [
                {"ip": "10.0.0.1", "asn": 64500},
                {"ip": "10.0.0.2", "asn": 4200000001u32},
                {"ip": "2001:db8::1", "asn": 4200000002u32},
                {"ip": "2001:db8::2", "asn": 64501},
            ],
        }),
    );

    // AFI/SAFI-specific RIB subtypes, plain and ADD-PATH.
    let v4_cases = [
        (RIB_IPV4_UNICAST, "rib_ipv4_unicast", false),
        (RIB_IPV4_MULTICAST, "rib_ipv4_multicast", false),
        (RIB_IPV4_UNICAST_ADDPATH, "rib_ipv4_unicast_addpath", true),
        (RIB_IPV4_MULTICAST_ADDPATH, "rib_ipv4_multicast_addpath", true),
    ];
    for (i, (subtype, kind, addpath)) in v4_cases.iter().enumerate() {
        let ts = b.next_timestamp();
        let seq = i as u32 + 1;
        let prefix = [10, 100 + i as u8, 0, 0];
        let mut e0 = RibEntry::new(0, ts, records::standard_attrs_v4(seq));
        let mut e1 = RibEntry::new(1, ts, records::standard_attrs_v4(seq + 10));
        if *addpath {
            e0.path_id = Some(seq);
            e1.path_id = Some(seq + 100);
        }
        b.push(
            records::rib_afi_safi(ts, *subtype, seq, &bgp::nlri_v4(prefix, 16), &[e0, e1]),
            kind,
            Expect::Valid,
            "TABLE_DUMP_V2 IPv4 RIB record with 2 RIB entries",
            json!({
                "sequence": seq,
                "prefix": format!("10.{}.0.0/16", 100 + i),
                "entry_count": 2,
                "peer_indexes": [0, 1],
                "path_ids": if *addpath { json!([seq, seq + 100]) } else { json!(null) },
            }),
        );
    }

    let v6_cases = [
        (RIB_IPV6_UNICAST, "rib_ipv6_unicast", false),
        (RIB_IPV6_MULTICAST, "rib_ipv6_multicast", false),
        (RIB_IPV6_UNICAST_ADDPATH, "rib_ipv6_unicast_addpath", true),
        (RIB_IPV6_MULTICAST_ADDPATH, "rib_ipv6_multicast_addpath", true),
    ];
    for (i, (subtype, kind, addpath)) in v6_cases.iter().enumerate() {
        let ts = b.next_timestamp();
        let seq = i as u32 + 10;
        let mut p = v6(0);
        p[4] = i as u8 + 1;
        let mut e = RibEntry::new(2, ts, records::standard_attrs_v6(seq));
        if *addpath {
            e.path_id = Some(seq);
        }
        b.push(
            records::rib_afi_safi(ts, *subtype, seq, &bgp::nlri_v6(p, 48), &[e]),
            kind,
            Expect::Valid,
            "TABLE_DUMP_V2 IPv6 RIB record with 1 RIB entry",
            json!({
                "sequence": seq,
                "prefix": format!("2001:db8:{:x}00::/48", i as u8 + 1),
                "entry_count": 1,
                "peer_indexes": [2],
                "path_ids": if *addpath { json!([seq]) } else { json!(null) },
            }),
        );
    }

    // RIB_GENERIC, plain and ADD-PATH (NLRI carries the path id itself).
    let ts = b.next_timestamp();
    let entry = RibEntry::new(1, ts, records::standard_attrs_v4(42));
    b.push(
        records::rib_generic(ts, RIB_GENERIC, 20, BGP_AFI_IPV4, SAFI_UNICAST, &bgp::nlri_v4([203, 0, 113, 0], 24), &[entry]),
        "rib_generic",
        Expect::Valid,
        "TABLE_DUMP_V2 RIB_GENERIC record (AFI 1 / SAFI 1)",
        json!({"sequence": 20, "afi": 1, "safi": 1, "prefix": "203.0.113.0/24", "entry_count": 1}),
    );

    let ts = b.next_timestamp();
    let entry = RibEntry::new(1, ts, records::standard_attrs_v4(43));
    b.push(
        records::rib_generic(
            ts,
            RIB_GENERIC_ADDPATH,
            21,
            BGP_AFI_IPV4,
            SAFI_UNICAST,
            &bgp::nlri_v4_addpath(7, [203, 0, 113, 128], 25),
            &[entry],
        ),
        "rib_generic_addpath",
        Expect::Valid,
        "TABLE_DUMP_V2 RIB_GENERIC_ADDPATH record (path id in NLRI)",
        json!({"sequence": 21, "afi": 1, "safi": 1, "prefix": "203.0.113.128/25", "path_id": 7, "entry_count": 1}),
    );

    // RIB_GENERIC carrying the MPLS VPN address families (SAFI 128,
    // RFC 4364): the NLRI is label + Route Distinguisher + prefix, the
    // length octet counts all three, and the next hop is RD-prefixed.
    let ts = b.next_timestamp();
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_4b(&[64500, 4_200_000_001]));
    attrs.extend(bgp::attr_mp_reach_td2(&bgp::vpn_next_hop(&[192, 0, 2, 5])));
    attrs.extend(bgp::attr_ext_communities(&[[0x00, 0x02, 0xFB, 0xF4, 0x00, 0x00, 0x00, 0x01]])); // RT 64500:1
    let entry = RibEntry::new(1, ts, attrs);
    b.push(
        records::rib_generic(ts, RIB_GENERIC, 22, BGP_AFI_IPV4, SAFI_MPLS_VPN, &bgp::nlri_vpn(100, bgp::rd_type0(64500, 1), &[10, 30, 0, 0], 24), &[entry]),
        "rib_generic_vpnv4",
        Expect::Valid,
        "TABLE_DUMP_V2 RIB_GENERIC VPNv4 route (AFI 1 / SAFI 128): label + type-0 RD + prefix NLRI, 12-byte RD-prefixed next hop, Route Target",
        json!({"sequence": 22, "afi": 1, "safi": 128, "rd": "64500:1", "label": 100, "prefix": "10.30.0.0/24", "nlri_bits": 112, "route_target": "rt:64500:1", "entry_count": 1}),
    );

    let ts = b.next_timestamp();
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_4b(&[64500, 4_200_000_002]));
    attrs.extend(bgp::attr_mp_reach_td2(&bgp::vpn_next_hop(&v6(9))));
    attrs.extend(bgp::attr_ext_communities(&[[0x00, 0x02, 0xFB, 0xF4, 0x00, 0x00, 0x00, 0x02]])); // RT 64500:2
    let entry = RibEntry::new(2, ts, attrs);
    let mut p = v6(0);
    p[5] = 0x64;
    b.push(
        records::rib_generic(ts, RIB_GENERIC, 23, BGP_AFI_IPV6, SAFI_MPLS_VPN, &bgp::nlri_vpn(200, bgp::rd_type1([192, 0, 2, 66], 2), &p, 48), &[entry]),
        "rib_generic_vpnv6",
        Expect::Valid,
        "TABLE_DUMP_V2 RIB_GENERIC VPNv6 route (AFI 2 / SAFI 128): label + type-1 RD + prefix NLRI, 24-byte RD-prefixed next hop, Route Target",
        json!({"sequence": 23, "afi": 2, "safi": 128, "rd": "192.0.2.66:2", "label": 200, "prefix": "2001:db8:64::/48", "nlri_bits": 136, "route_target": "rt:64500:2", "entry_count": 1}),
    );

    // --- legacy TABLE_DUMP ---------------------------------------------
    let ts = b.next_timestamp();
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500, 65000]));
    attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
    b.push(
        records::table_dump(ts, AFI_IPV4, 0, 1, &[10, 200, 0, 0], 16, ts, &[192, 0, 2, 1], 64500, &attrs),
        "table_dump_ipv4",
        Expect::Valid,
        "Legacy TABLE_DUMP AFI_IPv4 RIB entry",
        json!({"view": 0, "sequence": 1, "prefix": "10.200.0.0/16", "peer_ip": "192.0.2.1", "peer_as": 64500}),
    );

    let ts = b.next_timestamp();
    let mut attrs = bgp::attr_origin(0);
    attrs.extend(bgp::attr_as_path_2b(&[64500, 65001]));
    attrs.extend(bgp::attr_mp_reach(BGP_AFI_IPV6, SAFI_UNICAST, &v6(9), &bgp::nlri_v6(v6(0), 32)));
    b.push(
        records::table_dump(ts, AFI_IPV6, 0, 2, &v6(0), 32, ts, &v6(1), 64500, &attrs),
        "table_dump_ipv6",
        Expect::Valid,
        "Legacy TABLE_DUMP AFI_IPv6 RIB entry",
        json!({"view": 0, "sequence": 2, "prefix": "2001:db8::/32", "peer_ip": "2001:db8::1", "peer_as": 64500}),
    );

    // --- BGP4MP ----------------------------------------------------------
    let ts = b.next_timestamp();
    b.push(
        records::bgp4mp_state_change(ts, BGP4MP_STATE_CHANGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], STATE_OPEN_CONFIRM, STATE_ESTABLISHED),
        "bgp4mp_state_change",
        Expect::Valid,
        "BGP4MP_STATE_CHANGE OpenConfirm -> Established (2-byte AS)",
        json!({"peer_as": 64500, "local_as": 64501, "peer_ip": "192.0.2.1", "old_state": 5, "new_state": 6}),
    );

    let ts = b.next_timestamp();
    b.push(
        records::bgp4mp_state_change(ts, BGP4MP_STATE_CHANGE_AS4, 4_200_000_001, 4_200_000_002, 1, &v6(1), &v6(2), STATE_IDLE, STATE_CONNECT),
        "bgp4mp_state_change_as4",
        Expect::Valid,
        "BGP4MP_STATE_CHANGE_AS4 Idle -> Connect (4-byte AS, IPv6 peers)",
        json!({"peer_as": 4200000001u32, "local_as": 4200000002u32, "peer_ip": "2001:db8::1", "old_state": 1, "new_state": 2}),
    );

    // BGP4MP_MESSAGE with each of the four BGP message types.
    let update = {
        let mut attrs = bgp::attr_origin(0);
        attrs.extend(bgp::attr_as_path_2b(&[64500, 65000]));
        attrs.extend(bgp::attr_next_hop([192, 0, 2, 1]));
        bgp::bgp_update(&bgp::nlri_v4([198, 51, 100, 0], 25), &attrs, &bgp::nlri_v4([198, 51, 100, 128], 25))
    };
    let msg_cases: [(&str, Vec<u8>, u8, &str); 4] = [
        ("bgp4mp_message_update", update, BGP_UPDATE, "BGP4MP_MESSAGE carrying an UPDATE (withdraw + announce)"),
        ("bgp4mp_message_open", bgp::bgp_open(64500, 180, [192, 0, 2, 10]), BGP_OPEN, "BGP4MP_MESSAGE carrying an OPEN"),
        ("bgp4mp_message_keepalive", bgp::bgp_keepalive(), BGP_KEEPALIVE, "BGP4MP_MESSAGE carrying a KEEPALIVE"),
        ("bgp4mp_message_notification", bgp::bgp_notification(6, 2, &[]), BGP_NOTIFICATION, "BGP4MP_MESSAGE carrying a NOTIFICATION (Cease/Shutdown)"),
    ];
    for (kind, msg, bgp_type, desc) in msg_cases {
        let ts = b.next_timestamp();
        b.push(
            records::bgp4mp_message(ts, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &msg),
            kind,
            Expect::Valid,
            desc,
            json!({"peer_as": 64500, "local_as": 64501, "peer_ip": "192.0.2.1", "bgp_message_type": bgp_type,
                   "announced": if bgp_type == BGP_UPDATE { json!(["198.51.100.128/25"]) } else { json!(null) },
                   "withdrawn": if bgp_type == BGP_UPDATE { json!(["198.51.100.0/25"]) } else { json!(null) }}),
        );
    }

    // AS4 / LOCAL / ADDPATH message subtype matrix, IPv6 transport, one
    // UPDATE each. Non-AS4 subtypes MUST carry 2-byte AS numbers in the
    // AS_PATH as well (RFC 6396 section 4.4.2).
    let update6 = |as4: bool, addpath: bool| {
        let mut attrs = bgp::attr_origin(2);
        if as4 {
            attrs.extend(bgp::attr_as_path_4b(&[4_200_000_001, 64510]));
        } else {
            attrs.extend(bgp::attr_as_path_2b(&[64500, 64510]));
        }
        let nlri = bgp::nlri_v6(v6(0), 64);
        attrs.extend(bgp::attr_mp_reach(BGP_AFI_IPV6, SAFI_UNICAST, &v6(9), &if addpath { bgp::nlri_v6_addpath(3, v6(0), 64) } else { nlri }));
        bgp::bgp_update(&[], &attrs, &[])
    };
    let subtype_cases = [
        (BGP4MP_MESSAGE_AS4, "bgp4mp_message_as4", false),
        (BGP4MP_MESSAGE_LOCAL, "bgp4mp_message_local", false),
        (BGP4MP_MESSAGE_AS4_LOCAL, "bgp4mp_message_as4_local", false),
        (BGP4MP_MESSAGE_ADDPATH, "bgp4mp_message_addpath", true),
        (BGP4MP_MESSAGE_AS4_ADDPATH, "bgp4mp_message_as4_addpath", true),
        (BGP4MP_MESSAGE_LOCAL_ADDPATH, "bgp4mp_message_local_addpath", true),
        (BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH, "bgp4mp_message_as4_local_addpath", true),
    ];
    for (subtype, kind, addpath) in subtype_cases {
        let ts = b.next_timestamp();
        let as4 = matches!(subtype, BGP4MP_MESSAGE_AS4 | BGP4MP_MESSAGE_AS4_LOCAL | BGP4MP_MESSAGE_AS4_ADDPATH | BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH);
        let (peer_as, local_as) = if as4 { (4_200_000_001, 4_200_000_002) } else { (64500, 64501) };
        b.push(
            records::bgp4mp_message(ts, BGP4MP, None, subtype, peer_as, local_as, 2, &v6(1), &v6(2), &update6(as4, addpath)),
            kind,
            Expect::Valid,
            "BGP4MP message subtype carrying an IPv6 UPDATE via MP_REACH_NLRI",
            json!({"peer_as": peer_as, "local_as": local_as, "peer_ip": "2001:db8::1",
                   "bgp_message_type": BGP_UPDATE, "announced": ["2001:db8::/64"],
                   "path_id": if addpath { json!(3) } else { json!(null) }}),
        );
    }

    // BGP4MP UPDATE announcing a VPNv4 route via the full RFC 4760
    // MP_REACH_NLRI: SAFI 128, 12-byte RD-prefixed next hop, and a
    // label + RD + prefix NLRI whose length octet counts all three.
    let ts = b.next_timestamp();
    let update = {
        let mut a = bgp::attr_origin(0);
        a.extend(bgp::attr_as_path_2b(&[64500, 65000]));
        a.extend(bgp::attr_ext_communities(&[[0x00, 0x02, 0xFB, 0xF4, 0x00, 0x00, 0x00, 0x01]])); // RT 64500:1
        a.extend(bgp::attr_mp_reach(
            BGP_AFI_IPV4,
            SAFI_MPLS_VPN,
            &bgp::vpn_next_hop(&[192, 0, 2, 5]),
            &bgp::nlri_vpn(100, bgp::rd_type0(64500, 1), &[10, 30, 0, 0], 24),
        ));
        bgp::bgp_update(&[], &a, &[])
    };
    b.push(
        records::bgp4mp_message(ts, BGP4MP, None, BGP4MP_MESSAGE, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &update),
        "bgp4mp_message_vpnv4_update",
        Expect::Valid,
        "BGP4MP_MESSAGE UPDATE announcing a VPNv4 route (AFI 1 / SAFI 128) via MP_REACH_NLRI with an RD-prefixed next hop and a Route Target",
        json!({"peer_as": 64500, "local_as": 64501, "bgp_message_type": BGP_UPDATE,
               "afi": 1, "safi": 128, "rd": "64500:1", "label": 100,
               "announced": ["10.30.0.0/24"], "route_target": "rt:64500:1"}),
    );

    // BGP4MP_ET: extended timestamp header.
    let ts = b.next_timestamp();
    b.push(
        records::bgp4mp_message(ts, BGP4MP_ET, Some(250_000), BGP4MP_MESSAGE_AS4, 4_200_000_001, 4_200_000_002, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &bgp::bgp_keepalive()),
        "bgp4mp_et_message_as4",
        Expect::Valid,
        "BGP4MP_ET record (microsecond timestamp) carrying a KEEPALIVE",
        json!({"microsecond": 250000, "peer_as": 4200000001u32, "bgp_message_type": BGP_KEEPALIVE}),
    );

    // --- IGP types -------------------------------------------------------
    // Minimal OSPFv2 Hello: version 2, type 1, plausible header, no neighbors.
    let ts = b.next_timestamp();
    let ospf2_pdu: Vec<u8> = vec![
        2, 1, 0, 44, // version, type=Hello, packet length 44
        192, 0, 2, 30, // router id
        0, 0, 0, 0, // area 0
        0, 0, 0, 0, // checksum 0 (synthetic), autype 0
        0, 0, 0, 0, // authentication
        0, 0, 0, 0, //
        255, 255, 255, 0, // network mask
        0, 10, 2, 1, // hello interval 10, options, priority 1
        0, 0, 0, 40, // router dead interval
        0, 0, 0, 0, // designated router
        0, 0, 0, 0, // backup designated router
    ];
    b.push(
        records::ospfv2(ts, [192, 0, 2, 30], [192, 0, 2, 31], &ospf2_pdu),
        "ospfv2",
        Expect::Valid,
        "OSPFv2 record with a minimal Hello PDU",
        json!({"remote_ip": "192.0.2.30", "local_ip": "192.0.2.31", "ospf_type": 1}),
    );

    // Minimal OSPFv3 Hello.
    let ospf3_pdu: Vec<u8> = vec![
        3, 1, 0, 36, // version 3, type=Hello, length 36
        192, 0, 2, 40, // router id
        0, 0, 0, 0, // area 0
        0, 0, 0, 0, // checksum, instance id, reserved
        0, 0, 0, 5, // interface id
        1, 0, 0, 19, // priority, options
        0, 10, 0, 40, // hello interval, dead interval
        0, 0, 0, 0, // designated router
        0, 0, 0, 0, // backup designated router
    ];
    let ts = b.next_timestamp();
    b.push(
        records::ospfv3(ts, None, v6(30), v6(31), &ospf3_pdu),
        "ospfv3",
        Expect::Valid,
        "OSPFv3 record with a minimal Hello PDU",
        json!({"remote_ip": "2001:db8::1e", "local_ip": "2001:db8::1f", "ospf_type": 1}),
    );
    let ts = b.next_timestamp();
    b.push(
        records::ospfv3(ts, Some(500_000), v6(30), v6(31), &ospf3_pdu),
        "ospfv3_et",
        Expect::Valid,
        "OSPFv3_ET record (microsecond timestamp)",
        json!({"microsecond": 500000, "remote_ip": "2001:db8::1e", "local_ip": "2001:db8::1f"}),
    );

    // Minimal IS-IS Hello PDU (LAN Level-1): IEEE 802 header stripped,
    // starts at the common IS-IS header (0x83 ...).
    let isis_pdu: Vec<u8> = vec![
        0x83, 27, 1, 0, // NLPID 0x83, header length 27, version 1, sysid len 0(=6)
        15, 1, 0, 0, // PDU type 15 (L1 LAN Hello), version 1, reserved, max area 0(=3)
        1, // circuit type L1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // source id
        0, 30, // holding time
        0, 27, // PDU length
        64, // priority
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, // LAN id
    ];
    let ts = b.next_timestamp();
    b.push(
        records::isis(ts, None, &isis_pdu),
        "isis",
        Expect::Valid,
        "ISIS record with a minimal L1 LAN Hello PDU",
        json!({"pdu_type": 15, "pdu_len": isis_pdu.len()}),
    );
    let ts = b.next_timestamp();
    b.push(
        records::isis(ts, Some(750_000), &isis_pdu),
        "isis_et",
        Expect::Valid,
        "ISIS_ET record (microsecond timestamp)",
        json!({"microsecond": 750000, "pdu_type": 15}),
    );
}

fn emit_skip(b: &mut Builder) {
    // Unknown MRT type / subtypes: header length is honest, so a parser
    // must be able to hop over these.
    let ts = b.next_timestamp();
    b.push(
        invalid::unknown_mrt_type(ts, 99),
        "invalid_unknown_type",
        Expect::Skip,
        "MRT record with undefined Type 99",
        json!({"reason": "unknown_mrt_type"}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::unknown_subtype(ts, TABLE_DUMP_V2, 99),
        "invalid_td2_unknown_subtype",
        Expect::Skip,
        "TABLE_DUMP_V2 record with undefined Subtype 99",
        json!({"reason": "unknown_subtype"}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::unknown_subtype(ts, BGP4MP, 99),
        "invalid_bgp4mp_unknown_subtype",
        Expect::Skip,
        "BGP4MP record with undefined Subtype 99",
        json!({"reason": "unknown_subtype"}),
    );

    // Fixed-size attribute TLVs encoded with the wrong length. Framing is
    // fully consistent; only the per-type size rule is violated.
    let wrong_size_cases: [(&str, u8, u8, u16, u16, &str); 6] = [
        ("invalid_attr_origin_len4", FLAG_TRANSITIVE, ATTR_ORIGIN, 4, 1, "ORIGIN must be 1 byte, encoded with 4"),
        ("invalid_attr_med_len2", FLAG_OPTIONAL, ATTR_MULTI_EXIT_DISC, 2, 4, "MULTI_EXIT_DISC must be 4 bytes, encoded with 2"),
        ("invalid_attr_med_len8", FLAG_OPTIONAL, ATTR_MULTI_EXIT_DISC, 8, 4, "MULTI_EXIT_DISC must be 4 bytes, encoded with 8"),
        ("invalid_attr_nexthop_len16", FLAG_TRANSITIVE, ATTR_NEXT_HOP, 16, 4, "NEXT_HOP must be 4 bytes, encoded with 16"),
        ("invalid_attr_aggregator4_len4", FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_AS4_AGGREGATOR, 4, 8, "AS4_AGGREGATOR must be 8 bytes, encoded with 4"),
        ("invalid_attr_aggregator4_len16", FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_AS4_AGGREGATOR, 16, 8, "AS4_AGGREGATOR must be 8 bytes, encoded with 16"),
    ];
    for (kind, flags, code, encoded_len, required_len, desc) in wrong_size_cases {
        let ts = b.next_timestamp();
        b.push(
            invalid::bgp4mp_wrong_attr_size(ts, flags, code, encoded_len),
            kind,
            Expect::Skip,
            desc,
            json!({"reason": "attr_wrong_fixed_size", "attr_code": code, "encoded_len": encoded_len, "required_len": required_len}),
        );
    }
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_duplicate_origin_bad_len(ts),
        "invalid_attr_duplicate_origin_len4",
        Expect::Skip,
        "UPDATE carries a valid ORIGIN followed by a second ORIGIN encoded with length 4",
        json!({"reason": "duplicate_attribute_and_attr_wrong_fixed_size", "attr_code": ATTR_ORIGIN, "encoded_len": 4, "required_len": 1}),
    );

    // TLV length that overruns its container.
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_attr_overrun(ts, 200, 4),
        "invalid_attr_len_overrun",
        Expect::Skip,
        "Path attribute declares 200 value bytes but only 4 follow in the attribute section",
        json!({"reason": "attr_len_overruns_container", "declared": 200, "actual": 4}),
    );

    // Broken BGP message headers inside a well-framed MRT record.
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_bad_marker(ts),
        "invalid_bgp_marker",
        Expect::Skip,
        "BGP message whose 16-byte marker is not all-ones",
        json!({"reason": "bad_bgp_marker"}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_bad_bgp_length(ts, 10),
        "invalid_bgp_length_too_small",
        Expect::Skip,
        "BGP header Length 10 (minimum legal is 19)",
        json!({"reason": "bgp_length_out_of_range", "declared": 10}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_bad_bgp_length(ts, 5000),
        "invalid_bgp_length_too_large",
        Expect::Skip,
        "BGP header Length 5000 (maximum legal is 4096) and larger than the MRT record",
        json!({"reason": "bgp_length_out_of_range", "declared": 5000}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_truncated_bgp(ts),
        "invalid_bgp_truncated",
        Expect::Skip,
        "MRT record body ends inside the BGP marker",
        json!({"reason": "inner_truncation"}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_empty_body(ts),
        "invalid_bgp4mp_empty_body",
        Expect::Skip,
        "BGP4MP_MESSAGE record with Length 0: mandatory fields absent",
        json!({"reason": "empty_body"}),
    );

    // TABLE_DUMP_V2 damage.
    let ts = b.next_timestamp();
    b.push(
        invalid::rib_attr_len_overrun(ts, 900),
        "invalid_rib_attr_len_overrun",
        Expect::Skip,
        "RIB entry Attribute Length exceeds the bytes remaining in the record",
        json!({"reason": "attr_len_overruns_record"}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::rib_bad_prefix_len(ts, 901, false, 33),
        "invalid_rib_v4_prefix_len_33",
        Expect::Skip,
        "RIB_IPV4_UNICAST NLRI with prefix length 33",
        json!({"reason": "prefix_len_out_of_range", "bits": 33}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::rib_bad_prefix_len(ts, 902, true, 129),
        "invalid_rib_v6_prefix_len_129",
        Expect::Skip,
        "RIB_IPV6_UNICAST NLRI with prefix length 129",
        json!({"reason": "prefix_len_out_of_range", "bits": 129}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::rib_generic_vpn_bad_prefix_len(ts, 903, 64),
        "invalid_rib_vpn_prefix_len_too_short",
        Expect::Skip,
        "RIB_GENERIC VPNv4 (SAFI 128) NLRI of 64 bits, too short to contain the mandatory label (24) + RD (64)",
        json!({"reason": "vpn_prefix_len_too_short", "bits": 64, "minimum": 88}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::rib_generic_vpn_bad_prefix_len(ts, 904, 200),
        "invalid_rib_vpn_prefix_len_too_long",
        Expect::Skip,
        "RIB_GENERIC VPNv4 (SAFI 128) NLRI of 200 bits, past label + RD + a full IPv4 address (120)",
        json!({"reason": "prefix_len_out_of_range", "bits": 200, "maximum": 120}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::peer_index_count_mismatch(ts, 10, 2),
        "invalid_peer_index_count",
        Expect::Skip,
        "PEER_INDEX_TABLE claims 10 peers but encodes only 2",
        json!({"reason": "count_overruns_record", "claimed": 10, "actual": 2}),
    );

    // Legacy TABLE_DUMP damage.
    let ts = b.next_timestamp();
    b.push(
        invalid::table_dump_attr_overrun(ts),
        "invalid_table_dump_attr_overrun",
        Expect::Skip,
        "TABLE_DUMP Attribute Length exceeds the bytes remaining in the record",
        json!({"reason": "attr_len_overruns_record"}),
    );
}

/// Records that cross the community attribute families (standard RFC 1997,
/// extended RFC 4360, large RFC 8092) with the ADD-PATH carriers. The first
/// group is fully legal; the second group is deliberately illegal but keeps
/// honest MRT framing, so a robust parser must reject/skip the record and
/// keep loading. Every record here still carries at least one community
/// attribute AND an ADD-PATH element, exercising their interaction.
fn emit_combo(b: &mut Builder) {
    // Reusable community payloads (deterministic).
    let std_comms: [u32; 3] = [(64500u32 << 16) | 10, COMM_NO_EXPORT, COMM_NO_ADVERTISE];
    // Two 8-byte extended communities: RT 252:10 and Route Origin 253:20.
    let ext_comms: [[u8; 8]; 2] =
        [[0x00, 0x02, 0x00, 0xFC, 0x00, 0x00, 0x00, 0x0A], [0x00, 0x03, 0x00, 0xFD, 0x00, 0x00, 0x00, 0x14]];
    let large_comms: [[u32; 3]; 2] = [[64500, 1, 2], [4_200_000_001, 7, 8]];

    // Base v4 RIB attribute set (origin, AS4 path, next hop) that each combo
    // extends with one or more community attributes.
    let base_v4 = |salt: u32| {
        let mut a = bgp::attr_origin(0);
        a.extend(bgp::attr_as_path_4b(&[64500 + salt, 4_200_000_000 + salt]));
        a.extend(bgp::attr_next_hop([192, 0, 2, (1 + salt) as u8]));
        a
    };

    // Helper: emit a TABLE_DUMP_V2 IPv4 RIB record (any subtype) with a single
    // entry built from `attrs`, using `path_id` (None = no Path Identifier in
    // the entry, regardless of subtype).
    let push_rib_v4 =
        |b: &mut Builder, subtype: u16, seq: u32, path_id: Option<u32>, prefix: [u8; 4], bits: u8, attrs: Vec<u8>, kind: &str, expect: Expect, desc: &str, details: serde_json::Value| {
            let ts = b.next_timestamp();
            let mut e = RibEntry::new(1, ts, attrs);
            e.path_id = path_id;
            b.push(records::rib_afi_safi(ts, subtype, seq, &bgp::nlri_v4(prefix, bits), &[e]), kind, expect, desc, details);
        };

    // ---------------------------------------------------------- legal combos

    // Standard communities + ADD-PATH RIB entry.
    let mut a = base_v4(1);
    a.extend(bgp::attr_communities(&std_comms));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 100, Some(1001), [10, 1, 0, 0], 16, a,
        "combo_rib_v4_addpath_std_comm", Expect::Valid,
        "RIB_IPV4_UNICAST_ADDPATH entry with a Path Identifier and standard (RFC 1997) communities, including well-known NO_EXPORT/NO_ADVERTISE",
        json!({"subtype": "rib_ipv4_unicast_addpath", "path_id": 1001, "communities": ["64500:10", "0xFFFFFF01", "0xFFFFFF02"]}),
    );

    // Extended communities + ADD-PATH RIB entry.
    let mut a = base_v4(2);
    a.extend(bgp::attr_ext_communities(&ext_comms));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 101, Some(1002), [10, 2, 0, 0], 16, a,
        "combo_rib_v4_addpath_ext_comm", Expect::Valid,
        "RIB_IPV4_UNICAST_ADDPATH entry with a Path Identifier and extended (RFC 4360) communities",
        json!({"subtype": "rib_ipv4_unicast_addpath", "path_id": 1002, "ext_communities": ["rt:252:10", "soo:253:20"]}),
    );

    // Large communities + ADD-PATH RIB entry.
    let mut a = base_v4(3);
    a.extend(bgp::attr_large_communities(&large_comms));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 102, Some(1003), [10, 3, 0, 0], 16, a,
        "combo_rib_v4_addpath_large_comm", Expect::Valid,
        "RIB_IPV4_UNICAST_ADDPATH entry with a Path Identifier and large (RFC 8092) communities",
        json!({"subtype": "rib_ipv4_unicast_addpath", "path_id": 1003, "large_communities": ["64500:1:2", "4200000001:7:8"]}),
    );

    // All three community families together, two ADD-PATH entries on an IPv6 RIB.
    let ts = b.next_timestamp();
    let mut attrs = bgp::attr_origin(1);
    attrs.extend(bgp::attr_as_path_4b(&[64500, 4_200_000_002]));
    attrs.extend(bgp::attr_mp_reach_td2(&v6(9)));
    attrs.extend(bgp::attr_communities(&std_comms));
    attrs.extend(bgp::attr_ext_communities(&ext_comms));
    attrs.extend(bgp::attr_large_communities(&large_comms));
    let mut e0 = RibEntry::new(2, ts, attrs.clone());
    e0.path_id = Some(2001);
    let mut e1 = RibEntry::new(2, ts, attrs);
    e1.path_id = Some(2002);
    b.push(
        records::rib_afi_safi(ts, RIB_IPV6_UNICAST_ADDPATH, 103, &bgp::nlri_v6(v6(0), 48), &[e0, e1]),
        "combo_rib_v6_addpath_all_comm",
        Expect::Valid,
        "RIB_IPV6_UNICAST_ADDPATH with two Path Identifiers, each entry carrying standard + extended + large communities",
        json!({"subtype": "rib_ipv6_unicast_addpath", "path_ids": [2001, 2002], "community_families": ["standard", "extended", "large"]}),
    );

    // RIB_GENERIC_ADDPATH: Path Identifier lives in the NLRI, plus communities.
    let ts = b.next_timestamp();
    let mut attrs = base_v4(4);
    attrs.extend(bgp::attr_communities(&std_comms));
    attrs.extend(bgp::attr_large_communities(&large_comms));
    let entry = RibEntry::new(1, ts, attrs);
    b.push(
        records::rib_generic(ts, RIB_GENERIC_ADDPATH, 104, BGP_AFI_IPV4, SAFI_UNICAST, &bgp::nlri_v4_addpath(3003, [203, 0, 113, 0], 24), &[entry]),
        "combo_rib_generic_addpath_comm",
        Expect::Valid,
        "RIB_GENERIC_ADDPATH (Path Identifier in the NLRI) with standard + large communities",
        json!({"subtype": "rib_generic_addpath", "path_id": 3003, "community_families": ["standard", "large"]}),
    );

    // BGP4MP_MESSAGE_ADDPATH UPDATE: Path Identifier in the announced NLRI,
    // attributes carry standard + large communities.
    let ts = b.next_timestamp();
    let update = {
        let mut a = bgp::attr_origin(0);
        a.extend(bgp::attr_as_path_2b(&[64500, 65000]));
        a.extend(bgp::attr_next_hop([192, 0, 2, 1]));
        a.extend(bgp::attr_communities(&std_comms));
        a.extend(bgp::attr_large_communities(&large_comms));
        bgp::bgp_update(&[], &a, &bgp::nlri_v4_addpath(4004, [198, 51, 100, 0], 24))
    };
    b.push(
        records::bgp4mp_message(ts, BGP4MP, None, BGP4MP_MESSAGE_ADDPATH, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &update),
        "combo_bgp4mp_addpath_comm",
        Expect::Valid,
        "BGP4MP_MESSAGE_ADDPATH UPDATE: ADD-PATH Path Identifier in the NLRI, standard + large communities in the attributes",
        json!({"subtype": "bgp4mp_message_addpath", "path_id": 4004, "announced": ["198.51.100.0/24"], "community_families": ["standard", "large"]}),
    );

    // Path Identifier 0 with communities — legal (RFC 7911 allows id 0).
    let mut a = base_v4(5);
    a.extend(bgp::attr_communities(&std_comms));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 105, Some(0), [10, 5, 0, 0], 16, a,
        "combo_rib_v4_addpath_pathid0_comm", Expect::Valid,
        "RIB_IPV4_UNICAST_ADDPATH entry with Path Identifier 0 (legal) and standard communities",
        json!({"subtype": "rib_ipv4_unicast_addpath", "path_id": 0, "communities": ["64500:10", "0xFFFFFF01", "0xFFFFFF02"]}),
    );

    // A large-but-legal community block: ~1000 standard communities (≈4 KB of
    // value) forces the extended-length (2-byte) attribute encoding and
    // exercises how a parser handles many communities on one prefix. A
    // TABLE_DUMP_V2 RIB entry can hold this: its Attribute Length is 16 bits
    // (≤65535 bytes, ~16383 standard communities) and the MRT record Length is
    // 32 bits, so — unlike a BGP UPDATE message — it is not bounded by 4096.
    const MANY: u32 = 1000;
    let many_comms: Vec<u32> = (0..MANY).map(|i| (64500u32 << 16) | (i & 0xFFFF)).collect();
    let mut a = base_v4(12);
    a.extend(bgp::attr_communities(&many_comms));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 112, Some(10010), [10, 12, 0, 0], 16, a,
        "combo_rib_v4_addpath_many_comm", Expect::Valid,
        "RIB_IPV4_UNICAST_ADDPATH entry with a Path Identifier and 1000 standard communities (extended-length attribute)",
        json!({"subtype": "rib_ipv4_unicast_addpath", "path_id": 10010, "community_count": MANY, "community_bytes": MANY * 4}),
    );

    // ---------------------------------------------- illegal-but-skippable combos
    // MRT framing stays honest (Length covers the body exactly); only the
    // BGP/ADD-PATH content rules are broken. A parser must skip and continue.

    // ADD-PATH element present in a NON-ADD-PATH subtype: the entry carries a
    // 4-byte Path Identifier but the subtype (RIB_IPV4_UNICAST) says there is
    // none, so the parser reads it as part of the Attribute Length field.
    let mut a = base_v4(6);
    a.extend(bgp::attr_communities(&std_comms));
    push_rib_v4(
        b, RIB_IPV4_UNICAST, 106, Some(5005), [10, 6, 0, 0], 16, a,
        "combo_rib_pathid_in_nonaddpath", Expect::Skip,
        "Path Identifier encoded in a RIB_IPV4_UNICAST (non-ADD-PATH) entry: subtype forbids the id, so attribute parsing desynchronises",
        json!({"reason": "path_id_in_non_addpath_subtype", "subtype": "rib_ipv4_unicast", "stray_path_id": 5005}),
    );

    // ADD-PATH subtype but the Path Identifier is absent: the parser expects
    // 4 id bytes before Attribute Length and reads attribute bytes instead.
    let mut a = base_v4(7);
    a.extend(bgp::attr_communities(&std_comms));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 107, None, [10, 7, 0, 0], 16, a,
        "combo_rib_addpath_missing_pathid", Expect::Skip,
        "RIB_IPV4_UNICAST_ADDPATH entry with the mandatory Path Identifier omitted: entry framing desynchronises",
        json!({"reason": "missing_path_id_in_addpath_subtype", "subtype": "rib_ipv4_unicast_addpath"}),
    );

    // Standard COMMUNITY value length not a multiple of 4 (6 bytes), alongside
    // a valid ADD-PATH Path Identifier.
    let mut a = base_v4(8);
    a.extend(bgp::attr_community_raw(ATTR_COMMUNITY, &[0xFC, 0x00, 0x00, 0x0A, 0x12, 0x34]));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 108, Some(6006), [10, 8, 0, 0], 16, a,
        "combo_std_comm_bad_len_addpath", Expect::Skip,
        "ADD-PATH entry whose standard COMMUNITY attribute value is 6 bytes (not a multiple of 4)",
        json!({"reason": "community_len_not_multiple", "attr_code": ATTR_COMMUNITY, "value_len": 6, "multiple_of": 4, "path_id": 6006}),
    );

    // Extended COMMUNITY value length not a multiple of 8 (6 bytes).
    let mut a = base_v4(9);
    a.extend(bgp::attr_community_raw(ATTR_EXT_COMMUNITY, &[0x00, 0x02, 0x00, 0xFC, 0x00, 0x00]));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 109, Some(7007), [10, 9, 0, 0], 16, a,
        "combo_ext_comm_bad_len_addpath", Expect::Skip,
        "ADD-PATH entry whose extended COMMUNITY attribute value is 6 bytes (not a multiple of 8)",
        json!({"reason": "community_len_not_multiple", "attr_code": ATTR_EXT_COMMUNITY, "value_len": 6, "multiple_of": 8, "path_id": 7007}),
    );

    // Large COMMUNITY value length not a multiple of 12 (8 bytes).
    let mut a = base_v4(10);
    a.extend(bgp::attr_community_raw(ATTR_LARGE_COMMUNITY, &[0x00, 0x00, 0xFC, 0x14, 0x00, 0x00, 0x00, 0x01]));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 110, Some(8008), [10, 10, 0, 0], 16, a,
        "combo_large_comm_bad_len_addpath", Expect::Skip,
        "ADD-PATH entry whose large COMMUNITY attribute value is 8 bytes (not a multiple of 12)",
        json!({"reason": "community_len_not_multiple", "attr_code": ATTR_LARGE_COMMUNITY, "value_len": 8, "multiple_of": 12, "path_id": 8008}),
    );

    // Duplicate COMMUNITY attribute in a single ADD-PATH entry (RFC 4271:
    // a given attribute type must appear at most once).
    let mut a = base_v4(11);
    a.extend(bgp::attr_communities(&std_comms));
    a.extend(bgp::attr_communities(&[COMM_NO_EXPORT_SUBCONFED]));
    push_rib_v4(
        b, RIB_IPV4_UNICAST_ADDPATH, 111, Some(9009), [10, 11, 0, 0], 16, a,
        "combo_dup_community_addpath", Expect::Skip,
        "ADD-PATH entry carrying the COMMUNITY attribute twice (attribute types must be unique per RFC 4271)",
        json!({"reason": "duplicate_attribute", "attr_code": ATTR_COMMUNITY, "path_id": 9009}),
    );

    // BGP4MP_MESSAGE_ADDPATH subtype but the NLRI omits the Path Identifier
    // (plain NLRI), while attributes carry communities.
    let ts = b.next_timestamp();
    let update = {
        let mut a = bgp::attr_origin(0);
        a.extend(bgp::attr_as_path_2b(&[64500, 65000]));
        a.extend(bgp::attr_next_hop([192, 0, 2, 1]));
        a.extend(bgp::attr_communities(&std_comms));
        bgp::bgp_update(&[], &a, &bgp::nlri_v4([198, 51, 100, 128], 25))
    };
    b.push(
        records::bgp4mp_message(ts, BGP4MP, None, BGP4MP_MESSAGE_ADDPATH, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &update),
        "combo_bgp4mp_addpath_plain_nlri",
        Expect::Skip,
        "BGP4MP_MESSAGE_ADDPATH UPDATE whose announced NLRI omits the mandatory Path Identifier (plain NLRI in an ADD-PATH subtype)",
        json!({"reason": "missing_path_id_in_addpath_nlri", "subtype": "bgp4mp_message_addpath"}),
    );

    // Too many communities for a BGP message: enough standard communities to
    // push the enclosing BGP UPDATE past the 4096-byte maximum of RFC 4271
    // section 4. The 2-byte BGP Length field still encodes the value honestly,
    // but it exceeds the protocol limit, so the message is invalid.
    let ts = b.next_timestamp();
    const OVER: u32 = 1100; // 1100 * 4 = 4400 community bytes -> message > 4096
    let over_comms: Vec<u32> = (0..OVER).map(|i| (64500u32 << 16) | (i & 0xFFFF)).collect();
    let update = {
        let mut a = bgp::attr_origin(0);
        a.extend(bgp::attr_as_path_2b(&[64500, 65000]));
        a.extend(bgp::attr_next_hop([192, 0, 2, 1]));
        a.extend(bgp::attr_communities(&over_comms));
        bgp::bgp_update(&[], &a, &bgp::nlri_v4_addpath(11011, [198, 51, 100, 0], 24))
    };
    let over_len = update.len();
    b.push(
        records::bgp4mp_message(ts, BGP4MP, None, BGP4MP_MESSAGE_ADDPATH, 64500, 64501, 1, &[192, 0, 2, 1], &[192, 0, 2, 2], &update),
        "combo_bgp4mp_addpath_comm_over_4096",
        Expect::Skip,
        "BGP4MP_MESSAGE_ADDPATH UPDATE carrying 1100 communities: the BGP message exceeds the 4096-byte RFC 4271 maximum",
        json!({"reason": "bgp_message_exceeds_4096", "subtype": "bgp4mp_message_addpath", "path_id": 11011, "community_count": OVER, "bgp_message_len": over_len}),
    );
}

/// RFC 7606 attribute error-handling corpus. Every record has honest MRT and
/// BGP framing; a single path attribute breaks a per-attribute rule. These are
/// the malformations that most commonly crash or mis-parse real BGP/MRT
/// implementations. All are skip-class except the two that are valid-but-tricky
/// (a longer AS4_PATH, and an unknown optional-transitive attribute).
fn emit_attr_errors(b: &mut Builder) {
    // --- AS_PATH segment structure (RFC 7606: unknown type / overrun / underrun / zero-length) ---
    let as_path_cases: [(&str, &[u8], &str, serde_json::Value); 4] = [
        (
            "attr_as_path_zero_len_segment",
            &[2, 0],
            "AS_PATH with an AS_SEQUENCE segment of count 0 (zero-length segment)",
            json!({"reason": "as_path_zero_length_segment", "segment_type": 2, "count": 0}),
        ),
        (
            "attr_as_path_unknown_segment_type",
            &[5, 1, 0x00, 0x64],
            "AS_PATH segment with undefined type 5 (valid: 1 SET, 2 SEQUENCE, 3/4 CONFED)",
            json!({"reason": "as_path_unknown_segment_type", "segment_type": 5}),
        ),
        (
            "attr_as_path_count_overrun",
            &[2, 4, 0x00, 0x64, 0x00, 0xC8],
            "AS_PATH segment declares 4 ASNs but only 2 are present (segments overrun the attribute)",
            json!({"reason": "as_path_segment_overrun", "declared_count": 4, "present": 2}),
        ),
        (
            "attr_as_path_trailing_bytes",
            &[2, 2, 0x00, 0x64, 0x00, 0xC8, 0x00, 0x2A],
            "AS_PATH segment of 2 ASNs followed by 2 stray bytes (segments underrun the attribute)",
            json!({"reason": "as_path_segment_underrun", "declared_count": 2, "trailing_bytes": 2}),
        ),
    ];
    for (kind, seg, desc, details) in as_path_cases {
        let ts = b.next_timestamp();
        b.push(invalid::bgp4mp_as_path_raw(ts, seg), kind, Expect::Skip, desc, details);
    }

    // AS4_PATH longer than AS_PATH: valid per RFC 6793 (AS4_PATH is ignored),
    // but a classic parser panic when the two are merged blindly.
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_as4_path_longer(ts),
        "attr_as4_path_longer_than_as_path",
        Expect::Valid,
        "AS_PATH of one AS_TRANS (23456) with an AS4_PATH of three 4-byte ASNs; RFC 6793 says ignore the longer AS4_PATH",
        json!({"as_path": [23456], "as4_path_len": 3, "note": "valid: AS4_PATH ignored when longer than AS_PATH"}),
    );

    // --- attribute flags (RFC 7606 attribute-flags error) ---
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_attr_bad_flags(ts, FLAG_OPTIONAL, ATTR_ORIGIN, &[0]),
        "attr_origin_optional_flag",
        Expect::Skip,
        "ORIGIN (a well-known attribute) encoded with the Optional flag set instead of Transitive",
        json!({"reason": "attr_flags_error", "attr_code": ATTR_ORIGIN, "expected_flags": "transitive", "got_flags": "optional"}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_spurious_ext_len(ts),
        "attr_spurious_extended_length",
        Expect::Skip,
        "MULTI_EXIT_DISC (4-byte value) with the Extended Length flag set, which RFC 4271 allows only for values > 255 bytes",
        json!({"reason": "attr_flags_error", "attr_code": ATTR_MULTI_EXIT_DISC, "flag": "extended_length", "value_len": 4}),
    );

    // --- MP_REACH_NLRI / MP_UNREACH_NLRI ---
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_mp_reach_bad_nh_len(ts),
        "attr_mp_reach_bad_nexthop_len",
        Expect::Skip,
        "MP_REACH_NLRI whose Next Hop Length (32) exceeds the next-hop bytes present, so the NLRI cannot be located",
        json!({"reason": "mp_reach_nexthop_len_inconsistent", "declared_nh_len": 32, "actual_nh_len": 16}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_mp_unreach_short(ts),
        "attr_mp_unreach_too_short",
        Expect::Skip,
        "MP_UNREACH_NLRI of 2 bytes, too short to hold the AFI + SAFI (RFC 7606: length < 3)",
        json!({"reason": "mp_unreach_len_too_short", "value_len": 2, "minimum": 3}),
    );

    // --- illegal zero-length attributes (only AS_PATH/ATOMIC_AGGREGATE may be 0) ---
    let zero_cases: [(&str, u8, u8, &str); 3] = [
        ("attr_zero_len_origin", FLAG_TRANSITIVE, ATTR_ORIGIN, "ORIGIN"),
        ("attr_zero_len_nexthop", FLAG_TRANSITIVE, ATTR_NEXT_HOP, "NEXT_HOP"),
        ("attr_zero_len_community", FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_COMMUNITY, "COMMUNITY"),
    ];
    for (kind, flags, code, name) in zero_cases {
        let ts = b.next_timestamp();
        b.push(
            invalid::bgp4mp_zero_len_attr(ts, flags, code),
            kind,
            Expect::Skip,
            &format!("{name} attribute encoded with length 0 (illegal for all but AS_PATH/ATOMIC_AGGREGATE)"),
            json!({"reason": "illegal_zero_length_attribute", "attr_code": code}),
        );
    }

    // --- aggregate attributes ---
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_atomic_aggregate_nonzero(ts),
        "attr_atomic_aggregate_nonzero",
        Expect::Skip,
        "ATOMIC_AGGREGATE encoded with length 4 (must be 0)",
        json!({"reason": "attr_wrong_fixed_size", "attr_code": ATTR_ATOMIC_AGGREGATE, "encoded_len": 4, "required_len": 0}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_aggregator_bad_len(ts, 4),
        "attr_aggregator_bad_len",
        Expect::Skip,
        "AGGREGATOR encoded with length 4 (must be 6 for a 2-byte AS or 8 for a 4-byte AS)",
        json!({"reason": "attr_wrong_fixed_size", "attr_code": ATTR_AGGREGATOR, "encoded_len": 4, "required_len": [6, 8]}),
    );

    // --- unknown / reserved attribute types ---
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_extra_attr(ts, 40),
        "attr_unknown_optional_transitive",
        Expect::Valid,
        "UPDATE carrying an unassigned optional-transitive attribute (type 40): a conforming parser retains it as raw and still loads the record",
        json!({"attr_code": 40, "flags": "optional_transitive", "note": "valid: unknown transitive attribute is retained, not an error"}),
    );
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_extra_attr(ts, 0),
        "attr_type_code_zero",
        Expect::Skip,
        "UPDATE carrying an attribute of reserved type code 0 (invalid per RFC 4271)",
        json!({"reason": "reserved_attr_type", "attr_code": 0}),
    );

    // --- TABLE_DUMP_V2 RIB entry referencing a non-existent peer ---
    let ts = b.next_timestamp();
    b.push(
        invalid::rib_bad_peer_index(ts, 950, 99),
        "attr_rib_bad_peer_index",
        Expect::Skip,
        "RIB_IPV4_UNICAST entry whose Peer Index 99 is absent from the 4-entry PEER_INDEX_TABLE",
        json!({"reason": "peer_index_out_of_range", "peer_index": 99, "peer_count": 4}),
    );

    // --- BGP4MP_ET too short for the microsecond field ---
    let ts = b.next_timestamp();
    b.push(
        invalid::bgp4mp_et_short(ts),
        "attr_bgp4mp_et_short",
        Expect::Skip,
        "BGP4MP_ET record whose 2-byte body cannot hold the mandatory 4-byte Microsecond Timestamp",
        json!({"reason": "et_body_too_short_for_microseconds", "body_len": 2, "minimum": 4}),
    );
}

fn emit_fatal(b: &mut Builder, fatal: FatalKind) {
    let ts = b.next_timestamp();
    match fatal {
        FatalKind::LengthOverrunsEof => b.push_raw(
            invalid::tail_length_overruns_eof(ts, 1000, 16),
            BGP4MP,
            BGP4MP_MESSAGE,
            ts,
            fatal.kind_name(),
            "Header Length claims 1000 bytes; only 16 remain before EOF. Loading must abort here.",
        ),
        FatalKind::TruncatedHeader => b.push_raw(
            invalid::tail_truncated_header(ts, 7),
            BGP4MP,
            BGP4MP_MESSAGE,
            ts,
            fatal.kind_name(),
            "File ends after 7 bytes of a 12-byte MRT common header. Loading must abort here.",
        ),
        FatalKind::HugeLength => b.push_raw(
            invalid::tail_length_overruns_eof(ts, u32::MAX, 8),
            BGP4MP,
            BGP4MP_MESSAGE,
            ts,
            fatal.kind_name(),
            "Header Length is 0xFFFFFFFF. Loading must abort here.",
        ),
    }
}
