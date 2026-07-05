//! BGP message and path attribute encoding (RFC 4271, RFC 4760, RFC 1997).

use crate::types::*;
use crate::writer::Buf;

/// Encode a path attribute with a correct length field. The extended-length
/// flag is set automatically when the value exceeds 255 bytes.
pub fn attribute(flags: u8, code: u8, value: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    if value.len() > 255 {
        b.u8(flags | FLAG_EXT_LEN).u8(code).u16(value.len() as u16);
    } else {
        b.u8(flags & !FLAG_EXT_LEN).u8(code).u8(value.len() as u8);
    }
    b.bytes(value);
    b.into_vec()
}

/// Encode a path attribute whose declared length is chosen by the caller and
/// may disagree with the actual value length. Used to build malformed TLVs.
pub fn attribute_declared(flags: u8, code: u8, declared_len: u16, value: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    if flags & FLAG_EXT_LEN != 0 {
        b.u8(flags).u8(code).u16(declared_len);
    } else {
        b.u8(flags).u8(code).u8(declared_len as u8);
    }
    b.bytes(value);
    b.into_vec()
}

pub fn attr_origin(origin: u8) -> Vec<u8> {
    attribute(FLAG_TRANSITIVE, ATTR_ORIGIN, &[origin])
}

/// AS_PATH with one AS_SEQUENCE segment of 2-byte AS numbers (pre-AS4 form).
pub fn attr_as_path_2b(asns: &[u16]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u8(2).u8(asns.len() as u8); // segment type AS_SEQUENCE, count
    for &a in asns {
        b.u16(a);
    }
    attribute(FLAG_TRANSITIVE, ATTR_AS_PATH, &b.into_vec())
}

/// AS_PATH with one AS_SEQUENCE segment of 4-byte AS numbers
/// (AS4 encoding, as required inside TABLE_DUMP_V2 RIB entries).
pub fn attr_as_path_4b(asns: &[u32]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u8(2).u8(asns.len() as u8);
    for &a in asns {
        b.u32(a);
    }
    attribute(FLAG_TRANSITIVE, ATTR_AS_PATH, &b.into_vec())
}

pub fn attr_next_hop(ip: [u8; 4]) -> Vec<u8> {
    attribute(FLAG_TRANSITIVE, ATTR_NEXT_HOP, &ip)
}

pub fn attr_med(v: u32) -> Vec<u8> {
    attribute(FLAG_OPTIONAL, ATTR_MULTI_EXIT_DISC, &v.to_be_bytes())
}

pub fn attr_local_pref(v: u32) -> Vec<u8> {
    attribute(FLAG_TRANSITIVE, ATTR_LOCAL_PREF, &v.to_be_bytes())
}

pub fn attr_atomic_aggregate() -> Vec<u8> {
    attribute(FLAG_TRANSITIVE, ATTR_ATOMIC_AGGREGATE, &[])
}

pub fn attr_aggregator_2b(asn: u16, ip: [u8; 4]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u16(asn).bytes(&ip);
    attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_AGGREGATOR, &b.into_vec())
}

pub fn attr_aggregator_4b(asn: u32, ip: [u8; 4]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u32(asn).bytes(&ip);
    attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_AGGREGATOR, &b.into_vec())
}

pub fn attr_communities(comms: &[u32]) -> Vec<u8> {
    let mut b = Buf::new();
    for &c in comms {
        b.u32(c);
    }
    attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_COMMUNITY, &b.into_vec())
}

/// Extended Communities (RFC 4360): each community is 8 bytes wide.
pub fn attr_ext_communities(comms: &[[u8; 8]]) -> Vec<u8> {
    let mut b = Buf::new();
    for c in comms {
        b.bytes(c);
    }
    attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_EXT_COMMUNITY, &b.into_vec())
}

/// IPv6 Address Specific Extended Communities (RFC 5701, attribute 25):
/// each community is 20 bytes — type, subtype, 16-byte IPv6 global
/// administrator, 2-byte local administrator.
pub fn attr_ipv6_ext_communities(comms: &[[u8; 20]]) -> Vec<u8> {
    let mut b = Buf::new();
    for c in comms {
        b.bytes(c);
    }
    attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_IPV6_EXT_COMMUNITY, &b.into_vec())
}

/// Large Communities (RFC 8092): each community is three 4-byte integers
/// (Global Administrator, Local Data Part 1, Local Data Part 2).
pub fn attr_large_communities(comms: &[[u32; 3]]) -> Vec<u8> {
    let mut b = Buf::new();
    for c in comms {
        b.u32(c[0]).u32(c[1]).u32(c[2]);
    }
    attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_LARGE_COMMUNITY, &b.into_vec())
}

/// A community-family attribute whose value length is exactly `value.len()`
/// (honest TLV framing) but chosen by the caller so it can violate the
/// "multiple of 4/8/12" rule for its type. For malformed corpora.
pub fn attr_community_raw(code: u8, value: &[u8]) -> Vec<u8> {
    attribute(FLAG_OPTIONAL | FLAG_TRANSITIVE, code, value)
}

/// MP_REACH_NLRI in its full RFC 4760 form (AFI, SAFI, next hop, reserved, NLRI).
pub fn attr_mp_reach(afi: u16, safi: u8, next_hop: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u16(afi).u8(safi).u8(next_hop.len() as u8).bytes(next_hop).u8(0).bytes(nlri);
    attribute(FLAG_OPTIONAL, ATTR_MP_REACH_NLRI, &b.into_vec())
}

/// The abbreviated MP_REACH_NLRI form used inside TABLE_DUMP_V2 RIB entries
/// (RFC 6396 section 4.3.4): only next hop length + next hop.
pub fn attr_mp_reach_td2(next_hop: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u8(next_hop.len() as u8).bytes(next_hop);
    attribute(FLAG_OPTIONAL, ATTR_MP_REACH_NLRI, &b.into_vec())
}

pub fn attr_mp_unreach(afi: u16, safi: u8, nlri: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u16(afi).u8(safi).bytes(nlri);
    attribute(FLAG_OPTIONAL, ATTR_MP_UNREACH_NLRI, &b.into_vec())
}

/// NLRI-encode an IPv4 prefix: length in bits, then just enough octets.
pub fn nlri_v4(prefix: [u8; 4], bits: u8) -> Vec<u8> {
    let n = (bits as usize).div_ceil(8);
    let mut v = vec![bits];
    v.extend_from_slice(&prefix[..n]);
    v
}

/// NLRI-encode an IPv6 prefix.
pub fn nlri_v6(prefix: [u8; 16], bits: u8) -> Vec<u8> {
    let n = (bits as usize).div_ceil(8);
    let mut v = vec![bits];
    v.extend_from_slice(&prefix[..n]);
    v
}

/// ADD-PATH NLRI: 4-byte Path Identifier before the prefix (RFC 7911).
pub fn nlri_v4_addpath(path_id: u32, prefix: [u8; 4], bits: u8) -> Vec<u8> {
    let mut v = path_id.to_be_bytes().to_vec();
    v.extend_from_slice(&nlri_v4(prefix, bits));
    v
}

pub fn nlri_v6_addpath(path_id: u32, prefix: [u8; 16], bits: u8) -> Vec<u8> {
    let mut v = path_id.to_be_bytes().to_vec();
    v.extend_from_slice(&nlri_v6(prefix, bits));
    v
}

/// Type 0 Route Distinguisher: 2-byte AS administrator + 4-byte assigned
/// number (RFC 4364 section 4.2).
pub fn rd_type0(asn: u16, number: u32) -> [u8; 8] {
    let mut rd = [0u8; 8];
    rd[..2].copy_from_slice(&0u16.to_be_bytes());
    rd[2..4].copy_from_slice(&asn.to_be_bytes());
    rd[4..].copy_from_slice(&number.to_be_bytes());
    rd
}

/// Type 1 Route Distinguisher: IPv4 administrator + 2-byte assigned number.
pub fn rd_type1(ip: [u8; 4], number: u16) -> [u8; 8] {
    let mut rd = [0u8; 8];
    rd[..2].copy_from_slice(&1u16.to_be_bytes());
    rd[2..6].copy_from_slice(&ip);
    rd[6..].copy_from_slice(&number.to_be_bytes());
    rd
}

/// Type 2 Route Distinguisher: 4-byte AS administrator + 2-byte assigned
/// number (RFC 4364 section 4.2).
pub fn rd_type2(asn: u32, number: u16) -> [u8; 8] {
    let mut rd = [0u8; 8];
    rd[..2].copy_from_slice(&2u16.to_be_bytes());
    rd[2..6].copy_from_slice(&asn.to_be_bytes());
    rd[6..].copy_from_slice(&number.to_be_bytes());
    rd
}

/// NLRI-encode an MPLS VPN route (SAFI 128, RFC 4364 section 4.3.4): the
/// length octet counts the label (24 bits) and the RD (64 bits) in addition
/// to the prefix bits. One label with the Bottom-of-Stack bit set.
pub fn nlri_vpn(label: u32, rd: [u8; 8], prefix: &[u8], prefix_bits: u8) -> Vec<u8> {
    let n = (prefix_bits as usize).div_ceil(8);
    let mut v = vec![24 + 64 + prefix_bits];
    let stack_entry = (label << 4) | 0x1; // 20-bit label, EXP 0, Bottom-of-Stack
    v.extend_from_slice(&stack_entry.to_be_bytes()[1..]);
    v.extend_from_slice(&rd);
    v.extend_from_slice(&prefix[..n]);
    v
}

/// The next hop carried in MP_REACH_NLRI for SAFI 128: the IP address
/// prefixed with an 8-byte all-zero RD (RFC 4364 section 4.3.2), so it is
/// 12 bytes for VPNv4 and 24 bytes for VPNv6.
pub fn vpn_next_hop(ip: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; 8];
    v.extend_from_slice(ip);
    v
}

/// Frame a BGP message: 16-byte all-ones marker, length, type, payload.
pub fn bgp_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    bgp_message_raw([0xFF; 16], (19 + payload.len()) as u16, msg_type, payload)
}

/// Frame a BGP message with caller-controlled marker and length field.
pub fn bgp_message_raw(marker: [u8; 16], length: u16, msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.bytes(&marker).u16(length).u8(msg_type).bytes(payload);
    b.into_vec()
}

/// BGP UPDATE payload from pre-encoded parts.
pub fn bgp_update(withdrawn: &[u8], attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u16(withdrawn.len() as u16).bytes(withdrawn);
    b.u16(attrs.len() as u16).bytes(attrs);
    b.bytes(nlri);
    bgp_message(BGP_UPDATE, &b.into_vec())
}

/// BGP UPDATE whose Total Path Attribute Length field is caller-chosen
/// (may disagree with the real attribute bytes). For malformed corpora.
pub fn bgp_update_declared_attr_len(withdrawn: &[u8], declared_attr_len: u16, attrs: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u16(withdrawn.len() as u16).bytes(withdrawn);
    b.u16(declared_attr_len).bytes(attrs);
    b.bytes(nlri);
    bgp_message(BGP_UPDATE, &b.into_vec())
}

pub fn bgp_open(asn: u16, hold_time: u16, bgp_id: [u8; 4]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u8(4).u16(asn).u16(hold_time).bytes(&bgp_id).u8(0); // version 4, no optional params
    bgp_message(BGP_OPEN, &b.into_vec())
}

pub fn bgp_keepalive() -> Vec<u8> {
    bgp_message(BGP_KEEPALIVE, &[])
}

pub fn bgp_notification(code: u8, subcode: u8, data: &[u8]) -> Vec<u8> {
    let mut b = Buf::new();
    b.u8(code).u8(subcode).bytes(data);
    bgp_message(BGP_NOTIFICATION, &b.into_vec())
}
