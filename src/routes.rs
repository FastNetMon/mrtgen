//! Route-list mode: build an MRT file from a user-supplied JSON route list
//! instead of the built-in corpus.
//!
//! The input is a JSON array of route objects:
//!
//! ```json
//! [
//!   {
//!     "prefix": "1.2.3.0/24",
//!     "nexthop": "1.1.1.1",
//!     "as_path": [64500, 65000],
//!     "origin": "igp",
//!     "med": 100,
//!     "local_pref": 200,
//!     "standard_communities": ["111:222", "no-export"],
//!     "extended_communities": ["rt:64500:1"],
//!     "large_communities": ["64500:1:2"],
//!     "path_id": 7
//!   }
//! ]
//! ```
//!
//! Only `prefix` and `nexthop` are required; the address family (IPv4/IPv6)
//! is derived from the prefix and the next hop must match it. Every record
//! is emitted as `expect: valid` in the manifest, with the route's fields
//! echoed under `details` so CI can assert the parser recovered them.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::bgp;
use crate::generator::Corpus;
use crate::manifest::{Counts, Expect, Manifest, RecordEntry};
use crate::records::{self, Peer, RibEntry};
use crate::types::*;

/// How the route list is encoded into MRT records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteFormat {
    /// TABLE_DUMP_V2: one PEER_INDEX_TABLE followed by one RIB record per
    /// route (RIB_IPV4/IPV6_UNICAST, or the _ADDPATH subtype when the route
    /// carries a `path_id`).
    #[default]
    TableDumpV2,
    /// BGP4MP: one BGP4MP_MESSAGE_AS4 record per route, each carrying a BGP
    /// UPDATE that announces the prefix (_ADDPATH subtype with `path_id`).
    Bgp4mp,
}

/// One route as supplied by the user. Unknown keys are rejected so typos
/// (e.g. `local_perf`) fail loudly instead of being silently dropped.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
    /// CIDR prefix, e.g. `"1.2.3.0/24"` or `"2001:db8::/48"`. Exactly one
    /// of `prefix` and `flowspec` must be present.
    pub prefix: Option<String>,
    /// Next hop address; family must match the prefix. Required for prefix
    /// routes, optional for flowspec rules (0-length next hop when absent).
    #[serde(alias = "next_hop")]
    pub nexthop: Option<String>,
    /// AS numbers of one AS_SEQUENCE segment. Default `[64500]`;
    /// an explicit empty list encodes an empty AS_PATH (iBGP style).
    pub as_path: Option<Vec<u32>>,
    /// `"igp"` / `"egp"` / `"incomplete"` or the numeric code 0-2. Default igp.
    pub origin: Option<OriginSpec>,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    #[serde(default)]
    pub atomic_aggregate: bool,
    /// RFC 4271 AGGREGATOR as `"asn:a.b.c.d"`; always the 4-byte-AS form
    /// (the encodings here are AS4 contexts, RFC 6793).
    pub aggregator: Option<String>,
    /// RFC 4456 ORIGINATOR_ID: the originator's IPv4 router id.
    pub originator_id: Option<String>,
    /// RFC 4456 CLUSTER_LIST: IPv4 cluster ids, outermost first.
    #[serde(default)]
    pub cluster_list: Vec<String>,
    /// RFC 7311 AIGP metric (one type-1 TLV).
    pub aigp: Option<u64>,
    /// RFC 1997: `"asn:value"`, a well-known name (`no-export`,
    /// `no-advertise`, `no-export-subconfed`) or a raw `0xNNNNNNNN` word.
    #[serde(default, alias = "communities")]
    pub standard_communities: Vec<String>,
    /// RFC 4360: `"rt:admin:value"`, `"soo:admin:value"` or 16 raw hex digits.
    #[serde(default)]
    pub extended_communities: Vec<String>,
    /// RFC 5701 (attribute 25): `"rt:<ipv6>:<local>"`, `"soo:<ipv6>:<local>"`
    /// or 40 raw hex digits (20 bytes).
    #[serde(default)]
    pub ipv6_extended_communities: Vec<String>,
    /// RFC 8092: `"global:local1:local2"`.
    #[serde(default)]
    pub large_communities: Vec<String>,
    /// RFC 7911 ADD-PATH Path Identifier; selects the _ADDPATH subtype.
    pub path_id: Option<u32>,
    /// Route Distinguisher; presence selects MPLS VPN (SAFI 128, RFC 4364).
    /// `"asn:number"` (type 0 for a 2-byte ASN, type 2 for a 4-byte ASN) or
    /// `"a.b.c.d:number"` (type 1).
    pub rd: Option<String>,
    /// MPLS label (< 2^20) for the VPN NLRI; only with `rd`. Default 0.
    pub label: Option<u32>,
    /// FlowSpec rule (SAFI 133, RFC 8955/8956) instead of a prefix.
    /// Only encodable with `--routes-format bgp4mp`.
    pub flowspec: Option<crate::flowspec::FlowSpec>,
    /// FlowSpec traffic-filtering actions (RFC 8955 section 7), encoded as
    /// extended communities. Requires `flowspec`.
    pub actions: Option<Actions>,
    /// Escape hatch: arbitrary path attributes appended after all built-in
    /// attributes, in the given order. Framing is always honest (the length
    /// field matches the value; the extended-length flag is managed
    /// automatically). Duplicating a code the route already carries is
    /// allowed deliberately, for parser testing.
    #[serde(default)]
    pub raw_attributes: Vec<RawAttribute>,
}

/// One caller-supplied path attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAttribute {
    /// Flags byte (e.g. 192) or names from `optional` / `transitive` /
    /// `partial`.
    pub flags: FlagsSpec,
    /// Attribute type code.
    pub code: u8,
    /// Attribute value as hex digits; may be empty.
    #[serde(default)]
    pub value_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlagsSpec {
    Byte(u8),
    Names(Vec<String>),
}

/// FlowSpec traffic-filtering actions (RFC 8955 section 7).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actions {
    /// traffic-rate-bytes (0x8006), bytes per second; 0 discards the flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_bytes: Option<f32>,
    /// traffic-rate-packets (0x800c), packets per second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_packets: Option<f32>,
    /// rt-redirect (0x8008/0x8108/0x8208): `"admin:value"` where admin is a
    /// 2-byte ASN, an IPv4 address, or a 4-byte ASN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    /// traffic-marking (0x8009): remark to this DSCP value (0-63).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic_marking: Option<u8>,
    /// traffic-action (0x8007) T bit: keep evaluating later rules when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_action: Option<bool>,
    /// traffic-action (0x8007) S bit: enable sampling/logging.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OriginSpec {
    Code(u8),
    Name(String),
}

/// Parse a JSON array of [`RouteSpec`]s.
pub fn routes_from_json(s: &str) -> Result<Vec<RouteSpec>, String> {
    serde_json::from_str(s).map_err(|e| format!("routes JSON: {e}"))
}

struct ParsedRoute {
    v6: bool,
    /// Full-width prefix address bytes (4 or 16).
    prefix: Vec<u8>,
    bits: u8,
    /// Next hop bytes (4 or 16), same family as the prefix.
    nexthop: Vec<u8>,
    origin: u8,
    as_path: Vec<u32>,
    /// Concatenated path attributes, without the next-hop carrier (which
    /// differs between the TABLE_DUMP_V2 and BGP4MP encodings).
    std_comms: Vec<u32>,
    aggregator: Option<(u32, [u8; 4])>,
    originator_id: Option<[u8; 4]>,
    cluster_list: Vec<[u8; 4]>,
    ext_comms: Vec<[u8; 8]>,
    ipv6_ext_comms: Vec<[u8; 20]>,
    large_comms: Vec<[u32; 3]>,
    /// SAFI 128 route: encoded Route Distinguisher plus MPLS label.
    rd: Option<[u8; 8]>,
    label: u32,
    /// SAFI 133 rule: the encoded FlowSpec NLRI (without any Path Identifier).
    flow_nlri: Option<Vec<u8>>,
    /// User-supplied attributes: (flags without the ext-len bit, code, value).
    raw_attrs: Vec<(u8, u8, Vec<u8>)>,
}

pub(crate) fn parse_prefix(s: &str) -> Result<(bool, Vec<u8>, u8), String> {
    let (addr, len) = s.split_once('/').ok_or_else(|| format!("prefix '{s}': expected address/length"))?;
    let bits: u8 = len.parse().map_err(|_| format!("prefix '{s}': bad length '{len}'"))?;
    if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        if bits > 32 {
            return Err(format!("prefix '{s}': length {bits} exceeds 32"));
        }
        Ok((false, v4.octets().to_vec(), bits))
    } else if let Ok(v6) = addr.parse::<Ipv6Addr>() {
        if bits > 128 {
            return Err(format!("prefix '{s}': length {bits} exceeds 128"));
        }
        Ok((true, v6.octets().to_vec(), bits))
    } else {
        Err(format!("prefix '{s}': not a valid IPv4/IPv6 address"))
    }
}

fn parse_nexthop(s: &str, v6: bool) -> Result<Vec<u8>, String> {
    if v6 {
        s.parse::<Ipv6Addr>().map(|a| a.octets().to_vec()).map_err(|_| format!("nexthop '{s}': IPv6 prefix requires an IPv6 next hop"))
    } else {
        s.parse::<Ipv4Addr>().map(|a| a.octets().to_vec()).map_err(|_| format!("nexthop '{s}': IPv4 prefix requires an IPv4 next hop"))
    }
}

fn parse_origin(o: &Option<OriginSpec>) -> Result<u8, String> {
    match o {
        None => Ok(0),
        Some(OriginSpec::Code(c @ 0..=2)) => Ok(*c),
        Some(OriginSpec::Code(c)) => Err(format!("origin {c}: must be 0 (igp), 1 (egp) or 2 (incomplete)")),
        Some(OriginSpec::Name(n)) => match n.to_ascii_lowercase().as_str() {
            "igp" => Ok(0),
            "egp" => Ok(1),
            "incomplete" => Ok(2),
            other => Err(format!("origin '{other}': expected igp, egp or incomplete")),
        },
    }
}

fn parse_std_community(s: &str) -> Result<u32, String> {
    match s.to_ascii_lowercase().as_str() {
        "no-export" => return Ok(COMM_NO_EXPORT),
        "no-advertise" => return Ok(COMM_NO_ADVERTISE),
        "no-export-subconfed" => return Ok(COMM_NO_EXPORT_SUBCONFED),
        _ => {}
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).map_err(|_| format!("community '{s}': bad hex word"));
    }
    let (a, b) = s.split_once(':').ok_or_else(|| format!("community '{s}': expected 'asn:value', a well-known name or 0xNNNNNNNN"))?;
    let a: u16 = a.parse().map_err(|_| format!("community '{s}': ASN part must be 0-65535"))?;
    let b: u16 = b.parse().map_err(|_| format!("community '{s}': value part must be 0-65535"))?;
    Ok(((a as u32) << 16) | b as u32)
}

fn parse_ext_community(s: &str) -> Result<[u8; 8], String> {
    let lower = s.to_ascii_lowercase();
    let typed = lower.strip_prefix("rt:").map(|r| (0x02u8, r)).or_else(|| lower.strip_prefix("soo:").map(|r| (0x03u8, r)));
    if let Some((subtype, rest)) = typed {
        let (admin, value) = rest.split_once(':').ok_or_else(|| format!("extended community '{s}': expected type:admin:value"))?;
        let admin: u32 = admin.parse().map_err(|_| format!("extended community '{s}': bad administrator"))?;
        let mut c = [0u8; 8];
        c[1] = subtype;
        if admin <= u16::MAX as u32 {
            // Two-Octet AS specific (type 0x00): 2-byte admin, 4-byte value.
            let value: u32 = value.parse().map_err(|_| format!("extended community '{s}': bad value"))?;
            c[0] = 0x00;
            c[2..4].copy_from_slice(&(admin as u16).to_be_bytes());
            c[4..].copy_from_slice(&value.to_be_bytes());
        } else {
            // Four-Octet AS specific (type 0x02): 4-byte admin, 2-byte value.
            let value: u16 = value.parse().map_err(|_| format!("extended community '{s}': value must be 0-65535 with a 4-byte-AS administrator"))?;
            c[0] = 0x02;
            c[2..6].copy_from_slice(&admin.to_be_bytes());
            c[6..].copy_from_slice(&value.to_be_bytes());
        }
        return Ok(c);
    }
    let hex = lower.strip_prefix("0x").unwrap_or(&lower);
    if hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut c = [0u8; 8];
        for (i, chunk) in c.iter_mut().enumerate() {
            *chunk = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        return Ok(c);
    }
    Err(format!("extended community '{s}': expected rt:admin:value, soo:admin:value or 16 hex digits"))
}

/// RFC 5701 IPv6 address-specific extended community: `"rt:<ipv6>:<local>"`,
/// `"soo:<ipv6>:<local>"` or 40 raw hex digits.
fn parse_ipv6_ext_community(s: &str) -> Result<[u8; 20], String> {
    let lower = s.to_ascii_lowercase();
    for (prefix, subtype) in [("rt:", 0x02u8), ("soo:", 0x03)] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let (addr, local) = rest.rsplit_once(':').ok_or_else(|| format!("ipv6 extended community '{s}': expected type:ipv6:local"))?;
            let ip: Ipv6Addr = addr.parse().map_err(|_| format!("ipv6 extended community '{s}': bad IPv6 administrator"))?;
            let local: u16 = local.parse().map_err(|_| format!("ipv6 extended community '{s}': local administrator must be 0-65535"))?;
            let mut c = [0u8; 20];
            c[1] = subtype; // type 0x00: transitive IPv6-address-specific
            c[2..18].copy_from_slice(&ip.octets());
            c[18..].copy_from_slice(&local.to_be_bytes());
            return Ok(c);
        }
    }
    let hex = lower.strip_prefix("0x").unwrap_or(&lower);
    if hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut c = [0u8; 20];
        for (i, byte) in c.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        return Ok(c);
    }
    Err(format!("ipv6 extended community '{s}': expected rt:<ipv6>:<local>, soo:<ipv6>:<local> or 40 hex digits"))
}

/// Route Distinguisher: `"asn:number"` (type 0 or, with a 4-byte ASN,
/// type 2) or `"a.b.c.d:number"` (type 1).
fn parse_rd(s: &str) -> Result<[u8; 8], String> {
    let (admin, number) = s.split_once(':').ok_or_else(|| format!("rd '{s}': expected admin:number"))?;
    if let Ok(ip) = admin.parse::<Ipv4Addr>() {
        let n: u16 = number.parse().map_err(|_| format!("rd '{s}': type-1 assigned number must be 0-65535"))?;
        return Ok(bgp::rd_type1(ip.octets(), n));
    }
    let a: u64 = admin.parse().map_err(|_| format!("rd '{s}': administrator must be an ASN or an IPv4 address"))?;
    if a <= u16::MAX as u64 {
        let n: u32 = number.parse().map_err(|_| format!("rd '{s}': type-0 assigned number must be 0-4294967295"))?;
        Ok(bgp::rd_type0(a as u16, n))
    } else if a <= u32::MAX as u64 {
        let n: u16 = number.parse().map_err(|_| format!("rd '{s}': type-2 assigned number must be 0-65535 with a 4-byte-AS administrator"))?;
        Ok(bgp::rd_type2(a as u32, n))
    } else {
        Err(format!("rd '{s}': administrator {a} exceeds 32 bits"))
    }
}

/// AGGREGATOR: `"asn:a.b.c.d"`.
fn parse_aggregator(s: &str) -> Result<(u32, [u8; 4]), String> {
    let (asn, ip) = s.split_once(':').ok_or_else(|| format!("aggregator '{s}': expected asn:a.b.c.d"))?;
    let asn: u32 = asn.parse().map_err(|_| format!("aggregator '{s}': bad ASN"))?;
    let ip: Ipv4Addr = ip.parse().map_err(|_| format!("aggregator '{s}': bad IPv4 aggregator id"))?;
    Ok((asn, ip.octets()))
}

fn parse_router_id(s: &str, what: &str) -> Result<[u8; 4], String> {
    s.parse::<Ipv4Addr>().map(|a| a.octets()).map_err(|_| format!("{what} '{s}': expected an IPv4 router id"))
}

fn parse_large_community(s: &str) -> Result<[u32; 3], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err(format!("large community '{s}': expected global:local1:local2"));
    }
    let mut c = [0u32; 3];
    for (i, p) in parts.iter().enumerate() {
        c[i] = p.parse().map_err(|_| format!("large community '{s}': each part must be 0-4294967295"))?;
    }
    Ok(c)
}

/// rt-redirect action community (RFC 8955 section 7.4): the administrator
/// picks the form — 2-byte AS (0x8008), IPv4 (0x8108) or 4-byte AS (0x8208).
fn redirect_community(s: &str) -> Result<[u8; 8], String> {
    let (admin, number) = s.split_once(':').ok_or_else(|| format!("redirect '{s}': expected admin:value"))?;
    let mut c = [0u8; 8];
    c[1] = 0x08;
    if let Ok(ip) = admin.parse::<Ipv4Addr>() {
        let n: u16 = number.parse().map_err(|_| format!("redirect '{s}': value must be 0-65535 with an IPv4 administrator"))?;
        c[0] = 0x81;
        c[2..6].copy_from_slice(&ip.octets());
        c[6..].copy_from_slice(&n.to_be_bytes());
        return Ok(c);
    }
    let a: u64 = admin.parse().map_err(|_| format!("redirect '{s}': administrator must be an ASN or an IPv4 address"))?;
    if a <= u16::MAX as u64 {
        let n: u32 = number.parse().map_err(|_| format!("redirect '{s}': bad value"))?;
        c[0] = 0x80;
        c[2..4].copy_from_slice(&(a as u16).to_be_bytes());
        c[4..].copy_from_slice(&n.to_be_bytes());
    } else if a <= u32::MAX as u64 {
        let n: u16 = number.parse().map_err(|_| format!("redirect '{s}': value must be 0-65535 with a 4-byte-AS administrator"))?;
        c[0] = 0x82;
        c[2..6].copy_from_slice(&(a as u32).to_be_bytes());
        c[6..].copy_from_slice(&n.to_be_bytes());
    } else {
        return Err(format!("redirect '{s}': administrator {a} exceeds 32 bits"));
    }
    Ok(c)
}

/// traffic-rate-bytes / traffic-rate-packets: 2-octet AS id (0 here) plus an
/// IEEE 754 float32 rate.
fn rate_community(subtype: u8, rate: f32, what: &str) -> Result<[u8; 8], String> {
    if !rate.is_finite() || rate < 0.0 {
        return Err(format!("{what}: rate must be a non-negative finite number (RFC 8955 section 7.1)"));
    }
    let mut c = [0u8; 8];
    c[0] = 0x80;
    c[1] = subtype;
    c[4..].copy_from_slice(&rate.to_be_bytes());
    Ok(c)
}

/// Encode the traffic-filtering actions as extended communities.
fn action_communities(a: &Actions) -> Result<Vec<[u8; 8]>, String> {
    let mut v = Vec::new();
    if let Some(rate) = a.rate_limit_bytes {
        v.push(rate_community(0x06, rate, "actions.rate_limit_bytes")?);
    }
    if let Some(rate) = a.rate_limit_packets {
        v.push(rate_community(0x0c, rate, "actions.rate_limit_packets")?);
    }
    if a.terminal_action.is_some() || a.sample.is_some() {
        let mut c = [0u8; 8];
        c[0] = 0x80;
        c[1] = 0x07;
        c[7] = ((a.sample.unwrap_or(false) as u8) << 1) | a.terminal_action.unwrap_or(false) as u8;
        v.push(c);
    }
    if let Some(r) = &a.redirect {
        v.push(redirect_community(r)?);
    }
    if let Some(dscp) = a.traffic_marking {
        if dscp > 63 {
            return Err(format!("actions.traffic_marking: DSCP {dscp} exceeds 63"));
        }
        let mut c = [0u8; 8];
        c[0] = 0x80;
        c[1] = 0x09;
        c[7] = dscp;
        v.push(c);
    }
    Ok(v)
}

fn parse_raw_attribute(a: &RawAttribute) -> Result<(u8, u8, Vec<u8>), String> {
    let flags = match &a.flags {
        FlagsSpec::Byte(b) => *b,
        FlagsSpec::Names(names) => {
            let mut f = 0u8;
            for n in names {
                f |= match n.to_ascii_lowercase().as_str() {
                    "optional" => FLAG_OPTIONAL,
                    "transitive" => FLAG_TRANSITIVE,
                    "partial" => FLAG_PARTIAL,
                    other => return Err(format!("raw attribute flags: unknown name '{other}' (expected optional, transitive or partial)")),
                };
            }
            f
        }
    };
    let hex = a.value_hex.to_ascii_lowercase();
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("raw attribute {}: value_hex must be an even number of hex digits", a.code));
    }
    let value = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
    Ok((flags, a.code, value))
}

fn parse_route(i: usize, r: &RouteSpec) -> Result<ParsedRoute, String> {
    let ctx = |e: String| format!("route {i}: {e}");
    let (v6, prefix, bits, flow_nlri) = match (&r.prefix, &r.flowspec) {
        (Some(_), Some(_)) => return Err(ctx("prefix and flowspec are mutually exclusive".into())),
        (None, None) => return Err(ctx("each route needs a prefix or a flowspec rule".into())),
        (Some(pfx), None) => {
            let (v6, p, b) = parse_prefix(pfx).map_err(ctx)?;
            (v6, p, b, None)
        }
        (None, Some(fs)) => {
            let (nlri, v6) = crate::flowspec::encode_nlri(fs).map_err(ctx)?;
            (v6, Vec::new(), 0, Some(nlri))
        }
    };
    if r.actions.is_some() && r.flowspec.is_none() {
        return Err(ctx("actions require a flowspec rule".into()));
    }
    let rd = r.rd.as_deref().map(parse_rd).transpose().map_err(ctx)?;
    if rd.is_some() && flow_nlri.is_some() {
        return Err(ctx("rd cannot be combined with flowspec (VPN flowspec / SAFI 134 is not supported)".into()));
    }
    if r.label.is_some() && rd.is_none() {
        return Err(ctx("label requires rd (labels are only encoded in SAFI 128 NLRI)".into()));
    }
    let label = r.label.unwrap_or(0);
    if label >= 1 << 20 {
        return Err(ctx(format!("label {label} exceeds the 20-bit MPLS label space")));
    }
    let nexthop = match &r.nexthop {
        Some(nh) => parse_nexthop(nh, v6).map_err(ctx)?,
        None if flow_nlri.is_some() => Vec::new(),
        None => return Err(ctx("nexthop is required for prefix routes".into())),
    };
    let mut ext_comms: Vec<[u8; 8]> = r.extended_communities.iter().map(|c| parse_ext_community(c)).collect::<Result<_, _>>().map_err(ctx)?;
    if let Some(actions) = &r.actions {
        ext_comms.extend(action_communities(actions).map_err(ctx)?);
    }
    Ok(ParsedRoute {
        v6,
        prefix,
        bits,
        nexthop,
        origin: parse_origin(&r.origin).map_err(ctx)?,
        as_path: r.as_path.clone().unwrap_or_else(|| vec![64500]),
        std_comms: r.standard_communities.iter().map(|c| parse_std_community(c)).collect::<Result<_, _>>().map_err(ctx)?,
        aggregator: r.aggregator.as_deref().map(parse_aggregator).transpose().map_err(ctx)?,
        originator_id: r.originator_id.as_deref().map(|s| parse_router_id(s, "originator_id")).transpose().map_err(ctx)?,
        cluster_list: r.cluster_list.iter().map(|s| parse_router_id(s, "cluster_list")).collect::<Result<_, _>>().map_err(ctx)?,
        ext_comms,
        ipv6_ext_comms: r.ipv6_extended_communities.iter().map(|c| parse_ipv6_ext_community(c)).collect::<Result<_, _>>().map_err(ctx)?,
        large_comms: r.large_communities.iter().map(|c| parse_large_community(c)).collect::<Result<_, _>>().map_err(ctx)?,
        rd,
        label,
        flow_nlri,
        raw_attrs: r.raw_attributes.iter().map(parse_raw_attribute).collect::<Result<_, _>>().map_err(ctx)?,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Prepend the RFC 7911 ADD-PATH Path Identifier to an NLRI when present.
fn with_path_id(path_id: Option<u32>, nlri: Vec<u8>) -> Vec<u8> {
    match path_id {
        Some(id) => {
            let mut v = id.to_be_bytes().to_vec();
            v.extend_from_slice(&nlri);
            v
        }
        None => nlri,
    }
}

/// AS_PATH attribute; an empty AS list encodes an empty (zero-segment) path.
fn attr_as_path(asns: &[u32]) -> Vec<u8> {
    if asns.is_empty() {
        bgp::attribute(FLAG_TRANSITIVE, ATTR_AS_PATH, &[])
    } else {
        bgp::attr_as_path_4b(asns)
    }
}

/// Attributes shared by both encodings, split around the next-hop carrier
/// slot (NEXT_HOP vs MP_REACH_NLRI differs between families/encodings).
fn common_attrs(p: &ParsedRoute, spec: &RouteSpec) -> (Vec<u8>, Vec<u8>) {
    let mut head = bgp::attr_origin(p.origin);
    head.extend(attr_as_path(&p.as_path));
    // Everything after the type-3/14 next-hop carrier slot.
    let mut tail = Vec::new();
    if let Some(med) = spec.med {
        tail.extend(bgp::attr_med(med));
    }
    if let Some(lp) = spec.local_pref {
        tail.extend(bgp::attr_local_pref(lp));
    }
    if spec.atomic_aggregate {
        tail.extend(bgp::attr_atomic_aggregate());
    }
    if let Some((asn, id)) = p.aggregator {
        tail.extend(bgp::attr_aggregator_4b(asn, id));
    }
    if !p.std_comms.is_empty() {
        tail.extend(bgp::attr_communities(&p.std_comms));
    }
    if let Some(id) = p.originator_id {
        tail.extend(bgp::attr_originator_id(id));
    }
    if !p.cluster_list.is_empty() {
        tail.extend(bgp::attr_cluster_list(&p.cluster_list));
    }
    if !p.ext_comms.is_empty() {
        tail.extend(bgp::attr_ext_communities(&p.ext_comms));
    }
    if !p.ipv6_ext_comms.is_empty() {
        tail.extend(bgp::attr_ipv6_ext_communities(&p.ipv6_ext_comms));
    }
    if let Some(metric) = spec.aigp {
        tail.extend(bgp::attr_aigp(metric));
    }
    if !p.large_comms.is_empty() {
        tail.extend(bgp::attr_large_communities(&p.large_comms));
    }
    for (flags, code, value) in &p.raw_attrs {
        tail.extend(bgp::attribute(*flags, *code, value));
    }
    (head, tail)
}

fn route_details(spec: &RouteSpec, p: &ParsedRoute) -> serde_json::Value {
    json!({
        "prefix": spec.prefix,
        "nexthop": spec.nexthop,
        "flowspec": spec.flowspec,
        "actions": spec.actions,
        "nlri_hex": p.flow_nlri.as_ref().map(|n| hex(n)),
        "action_ext_communities_hex": spec.actions.as_ref().map(|a| {
            action_communities(a).unwrap_or_default().iter().map(|c| hex(&c[..])).collect::<Vec<_>>()
        }),
        "as_path": p.as_path,
        "origin": p.origin,
        "med": spec.med,
        "local_pref": spec.local_pref,
        "atomic_aggregate": spec.atomic_aggregate,
        "aggregator": p.aggregator.map(|(asn, ip)| json!({"as": asn, "id": Ipv4Addr::from(ip).to_string()})),
        "originator_id": p.originator_id.map(|ip| Ipv4Addr::from(ip).to_string()),
        "cluster_list": p.cluster_list.iter().map(|ip| Ipv4Addr::from(*ip).to_string()).collect::<Vec<_>>(),
        "aigp": spec.aigp,
        "standard_communities": spec.standard_communities,
        "extended_communities": spec.extended_communities,
        "ipv6_extended_communities": spec.ipv6_extended_communities,
        "ipv6_ext_communities_hex": p.ipv6_ext_comms.iter().map(|c| hex(&c[..])).collect::<Vec<_>>(),
        "large_communities": spec.large_communities,
        "path_id": spec.path_id,
        "rd": spec.rd,
        "label": if spec.rd.is_some() { json!(p.label) } else { json!(null) },
        // Resolved form: the flags byte exactly as emitted (extended-length
        // bit normalized against the value size).
        "raw_attributes": p.raw_attrs.iter().map(|(f, c, v)| {
            let emitted = if v.len() > 255 { f | FLAG_EXT_LEN } else { f & !FLAG_EXT_LEN };
            json!({"flags": emitted, "code": c, "value_hex": hex(v)})
        }).collect::<Vec<_>>(),
    })
}

/// Build an MRT file (plus manifest) from `routes`. Record N is stamped
/// `base_timestamp + N`; output is deterministic for a given input.
pub fn generate_from_routes(routes: &[RouteSpec], format: RouteFormat, base_timestamp: u32) -> Result<Corpus, String> {
    let parsed: Vec<ParsedRoute> = routes.iter().enumerate().map(|(i, r)| parse_route(i, r)).collect::<Result<_, _>>()?;

    let mut bytes = Vec::new();
    let mut entries: Vec<RecordEntry> = Vec::new();
    let mut counts = Counts::default();
    let mut push = |bytes: &mut Vec<u8>, entries: &mut Vec<RecordEntry>, rec: crate::writer::MrtRecord, kind: &str, description: String, details: serde_json::Value| {
        let offset = bytes.len() as u64;
        rec.encode_into(bytes);
        counts.valid += 1;
        entries.push(RecordEntry {
            index: entries.len(),
            offset,
            size: rec.encoded_len() as u64,
            mrt_type: rec.mrt_type,
            subtype: rec.subtype,
            timestamp: rec.timestamp,
            kind: kind.to_string(),
            expect: Expect::Valid,
            description,
            details,
        });
    };

    match format {
        RouteFormat::TableDumpV2 => {
            if let Some(i) = parsed.iter().position(|p| p.flow_nlri.is_some()) {
                return Err(format!("route {i}: flowspec requires --routes-format bgp4mp (FlowSpec rules are UPDATE-stream artifacts and common MRT parsers cannot walk RIB_GENERIC/SAFI-133 records)"));
            }
            // Peer 0 answers IPv4 routes, peer 1 IPv6 routes.
            let peers = vec![
                Peer { bgp_id: [192, 0, 2, 1], ip: vec![192, 0, 2, 1], asn: 64500, as4: true },
                Peer { bgp_id: [192, 0, 2, 2], ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets().to_vec(), asn: 64500, as4: true },
            ];
            push(
                &mut bytes,
                &mut entries,
                records::peer_index_table(base_timestamp, [192, 0, 2, 100], "mrtgen-routes", &peers),
                "route_peer_index_table",
                "TABLE_DUMP_V2 PEER_INDEX_TABLE for the user route list".into(),
                json!({"peer_count": 2}),
            );
            for (i, (spec, p)) in routes.iter().zip(&parsed).enumerate() {
                let ts = base_timestamp + entries.len() as u32;
                let (head, tail) = common_attrs(p, spec);
                let mut attrs = head;
                if p.rd.is_some() {
                    // SAFI 128: RD-prefixed next hop in the abbreviated
                    // TABLE_DUMP_V2 MP_REACH_NLRI form (RFC 6396 4.3.4).
                    attrs.extend(bgp::attr_mp_reach_td2(&bgp::vpn_next_hop(&p.nexthop)));
                } else if p.v6 {
                    attrs.extend(bgp::attr_mp_reach_td2(&p.nexthop));
                } else {
                    attrs.extend(bgp::attr_next_hop(p.nexthop.clone().try_into().unwrap()));
                }
                attrs.extend(tail);
                let target = spec.prefix.as_deref().unwrap_or("flowspec");
                if attrs.len() > u16::MAX as usize {
                    return Err(format!("route {i} ('{target}'): encoded attributes are {} bytes, over the 65535-byte RIB entry limit", attrs.len()));
                }
                let peer_index = if p.v6 { 1 } else { 0 };
                let rec = if let Some(rd) = p.rd {
                    // VPN routes ride RIB_GENERIC; the ADD-PATH variant puts
                    // the Path Identifier in the NLRI (RFC 8050 section 4.2).
                    let entry = RibEntry::new(peer_index, ts, attrs);
                    let (subtype, kind) = match (p.v6, spec.path_id.is_some()) {
                        (false, false) => (RIB_GENERIC, "route_rib_generic_vpnv4"),
                        (false, true) => (RIB_GENERIC_ADDPATH, "route_rib_generic_vpnv4_addpath"),
                        (true, false) => (RIB_GENERIC, "route_rib_generic_vpnv6"),
                        (true, true) => (RIB_GENERIC_ADDPATH, "route_rib_generic_vpnv6_addpath"),
                    };
                    let afi = if p.v6 { BGP_AFI_IPV6 } else { BGP_AFI_IPV4 };
                    let nlri = with_path_id(spec.path_id, bgp::nlri_vpn(p.label, rd, &p.prefix, p.bits));
                    (records::rib_generic(ts, subtype, i as u32, afi, SAFI_MPLS_VPN, &nlri, &[entry]), kind)
                } else {
                    let mut entry = RibEntry::new(peer_index, ts, attrs);
                    entry.path_id = spec.path_id;
                    let (subtype, kind) = match (p.v6, spec.path_id.is_some()) {
                        (false, false) => (RIB_IPV4_UNICAST, "route_rib_ipv4_unicast"),
                        (false, true) => (RIB_IPV4_UNICAST_ADDPATH, "route_rib_ipv4_unicast_addpath"),
                        (true, false) => (RIB_IPV6_UNICAST, "route_rib_ipv6_unicast"),
                        (true, true) => (RIB_IPV6_UNICAST_ADDPATH, "route_rib_ipv6_unicast_addpath"),
                    };
                    let nlri = if p.v6 { bgp::nlri_v6(p.prefix.clone().try_into().unwrap(), p.bits) } else { bgp::nlri_v4(p.prefix.clone().try_into().unwrap(), p.bits) };
                    (records::rib_afi_safi(ts, subtype, i as u32, &nlri, &[entry]), kind)
                };
                push(
                    &mut bytes,
                    &mut entries,
                    rec.0,
                    rec.1,
                    format!("User route {target} via {}", spec.nexthop.as_deref().unwrap_or("-")),
                    route_details(spec, p),
                );
            }
        }
        RouteFormat::Bgp4mp => {
            for (i, (spec, p)) in routes.iter().zip(&parsed).enumerate() {
                let ts = base_timestamp + entries.len() as u32;
                let (head, tail) = common_attrs(p, spec);
                let mut attrs = head;
                let mut nlri = Vec::new();
                if let Some(flow) = &p.flow_nlri {
                    // SAFI 133: FlowSpec NLRI in MP_REACH_NLRI; the next hop
                    // may legitimately be 0 bytes long.
                    let afi = if p.v6 { BGP_AFI_IPV6 } else { BGP_AFI_IPV4 };
                    let announced = with_path_id(spec.path_id, flow.clone());
                    attrs.extend(bgp::attr_mp_reach(afi, SAFI_FLOWSPEC, &p.nexthop, &announced));
                } else if let Some(rd) = p.rd {
                    // SAFI 128: full RFC 4760 MP_REACH_NLRI with an
                    // RD-prefixed next hop; label + RD + prefix NLRI.
                    let afi = if p.v6 { BGP_AFI_IPV6 } else { BGP_AFI_IPV4 };
                    let announced = with_path_id(spec.path_id, bgp::nlri_vpn(p.label, rd, &p.prefix, p.bits));
                    attrs.extend(bgp::attr_mp_reach(afi, SAFI_MPLS_VPN, &bgp::vpn_next_hop(&p.nexthop), &announced));
                } else if p.v6 {
                    let announced = with_path_id(spec.path_id, bgp::nlri_v6(p.prefix.clone().try_into().unwrap(), p.bits));
                    attrs.extend(bgp::attr_mp_reach(BGP_AFI_IPV6, SAFI_UNICAST, &p.nexthop, &announced));
                } else {
                    attrs.extend(bgp::attr_next_hop(p.nexthop.clone().try_into().unwrap()));
                    nlri = with_path_id(spec.path_id, bgp::nlri_v4(p.prefix.clone().try_into().unwrap(), p.bits));
                }
                attrs.extend(tail);
                let target = spec.prefix.as_deref().unwrap_or("flowspec");
                let update = bgp::bgp_update(&[], &attrs, &nlri);
                if update.len() > 4096 {
                    return Err(format!("route {i} ('{target}'): BGP UPDATE is {} bytes, over the 4096-byte message limit (use table-dump-v2 for oversized attribute sets)", update.len()));
                }
                let peer_as = p.as_path.first().copied().unwrap_or(64500);
                let addpath = spec.path_id.is_some();
                let subtype = if addpath { BGP4MP_MESSAGE_AS4_ADDPATH } else { BGP4MP_MESSAGE_AS4 };
                let kind = match (p.flow_nlri.is_some(), p.rd.is_some(), addpath) {
                    (true, _, false) => "route_bgp4mp_flowspec",
                    (true, _, true) => "route_bgp4mp_flowspec_addpath",
                    (false, true, false) => "route_bgp4mp_update_vpn",
                    (false, true, true) => "route_bgp4mp_update_vpn_addpath",
                    (false, false, false) => "route_bgp4mp_update",
                    (false, false, true) => "route_bgp4mp_update_addpath",
                };
                let (peer_ip, local_ip): (Vec<u8>, Vec<u8>) = if p.v6 {
                    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets().to_vec(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets().to_vec())
                } else {
                    (vec![192, 0, 2, 1], vec![192, 0, 2, 2])
                };
                push(
                    &mut bytes,
                    &mut entries,
                    records::bgp4mp_message(ts, BGP4MP, None, subtype, peer_as, 64511, 1, &peer_ip, &local_ip, &update),
                    kind,
                    if p.flow_nlri.is_some() {
                        "BGP UPDATE announcing a FlowSpec rule (SAFI 133) via MP_REACH_NLRI".to_string()
                    } else {
                        format!("BGP UPDATE announcing user route {target} via {}", spec.nexthop.as_deref().unwrap_or("-"))
                    },
                    route_details(spec, p),
                );
            }
        }
    }

    let manifest = Manifest {
        generator: "mrtgen".into(),
        generator_version: env!("CARGO_PKG_VERSION").into(),
        file_size: bytes.len() as u64,
        counts,
        records: entries,
    };
    Ok(Corpus { bytes, manifest })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"[
        {"prefix": "1.2.3.0/24", "nexthop": "1.1.1.1",
         "standard_communities": ["111:222", "222:333"]},
        {"prefix": "2001:db8:64::/48", "nexthop": "2001:db8::9",
         "as_path": [64500, 4200000001], "origin": "incomplete",
         "med": 50, "local_pref": 150,
         "extended_communities": ["rt:64500:1", "soo:4200000001:7"],
         "large_communities": ["64500:1:2"], "path_id": 9}
    ]"#;

    #[test]
    fn parses_example() {
        let routes = routes_from_json(EXAMPLE).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].standard_communities, ["111:222", "222:333"]);
        assert_eq!(routes[1].path_id, Some(9));
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","local_perf":1}]"#).is_err());
    }

    #[test]
    fn rejects_family_mismatch() {
        let routes = routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"2001:db8::1"}]"#).unwrap();
        let err = generate_from_routes(&routes, RouteFormat::TableDumpV2, 0).unwrap_err();
        assert!(err.contains("IPv4 prefix requires an IPv4 next hop"), "{err}");
    }

    #[test]
    fn community_parsers() {
        assert_eq!(parse_std_community("111:222").unwrap(), (111 << 16) | 222);
        assert_eq!(parse_std_community("no-export").unwrap(), COMM_NO_EXPORT);
        assert_eq!(parse_std_community("0xFFFFFF02").unwrap(), COMM_NO_ADVERTISE);
        assert!(parse_std_community("70000:1").is_err());
        assert_eq!(parse_ext_community("rt:64500:1").unwrap(), [0x00, 0x02, 0xFB, 0xF4, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(parse_ext_community("rt:4200000001:7").unwrap(), [0x02, 0x02, 0xFA, 0x56, 0xEA, 0x01, 0x00, 0x07]);
        assert_eq!(parse_ext_community("0002FBF400000001").unwrap(), [0x00, 0x02, 0xFB, 0xF4, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(parse_large_community("64500:1:2").unwrap(), [64500, 1, 2]);
    }

    #[test]
    fn generates_table_dump_v2() {
        let routes = routes_from_json(EXAMPLE).unwrap();
        let corpus = generate_from_routes(&routes, RouteFormat::TableDumpV2, 1_600_000_000).unwrap();
        // PEER_INDEX_TABLE + one RIB record per route.
        assert_eq!(corpus.manifest.records.len(), 3);
        assert_eq!(corpus.manifest.counts.valid, 3);
        assert_eq!(corpus.manifest.records[1].subtype, RIB_IPV4_UNICAST);
        assert_eq!(corpus.manifest.records[2].subtype, RIB_IPV6_UNICAST_ADDPATH);
        assert_eq!(corpus.manifest.file_size, corpus.bytes.len() as u64);
        // The two standard communities of route 0 appear on the wire.
        let comms: Vec<u8> = [(111u32 << 16) | 222, (222u32 << 16) | 333].iter().flat_map(|c| c.to_be_bytes()).collect();
        assert!(corpus.bytes.windows(comms.len()).any(|w| w == comms));
    }

    #[test]
    fn generates_bgp4mp() {
        let routes = routes_from_json(EXAMPLE).unwrap();
        let corpus = generate_from_routes(&routes, RouteFormat::Bgp4mp, 1_600_000_000).unwrap();
        assert_eq!(corpus.manifest.records.len(), 2);
        assert_eq!(corpus.manifest.records[0].subtype, BGP4MP_MESSAGE_AS4);
        assert_eq!(corpus.manifest.records[1].subtype, BGP4MP_MESSAGE_AS4_ADDPATH);
    }

    #[test]
    fn raw_attributes() {
        let routes = routes_from_json(
            r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","raw_attributes":[
                {"flags": 192, "code": 99, "value_hex": "DEADbeef"},
                {"flags": ["optional", "transitive", "partial"], "code": 200},
                {"flags": ["optional"], "code": 201, "value_hex": "aa"}]}]"#,
        )
        .unwrap();
        let corpus = generate_from_routes(&routes, RouteFormat::Bgp4mp, 0).unwrap();
        for wire in [vec![0xC0u8, 99, 4, 0xDE, 0xAD, 0xBE, 0xEF], vec![0xE0, 200, 0], vec![0x80, 201, 1, 0xAA]] {
            assert!(corpus.bytes.windows(wire.len()).any(|w| w == wire), "raw attribute {wire:02x?} not on the wire");
        }
        let det = &corpus.manifest.records[0].details["raw_attributes"];
        assert_eq!(det[0]["value_hex"], "deadbeef");
        assert_eq!(det[1]["flags"], 0xE0);

        // Extended-length is applied automatically past 255 value bytes.
        let long = "ab".repeat(300);
        let routes = routes_from_json(&format!(
            r#"[{{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","raw_attributes":[{{"flags": 192, "code": 99, "value_hex": "{long}"}}]}}]"#
        ))
        .unwrap();
        let corpus = generate_from_routes(&routes, RouteFormat::TableDumpV2, 0).unwrap();
        let mut wire = vec![0xC0 | FLAG_EXT_LEN, 99, 0x01, 0x2C];
        wire.extend(std::iter::repeat_n(0xAB, 300));
        assert!(corpus.bytes.windows(wire.len()).any(|w| w == wire), "extended-length raw attribute not found");
        assert_eq!(corpus.manifest.records[1].details["raw_attributes"][0]["flags"], 0xC0 | FLAG_EXT_LEN);

        // Bad hex is rejected.
        let routes = routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","raw_attributes":[{"flags":192,"code":1,"value_hex":"abc"}]}]"#).unwrap();
        assert!(generate_from_routes(&routes, RouteFormat::Bgp4mp, 0).unwrap_err().contains("even number of hex digits"));
    }

    #[test]
    fn ipv6_ext_community_parsing() {
        let c = parse_ipv6_ext_community("rt:2001:db8::1:5").unwrap();
        assert_eq!(c[0..2], [0x00, 0x02]);
        assert_eq!(c[2..18], Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        assert_eq!(c[18..], [0, 5]);
        let c = parse_ipv6_ext_community("soo:2001:db8::2:65535").unwrap();
        assert_eq!(c[1], 0x03);
        assert_eq!(c[18..], [0xFF, 0xFF]);
        let raw = "000220010db8000000000000000000000001000a";
        assert_eq!(hex(&parse_ipv6_ext_community(raw).unwrap()), raw);
        assert!(parse_ipv6_ext_community("rt:1.2.3.4:5").is_err());
        assert!(parse_ipv6_ext_community("deadbeef").is_err());

        // End to end: the attribute must appear with code 25 and 20-byte value.
        let routes = routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","ipv6_extended_communities":["rt:2001:db8::1:5"]}]"#).unwrap();
        let corpus = generate_from_routes(&routes, RouteFormat::Bgp4mp, 0).unwrap();
        let mut attr = vec![FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_IPV6_EXT_COMMUNITY, 20];
        attr.extend_from_slice(&parse_ipv6_ext_community("rt:2001:db8::1:5").unwrap());
        assert!(corpus.bytes.windows(attr.len()).any(|w| w == attr), "attr 25 not found on the wire");
    }

    #[test]
    fn rr_and_aggregator_attributes() {
        let routes = routes_from_json(
            r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1",
                 "aggregator":"4200000001:192.0.2.7","originator_id":"10.0.0.1",
                 "cluster_list":["10.0.0.2","10.0.0.3"],"aigp":4294967296}]"#,
        )
        .unwrap();
        let corpus = generate_from_routes(&routes, RouteFormat::Bgp4mp, 0).unwrap();
        let aggregator = [FLAG_OPTIONAL | FLAG_TRANSITIVE, ATTR_AGGREGATOR, 8, 0xFA, 0x56, 0xEA, 0x01, 192, 0, 2, 7];
        let originator = [FLAG_OPTIONAL, ATTR_ORIGINATOR_ID, 4, 10, 0, 0, 1];
        let clusters = [FLAG_OPTIONAL, ATTR_CLUSTER_LIST, 8, 10, 0, 0, 2, 10, 0, 0, 3];
        let aigp = [FLAG_OPTIONAL, ATTR_AIGP, 11, 1, 0, 11, 0, 0, 0, 1, 0, 0, 0, 0];
        for attr in [&aggregator[..], &originator, &clusters, &aigp] {
            assert!(corpus.bytes.windows(attr.len()).any(|w| w == attr), "attribute {attr:02x?} not found on the wire");
        }
        let det = &corpus.manifest.records[0].details;
        assert_eq!(det["aggregator"], serde_json::json!({"as": 4200000001u32, "id": "192.0.2.7"}));
        assert_eq!(det["originator_id"], "10.0.0.1");
        assert_eq!(det["cluster_list"], serde_json::json!(["10.0.0.2", "10.0.0.3"]));
        assert_eq!(det["aigp"], 4294967296u64);
        assert!(generate_from_routes(&routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","aggregator":"64500"}]"#).unwrap(), RouteFormat::Bgp4mp, 0).is_err());
        assert!(generate_from_routes(&routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","originator_id":"2001:db8::1"}]"#).unwrap(), RouteFormat::Bgp4mp, 0).is_err());
    }

    #[test]
    fn rd_parsing() {
        assert_eq!(parse_rd("64500:1").unwrap(), [0, 0, 0xFB, 0xF4, 0, 0, 0, 1]);
        assert_eq!(parse_rd("192.0.2.66:2").unwrap(), [0, 1, 192, 0, 2, 66, 0, 2]);
        assert_eq!(parse_rd("4200000001:7").unwrap(), [0, 2, 0xFA, 0x56, 0xEA, 0x01, 0, 7]);
        assert!(parse_rd("4200000001:70000").is_err(), "type-2 number must fit u16");
        assert!(parse_rd("64500").is_err());
    }

    #[test]
    fn vpn_routes() {
        let routes = routes_from_json(
            r#"[
            {"prefix":"10.30.0.0/24","nexthop":"192.0.2.5","rd":"64500:1","label":100},
            {"prefix":"2001:db8:64::/48","nexthop":"2001:db8::9","rd":"192.0.2.66:2","label":200,"path_id":3}
        ]"#,
        )
        .unwrap();
        let td2 = generate_from_routes(&routes, RouteFormat::TableDumpV2, 0).unwrap();
        assert_eq!(td2.manifest.records[1].subtype, RIB_GENERIC);
        assert_eq!(td2.manifest.records[1].kind, "route_rib_generic_vpnv4");
        assert_eq!(td2.manifest.records[2].subtype, RIB_GENERIC_ADDPATH);
        assert_eq!(td2.manifest.records[2].kind, "route_rib_generic_vpnv6_addpath");
        // The VPNv4 NLRI must be: bits(24+64+24) | label stack | RD | prefix.
        let mut nlri = vec![24 + 64 + 24];
        nlri.extend_from_slice(&((100u32 << 4) | 1).to_be_bytes()[1..]);
        nlri.extend_from_slice(&[0, 0, 0xFB, 0xF4, 0, 0, 0, 1]);
        nlri.extend_from_slice(&[10, 30, 0]);
        assert!(td2.bytes.windows(nlri.len()).any(|w| w == nlri), "VPNv4 NLRI bytes not found");

        let b4 = generate_from_routes(&routes, RouteFormat::Bgp4mp, 0).unwrap();
        assert_eq!(b4.manifest.records[0].kind, "route_bgp4mp_update_vpn");
        assert_eq!(b4.manifest.records[0].subtype, BGP4MP_MESSAGE_AS4);
        assert_eq!(b4.manifest.records[1].kind, "route_bgp4mp_update_vpn_addpath");
        assert_eq!(b4.manifest.records[1].subtype, BGP4MP_MESSAGE_AS4_ADDPATH);
    }

    #[test]
    fn label_requires_rd_and_fits() {
        let routes = routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","label":5}]"#).unwrap();
        let err = generate_from_routes(&routes, RouteFormat::TableDumpV2, 0).unwrap_err();
        assert!(err.contains("label requires rd"), "{err}");
        let routes = routes_from_json(r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","rd":"64500:1","label":1048576}]"#).unwrap();
        let err = generate_from_routes(&routes, RouteFormat::TableDumpV2, 0).unwrap_err();
        assert!(err.contains("20-bit"), "{err}");
    }

    #[test]
    fn flowspec_routes() {
        let routes = routes_from_json(
            r#"[{"flowspec": {"dst_prefix": "192.0.2.0/24", "protocol": [6], "port": [25]},
                 "actions": {"rate_limit_bytes": 0, "redirect": "64500:1", "terminal_action": true}}]"#,
        )
        .unwrap();
        // TD2 refuses flowspec.
        let err = generate_from_routes(&routes, RouteFormat::TableDumpV2, 0).unwrap_err();
        assert!(err.contains("bgp4mp"), "{err}");

        let b4 = generate_from_routes(&routes, RouteFormat::Bgp4mp, 0).unwrap();
        let rec = &b4.manifest.records[0];
        assert_eq!(rec.kind, "route_bgp4mp_flowspec");
        assert_eq!(rec.subtype, BGP4MP_MESSAGE_AS4);
        assert_eq!(rec.details["nlri_hex"], "0b0118c00002038106048119");
        // MP_REACH header: AFI 1, SAFI 133, next hop length 0, reserved 0,
        // then the RFC 8955 example-1 NLRI.
        let mut mp = vec![0x00, 0x01, 133, 0, 0];
        mp.extend_from_slice(&[0x0b, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x03, 0x81, 0x06, 0x04, 0x81, 0x19]);
        assert!(b4.bytes.windows(mp.len()).any(|w| w == mp), "MP_REACH flowspec bytes not found");
        // Action communities: traffic-rate-bytes 0, traffic-action T bit,
        // rt-redirect 64500:1.
        for comm in [
            [0x80, 0x06, 0, 0, 0, 0, 0, 0],
            [0x80, 0x07, 0, 0, 0, 0, 0, 0x01],
            [0x80, 0x08, 0xFB, 0xF4, 0, 0, 0, 0x01],
        ] {
            assert!(b4.bytes.windows(8).any(|w| w == comm), "action community {comm:02x?} not found");
        }
    }

    #[test]
    fn flowspec_validation_errors() {
        let cases = [
            (r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","flowspec":{"protocol":[6]}}]"#, "mutually exclusive"),
            (r#"[{"nexthop":"1.1.1.1"}]"#, "prefix or a flowspec"),
            (r#"[{"prefix":"1.2.3.0/24"}]"#, "nexthop is required"),
            (r#"[{"prefix":"1.2.3.0/24","nexthop":"1.1.1.1","actions":{"sample":true}}]"#, "actions require"),
            (r#"[{"flowspec":{"protocol":[6]},"rd":"64500:1"}]"#, "cannot be combined with flowspec"),
            (r#"[{"flowspec":{"protocol":[6]},"actions":{"traffic_marking":64}}]"#, "exceeds 63"),
            (r#"[{"flowspec":{"protocol":[6]},"actions":{"rate_limit_bytes":-1}}]"#, "non-negative"),
        ];
        for (json, needle) in cases {
            let routes = routes_from_json(json).unwrap();
            let err = generate_from_routes(&routes, RouteFormat::Bgp4mp, 0).unwrap_err();
            assert!(err.contains(needle), "expected '{needle}' in: {err}");
        }
    }

    #[test]
    fn redirect_community_forms() {
        assert_eq!(redirect_community("64500:1").unwrap(), [0x80, 0x08, 0xFB, 0xF4, 0, 0, 0, 1]);
        assert_eq!(redirect_community("192.0.2.1:7").unwrap(), [0x81, 0x08, 192, 0, 2, 1, 0, 7]);
        assert_eq!(redirect_community("4200000001:7").unwrap(), [0x82, 0x08, 0xFA, 0x56, 0xEA, 0x01, 0, 7]);
        assert!(redirect_community("4200000001:70000").is_err());
    }

    #[test]
    fn deterministic() {
        let routes = routes_from_json(EXAMPLE).unwrap();
        let a = generate_from_routes(&routes, RouteFormat::TableDumpV2, 42).unwrap();
        let b = generate_from_routes(&routes, RouteFormat::TableDumpV2, 42).unwrap();
        assert_eq!(a.bytes, b.bytes);
    }
}
