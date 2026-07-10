//! FlowSpec NLRI encoding (RFC 8955 for IPv4, RFC 8956 for IPv6).
//!
//! A [`FlowSpec`] describes the match components of one Flow Specification
//! rule; [`encode_nlri`] turns it into the on-the-wire NLRI (length octet(s)
//! followed by the components in ascending type order). Traffic actions are
//! not part of the NLRI — they travel as extended communities and are built
//! in `routes.rs`.

use serde::{Deserialize, Serialize};

use crate::routes::{parse_prefix, prefix_has_host_bits};

// Component type codes (RFC 8955 section 4.2.2, RFC 8956 section 3).
const T_DST_PREFIX: u8 = 1;
const T_SRC_PREFIX: u8 = 2;
const T_PROTOCOL: u8 = 3;
const T_PORT: u8 = 4;
const T_DST_PORT: u8 = 5;
const T_SRC_PORT: u8 = 6;
const T_ICMP_TYPE: u8 = 7;
const T_ICMP_CODE: u8 = 8;
const T_TCP_FLAGS: u8 = 9;
const T_PACKET_LENGTH: u8 = 10;
const T_DSCP: u8 = 11;
const T_FRAGMENT: u8 = 12;
const T_FLOW_LABEL: u8 = 13;

/// Match components of one Flow Specification rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowSpec {
    /// `"ipv4"` (default) or `"ipv6"`; only needed when neither prefix
    /// component is present, otherwise the family is taken from them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub afi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_prefix: Option<String>,
    /// IP protocol (v4) / last next header (v6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dst_port: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub src_port: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icmp_type: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icmp_code: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tcp_flags: Vec<BitmaskMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packet_length: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dscp: Vec<NumericMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fragment: Vec<BitmaskMatch>,
    /// IPv6 only (RFC 8956 section 3.7).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flow_label: Vec<NumericMatch>,
    /// Escape hatch for hostile corpora: raw component bytes appended
    /// verbatim after the typed components, inside the correctly-framed
    /// NLRI. This is the only way to express RFC violations the typed
    /// fields refuse — duplicate or out-of-order components, unknown
    /// component types, truncated operator lists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_components_hex: Option<String>,
}

/// One {op, value} element of a numeric-operator component. A bare number
/// means equality; items in a list are ORed together (`range` produces a
/// `>= a` AND `<= b` pair).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NumericMatch {
    Value(u64),
    Op(NumericOp),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NumericOp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub le: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ge: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<[u64; 2]>,
}

/// One {bitmask_op, bitmask} element for `tcp_flags` / `fragment`.
/// `match` sets the m bit (exact match of all bits), `not` negates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitmaskMatch {
    pub flags: FlagValue,
    #[serde(default, rename = "match")]
    pub match_: bool,
    #[serde(default)]
    pub not: bool,
}

/// Flag bits given numerically or as names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FlagValue {
    Num(u64),
    Names(Vec<String>),
}

const TCP_FLAG_NAMES: [(&str, u64); 8] = [
    ("fin", 0x01),
    ("syn", 0x02),
    ("rst", 0x04),
    ("psh", 0x08),
    ("ack", 0x10),
    ("urg", 0x20),
    ("ece", 0x40),
    ("cwr", 0x80),
];

// RFC 8955 Figure 4; RFC 8956 drops dont-fragment for IPv6 but we do not
// second-guess the user beyond the numeric range.
const FRAGMENT_FLAG_NAMES: [(&str, u64); 4] = [
    ("dont-fragment", 0x01),
    ("is-fragment", 0x02),
    ("first-fragment", 0x04),
    ("last-fragment", 0x08),
];

fn resolve_flags(v: &FlagValue, table: &[(&str, u64)], what: &str) -> Result<u64, String> {
    match v {
        FlagValue::Num(n) => Ok(*n),
        FlagValue::Names(names) => {
            let mut bits = 0u64;
            for n in names {
                let low = n.to_ascii_lowercase();
                bits |= table
                    .iter()
                    .find(|(name, _)| *name == low)
                    .ok_or_else(|| format!("{what}: unknown flag '{n}' (expected one of {:?})", table.iter().map(|(n, _)| *n).collect::<Vec<_>>()))?
                    .1;
            }
            Ok(bits)
        }
    }
}

/// Minimal 1/2/4/8-byte encoding of `v`: (len code for the op byte, bytes).
fn value_bytes(v: u64) -> (u8, Vec<u8>) {
    if v <= 0xFF {
        (0, vec![v as u8])
    } else if v <= 0xFFFF {
        (1, (v as u16).to_be_bytes().to_vec())
    } else if v <= 0xFFFF_FFFF {
        (2, (v as u32).to_be_bytes().to_vec())
    } else {
        (3, v.to_be_bytes().to_vec())
    }
}

// Numeric operator comparison bits (RFC 8955 section 4.2.1.1).
const OP_EQ: u8 = 0x01;
const OP_GT: u8 = 0x02;
const OP_LT: u8 = 0x04;
const OP_AND: u8 = 0x40;
const OP_END: u8 = 0x80;

/// Expand one match item into {op-bits-sans-end, value} pairs.
fn numeric_pairs(item: &NumericMatch, what: &str) -> Result<Vec<(u8, u64)>, String> {
    let op = match item {
        NumericMatch::Value(v) => return Ok(vec![(OP_EQ, *v)]),
        NumericMatch::Op(op) => op,
    };
    let mut pairs = Vec::new();
    if let Some(v) = op.eq {
        pairs.push((OP_EQ, v));
    }
    if let Some(v) = op.lt {
        pairs.push((OP_LT, v));
    }
    if let Some(v) = op.le {
        pairs.push((OP_LT | OP_EQ, v));
    }
    if let Some(v) = op.gt {
        pairs.push((OP_GT, v));
    }
    if let Some(v) = op.ge {
        pairs.push((OP_GT | OP_EQ, v));
    }
    if let Some([a, b]) = op.range {
        pairs.push((OP_GT | OP_EQ, a));
        pairs.push((OP_AND | OP_LT | OP_EQ, b));
    }
    let expected = if op.range.is_some() { 2 } else { 1 };
    match pairs.len() {
        0 => Err(format!("{what}: empty operator object (use eq/lt/le/gt/ge or range)")),
        n if n != expected => Err(format!("{what}: give one operator per list item (items are ORed; use range for an interval)")),
        _ => Ok(pairs),
    }
}

fn validate_numeric_max(items: &[NumericMatch], what: &str, max: u64) -> Result<(), String> {
    for item in items {
        for (_, value) in numeric_pairs(item, what)? {
            if value > max {
                return Err(format!("{what}: value {value} exceeds {max}"));
            }
        }
    }
    Ok(())
}

fn parse_hex(s: &str, what: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("{what}: odd-length hex string"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("{what}: invalid hex at offset {i}")))
        .collect()
}

fn validate_prefix(spec: &str, what: &str) -> Result<(), String> {
    let (_, addr, bits) = parse_prefix(spec)?;
    if prefix_has_host_bits(&addr, bits) {
        return Err(format!("{what}: prefix '{spec}' has non-zero host bits"));
    }
    Ok(())
}

/// Validate FlowSpec component values whose wire encoding is intentionally
/// generic but whose actual field domains are narrower.
pub fn validate_domains(fs: &FlowSpec) -> Result<(), String> {
    if let Some(p) = &fs.dst_prefix {
        validate_prefix(p, "flowspec dst_prefix")?;
    }
    if let Some(p) = &fs.src_prefix {
        validate_prefix(p, "flowspec src_prefix")?;
    }
    validate_numeric_max(&fs.protocol, "flowspec protocol", u8::MAX as u64)?;
    validate_numeric_max(&fs.port, "flowspec port", u16::MAX as u64)?;
    validate_numeric_max(&fs.dst_port, "flowspec dst_port", u16::MAX as u64)?;
    validate_numeric_max(&fs.src_port, "flowspec src_port", u16::MAX as u64)?;
    validate_numeric_max(&fs.icmp_type, "flowspec icmp_type", u8::MAX as u64)?;
    validate_numeric_max(&fs.icmp_code, "flowspec icmp_code", u8::MAX as u64)?;
    validate_numeric_max(&fs.packet_length, "flowspec packet_length", u16::MAX as u64)?;
    validate_numeric_max(&fs.dscp, "flowspec dscp", 63)?;
    validate_numeric_max(&fs.flow_label, "flowspec flow_label", 0x000f_ffff)?;
    Ok(())
}

/// Encode a numeric-operator component: type octet + {op, value} list.
fn encode_numeric(out: &mut Vec<u8>, ty: u8, items: &[NumericMatch], what: &str) -> Result<(), String> {
    if items.is_empty() {
        return Ok(());
    }
    out.push(ty);
    let mut pairs = Vec::new();
    for item in items {
        pairs.extend(numeric_pairs(item, what)?);
    }
    let last = pairs.len() - 1;
    for (i, (bits, v)) in pairs.into_iter().enumerate() {
        let (len_code, bytes) = value_bytes(v);
        let end = if i == last { OP_END } else { 0 };
        out.push(end | bits | (len_code << 4));
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

/// Encode a bitmask-operator component (RFC 8955 section 4.2.1.2).
fn encode_bitmask(out: &mut Vec<u8>, ty: u8, items: &[BitmaskMatch], table: &[(&str, u64)], what: &str, max_len: usize) -> Result<(), String> {
    if items.is_empty() {
        return Ok(());
    }
    out.push(ty);
    let last = items.len() - 1;
    for (i, item) in items.iter().enumerate() {
        let bits = resolve_flags(&item.flags, table, what)?;
        let (len_code, bytes) = value_bytes(bits);
        if bytes.len() > max_len {
            return Err(format!("{what}: bitmask 0x{bits:x} exceeds the {max_len}-octet limit for this component"));
        }
        let end = if i == last { OP_END } else { 0 };
        let m = if item.match_ { 0x01 } else { 0 };
        let not = if item.not { 0x02 } else { 0 };
        out.push(end | not | m | (len_code << 4));
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

/// Encode a destination/source prefix component. IPv6 prefix components
/// carry an extra offset octet (always 0 here, RFC 8956 section 3.1).
fn encode_prefix(out: &mut Vec<u8>, ty: u8, spec: &str, want_v6: Option<bool>, what: &str) -> Result<bool, String> {
    let (v6, addr, bits) = parse_prefix(spec)?;
    if let Some(want) = want_v6 {
        if want != v6 {
            return Err(format!("{what}: dst_prefix and src_prefix families differ"));
        }
    }
    out.push(ty);
    out.push(bits);
    if v6 {
        out.push(0); // offset
    }
    out.extend_from_slice(&addr[..(bits as usize).div_ceil(8)]);
    Ok(v6)
}

/// The address family of a rule: from its prefix components, else from the
/// explicit `afi` field, defaulting to IPv4.
pub fn family(fs: &FlowSpec) -> Result<bool, String> {
    if let Some(p) = fs.dst_prefix.as_deref().or(fs.src_prefix.as_deref()) {
        return Ok(parse_prefix(p)?.0);
    }
    match fs.afi.as_deref() {
        None | Some("ipv4") => Ok(false),
        Some("ipv6") => Ok(true),
        Some(other) => Err(format!("flowspec afi '{other}': expected ipv4 or ipv6")),
    }
}

/// Encode the complete FlowSpec NLRI: length octet(s) + components in
/// ascending type order. Returns the NLRI and the address family (v6?).
pub fn encode_nlri(fs: &FlowSpec) -> Result<(Vec<u8>, bool), String> {
    let v6 = family(fs)?;
    let mut c = Vec::new();
    if let Some(p) = &fs.dst_prefix {
        encode_prefix(&mut c, T_DST_PREFIX, p, Some(v6), "flowspec dst_prefix")?;
    }
    if let Some(p) = &fs.src_prefix {
        encode_prefix(&mut c, T_SRC_PREFIX, p, Some(v6), "flowspec src_prefix")?;
    }
    encode_numeric(&mut c, T_PROTOCOL, &fs.protocol, "flowspec protocol")?;
    encode_numeric(&mut c, T_PORT, &fs.port, "flowspec port")?;
    encode_numeric(&mut c, T_DST_PORT, &fs.dst_port, "flowspec dst_port")?;
    encode_numeric(&mut c, T_SRC_PORT, &fs.src_port, "flowspec src_port")?;
    encode_numeric(&mut c, T_ICMP_TYPE, &fs.icmp_type, "flowspec icmp_type")?;
    encode_numeric(&mut c, T_ICMP_CODE, &fs.icmp_code, "flowspec icmp_code")?;
    encode_bitmask(&mut c, T_TCP_FLAGS, &fs.tcp_flags, &TCP_FLAG_NAMES, "flowspec tcp_flags", 2)?;
    encode_numeric(&mut c, T_PACKET_LENGTH, &fs.packet_length, "flowspec packet_length")?;
    encode_numeric(&mut c, T_DSCP, &fs.dscp, "flowspec dscp")?;
    encode_bitmask(&mut c, T_FRAGMENT, &fs.fragment, &FRAGMENT_FLAG_NAMES, "flowspec fragment", 1)?;
    if !fs.flow_label.is_empty() {
        if !v6 {
            return Err("flowspec flow_label: IPv6 only (RFC 8956)".into());
        }
        encode_numeric(&mut c, T_FLOW_LABEL, &fs.flow_label, "flowspec flow_label")?;
    }
    if let Some(hex) = &fs.raw_components_hex {
        c.extend(parse_hex(hex, "flowspec raw_components_hex")?);
    }
    if c.is_empty() {
        return Err("flowspec: at least one match component is required".into());
    }
    // NLRI length: one octet below 240, else 0xFnnn over two (RFC 8955 4.1).
    let mut nlri = Vec::with_capacity(c.len() + 2);
    if c.len() < 240 {
        nlri.push(c.len() as u8);
    } else if c.len() < 4096 {
        nlri.push(0xF0 | (c.len() >> 8) as u8);
        nlri.push(c.len() as u8);
    } else {
        return Err(format!("flowspec: encoded components are {} bytes, over the 4095-byte NLRI limit", c.len()));
    }
    nlri.extend_from_slice(&c);
    Ok((nlri, v6))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(json: &str) -> FlowSpec {
        serde_json::from_str(json).unwrap()
    }

    /// RFC 8955 section 4.3.1: "all packets to 192.0.2.0/24 and TCP port 25".
    #[test]
    fn rfc8955_example_1() {
        let f = fs(r#"{"dst_prefix": "192.0.2.0/24", "protocol": [6], "port": [25]}"#);
        let (nlri, v6) = encode_nlri(&f).unwrap();
        assert!(!v6);
        assert_eq!(nlri, [0x0b, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x03, 0x81, 0x06, 0x04, 0x81, 0x19]);
    }

    /// RFC 8955 section 4.3.2: "packets to 192.0.2.0/24 from 203.0.113.0/24
    /// and port {range [137, 139] or 8080}".
    #[test]
    fn rfc8955_example_2() {
        let f = fs(r#"{"dst_prefix": "192.0.2.0/24", "src_prefix": "203.0.113.0/24",
                       "port": [{"range": [137, 139]}, 8080]}"#);
        let (nlri, _) = encode_nlri(&f).unwrap();
        assert_eq!(
            nlri,
            [0x12, 0x01, 0x18, 0xc0, 0x00, 0x02, 0x02, 0x18, 0xcb, 0x00, 0x71, 0x04, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90]
        );
    }

    /// RFC 8955 section 4.3.3: "packets to 192.0.2.1/32 and fragment {DF or FF}".
    #[test]
    fn rfc8955_example_3() {
        let f = fs(r#"{"dst_prefix": "192.0.2.1/32",
                       "fragment": [{"flags": ["dont-fragment", "first-fragment"]}]}"#);
        let (nlri, _) = encode_nlri(&f).unwrap();
        assert_eq!(nlri, [0x09, 0x01, 0x20, 0xc0, 0x00, 0x02, 0x01, 0x0c, 0x80, 0x05]);
    }

    /// IPv6 prefix components carry the extra offset octet (RFC 8956).
    #[test]
    fn v6_prefix_offset_and_flow_label() {
        let f = fs(r#"{"dst_prefix": "2001:db8::/32", "flow_label": [7]}"#);
        let (nlri, v6) = encode_nlri(&f).unwrap();
        assert!(v6);
        assert_eq!(nlri, [0x0a, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x0d, 0x81, 0x07]);
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(encode_nlri(&fs(r#"{}"#)).is_err(), "empty rule");
        assert!(encode_nlri(&fs(r#"{"dst_prefix": "1.2.3.0/24", "flow_label": [1]}"#)).is_err(), "v4 flow_label");
        assert!(encode_nlri(&fs(r#"{"dst_prefix": "1.2.3.0/24", "src_prefix": "2001:db8::/32"}"#)).is_err(), "family mismatch");
        assert!(encode_nlri(&fs(r#"{"port": [{}]}"#)).is_err(), "empty op");
        assert!(encode_nlri(&fs(r#"{"fragment": [{"flags": ["nope"]}]}"#)).is_err(), "bad flag name");
    }

    /// Raw component bytes go in verbatim after the typed components,
    /// letting hostile corpora express duplicate / out-of-order / unknown
    /// components the typed fields refuse.
    #[test]
    fn raw_components_appended() {
        // Typed dst_port 80 followed by a raw protocol component (type 3
        // after type 5 - deliberate RFC 8955 ordering violation).
        let f = fs(r#"{"dst_port": [80], "raw_components_hex": "038106"}"#);
        let (nlri, v6) = encode_nlri(&f).unwrap();
        assert!(!v6);
        assert_eq!(nlri, [0x06, 0x05, 0x81, 0x50, 0x03, 0x81, 0x06]);

        // Raw-only rule: duplicate destination prefixes.
        let f = fs(r#"{"raw_components_hex": "0118c000020118c00002"}"#);
        let (nlri, _) = encode_nlri(&f).unwrap();
        assert_eq!(nlri[0] as usize, nlri.len() - 1);
        assert_eq!(&nlri[1..6], &nlri[6..11]);

        assert!(encode_nlri(&fs(r#"{"raw_components_hex": "abc"}"#)).is_err(), "odd hex");
        assert!(encode_nlri(&fs(r#"{"raw_components_hex": "zz"}"#)).is_err(), "bad hex");
        assert!(encode_nlri(&fs(r#"{"raw_components_hex": ""}"#)).is_err(), "empty rule");
    }

    #[test]
    fn tcp_flags_match_not_bits() {
        let f = fs(r#"{"tcp_flags": [{"flags": ["syn", "ack"], "match": true, "not": true}]}"#);
        let (nlri, _) = encode_nlri(&f).unwrap();
        // type 9, op = end | not | m, value 0x12
        assert_eq!(nlri, [0x03, 0x09, 0x83, 0x12]);
    }

    #[test]
    fn nlri_length_encoding_boundaries() {
        for len in [1usize, 239, 240, 4095] {
            let f = FlowSpec { raw_components_hex: Some("00".repeat(len)), ..FlowSpec::default() };
            let (nlri, _) = encode_nlri(&f).unwrap();
            let header = if len < 240 { 1 } else { 2 };
            assert_eq!(nlri.len(), len + header);
            if len < 240 {
                assert_eq!(nlri[0] as usize, len);
            } else {
                assert_eq!((((nlri[0] & 0x0f) as usize) << 8) | nlri[1] as usize, len);
                assert_eq!(nlri[0] & 0xf0, 0xf0);
            }
        }
        let too_large = FlowSpec { raw_components_hex: Some("00".repeat(4096)), ..FlowSpec::default() };
        assert!(encode_nlri(&too_large).unwrap_err().contains("4095-byte"));
    }

    #[test]
    fn numeric_value_width_boundaries() {
        for (value, code, width) in [
            (0xff, 0, 1), (0x100, 1, 2), (0xffff, 1, 2),
            (0x1_0000, 2, 4), (0xffff_ffff, 2, 4),
            (0x1_0000_0000, 3, 8),
        ] {
            let (got_code, bytes) = value_bytes(value);
            assert_eq!(got_code, code, "value {value}");
            assert_eq!(bytes.len(), width, "value {value}");
        }
    }
}
