//! Machine-readable description of a generated corpus, for CI validation.

use serde::{Deserialize, Serialize};

/// Generation profile recorded in the manifest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusProfile {
    /// Compact protocol and boundary coverage suitable for normal CI.
    #[default]
    Standard,
    /// Standard coverage plus high-volume and near-limit records.
    Stress,
    /// A corpus produced from a caller-supplied route list.
    Routes,
}

/// Expected outcome when a conforming MRT parser encounters a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// The record is well-formed and must be fully parsed.
    Valid,
    /// The record is damaged in a way that is recoverable: its MRT header
    /// length is trustworthy, so the parser must skip it and continue
    /// with the next record.
    Skip,
    /// The record damages the framing itself (length overruns EOF,
    /// truncated header). A parser cannot resync; loading must stop here.
    Abort,
}

/// One record in the generated file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordEntry {
    /// 0-based position in the file.
    pub index: usize,
    /// Byte offset of the record's MRT common header.
    pub offset: u64,
    /// Total encoded size in bytes (header + body as written, which for
    /// broken records may disagree with the header's Length field).
    pub size: u64,
    pub mrt_type: u16,
    pub subtype: u16,
    pub timestamp: u32,
    /// Stable machine-readable identifier of the test case,
    /// e.g. `rib_ipv4_unicast` or `invalid_attr_med_len8`.
    pub kind: String,
    pub expect: Expect,
    pub description: String,
    /// Stable selectors used to derive valid-only, recovery, and
    /// parser-specific subcorpora without relying on record ordering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Content facts a validator can assert after parsing
    /// (prefixes, AS numbers, message types, ...).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub generator: String,
    pub generator_version: String,
    #[serde(default)]
    pub profile: CorpusProfile,
    /// Total file size in bytes.
    pub file_size: u64,
    pub counts: Counts,
    pub records: Vec<RecordEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub valid: usize,
    pub skip: usize,
    pub abort: usize,
}

impl Manifest {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serialization cannot fail")
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
