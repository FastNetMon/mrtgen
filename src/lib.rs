//! # mrtgen — deterministic synthetic MRT corpus generator
//!
//! Generates MRT files (RFC 6396, with RFC 8050 ADD-PATH extensions) that
//! exercise an MRT parser end to end:
//!
//! * **valid records** covering every standard type and subtype
//!   (TABLE_DUMP, TABLE_DUMP_V2 incl. ADD-PATH, BGP4MP/BGP4MP_ET,
//!   OSPFv2/OSPFv3(_ET), ISIS(_ET));
//! * **skip-class invalid records** — honest MRT framing, broken content
//!   (unknown types, wrong fixed-size attribute TLV lengths such as a
//!   4-byte MED declared as 2/8/16 bytes, TLVs overrunning their
//!   container, bad BGP markers/lengths, inner truncation) — a parser is
//!   expected to skip these and continue;
//! * **communities × ADD-PATH combination records** — every record carries a
//!   community attribute (standard/extended/large) and an ADD-PATH element,
//!   in legal and deliberately-illegal-but-skippable combinations;
//! * **attribute error-handling records (RFC 7606)** — honest framing with a
//!   single malformed path attribute (bad AS_PATH segment, bad flags/length,
//!   MP_REACH/UNREACH damage, illegal zero-length, unknown/reserved type);
//! * **abort-class tails** (optional) — the framing itself lies (Length
//!   past EOF, truncated header), after which loading must stop.
//!
//! Alternatively, [`routes`] builds a file from a user-supplied JSON route
//! list (prefix, next hop, communities, ...) instead of the built-in corpus,
//! encoded either as a TABLE_DUMP_V2 RIB dump or as BGP4MP UPDATEs.
//!
//! Output is byte-for-byte deterministic for a given [`GeneratorConfig`]:
//! no clocks, no randomness. A JSON [`Manifest`] lists every record with
//! its byte offset, size, type/subtype, expected parser outcome
//! (`valid` / `skip` / `abort`) and content facts, so a CI job can assert
//! that everything expected was loaded and nothing else.
//!
//! ## Library use
//!
//! ```
//! use mrtgen::{generate, GeneratorConfig, FatalKind, Expect};
//!
//! let corpus = generate(&GeneratorConfig::default());
//! assert!(!corpus.bytes.is_empty());
//! // Feed corpus.bytes to the parser under test, then check every
//! // manifest record with expect == Expect::Valid was loaded.
//! let valid = corpus.manifest.records.iter()
//!     .filter(|r| r.expect == Expect::Valid).count();
//! assert_eq!(valid, corpus.manifest.counts.valid);
//!
//! // A separate file that must make the loader abort:
//! let fatal = generate(&GeneratorConfig {
//!     fatal: Some(FatalKind::TruncatedHeader),
//!     ..GeneratorConfig::default()
//! });
//! assert_eq!(fatal.manifest.counts.abort, 1);
//! ```
//!
//! Individual record builders are exposed in [`records`], [`bgp`] and
//! [`invalid`] for composing custom corpora on top of [`writer::MrtRecord`].

pub mod bgp;
pub mod flowspec;
pub mod generator;
pub mod invalid;
pub mod manifest;
pub mod records;
pub mod routes;
pub mod types;
pub mod writer;

pub use flowspec::FlowSpec;
pub use generator::{corpus_peers, generate, Corpus, FatalKind, GeneratorConfig};
pub use manifest::{Expect, Manifest, RecordEntry};
pub use routes::{generate_from_routes, routes_from_json, Actions, RawAttribute, RouteFormat, RouteSpec};
pub use writer::MrtRecord;
