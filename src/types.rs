//! MRT type and subtype constants per RFC 6396 and RFC 8050.

// MRT Types (RFC 6396 section 4)
pub const OSPFV2: u16 = 11;
pub const TABLE_DUMP: u16 = 12;
pub const TABLE_DUMP_V2: u16 = 13;
pub const BGP4MP: u16 = 16;
pub const BGP4MP_ET: u16 = 17;
pub const ISIS: u16 = 32;
pub const ISIS_ET: u16 = 33;
pub const OSPFV3: u16 = 48;
pub const OSPFV3_ET: u16 = 49;

// TABLE_DUMP subtypes (RFC 6396 section 4.2)
pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;

// TABLE_DUMP_V2 subtypes (RFC 6396 section 4.3, RFC 8050 section 5.2)
pub const PEER_INDEX_TABLE: u16 = 1;
pub const RIB_IPV4_UNICAST: u16 = 2;
pub const RIB_IPV4_MULTICAST: u16 = 3;
pub const RIB_IPV6_UNICAST: u16 = 4;
pub const RIB_IPV6_MULTICAST: u16 = 5;
pub const RIB_GENERIC: u16 = 6;
pub const RIB_IPV4_UNICAST_ADDPATH: u16 = 8;
pub const RIB_IPV4_MULTICAST_ADDPATH: u16 = 9;
pub const RIB_IPV6_UNICAST_ADDPATH: u16 = 10;
pub const RIB_IPV6_MULTICAST_ADDPATH: u16 = 11;
pub const RIB_GENERIC_ADDPATH: u16 = 12;

// BGP4MP / BGP4MP_ET subtypes (RFC 6396 section 4.4, RFC 8050 section 5.1)
pub const BGP4MP_STATE_CHANGE: u16 = 0;
pub const BGP4MP_MESSAGE: u16 = 1;
pub const BGP4MP_MESSAGE_AS4: u16 = 4;
pub const BGP4MP_STATE_CHANGE_AS4: u16 = 5;
pub const BGP4MP_MESSAGE_LOCAL: u16 = 6;
pub const BGP4MP_MESSAGE_AS4_LOCAL: u16 = 7;
pub const BGP4MP_MESSAGE_ADDPATH: u16 = 8;
pub const BGP4MP_MESSAGE_AS4_ADDPATH: u16 = 9;
pub const BGP4MP_MESSAGE_LOCAL_ADDPATH: u16 = 10;
pub const BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH: u16 = 11;

// BGP FSM states used by BGP4MP_STATE_CHANGE (RFC 6396 section 4.4.1)
pub const STATE_IDLE: u16 = 1;
pub const STATE_CONNECT: u16 = 2;
pub const STATE_ACTIVE: u16 = 3;
pub const STATE_OPEN_SENT: u16 = 4;
pub const STATE_OPEN_CONFIRM: u16 = 5;
pub const STATE_ESTABLISHED: u16 = 6;

// BGP message types (RFC 4271 section 4.1)
pub const BGP_OPEN: u8 = 1;
pub const BGP_UPDATE: u8 = 2;
pub const BGP_NOTIFICATION: u8 = 3;
pub const BGP_KEEPALIVE: u8 = 4;

// BGP path attribute type codes
pub const ATTR_ORIGIN: u8 = 1;
pub const ATTR_AS_PATH: u8 = 2;
pub const ATTR_NEXT_HOP: u8 = 3;
pub const ATTR_MULTI_EXIT_DISC: u8 = 4;
pub const ATTR_LOCAL_PREF: u8 = 5;
pub const ATTR_ATOMIC_AGGREGATE: u8 = 6;
pub const ATTR_AGGREGATOR: u8 = 7;
pub const ATTR_COMMUNITY: u8 = 8;
/// ORIGINATOR_ID (RFC 4456).
pub const ATTR_ORIGINATOR_ID: u8 = 9;
/// CLUSTER_LIST (RFC 4456).
pub const ATTR_CLUSTER_LIST: u8 = 10;
pub const ATTR_MP_REACH_NLRI: u8 = 14;
pub const ATTR_MP_UNREACH_NLRI: u8 = 15;
pub const ATTR_EXT_COMMUNITY: u8 = 16;
pub const ATTR_AS4_PATH: u8 = 17;
pub const ATTR_AS4_AGGREGATOR: u8 = 18;
/// IPv6 Address Specific Extended Community (RFC 5701).
pub const ATTR_IPV6_EXT_COMMUNITY: u8 = 25;
/// AIGP (RFC 7311).
pub const ATTR_AIGP: u8 = 26;
pub const ATTR_LARGE_COMMUNITY: u8 = 32;

// Well-known communities (RFC 1997)
pub const COMM_NO_EXPORT: u32 = 0xFFFF_FF01;
pub const COMM_NO_ADVERTISE: u32 = 0xFFFF_FF02;
pub const COMM_NO_EXPORT_SUBCONFED: u32 = 0xFFFF_FF03;

// BGP path attribute flags
pub const FLAG_OPTIONAL: u8 = 0x80;
pub const FLAG_TRANSITIVE: u8 = 0x40;
pub const FLAG_PARTIAL: u8 = 0x20;
pub const FLAG_EXT_LEN: u8 = 0x10;

// Address families
pub const BGP_AFI_IPV4: u16 = 1;
pub const BGP_AFI_IPV6: u16 = 2;
pub const SAFI_UNICAST: u8 = 1;
pub const SAFI_MULTICAST: u8 = 2;
pub const SAFI_MPLS_VPN: u8 = 128;
/// Dissemination of Flow Specification rules (RFC 8955/8956); the AFI
/// selects IPv4 vs IPv6.
pub const SAFI_FLOWSPEC: u8 = 133;
