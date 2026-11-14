//! IPVS generic netlink vocabulary: command numbers, attribute types,
//! flags, the family name, and the address-family/protocol enums.
//!
//! Constants are copied from `/usr/include/linux/ip_vs.h`. They are public
//! for callers that use the `send_raw`/`recv_raw` escape hatches.

// ---------------------------------------------------------------------------
// Family
// ---------------------------------------------------------------------------

/// `IPVS_GENL_NAME` — the generic netlink family name.
pub const FAMILY_NAME: &str = "IPVS";
/// `IPVS_GENL_VERSION` — the family version.
pub const FAMILY_VERSION: u8 = 0x1;
/// `IP_VS_VERSION_CODE` reported by `GET_INFO`.
pub const VERSION_CODE: u32 = 0x010201;

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `IPVS_CMD_NEW_SERVICE`.
pub const CMD_NEW_SERVICE: u8 = 1;
/// `IPVS_CMD_SET_SERVICE`.
pub const CMD_SET_SERVICE: u8 = 2;
/// `IPVS_CMD_DEL_SERVICE`.
pub const CMD_DEL_SERVICE: u8 = 3;
/// `IPVS_CMD_GET_SERVICE`.
pub const CMD_GET_SERVICE: u8 = 4;
/// `IPVS_CMD_NEW_DEST`.
pub const CMD_NEW_DEST: u8 = 5;
/// `IPVS_CMD_SET_DEST`.
pub const CMD_SET_DEST: u8 = 6;
/// `IPVS_CMD_DEL_DEST`.
pub const CMD_DEL_DEST: u8 = 7;
/// `IPVS_CMD_GET_DEST`.
pub const CMD_GET_DEST: u8 = 8;
/// `IPVS_CMD_NEW_DAEMON`.
pub const CMD_NEW_DAEMON: u8 = 9;
/// `IPVS_CMD_DEL_DAEMON`.
pub const CMD_DEL_DAEMON: u8 = 10;
/// `IPVS_CMD_GET_DAEMON`.
pub const CMD_GET_DAEMON: u8 = 11;
/// `IPVS_CMD_SET_CONFIG`.
pub const CMD_SET_CONFIG: u8 = 12;
/// `IPVS_CMD_GET_CONFIG`.
pub const CMD_GET_CONFIG: u8 = 13;
/// `IPVS_CMD_SET_INFO` — only used as the command of a `GET_INFO` reply.
pub const CMD_SET_INFO: u8 = 14;
/// `IPVS_CMD_GET_INFO`.
pub const CMD_GET_INFO: u8 = 15;
/// `IPVS_CMD_ZERO`.
pub const CMD_ZERO: u8 = 16;
/// `IPVS_CMD_FLUSH`.
pub const CMD_FLUSH: u8 = 17;

// ---------------------------------------------------------------------------
// First-level command attributes
// ---------------------------------------------------------------------------

/// `IPVS_CMD_ATTR_SERVICE` — nested service attributes.
pub const CMD_ATTR_SERVICE: u16 = 1;
/// `IPVS_CMD_ATTR_DEST` — nested destination attributes.
pub const CMD_ATTR_DEST: u16 = 2;
/// `IPVS_CMD_ATTR_DAEMON` — nested sync-daemon attributes.
pub const CMD_ATTR_DAEMON: u16 = 3;
/// `IPVS_CMD_ATTR_TIMEOUT_TCP`.
pub const CMD_ATTR_TIMEOUT_TCP: u16 = 4;
/// `IPVS_CMD_ATTR_TIMEOUT_TCP_FIN`.
pub const CMD_ATTR_TIMEOUT_TCP_FIN: u16 = 5;
/// `IPVS_CMD_ATTR_TIMEOUT_UDP`.
pub const CMD_ATTR_TIMEOUT_UDP: u16 = 6;

// ---------------------------------------------------------------------------
// Service attributes
// ---------------------------------------------------------------------------

/// `IPVS_SVC_ATTR_AF`.
pub const SVC_ATTR_AF: u16 = 1;
/// `IPVS_SVC_ATTR_PROTOCOL`.
pub const SVC_ATTR_PROTOCOL: u16 = 2;
/// `IPVS_SVC_ATTR_ADDR`.
pub const SVC_ATTR_ADDR: u16 = 3;
/// `IPVS_SVC_ATTR_PORT`.
pub const SVC_ATTR_PORT: u16 = 4;
/// `IPVS_SVC_ATTR_FWMARK`.
pub const SVC_ATTR_FWMARK: u16 = 5;
/// `IPVS_SVC_ATTR_SCHED_NAME`.
pub const SVC_ATTR_SCHED_NAME: u16 = 6;
/// `IPVS_SVC_ATTR_FLAGS`.
pub const SVC_ATTR_FLAGS: u16 = 7;
/// `IPVS_SVC_ATTR_TIMEOUT`.
pub const SVC_ATTR_TIMEOUT: u16 = 8;
/// `IPVS_SVC_ATTR_NETMASK`.
pub const SVC_ATTR_NETMASK: u16 = 9;
/// `IPVS_SVC_ATTR_STATS` — nested 32-bit statistics.
pub const SVC_ATTR_STATS: u16 = 10;
/// `IPVS_SVC_ATTR_PE_NAME`.
pub const SVC_ATTR_PE_NAME: u16 = 11;
/// `IPVS_SVC_ATTR_STATS64` — nested 64-bit statistics.
pub const SVC_ATTR_STATS64: u16 = 12;

// ---------------------------------------------------------------------------
// Destination attributes
// ---------------------------------------------------------------------------

/// `IPVS_DEST_ATTR_ADDR`.
pub const DEST_ATTR_ADDR: u16 = 1;
/// `IPVS_DEST_ATTR_PORT`.
pub const DEST_ATTR_PORT: u16 = 2;
/// `IPVS_DEST_ATTR_FWD_METHOD`.
pub const DEST_ATTR_FWD_METHOD: u16 = 3;
/// `IPVS_DEST_ATTR_WEIGHT`.
pub const DEST_ATTR_WEIGHT: u16 = 4;
/// `IPVS_DEST_ATTR_U_THRESH`.
pub const DEST_ATTR_U_THRESH: u16 = 5;
/// `IPVS_DEST_ATTR_L_THRESH`.
pub const DEST_ATTR_L_THRESH: u16 = 6;
/// `IPVS_DEST_ATTR_ACTIVE_CONNS`.
pub const DEST_ATTR_ACTIVE_CONNS: u16 = 7;
/// `IPVS_DEST_ATTR_INACT_CONNS`.
pub const DEST_ATTR_INACT_CONNS: u16 = 8;
/// `IPVS_DEST_ATTR_PERSIST_CONNS`.
pub const DEST_ATTR_PERSIST_CONNS: u16 = 9;
/// `IPVS_DEST_ATTR_STATS` — nested 32-bit statistics.
pub const DEST_ATTR_STATS: u16 = 10;
/// `IPVS_DEST_ATTR_ADDR_FAMILY`.
pub const DEST_ATTR_ADDR_FAMILY: u16 = 11;
/// `IPVS_DEST_ATTR_STATS64` — nested 64-bit statistics.
pub const DEST_ATTR_STATS64: u16 = 12;
/// `IPVS_DEST_ATTR_TUN_TYPE`.
pub const DEST_ATTR_TUN_TYPE: u16 = 13;
/// `IPVS_DEST_ATTR_TUN_PORT`.
pub const DEST_ATTR_TUN_PORT: u16 = 14;
/// `IPVS_DEST_ATTR_TUN_FLAGS`.
pub const DEST_ATTR_TUN_FLAGS: u16 = 15;

// ---------------------------------------------------------------------------
// Sync-daemon attributes
// ---------------------------------------------------------------------------

/// `IPVS_DAEMON_ATTR_STATE`.
pub const DAEMON_ATTR_STATE: u16 = 1;
/// `IPVS_DAEMON_ATTR_MCAST_IFN`.
pub const DAEMON_ATTR_MCAST_IFN: u16 = 2;
/// `IPVS_DAEMON_ATTR_SYNC_ID`.
pub const DAEMON_ATTR_SYNC_ID: u16 = 3;
/// `IPVS_DAEMON_ATTR_SYNC_MAXLEN`.
pub const DAEMON_ATTR_SYNC_MAXLEN: u16 = 4;
/// `IPVS_DAEMON_ATTR_MCAST_GROUP` — IPv4 multicast group.
pub const DAEMON_ATTR_MCAST_GROUP: u16 = 5;
/// `IPVS_DAEMON_ATTR_MCAST_GROUP6` — IPv6 multicast group.
pub const DAEMON_ATTR_MCAST_GROUP6: u16 = 6;
/// `IPVS_DAEMON_ATTR_MCAST_PORT`.
pub const DAEMON_ATTR_MCAST_PORT: u16 = 7;
/// `IPVS_DAEMON_ATTR_MCAST_TTL`.
pub const DAEMON_ATTR_MCAST_TTL: u16 = 8;

// ---------------------------------------------------------------------------
// Statistics and info attributes
// ---------------------------------------------------------------------------

/// `IPVS_STATS_ATTR_CONNS`.
pub const STATS_ATTR_CONNS: u16 = 1;
/// `IPVS_STATS_ATTR_INPKTS`.
pub const STATS_ATTR_INPKTS: u16 = 2;
/// `IPVS_STATS_ATTR_OUTPKTS`.
pub const STATS_ATTR_OUTPKTS: u16 = 3;
/// `IPVS_STATS_ATTR_INBYTES`.
pub const STATS_ATTR_INBYTES: u16 = 4;
/// `IPVS_STATS_ATTR_OUTBYTES`.
pub const STATS_ATTR_OUTBYTES: u16 = 5;
/// `IPVS_STATS_ATTR_CPS`.
pub const STATS_ATTR_CPS: u16 = 6;
/// `IPVS_STATS_ATTR_INPPS`.
pub const STATS_ATTR_INPPS: u16 = 7;
/// `IPVS_STATS_ATTR_OUTPPS`.
pub const STATS_ATTR_OUTPPS: u16 = 8;
/// `IPVS_STATS_ATTR_INBPS`.
pub const STATS_ATTR_INBPS: u16 = 9;
/// `IPVS_STATS_ATTR_OUTBPS`.
pub const STATS_ATTR_OUTBPS: u16 = 10;
/// `IPVS_STATS_ATTR_PAD` — padding inserted before 64-bit values.
pub const STATS_ATTR_PAD: u16 = 11;

/// `IPVS_INFO_ATTR_VERSION`.
pub const INFO_ATTR_VERSION: u16 = 1;
/// `IPVS_INFO_ATTR_CONN_TAB_SIZE`.
pub const INFO_ATTR_CONN_TAB_SIZE: u16 = 2;

// ---------------------------------------------------------------------------
// Flags and enumerations
// ---------------------------------------------------------------------------

/// `IP_VS_SVC_F_PERSISTENT` — persistent connections.
pub const SVC_F_PERSISTENT: u32 = 0x0001;
/// `IP_VS_SVC_F_HASHED` — the service is hashed (kernel-managed).
pub const SVC_F_HASHED: u32 = 0x0002;
/// `IP_VS_SVC_F_ONEPACKET` — one-packet scheduling.
pub const SVC_F_ONEPACKET: u32 = 0x0004;
/// `IP_VS_SVC_F_SCHED1` — scheduler flag 1.
pub const SVC_F_SCHED1: u32 = 0x0008;
/// `IP_VS_SVC_F_SCHED2` — scheduler flag 2.
pub const SVC_F_SCHED2: u32 = 0x0010;
/// `IP_VS_SVC_F_SCHED3` — scheduler flag 3.
pub const SVC_F_SCHED3: u32 = 0x0020;

/// `IP_VS_CONN_F_MASQ` — masquerading/NAT.
pub const CONN_F_MASQ: u32 = 0x0000;
/// `IP_VS_CONN_F_LOCALNODE` — local node.
pub const CONN_F_LOCALNODE: u32 = 0x0001;
/// `IP_VS_CONN_F_TUNNEL` — tunneling.
pub const CONN_F_TUNNEL: u32 = 0x0002;
/// `IP_VS_CONN_F_DROUTE` — direct routing.
pub const CONN_F_DROUTE: u32 = 0x0003;
/// `IP_VS_CONN_F_BYPASS` — cache bypass.
pub const CONN_F_BYPASS: u32 = 0x0004;

/// `IP_VS_CONN_F_TUNNEL_TYPE_IPIP`.
pub const TUNNEL_TYPE_IPIP: u8 = 0;
/// `IP_VS_CONN_F_TUNNEL_TYPE_GUE`.
pub const TUNNEL_TYPE_GUE: u8 = 1;
/// `IP_VS_CONN_F_TUNNEL_TYPE_GRE`.
pub const TUNNEL_TYPE_GRE: u8 = 2;

/// `IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM`.
pub const TUNNEL_ENCAP_FLAG_NOCSUM: u16 = 0;
/// `IP_VS_TUNNEL_ENCAP_FLAG_CSUM`.
pub const TUNNEL_ENCAP_FLAG_CSUM: u16 = 1 << 0;
/// `IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM`.
pub const TUNNEL_ENCAP_FLAG_REMCSUM: u16 = 1 << 1;

/// `IP_VS_STATE_NONE` — the sync daemon is stopped.
pub const STATE_NONE: u32 = 0;
/// `IP_VS_STATE_MASTER`.
pub const STATE_MASTER: u32 = 1;
/// `IP_VS_STATE_BACKUP`.
pub const STATE_BACKUP: u32 = 2;

// ---------------------------------------------------------------------------
// Address families and protocols
// ---------------------------------------------------------------------------

/// An address family as carried by `IPVS_SVC_ATTR_AF` /
/// `IPVS_DEST_ATTR_ADDR_FAMILY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// `AF_INET`.
    Inet,
    /// `AF_INET6`.
    Inet6,
    /// Any other family value, kept verbatim.
    Other(u16),
}

impl AddressFamily {
    /// The numeric `AF_*` value.
    ///
    /// ```
    /// use linux_ipvs::proto::AddressFamily;
    /// assert_eq!(AddressFamily::Inet.number(), 2);
    /// assert_eq!(AddressFamily::Inet6.number(), 10);
    /// ```
    pub fn number(self) -> u16 {
        match self {
            Self::Inet => 2,
            Self::Inet6 => 10,
            Self::Other(value) => value,
        }
    }

    /// Decode an `AF_*` value.
    ///
    /// ```
    /// use linux_ipvs::proto::AddressFamily;
    /// assert_eq!(AddressFamily::from_number(10), AddressFamily::Inet6);
    /// ```
    pub fn from_number(value: u16) -> Self {
        match value {
            2 => Self::Inet,
            10 => Self::Inet6,
            other => Self::Other(other),
        }
    }
}

/// An IP protocol number as carried by `IPVS_SVC_ATTR_PROTOCOL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// `IPPROTO_TCP`.
    Tcp,
    /// `IPPROTO_UDP`.
    Udp,
    /// `IPPROTO_SCTP`.
    Sctp,
    /// Any other protocol number, kept verbatim.
    Other(u16),
}

impl Protocol {
    /// The numeric `IPPROTO_*` value.
    ///
    /// ```
    /// use linux_ipvs::proto::Protocol;
    /// assert_eq!(Protocol::Tcp.number(), 6);
    /// ```
    pub fn number(self) -> u16 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Sctp => 132,
            Self::Other(value) => value,
        }
    }

    /// Decode an `IPPROTO_*` value.
    ///
    /// ```
    /// use linux_ipvs::proto::Protocol;
    /// assert_eq!(Protocol::from_number(17), Protocol::Udp);
    /// ```
    pub fn from_number(value: u16) -> Self {
        match value {
            6 => Self::Tcp,
            17 => Self::Udp,
            132 => Self::Sctp,
            other => Self::Other(other),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire helpers shared by the typed modules
// ---------------------------------------------------------------------------

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::nl;

/// The address family of an IP address.
pub(crate) fn af_of(addr: IpAddr) -> AddressFamily {
    match addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    }
}

/// Address bytes as sent in `ADDR` attributes: 4 for IPv4, 16 for IPv6,
/// both in network order.
pub(crate) fn addr_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    }
}

/// Decode an `ADDR` payload. The kernel always emits 16 bytes
/// (`sizeof(union nf_inet_addr)`) even for IPv4; IPv4 lives in the first 4
/// bytes. Shorter payloads are accepted for IPv4 requests echoed back by
/// other tools.
pub(crate) fn decode_addr(af: AddressFamily, bytes: &[u8]) -> Result<IpAddr> {
    match af {
        AddressFamily::Inet => {
            if bytes.len() < 4 {
                return Err(nl::Error::Truncated {
                    needed: 4,
                    have: bytes.len(),
                }
                .into());
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        AddressFamily::Inet6 => {
            if bytes.len() < 16 {
                return Err(nl::Error::Truncated {
                    needed: 16,
                    have: bytes.len(),
                }
                .into());
            }
            Ok(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&bytes[..16]).unwrap(),
            )))
        }
        AddressFamily::Other(af) => Err(Error::UnsupportedAddressFamily { af }),
    }
}

/// Reject strings that exceed a kernel `NLA_NUL_STRING` policy length.
pub(crate) fn check_string(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.len() + 1 > max {
        return Err(Error::ValueTooLong {
            field,
            max,
            got: value.len(),
        });
    }
    Ok(())
}
