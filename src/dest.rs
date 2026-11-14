//! Real servers (destinations): identity, specification, forwarding method,
//! tunnel parameters, connection counts, and the `NEW`/`SET`/`DEL`/`GET_DEST`
//! commands plus the destination dump.

use std::fmt;
use std::net::IpAddr;

use crate::error::{Error, Result};
use crate::ipvs::{Dump, Ipvs, Rejected};
use crate::nl::{Attrs, NlAttr, NlMsg, RawAttr};
use crate::proto::{self, AddressFamily};
use crate::stats::{Stats, parse_stats};

/// The forwarding method of a real server (`IP_VS_CONN_F_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardMethod {
    /// Masquerading / NAT.
    Masq,
    /// Local node.
    LocalNode,
    /// IP tunneling.
    Tunnel,
    /// Direct routing.
    DirectRoute,
    /// Cache bypass.
    Bypass,
    /// Any other value, kept verbatim.
    Other(u32),
}

impl ForwardMethod {
    /// The numeric value used on the wire.
    ///
    /// ```
    /// use linux_ipvs::ForwardMethod;
    /// assert_eq!(ForwardMethod::DirectRoute.number(), 3);
    /// ```
    pub fn number(self) -> u32 {
        match self {
            Self::Masq => proto::CONN_F_MASQ,
            Self::LocalNode => proto::CONN_F_LOCALNODE,
            Self::Tunnel => proto::CONN_F_TUNNEL,
            Self::DirectRoute => proto::CONN_F_DROUTE,
            Self::Bypass => proto::CONN_F_BYPASS,
            Self::Other(value) => value,
        }
    }

    /// Decode a forwarding method.
    pub fn from_number(value: u32) -> Self {
        match value {
            proto::CONN_F_MASQ => Self::Masq,
            proto::CONN_F_LOCALNODE => Self::LocalNode,
            proto::CONN_F_TUNNEL => Self::Tunnel,
            proto::CONN_F_DROUTE => Self::DirectRoute,
            proto::CONN_F_BYPASS => Self::Bypass,
            other => Self::Other(other),
        }
    }
}

/// The tunnel encapsulation type (`IP_VS_CONN_F_TUNNEL_TYPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelType {
    /// IP-in-IP.
    Ipip,
    /// GUE.
    Gue,
    /// GRE.
    Gre,
    /// Any other value, kept verbatim.
    Other(u8),
}

impl TunnelType {
    /// The numeric value used on the wire.
    ///
    /// ```
    /// use linux_ipvs::TunnelType;
    /// assert_eq!(TunnelType::Gre.number(), 2);
    /// ```
    pub fn number(self) -> u8 {
        match self {
            Self::Ipip => proto::TUNNEL_TYPE_IPIP,
            Self::Gue => proto::TUNNEL_TYPE_GUE,
            Self::Gre => proto::TUNNEL_TYPE_GRE,
            Self::Other(value) => value,
        }
    }

    /// Decode a tunnel type.
    pub fn from_number(value: u8) -> Self {
        match value {
            proto::TUNNEL_TYPE_IPIP => Self::Ipip,
            proto::TUNNEL_TYPE_GUE => Self::Gue,
            proto::TUNNEL_TYPE_GRE => Self::Gre,
            other => Self::Other(other),
        }
    }
}

/// Tunnel encapsulation flags (`IP_VS_TUNNEL_ENCAP_FLAG_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct TunnelFlags(u16);

impl TunnelFlags {
    /// No checksum flag.
    pub const NONE: Self = Self(proto::TUNNEL_ENCAP_FLAG_NOCSUM);
    /// Checksum the outer header.
    pub const CSUM: Self = Self(proto::TUNNEL_ENCAP_FLAG_CSUM);
    /// Remote checksum offload.
    pub const REMCSUM: Self = Self(proto::TUNNEL_ENCAP_FLAG_REMCSUM);

    /// Wrap raw bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// The raw bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether no flag is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether every bit of `other` is set.
    ///
    /// ```
    /// use linux_ipvs::TunnelFlags;
    /// let flags = TunnelFlags::CSUM | TunnelFlags::REMCSUM;
    /// assert!(flags.contains(TunnelFlags::CSUM));
    /// assert!(!TunnelFlags::CSUM.contains(TunnelFlags::REMCSUM));
    /// ```
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set the bits of `other`.
    pub const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl std::ops::BitOr for TunnelFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for TunnelFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for TunnelFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// The identity of a real server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DestId {
    /// Address family.
    pub af: AddressFamily,
    /// Real-server address.
    pub addr: IpAddr,
    /// Real-server port.
    pub port: u16,
}

impl DestId {
    /// Build an identity; the family is derived from the address.
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{DestId, proto::AddressFamily};
    /// let dest = DestId::new(Ipv4Addr::new(198, 51, 100, 10), 8080);
    /// assert_eq!(dest.af, AddressFamily::Inet);
    /// ```
    pub fn new(addr: impl Into<IpAddr>, port: u16) -> Self {
        let addr = addr.into();
        Self {
            af: proto::af_of(addr),
            addr,
            port,
        }
    }
}

/// A real-server specification for `NEW_DEST`/`SET_DEST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestSpec {
    /// Destination identity.
    pub id: DestId,
    /// Forwarding method.
    pub fwd_method: ForwardMethod,
    /// Weight (`1` by default for a new destination).
    pub weight: i32,
    /// Upper connection threshold (`0` = unlimited).
    pub u_threshold: u32,
    /// Lower connection threshold (`0` = unlimited).
    pub l_threshold: u32,
    /// Tunnel type, for tunnel forwarding.
    pub tun_type: Option<TunnelType>,
    /// Tunnel destination port, for GUE/GRE.
    pub tun_port: Option<u16>,
    /// Tunnel encapsulation flags.
    pub tun_flags: TunnelFlags,
}

impl DestSpec {
    /// Build a specification with weight 1 and no thresholds or tunnel
    /// parameters.
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{DestSpec, ForwardMethod};
    /// let dest = DestSpec::new(Ipv4Addr::new(198, 51, 100, 10), 8080, ForwardMethod::DirectRoute);
    /// assert_eq!(dest.weight, 1);
    /// ```
    pub fn new(addr: impl Into<IpAddr>, port: u16, fwd_method: ForwardMethod) -> Self {
        Self {
            id: DestId::new(addr, port),
            fwd_method,
            weight: 1,
            u_threshold: 0,
            l_threshold: 0,
            tun_type: None,
            tun_port: None,
            tun_flags: TunnelFlags::NONE,
        }
    }

    /// The destination identity.
    pub fn id(&self) -> &DestId {
        &self.id
    }
}

/// A real server as reported by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dest {
    /// Destination specification.
    pub spec: DestSpec,
    /// Active connections.
    pub active_conns: u32,
    /// Inactive connections.
    pub inact_conns: u32,
    /// Persistent connections.
    pub persist_conns: u32,
    /// Counters, when the reply carried them.
    pub stats: Option<Stats>,
    /// Attributes this crate does not model, kept verbatim.
    pub unknown: Vec<RawAttr>,
}

fn id_attrs(id: &DestId) -> Vec<NlAttr> {
    vec![
        NlAttr::new(proto::DEST_ATTR_ADDR, proto::addr_bytes(id.addr)),
        NlAttr::be16(proto::DEST_ATTR_PORT, id.port),
        NlAttr::u16(proto::DEST_ATTR_ADDR_FAMILY, id.af.number()),
    ]
}

fn full_attrs(spec: &DestSpec) -> Vec<NlAttr> {
    let mut attrs = id_attrs(&spec.id);
    attrs.push(NlAttr::u32(
        proto::DEST_ATTR_FWD_METHOD,
        spec.fwd_method.number(),
    ));
    attrs.push(NlAttr::i32(proto::DEST_ATTR_WEIGHT, spec.weight));
    attrs.push(NlAttr::u32(proto::DEST_ATTR_U_THRESH, spec.u_threshold));
    attrs.push(NlAttr::u32(proto::DEST_ATTR_L_THRESH, spec.l_threshold));
    if let Some(tun_type) = spec.tun_type {
        attrs.push(NlAttr::u8(proto::DEST_ATTR_TUN_TYPE, tun_type.number()));
    }
    if let Some(port) = spec.tun_port {
        attrs.push(NlAttr::be16(proto::DEST_ATTR_TUN_PORT, port));
    }
    if !spec.tun_flags.is_empty() {
        attrs.push(NlAttr::u16(
            proto::DEST_ATTR_TUN_FLAGS,
            spec.tun_flags.bits(),
        ));
    }
    attrs
}

fn known(kind: u16) -> bool {
    matches!(
        kind,
        proto::DEST_ATTR_ADDR
            | proto::DEST_ATTR_PORT
            | proto::DEST_ATTR_FWD_METHOD
            | proto::DEST_ATTR_WEIGHT
            | proto::DEST_ATTR_U_THRESH
            | proto::DEST_ATTR_L_THRESH
            | proto::DEST_ATTR_ACTIVE_CONNS
            | proto::DEST_ATTR_INACT_CONNS
            | proto::DEST_ATTR_PERSIST_CONNS
            | proto::DEST_ATTR_STATS
            | proto::DEST_ATTR_ADDR_FAMILY
            | proto::DEST_ATTR_STATS64
            | proto::DEST_ATTR_TUN_TYPE
            | proto::DEST_ATTR_TUN_PORT
            | proto::DEST_ATTR_TUN_FLAGS
    )
}

fn parse_dest(message: &NlMsg) -> Result<Dest> {
    if message.cmd()? != proto::CMD_NEW_DEST {
        return Err(Error::unexpected("a NEW_DEST reply", message));
    }
    let outer = message.attrs()?;
    let nested = outer
        .get(proto::CMD_ATTR_DEST)
        .ok_or(Error::MissingAttribute {
            name: "IPVS_CMD_ATTR_DEST",
        })?;
    let attrs = Attrs::parse(nested.payload())?;

    let addr_payload = attrs
        .get(proto::DEST_ATTR_ADDR)
        .ok_or(Error::MissingAttribute {
            name: "IPVS_DEST_ATTR_ADDR",
        })?
        .payload();
    let af = match attrs.get(proto::DEST_ATTR_ADDR_FAMILY) {
        Some(attr) => AddressFamily::from_number(attr.as_u16()?),
        // The kernel always sends the family; infer it for robustness.
        None if addr_payload.len() == 4 => AddressFamily::Inet,
        None => AddressFamily::Inet6,
    };
    let port = attrs
        .get(proto::DEST_ATTR_PORT)
        .ok_or(Error::MissingAttribute {
            name: "IPVS_DEST_ATTR_PORT",
        })?
        .as_be16()?;
    let addr = proto::decode_addr(af, addr_payload)?;

    let mut spec = DestSpec::new(addr, port, ForwardMethod::Masq);
    if let Some(attr) = attrs.get(proto::DEST_ATTR_FWD_METHOD) {
        spec.fwd_method = ForwardMethod::from_number(attr.as_u32()?);
    }
    if let Some(attr) = attrs.get(proto::DEST_ATTR_WEIGHT) {
        spec.weight = attr.as_i32()?;
    }
    if let Some(attr) = attrs.get(proto::DEST_ATTR_U_THRESH) {
        spec.u_threshold = attr.as_u32()?;
    }
    if let Some(attr) = attrs.get(proto::DEST_ATTR_L_THRESH) {
        spec.l_threshold = attr.as_u32()?;
    }
    if let Some(attr) = attrs.get(proto::DEST_ATTR_TUN_TYPE) {
        spec.tun_type = Some(TunnelType::from_number(attr.as_u8()?));
    }
    if let Some(attr) = attrs.get(proto::DEST_ATTR_TUN_PORT) {
        spec.tun_port = Some(attr.as_be16()?);
    }
    if let Some(attr) = attrs.get(proto::DEST_ATTR_TUN_FLAGS) {
        spec.tun_flags = TunnelFlags::from_bits(attr.as_u16()?);
    }

    let stats = attrs
        .get(proto::DEST_ATTR_STATS64)
        .or_else(|| attrs.get(proto::DEST_ATTR_STATS))
        .map(parse_stats)
        .transpose()?;

    let number = |kind: u16| -> Result<u32> {
        Ok(attrs
            .get(kind)
            .map(NlAttr::as_u32)
            .transpose()?
            .unwrap_or(0))
    };

    let unknown = attrs
        .iter()
        .filter(|attr| !known(attr.kind()))
        .map(|attr| RawAttr {
            kind: attr.kind(),
            data: attr.payload().to_vec(),
        })
        .collect();

    Ok(Dest {
        spec,
        active_conns: number(proto::DEST_ATTR_ACTIVE_CONNS)?,
        inact_conns: number(proto::DEST_ATTR_INACT_CONNS)?,
        persist_conns: number(proto::DEST_ATTR_PERSIST_CONNS)?,
        stats,
        unknown,
    })
}

impl Ipvs {
    /// Add a real server to a service (`NEW_DEST`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{DestSpec, ForwardMethod, Ipvs, Protocol, ServiceId};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let service = ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp);
    /// let dest = DestSpec::new(Ipv4Addr::new(198, 51, 100, 10), 8080, ForwardMethod::DirectRoute);
    /// ipvs.add_dest(&service, &dest).unwrap();
    /// # }
    /// ```
    pub fn add_dest(&mut self, service: &crate::ServiceId, spec: &DestSpec) -> Result<()> {
        let attrs = vec![
            NlAttr::nested(
                proto::CMD_ATTR_SERVICE,
                crate::nl::encode_attrs(&crate::service::id_attrs(service)),
            ),
            NlAttr::nested(
                proto::CMD_ATTR_DEST,
                crate::nl::encode_attrs(&full_attrs(spec)),
            ),
        ];
        self.ack(proto::CMD_NEW_DEST, attrs)
    }

    /// Modify a real server (`SET_DEST`).
    pub fn set_dest(&mut self, service: &crate::ServiceId, spec: &DestSpec) -> Result<()> {
        let attrs = vec![
            NlAttr::nested(
                proto::CMD_ATTR_SERVICE,
                crate::nl::encode_attrs(&crate::service::id_attrs(service)),
            ),
            NlAttr::nested(
                proto::CMD_ATTR_DEST,
                crate::nl::encode_attrs(&full_attrs(spec)),
            ),
        ];
        self.ack(proto::CMD_SET_DEST, attrs)
    }

    /// Delete a real server (`DEL_DEST`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{DestId, Ipvs, Protocol, ServiceId};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let service = ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp);
    /// let dest = DestId::new(Ipv4Addr::new(198, 51, 100, 10), 8080);
    /// ipvs.del_dest(&service, &dest).unwrap();
    /// # }
    /// ```
    pub fn del_dest(&mut self, service: &crate::ServiceId, dest: &DestId) -> Result<()> {
        let attrs = vec![
            NlAttr::nested(
                proto::CMD_ATTR_SERVICE,
                crate::nl::encode_attrs(&crate::service::id_attrs(service)),
            ),
            NlAttr::nested(
                proto::CMD_ATTR_DEST,
                crate::nl::encode_attrs(&id_attrs(dest)),
            ),
        ];
        self.ack(proto::CMD_DEL_DEST, attrs)
    }

    /// Dump the real servers of one service (`GET_DEST` with `NLM_F_DUMP`).
    ///
    /// The kernel has no single-destination `GET`, so this is the only
    /// retrieval path.
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{Ipvs, Protocol, ServiceId};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let service = ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp);
    /// for dest in ipvs.list_dests(&service).unwrap().entries {
    ///     println!("{:?} weight {}", dest.spec.id, dest.spec.weight);
    /// }
    /// # }
    /// ```
    pub fn list_dests(&mut self, service: &crate::ServiceId) -> Result<Dump<Dest>> {
        let attrs = vec![NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            crate::nl::encode_attrs(&crate::service::id_attrs(service)),
        )];
        let replies = self.dump(proto::CMD_GET_DEST, attrs)?;
        let mut dump = Dump::new();
        dump.interrupted = replies.interrupted;
        dump.rejected = replies.rejected;
        for message in replies.messages {
            match parse_dest(&message) {
                Ok(dest) => dump.entries.push(dest),
                Err(error) => dump.rejected.push(Rejected::from_message(&message, error)),
            }
        }
        Ok(dump)
    }
}
