//! Virtual services: identity, full specification, flags, netmask, and the
//! `NEW`/`SET`/`DEL`/`GET_SERVICE` commands plus the service dump.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use crate::error::{Error, Result};
use crate::ipvs::{Dump, Ipvs, Rejected};
use crate::nl::{Attrs, NlAttr, NlMsg, RawAttr};
use crate::proto::{self, AddressFamily, Protocol};
use crate::stats::{Stats, parse_stats};

/// Maximum payload of `IPVS_SVC_ATTR_SCHED_NAME`, including the NUL.
const SCHED_NAME_MAX: usize = 15;
/// Maximum payload of `IPVS_SVC_ATTR_PE_NAME`, including the NUL.
const PE_NAME_MAX: usize = 16;

/// Virtual-service flags (`IP_VS_SVC_F_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct ServiceFlags(u32);

impl ServiceFlags {
    /// No flags.
    pub const EMPTY: Self = Self(0);
    /// Persistent connections (`IP_VS_SVC_F_PERSISTENT`).
    pub const PERSISTENT: Self = Self(proto::SVC_F_PERSISTENT);
    /// Hashed service entry. The kernel manages this bit.
    pub const HASHED: Self = Self(proto::SVC_F_HASHED);
    /// One-packet scheduling (`IP_VS_SVC_F_ONEPACKET`).
    pub const ONE_PACKET: Self = Self(proto::SVC_F_ONEPACKET);
    /// Scheduler flag 1.
    pub const SCHED1: Self = Self(proto::SVC_F_SCHED1);
    /// Scheduler flag 2.
    pub const SCHED2: Self = Self(proto::SVC_F_SCHED2);
    /// Scheduler flag 3.
    pub const SCHED3: Self = Self(proto::SVC_F_SCHED3);

    /// Wrap raw flag bits.
    ///
    /// ```
    /// use linux_ipvs::ServiceFlags;
    /// let flags = ServiceFlags::from_bits(ServiceFlags::PERSISTENT.bits());
    /// assert!(flags.contains(ServiceFlags::PERSISTENT));
    /// ```
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw flag bits.
    ///
    /// ```
    /// use linux_ipvs::ServiceFlags;
    /// assert_eq!(ServiceFlags::PERSISTENT.bits(), 0x0001);
    /// ```
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set the bits of `other`.
    pub const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl std::ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

/// The persistence netmask of a service.
///
/// The kernel encodes this in a single 4-byte attribute whose meaning
/// depends on the address family: an IPv4 mask (`255.255.255.0`) for IPv4
/// services, or a prefix length (`128`) for IPv6 services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Netmask {
    /// An IPv4 grouping mask.
    Mask(Ipv4Addr),
    /// An IPv6 prefix length (`1..=128`).
    Prefix(u8),
    /// Bytes the kernel returned that fit neither convention, kept verbatim.
    Raw([u8; 4]),
}

impl Netmask {
    /// The kernel's default netmask for a family: `255.255.255.255` for
    /// IPv4 and `/128` for IPv6.
    ///
    /// ```
    /// use linux_ipvs::proto::AddressFamily;
    /// use linux_ipvs::service::Netmask;
    /// assert_eq!(Netmask::default_for(AddressFamily::Inet6), Netmask::Prefix(128));
    /// ```
    pub fn default_for(af: AddressFamily) -> Self {
        match af {
            AddressFamily::Inet6 => Self::Prefix(128),
            _ => Self::Mask(Ipv4Addr::BROADCAST),
        }
    }

    fn encode(self, af: AddressFamily) -> Result<[u8; 4]> {
        match (af, self) {
            (AddressFamily::Inet, Self::Mask(mask)) => Ok(mask.octets()),
            (AddressFamily::Inet6, Self::Prefix(prefix)) if (1..=128).contains(&prefix) => {
                Ok(u32::from(prefix).to_ne_bytes())
            }
            (_, Self::Raw(bytes)) => Ok(bytes),
            _ => Err(Error::InvalidNetmask),
        }
    }

    fn decode(af: AddressFamily, bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 4] = bytes.try_into().map_err(|_| crate::nl::Error::BadPayload {
            kind: proto::SVC_ATTR_NETMASK,
            len: bytes.len(),
            expected: "4 bytes",
        })?;
        Ok(match af {
            AddressFamily::Inet => Self::Mask(Ipv4Addr::from(bytes)),
            AddressFamily::Inet6 => {
                let value = u32::from_ne_bytes(bytes);
                if (1..=128).contains(&value) {
                    Self::Prefix(value as u8)
                } else {
                    Self::Raw(bytes)
                }
            }
            AddressFamily::Other(_) => Self::Raw(bytes),
        })
    }
}

/// The identity of a virtual service: either an address/port/protocol tuple
/// or a firewall mark.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceId {
    /// A virtual address, port and protocol.
    Addr {
        /// Service address.
        addr: IpAddr,
        /// Service port.
        port: u16,
        /// Service protocol.
        protocol: Protocol,
    },
    /// A firewall mark. The kernel uses protocol TCP internally.
    Fwmark {
        /// Address family.
        af: AddressFamily,
        /// Firewall mark.
        fwmark: u32,
    },
}

impl ServiceId {
    /// Build an address/port/protocol identity. The address family is
    /// derived from the address.
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::proto::Protocol;
    /// use linux_ipvs::ServiceId;
    /// let id = ServiceId::addr(Ipv4Addr::new(192, 0, 2, 1), 80, Protocol::Tcp);
    /// assert_eq!(id.af(), linux_ipvs::proto::AddressFamily::Inet);
    /// ```
    pub fn addr(addr: impl Into<IpAddr>, port: u16, protocol: Protocol) -> Self {
        Self::Addr {
            addr: addr.into(),
            port,
            protocol,
        }
    }

    /// Build a firewall-mark identity.
    ///
    /// ```
    /// use linux_ipvs::proto::AddressFamily;
    /// use linux_ipvs::ServiceId;
    /// let id = ServiceId::fwmark(AddressFamily::Inet, 42);
    /// assert_eq!(id.af(), AddressFamily::Inet);
    /// ```
    pub fn fwmark(af: AddressFamily, fwmark: u32) -> Self {
        Self::Fwmark { af, fwmark }
    }

    /// The address family of this identity.
    pub fn af(&self) -> AddressFamily {
        match self {
            Self::Addr { addr, .. } => proto::af_of(*addr),
            Self::Fwmark { af, .. } => *af,
        }
    }
}

/// A complete virtual-service specification for `NEW_SERVICE`/`SET_SERVICE`.
///
/// `SET_SERVICE` replaces the whole user-controllable flag set (the kernel
/// always re-adds its own `HASHED` bit); build the spec from
/// [`Service::spec`] when modifying an existing service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// Service identity.
    pub id: ServiceId,
    /// Scheduler name (`rr`, `wrr`, `lc`, ...). The kernel requires a
    /// registered scheduler for `NEW_SERVICE`/`SET_SERVICE`; the crate
    /// deliberately picks none.
    pub sched_name: String,
    /// Service flags.
    pub flags: ServiceFlags,
    /// Persistent-connection timeout in seconds.
    pub timeout: u32,
    /// Persistence netmask.
    pub netmask: Netmask,
    /// Connection-tracking persistence engine name.
    pub pe_name: Option<String>,
}

impl ServiceSpec {
    /// Build a specification for an address/port/protocol service with the
    /// family's default netmask and no flags.
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::proto::Protocol;
    /// use linux_ipvs::{ServiceSpec, Netmask};
    /// let spec = ServiceSpec::addr(Ipv4Addr::new(192, 0, 2, 1), 80, Protocol::Tcp, "rr");
    /// assert_eq!(spec.sched_name, "rr");
    /// assert_eq!(spec.netmask, Netmask::Mask(Ipv4Addr::BROADCAST));
    /// ```
    pub fn addr(
        addr: impl Into<IpAddr>,
        port: u16,
        protocol: Protocol,
        sched_name: impl Into<String>,
    ) -> Self {
        let id = ServiceId::addr(addr, port, protocol);
        Self {
            netmask: Netmask::default_for(id.af()),
            id,
            sched_name: sched_name.into(),
            flags: ServiceFlags::EMPTY,
            timeout: 0,
            pe_name: None,
        }
    }

    /// Build a specification for a firewall-mark service.
    pub fn fwmark(af: AddressFamily, fwmark: u32, sched_name: impl Into<String>) -> Self {
        Self {
            id: ServiceId::fwmark(af, fwmark),
            sched_name: sched_name.into(),
            flags: ServiceFlags::EMPTY,
            timeout: 0,
            netmask: Netmask::default_for(af),
            pe_name: None,
        }
    }

    /// The service identity.
    pub fn id(&self) -> &ServiceId {
        &self.id
    }
}

/// A service as reported by the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Service identity.
    pub id: ServiceId,
    /// Scheduler name (`"none"` when no scheduler is bound).
    pub sched_name: String,
    /// Service flags.
    pub flags: ServiceFlags,
    /// Persistent-connection timeout in seconds.
    pub timeout: u32,
    /// Persistence netmask.
    pub netmask: Netmask,
    /// Connection-tracking persistence engine name.
    pub pe_name: Option<String>,
    /// Counters, when the reply carried them.
    pub stats: Option<Stats>,
    /// Attributes this crate does not model, kept verbatim.
    pub unknown: Vec<RawAttr>,
}

impl Service {
    /// A full specification derived from this service, suitable for
    /// [`Ipvs::set_service`].
    pub fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: self.id.clone(),
            sched_name: self.sched_name.clone(),
            flags: self.flags,
            timeout: self.timeout,
            netmask: self.netmask,
            pe_name: self.pe_name.clone(),
        }
    }
}

/// Encode the identifying attributes of a service.
pub(crate) fn id_attrs(id: &ServiceId) -> Vec<NlAttr> {
    let mut attrs = vec![NlAttr::u16(proto::SVC_ATTR_AF, id.af().number())];
    match id {
        ServiceId::Addr {
            addr,
            port,
            protocol,
        } => {
            attrs.push(NlAttr::u16(proto::SVC_ATTR_PROTOCOL, protocol.number()));
            attrs.push(NlAttr::new(proto::SVC_ATTR_ADDR, proto::addr_bytes(*addr)));
            attrs.push(NlAttr::be16(proto::SVC_ATTR_PORT, *port));
        }
        ServiceId::Fwmark { fwmark, .. } => {
            attrs.push(NlAttr::u32(proto::SVC_ATTR_FWMARK, *fwmark));
        }
    }
    attrs
}

fn full_attrs(spec: &ServiceSpec) -> Result<Vec<NlAttr>> {
    proto::check_string("IPVS_SVC_ATTR_SCHED_NAME", &spec.sched_name, SCHED_NAME_MAX)?;
    if let Some(pe) = &spec.pe_name {
        proto::check_string("IPVS_SVC_ATTR_PE_NAME", pe, PE_NAME_MAX)?;
    }
    let mut attrs = id_attrs(&spec.id);
    attrs.push(NlAttr::string(proto::SVC_ATTR_SCHED_NAME, &spec.sched_name));
    let mut flags = [0u8; 8];
    flags[..4].copy_from_slice(&spec.flags.bits().to_ne_bytes());
    flags[4..].copy_from_slice(&u32::MAX.to_ne_bytes());
    attrs.push(NlAttr::new(proto::SVC_ATTR_FLAGS, flags));
    attrs.push(NlAttr::u32(proto::SVC_ATTR_TIMEOUT, spec.timeout));
    attrs.push(NlAttr::new(
        proto::SVC_ATTR_NETMASK,
        spec.netmask.encode(spec.id.af())?,
    ));
    if let Some(pe) = &spec.pe_name {
        attrs.push(NlAttr::string(proto::SVC_ATTR_PE_NAME, pe));
    }
    Ok(attrs)
}

fn known(kind: u16) -> bool {
    matches!(
        kind,
        proto::SVC_ATTR_AF
            | proto::SVC_ATTR_PROTOCOL
            | proto::SVC_ATTR_ADDR
            | proto::SVC_ATTR_PORT
            | proto::SVC_ATTR_FWMARK
            | proto::SVC_ATTR_SCHED_NAME
            | proto::SVC_ATTR_FLAGS
            | proto::SVC_ATTR_TIMEOUT
            | proto::SVC_ATTR_NETMASK
            | proto::SVC_ATTR_STATS
            | proto::SVC_ATTR_PE_NAME
            | proto::SVC_ATTR_STATS64
    )
}

pub(crate) fn parse_service(message: &NlMsg) -> Result<Service> {
    if message.cmd()? != proto::CMD_NEW_SERVICE {
        return Err(Error::unexpected("a NEW_SERVICE reply", message));
    }
    let outer = message.attrs()?;
    let nested = outer
        .get(proto::CMD_ATTR_SERVICE)
        .ok_or(Error::MissingAttribute {
            name: "IPVS_CMD_ATTR_SERVICE",
        })?;
    let attrs = Attrs::parse(nested.payload())?;

    let af = AddressFamily::from_number(
        attrs
            .get(proto::SVC_ATTR_AF)
            .ok_or(Error::MissingAttribute {
                name: "IPVS_SVC_ATTR_AF",
            })?
            .as_u16()?,
    );

    let id = if let Some(fwmark) = attrs.get(proto::SVC_ATTR_FWMARK) {
        ServiceId::Fwmark {
            af,
            fwmark: fwmark.as_u32()?,
        }
    } else {
        let protocol = Protocol::from_number(
            attrs
                .get(proto::SVC_ATTR_PROTOCOL)
                .ok_or(Error::MissingAttribute {
                    name: "IPVS_SVC_ATTR_PROTOCOL",
                })?
                .as_u16()?,
        );
        let addr = proto::decode_addr(
            af,
            attrs
                .get(proto::SVC_ATTR_ADDR)
                .ok_or(Error::MissingAttribute {
                    name: "IPVS_SVC_ATTR_ADDR",
                })?
                .payload(),
        )?;
        let port = attrs
            .get(proto::SVC_ATTR_PORT)
            .ok_or(Error::MissingAttribute {
                name: "IPVS_SVC_ATTR_PORT",
            })?
            .as_be16()?;
        ServiceId::Addr {
            addr,
            port,
            protocol,
        }
    };

    let sched_name = attrs
        .get(proto::SVC_ATTR_SCHED_NAME)
        .map(NlAttr::as_str)
        .unwrap_or_else(|| "none".to_owned());

    // `IPVS_SVC_ATTR_FLAGS` is `struct ip_vs_flags { u32 flags; u32 mask; }`;
    // replies use a mask of all ones.
    let flags = attrs
        .get(proto::SVC_ATTR_FLAGS)
        .map(|attr| {
            if attr.len() >= 4 {
                Ok(ServiceFlags::from_bits(u32::from_ne_bytes(
                    attr.payload()[..4].try_into().unwrap(),
                )))
            } else {
                Err(crate::nl::Error::BadPayload {
                    kind: proto::SVC_ATTR_FLAGS,
                    len: attr.len(),
                    expected: "at least 4 bytes",
                })
            }
        })
        .transpose()?
        .unwrap_or_default();

    let netmask = attrs
        .get(proto::SVC_ATTR_NETMASK)
        .map(|attr| Netmask::decode(af, attr.payload()))
        .transpose()?
        .unwrap_or_else(|| Netmask::default_for(af));

    let pe_name = attrs
        .get(proto::SVC_ATTR_PE_NAME)
        .map(NlAttr::as_str)
        .filter(|name| !name.is_empty());

    let stats = attrs
        .get(proto::SVC_ATTR_STATS64)
        .or_else(|| attrs.get(proto::SVC_ATTR_STATS))
        .map(parse_stats)
        .transpose()?;

    let unknown = attrs
        .iter()
        .filter(|attr| !known(attr.kind()))
        .map(|attr| RawAttr {
            kind: attr.kind(),
            data: attr.payload().to_vec(),
        })
        .collect();

    Ok(Service {
        id,
        sched_name,
        flags,
        timeout: attrs
            .get(proto::SVC_ATTR_TIMEOUT)
            .map(NlAttr::as_u32)
            .transpose()?
            .unwrap_or(0),
        netmask,
        pe_name,
        stats,
        unknown,
    })
}

impl Ipvs {
    /// Add a virtual service (`NEW_SERVICE`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{Ipvs, Protocol, ServiceSpec};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let spec = ServiceSpec::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp, "rr");
    /// ipvs.add_service(&spec).unwrap();
    /// # }
    /// ```
    pub fn add_service(&mut self, spec: &ServiceSpec) -> Result<()> {
        let attrs = vec![NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            crate::nl::encode_attrs(&full_attrs(spec)?),
        )];
        self.ack(proto::CMD_NEW_SERVICE, attrs)
    }

    /// Replace a virtual service specification (`SET_SERVICE`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{Ipvs, Protocol, ServiceSpec};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let mut spec = ServiceSpec::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp, "wrr");
    /// spec.flags.insert(linux_ipvs::ServiceFlags::ONE_PACKET);
    /// ipvs.set_service(&spec).unwrap();
    /// # }
    /// ```
    pub fn set_service(&mut self, spec: &ServiceSpec) -> Result<()> {
        let attrs = vec![NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            crate::nl::encode_attrs(&full_attrs(spec)?),
        )];
        self.ack(proto::CMD_SET_SERVICE, attrs)
    }

    /// Delete a virtual service and its destinations (`DEL_SERVICE`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{Ipvs, Protocol, ServiceId};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let id = ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp);
    /// ipvs.del_service(&id).unwrap();
    /// # }
    /// ```
    pub fn del_service(&mut self, id: &ServiceId) -> Result<()> {
        let attrs = vec![NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            crate::nl::encode_attrs(&id_attrs(id)),
        )];
        self.ack(proto::CMD_DEL_SERVICE, attrs)
    }

    /// Fetch a single virtual service (`GET_SERVICE` without `NLM_F_DUMP`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use std::net::Ipv4Addr;
    /// use linux_ipvs::{Ipvs, Protocol, ServiceId};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let id = ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp);
    /// let service = ipvs.get_service(&id).unwrap();
    /// println!("scheduler {} flags {}", service.sched_name, service.flags);
    /// # }
    /// ```
    pub fn get_service(&mut self, id: &ServiceId) -> Result<Service> {
        let message = self.single(
            proto::CMD_GET_SERVICE,
            vec![NlAttr::nested(
                proto::CMD_ATTR_SERVICE,
                crate::nl::encode_attrs(&id_attrs(id)),
            )],
        )?;
        parse_service(&message)
    }

    /// Dump every virtual service (`GET_SERVICE` with `NLM_F_DUMP`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let dump = ipvs.list_services().unwrap();
    /// for service in &dump.entries {
    ///     println!("{:?} via {}", service.id, service.sched_name);
    /// }
    /// if dump.interrupted {
    ///     eprintln!("warning: dump was inconsistent; retry");
    /// }
    /// # }
    /// ```
    pub fn list_services(&mut self) -> Result<Dump<Service>> {
        let replies = self.dump(proto::CMD_GET_SERVICE, Vec::new())?;
        let mut dump = Dump::new();
        dump.interrupted = replies.interrupted;
        dump.rejected = replies.rejected;
        for message in replies.messages {
            match parse_service(&message) {
                Ok(service) => dump.entries.push(service),
                Err(error) => dump.rejected.push(Rejected::from_message(&message, error)),
            }
        }
        Ok(dump)
    }

    /// Zero the counters of one service (`ZERO` with a service attribute).
    pub fn zero_service(&mut self, id: &ServiceId) -> Result<()> {
        let attrs = vec![NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            crate::nl::encode_attrs(&id_attrs(id)),
        )];
        self.ack(proto::CMD_ZERO, attrs)
    }

    /// Zero every counter (`ZERO` without a service attribute).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// ipvs.zero_services().unwrap();
    /// # }
    /// ```
    pub fn zero_services(&mut self) -> Result<()> {
        self.ack(proto::CMD_ZERO, Vec::new())
    }

    /// Remove every service and destination (`FLUSH`). This is destructive
    /// and only ever happens on an explicit call.
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// ipvs.flush().unwrap();
    /// # }
    /// ```
    pub fn flush(&mut self) -> Result<()> {
        self.ack(proto::CMD_FLUSH, Vec::new())
    }
}
