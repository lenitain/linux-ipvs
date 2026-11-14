//! The IPVS synchronization daemon (`NEW`/`DEL`/`GET_DAEMON`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::ipvs::{Dump, Ipvs, Rejected};
use crate::nl::{Attrs, NlAttr, NlMsg, RawAttr};
use crate::proto;

/// Maximum payload of `IPVS_DAEMON_ATTR_MCAST_IFN`, including the NUL.
const IFN_MAX: usize = 15;

/// The state of the synchronization daemon (`IP_VS_STATE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DaemonState {
    /// Not running.
    #[default]
    None,
    /// Master.
    Master,
    /// Backup.
    Backup,
    /// Any other value, kept verbatim.
    Other(u32),
}

impl DaemonState {
    /// The numeric value used on the wire.
    ///
    /// ```
    /// use linux_ipvs::DaemonState;
    /// assert_eq!(DaemonState::Master.number(), 1);
    /// ```
    pub fn number(self) -> u32 {
        match self {
            Self::None => proto::STATE_NONE,
            Self::Master => proto::STATE_MASTER,
            Self::Backup => proto::STATE_BACKUP,
            Self::Other(value) => value,
        }
    }

    /// Decode a state value.
    pub fn from_number(value: u32) -> Self {
        match value {
            proto::STATE_NONE => Self::None,
            proto::STATE_MASTER => Self::Master,
            proto::STATE_BACKUP => Self::Backup,
            other => Self::Other(other),
        }
    }
}

/// Configuration of the IPVS synchronization daemon.
///
/// `NEW_DAEMON` starts a daemon; `DEL_DAEMON` stops the one named by
/// [`DaemonConfig::state`]. Optional fields are omitted from requests when
/// they are `None`, which leaves the kernel's defaults untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// Master or backup state (required).
    pub state: DaemonState,
    /// Multicast interface name (required by `NEW_DAEMON`).
    pub mcast_ifn: String,
    /// Sync ID (required by `NEW_DAEMON`).
    pub sync_id: u32,
    /// UDP payload size.
    pub sync_maxlen: Option<u16>,
    /// Multicast group address (IPv4 or IPv6).
    pub mcast_group: Option<IpAddr>,
    /// Multicast port.
    pub mcast_port: Option<u16>,
    /// Multicast TTL.
    pub mcast_ttl: Option<u8>,
    /// Attributes this crate does not model, kept verbatim.
    pub unknown: Vec<RawAttr>,
}

impl DaemonConfig {
    /// Build a minimal configuration (state, interface, sync id).
    ///
    /// ```
    /// use linux_ipvs::{DaemonConfig, DaemonState};
    /// let config = DaemonConfig::new(DaemonState::Master, "eth0", 1);
    /// assert_eq!(config.sync_id, 1);
    /// ```
    pub fn new(state: DaemonState, mcast_ifn: impl Into<String>, sync_id: u32) -> Self {
        Self {
            state,
            mcast_ifn: mcast_ifn.into(),
            sync_id,
            sync_maxlen: None,
            mcast_group: None,
            mcast_port: None,
            mcast_ttl: None,
            unknown: Vec::new(),
        }
    }
}

fn encode(config: &DaemonConfig) -> Result<Vec<NlAttr>> {
    proto::check_string("IPVS_DAEMON_ATTR_MCAST_IFN", &config.mcast_ifn, IFN_MAX)?;
    let mut attrs = vec![
        NlAttr::u32(proto::DAEMON_ATTR_STATE, config.state.number()),
        NlAttr::string(proto::DAEMON_ATTR_MCAST_IFN, &config.mcast_ifn),
        NlAttr::u32(proto::DAEMON_ATTR_SYNC_ID, config.sync_id),
    ];
    if let Some(value) = config.sync_maxlen {
        attrs.push(NlAttr::u16(proto::DAEMON_ATTR_SYNC_MAXLEN, value));
    }
    if let Some(group) = config.mcast_group {
        match group {
            IpAddr::V4(addr) => attrs.push(NlAttr::be32(
                proto::DAEMON_ATTR_MCAST_GROUP,
                u32::from(addr),
            )),
            IpAddr::V6(addr) => {
                attrs.push(NlAttr::new(proto::DAEMON_ATTR_MCAST_GROUP6, addr.octets()))
            }
        }
    }
    if let Some(value) = config.mcast_port {
        attrs.push(NlAttr::u16(proto::DAEMON_ATTR_MCAST_PORT, value));
    }
    if let Some(value) = config.mcast_ttl {
        attrs.push(NlAttr::u8(proto::DAEMON_ATTR_MCAST_TTL, value));
    }
    Ok(attrs)
}

fn known(kind: u16) -> bool {
    matches!(
        kind,
        proto::DAEMON_ATTR_STATE
            | proto::DAEMON_ATTR_MCAST_IFN
            | proto::DAEMON_ATTR_SYNC_ID
            | proto::DAEMON_ATTR_SYNC_MAXLEN
            | proto::DAEMON_ATTR_MCAST_GROUP
            | proto::DAEMON_ATTR_MCAST_GROUP6
            | proto::DAEMON_ATTR_MCAST_PORT
            | proto::DAEMON_ATTR_MCAST_TTL
    )
}

fn parse_daemon(message: &NlMsg) -> Result<DaemonConfig> {
    if message.cmd()? != proto::CMD_NEW_DAEMON {
        return Err(Error::unexpected("a NEW_DAEMON reply", message));
    }
    let outer = message.attrs()?;
    let nested = outer
        .get(proto::CMD_ATTR_DAEMON)
        .ok_or(Error::MissingAttribute {
            name: "IPVS_CMD_ATTR_DAEMON",
        })?;
    let attrs = Attrs::parse(nested.payload())?;

    let mcast_group = if let Some(attr) = attrs.get(proto::DAEMON_ATTR_MCAST_GROUP) {
        Some(IpAddr::V4(Ipv4Addr::from(attr.as_be32()?)))
    } else {
        attrs
            .get(proto::DAEMON_ATTR_MCAST_GROUP6)
            .map(|attr| -> Result<IpAddr> {
                let bytes: [u8; 16] =
                    attr.payload()
                        .try_into()
                        .map_err(|_| crate::nl::Error::BadPayload {
                            kind: proto::DAEMON_ATTR_MCAST_GROUP6,
                            len: attr.len(),
                            expected: "16 bytes",
                        })?;
                Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
            })
            .transpose()?
    };

    let unknown = attrs
        .iter()
        .filter(|attr| !known(attr.kind()))
        .map(|attr| RawAttr {
            kind: attr.kind(),
            data: attr.payload().to_vec(),
        })
        .collect();

    Ok(DaemonConfig {
        state: attrs
            .get(proto::DAEMON_ATTR_STATE)
            .map(NlAttr::as_u32)
            .transpose()?
            .map(DaemonState::from_number)
            .unwrap_or_default(),
        mcast_ifn: attrs
            .get(proto::DAEMON_ATTR_MCAST_IFN)
            .map(NlAttr::as_str)
            .unwrap_or_default(),
        sync_id: attrs
            .get(proto::DAEMON_ATTR_SYNC_ID)
            .map(NlAttr::as_u32)
            .transpose()?
            .unwrap_or(0),
        sync_maxlen: attrs
            .get(proto::DAEMON_ATTR_SYNC_MAXLEN)
            .map(NlAttr::as_u16)
            .transpose()?,
        mcast_group,
        mcast_port: attrs
            .get(proto::DAEMON_ATTR_MCAST_PORT)
            .map(NlAttr::as_u16)
            .transpose()?,
        mcast_ttl: attrs
            .get(proto::DAEMON_ATTR_MCAST_TTL)
            .map(NlAttr::as_u8)
            .transpose()?,
        unknown,
    })
}

impl Ipvs {
    /// Start the synchronization daemon (`NEW_DAEMON`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::{DaemonConfig, DaemonState, Ipvs};
    ///
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let mut config = DaemonConfig::new(DaemonState::Master, "eth0", 1);
    /// config.mcast_group = Some("239.0.0.1".parse().unwrap());
    /// ipvs.add_daemon(&config).unwrap();
    /// # }
    /// ```
    pub fn add_daemon(&mut self, config: &DaemonConfig) -> Result<()> {
        let attrs = vec![NlAttr::nested(
            proto::CMD_ATTR_DAEMON,
            crate::nl::encode_attrs(&encode(config)?),
        )];
        self.ack(proto::CMD_NEW_DAEMON, attrs)
    }

    /// Stop the synchronization daemon in `state` (`DEL_DAEMON`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::{DaemonState, Ipvs};
    /// let mut ipvs = Ipvs::new().unwrap();
    /// ipvs.del_daemon(DaemonState::Master).unwrap();
    /// # }
    /// ```
    pub fn del_daemon(&mut self, state: DaemonState) -> Result<()> {
        let attrs = vec![NlAttr::nested(
            proto::CMD_ATTR_DAEMON,
            crate::nl::encode_attrs(&[NlAttr::u32(proto::DAEMON_ATTR_STATE, state.number())]),
        )];
        self.ack(proto::CMD_DEL_DAEMON, attrs)
    }

    /// Dump the running synchronization daemons (`GET_DAEMON` with
    /// `NLM_F_DUMP`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// for daemon in ipvs.list_daemons().unwrap().entries {
    ///     println!("{:?} on {}", daemon.state, daemon.mcast_ifn);
    /// }
    /// # }
    /// ```
    pub fn list_daemons(&mut self) -> Result<Dump<DaemonConfig>> {
        let replies = self.dump(proto::CMD_GET_DAEMON, Vec::new())?;
        let mut dump = Dump::new();
        dump.interrupted = replies.interrupted;
        dump.rejected = replies.rejected;
        for message in replies.messages {
            match parse_daemon(&message) {
                Ok(daemon) => dump.entries.push(daemon),
                Err(error) => dump.rejected.push(Rejected::from_message(&message, error)),
            }
        }
        Ok(dump)
    }
}
