//! Statistics and general IPVS information (`GET_INFO`, `*_ATTR_STATS`).

use crate::error::{Error, Result};
use crate::ipvs::Ipvs;
use crate::nl::{Attrs, NlAttr};
use crate::proto::{self, INFO_ATTR_CONN_TAB_SIZE, INFO_ATTR_VERSION};

/// Service or destination counters.
///
/// The kernel sends both a 32-bit (`STATS`) and a 64-bit (`STATS64`)
/// container. This crate prefers the 64-bit container and falls back to the
/// 32-bit one when an older kernel omits `STATS64`. All fields are
/// host-order `u64` after decoding; the wire widths are an encoding detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Connections scheduled.
    pub conns: u64,
    /// Incoming packets.
    pub inpkts: u64,
    /// Outgoing packets.
    pub outpkts: u64,
    /// Incoming bytes.
    pub inbytes: u64,
    /// Outgoing bytes.
    pub outbytes: u64,
    /// Current connection rate.
    pub cps: u64,
    /// Current incoming-packet rate.
    pub inpps: u64,
    /// Current outgoing-packet rate.
    pub outpps: u64,
    /// Current incoming-byte rate.
    pub inbps: u64,
    /// Current outgoing-byte rate.
    pub outbps: u64,
}

impl Stats {
    /// All-zero counters; handy for tests.
    pub const ZERO: Self = Self {
        conns: 0,
        inpkts: 0,
        outpkts: 0,
        inbytes: 0,
        outbytes: 0,
        cps: 0,
        inpps: 0,
        outpps: 0,
        inbps: 0,
        outbps: 0,
    };
}

/// General IPVS information returned by `GET_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    /// `IP_VS_VERSION_CODE` (for example `0x010201`).
    pub version: u32,
    /// Size of the connection hash table.
    pub conn_tab_size: u32,
}

fn number(attrs: &Attrs, kind: u16) -> Result<Option<u64>> {
    let Some(attr) = attrs.get(kind) else {
        return Ok(None);
    };
    match attr.len() {
        8 => Ok(Some(attr.as_u64()?)),
        4 => Ok(Some(attr.as_u32()? as u64)),
        len => Err(crate::nl::Error::BadPayload {
            kind,
            len,
            expected: "4 or 8 bytes",
        }
        .into()),
    }
}

/// Decode one nested `STATS`/`STATS64` attribute. Unknown members (including
/// the kernel's alignment `PAD` attribute) are ignored.
pub(crate) fn parse_stats(attr: &NlAttr) -> Result<Stats> {
    let attrs = Attrs::parse(attr.payload())?;
    Ok(Stats {
        conns: number(&attrs, proto::STATS_ATTR_CONNS)?.unwrap_or(0),
        inpkts: number(&attrs, proto::STATS_ATTR_INPKTS)?.unwrap_or(0),
        outpkts: number(&attrs, proto::STATS_ATTR_OUTPKTS)?.unwrap_or(0),
        inbytes: number(&attrs, proto::STATS_ATTR_INBYTES)?.unwrap_or(0),
        outbytes: number(&attrs, proto::STATS_ATTR_OUTBYTES)?.unwrap_or(0),
        cps: number(&attrs, proto::STATS_ATTR_CPS)?.unwrap_or(0),
        inpps: number(&attrs, proto::STATS_ATTR_INPPS)?.unwrap_or(0),
        outpps: number(&attrs, proto::STATS_ATTR_OUTPPS)?.unwrap_or(0),
        inbps: number(&attrs, proto::STATS_ATTR_INBPS)?.unwrap_or(0),
        outbps: number(&attrs, proto::STATS_ATTR_OUTBPS)?.unwrap_or(0),
    })
}

impl Ipvs {
    /// Fetch general IPVS information (`GET_INFO`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let info = ipvs.info().unwrap();
    /// println!("version {:#x}, connection table {}", info.version, info.conn_tab_size);
    /// # }
    /// ```
    pub fn info(&mut self) -> Result<Info> {
        let message = self.single(proto::CMD_GET_INFO, Vec::new())?;
        if message.cmd()? != proto::CMD_SET_INFO {
            return Err(Error::unexpected("a SET_INFO reply", &message));
        }
        let attrs = message.attrs()?;
        let version = attrs
            .get(INFO_ATTR_VERSION)
            .ok_or(Error::MissingAttribute {
                name: "IPVS_INFO_ATTR_VERSION",
            })?
            .as_u32()?;
        let conn_tab_size = attrs
            .get(INFO_ATTR_CONN_TAB_SIZE)
            .ok_or(Error::MissingAttribute {
                name: "IPVS_INFO_ATTR_CONN_TAB_SIZE",
            })?
            .as_u32()?;
        Ok(Info {
            version,
            conn_tab_size,
        })
    }
}
