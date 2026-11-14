//! Connection timeouts (`GET_CONFIG` / `SET_CONFIG`).

use crate::error::{Error, Result};
use crate::ipvs::Ipvs;
use crate::nl::NlAttr;
use crate::proto;

/// Connection timeouts in seconds.
///
/// `GET_CONFIG` replies omit timeouts whose protocol is not built into the
/// kernel (`CONFIG_IP_VS_PROTO_TCP` / `..._UDP`), hence the `Option` fields.
/// `set_timeouts` sends only the fields that are `Some`, keeping the kernel
/// semantics of a partial update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timeouts {
    /// TCP established-connection timeout.
    pub tcp: Option<u32>,
    /// TCP FIN-wait timeout.
    pub tcp_fin: Option<u32>,
    /// UDP timeout.
    pub udp: Option<u32>,
}

impl Timeouts {
    /// All three timeouts at once.
    pub const fn new(tcp: u32, tcp_fin: u32, udp: u32) -> Self {
        Self {
            tcp: Some(tcp),
            tcp_fin: Some(tcp_fin),
            udp: Some(udp),
        }
    }

    fn attrs(&self) -> Vec<NlAttr> {
        let mut attrs = Vec::new();
        if let Some(value) = self.tcp {
            attrs.push(NlAttr::u32(proto::CMD_ATTR_TIMEOUT_TCP, value));
        }
        if let Some(value) = self.tcp_fin {
            attrs.push(NlAttr::u32(proto::CMD_ATTR_TIMEOUT_TCP_FIN, value));
        }
        if let Some(value) = self.udp {
            attrs.push(NlAttr::u32(proto::CMD_ATTR_TIMEOUT_UDP, value));
        }
        attrs
    }
}

impl Ipvs {
    /// Fetch the current connection timeouts (`GET_CONFIG`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let timeouts = ipvs.timeouts().unwrap();
    /// println!("tcp {:?} tcp_fin {:?} udp {:?}", timeouts.tcp, timeouts.tcp_fin, timeouts.udp);
    /// # }
    /// ```
    pub fn timeouts(&mut self) -> Result<Timeouts> {
        let message = self.single(proto::CMD_GET_CONFIG, Vec::new())?;
        if message.cmd()? != proto::CMD_SET_CONFIG {
            return Err(Error::unexpected("a SET_CONFIG reply", &message));
        }
        let attrs = message.attrs()?;
        Ok(Timeouts {
            tcp: attrs
                .get(proto::CMD_ATTR_TIMEOUT_TCP)
                .map(NlAttr::as_u32)
                .transpose()?,
            tcp_fin: attrs
                .get(proto::CMD_ATTR_TIMEOUT_TCP_FIN)
                .map(NlAttr::as_u32)
                .transpose()?,
            udp: attrs
                .get(proto::CMD_ATTR_TIMEOUT_UDP)
                .map(NlAttr::as_u32)
                .transpose()?,
        })
    }

    /// Update connection timeouts (`SET_CONFIG`). Only `Some` fields are
    /// sent.
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::{Ipvs, Timeouts};
    /// let mut ipvs = Ipvs::new().unwrap();
    /// ipvs.set_timeouts(&Timeouts::new(600, 120, 300)).unwrap();
    /// # }
    /// ```
    pub fn set_timeouts(&mut self, timeouts: &Timeouts) -> Result<()> {
        self.ack(proto::CMD_SET_CONFIG, timeouts.attrs())
    }
}
