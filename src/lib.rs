//! # linux-ipvs
//!
//! Complete mechanism layer for the Linux IPVS (IP Virtual Server) generic
//! netlink interface: virtual services, real servers, statistics, the
//! synchronization daemon, and connection timeouts.
//!
//! The crate implements the correctness layer completely — `nlmsghdr` /
//! `genlmsghdr` / `nlattr` encoding with 4-byte padding and nesting, family
//! resolution (`CTRL_CMD_GETFAMILY "IPVS"`), multipart dumps terminated by
//! `NLMSG_DONE`, byte order (network-order addresses and ports, host-order
//! scalars), typed kernel errors with extended acknowledgements, and
//! per-entry degradation that keeps unparsable dump entries verbatim — and
//! leaves policy (schedulers, health checks, event loops, threading,
//! keepalived-style configuration) to the caller.
//!
//! The core builds with zero dependencies (`default-features = false`). The
//! `std` feature adds the real `NETLINK_GENERIC` socket; with injection via
//! [`NetlinkTransport`] every command and error path can be exercised
//! without a kernel.
//!
//! ```no_run
//! # #[cfg(feature = "std")]
//! # {
//! use std::net::Ipv4Addr;
//! use linux_ipvs::{DestSpec, ForwardMethod, Ipvs, Protocol, ServiceSpec};
//!
//! let mut ipvs = Ipvs::new()?;                     // open socket + resolve family
//! let service = ServiceSpec::addr(
//!     Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp, "rr",
//! );
//! ipvs.add_service(&service)?;                     // NEW_SERVICE
//! let dest = DestSpec::new(
//!     Ipv4Addr::new(198, 51, 100, 10), 8080, ForwardMethod::DirectRoute,
//! );
//! ipvs.add_dest(service.id(), &dest)?;             // NEW_DEST
//! for entry in ipvs.list_services()?.entries {     // GET_SERVICE + DUMP
//!     println!("{:?}", entry.id);
//! }
//! # }
//! # Ok::<(), linux_ipvs::Error>(())
//! ```

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![warn(missing_docs)]

#[cfg(not(target_os = "linux"))]
compile_error!("linux-ipvs only supports Linux");

pub mod daemon;
pub mod dest;
pub mod error;
pub mod ipvs;
pub mod nl;
pub mod proto;
pub mod service;
pub mod stats;
pub mod timeout;

pub use crate::daemon::{DaemonConfig, DaemonState};
pub use crate::dest::{Dest, DestId, DestSpec, ForwardMethod, TunnelFlags, TunnelType};
pub use crate::error::{Error, KernelError, Result};
#[cfg(feature = "std")]
pub use crate::ipvs::NetlinkSocket;
pub use crate::ipvs::{Dump, Ipvs, NetlinkTransport, Rejected};
pub use crate::proto::{AddressFamily, Protocol};
pub use crate::service::{Netmask, Service, ServiceFlags, ServiceId, ServiceSpec};
pub use crate::stats::{Info, Stats};
pub use crate::timeout::Timeouts;
