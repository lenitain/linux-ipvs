//! Typed errors for the IPVS netlink layer.

use std::error::Error as StdError;
use std::fmt;
use std::io;

use crate::nl;

/// Result alias used by every fallible operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// A structured error from the Linux IPVS netlink family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelError {
    /// Positive errno (`EPERM` = 1, `ESRCH` = 3, ...).
    pub errno: i32,
    /// Extended-ack message (`NLMSGERR_ATTR_MSG`), when the kernel sent one.
    pub message: Option<String>,
    /// Extended-ack attribute offset (`NLMSGERR_ATTR_OFFS`), when present.
    pub offset: Option<u32>,
    /// Any other extended-ack attributes, kept verbatim.
    pub extack: Vec<nl::RawAttr>,
}

impl KernelError {
    /// Whether the kernel rejected the request for lack of permission
    /// (`EPERM` or `EACCES`), typically a missing `CAP_NET_ADMIN`.
    ///
    /// ```
    /// use linux_ipvs::KernelError;
    /// let e = KernelError { errno: 1, message: None, offset: None, extack: Vec::new() };
    /// assert!(e.is_permission_denied());
    /// ```
    pub fn is_permission_denied(&self) -> bool {
        matches!(self.errno, 1 | 13)
    }

    /// Whether the kernel reported that the object does not exist
    /// (`ENOENT` or `ESRCH`).
    ///
    /// ```
    /// use linux_ipvs::KernelError;
    /// let missing = KernelError { errno: 3, message: None, offset: None, extack: Vec::new() };
    /// assert!(missing.is_not_found());
    /// ```
    pub fn is_not_found(&self) -> bool {
        matches!(self.errno, 2 | 3)
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let os = io::Error::from_raw_os_error(self.errno);
        write!(f, "IPVS netlink error: {os} (errno {})", self.errno)?;
        if let Some(message) = &self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

impl StdError for KernelError {}

/// Everything that can go wrong while talking to the IPVS netlink family.
#[derive(Debug)]
pub enum Error {
    /// A syscall or transport error.
    Io(io::Error),
    /// The kernel message could not be decoded.
    Netlink(nl::Error),
    /// The kernel returned a negative errno, optionally with an extended ack.
    Kernel(KernelError),
    /// The `"IPVS"` generic netlink family is not registered (the `ip_vs`
    /// module is not loaded, or the kernel was built without IPVS).
    FamilyNotFound,
    /// A mandatory attribute is missing from a reply.
    MissingAttribute {
        /// Attribute name.
        name: &'static str,
    },
    /// The kernel replied with a command this code path did not expect.
    UnexpectedReply {
        /// What was expected.
        expected: &'static str,
        /// `nlmsg_type` of the message received.
        nlmsg_type: u16,
        /// Generic netlink command, when the message had one.
        cmd: Option<u8>,
    },
    /// A user-provided string does not fit the kernel's attribute policy.
    ValueTooLong {
        /// Field name.
        field: &'static str,
        /// Maximum payload length accepted by the kernel (including the NUL).
        max: usize,
        /// Actual length in bytes (excluding the added NUL).
        got: usize,
    },
    /// The netmask is not valid for the service address family (an IPv6
    /// service needs a prefix length in `1..=128`, an IPv4 service a mask).
    InvalidNetmask,
    /// An address family this crate cannot decode was encountered.
    UnsupportedAddressFamily {
        /// The numeric `AF_*` value.
        af: u16,
    },
}

impl Error {
    pub(crate) fn unexpected(expected: &'static str, msg: &nl::NlMsg) -> Self {
        let header = msg.header();
        Self::UnexpectedReply {
            expected,
            nlmsg_type: header.nlmsg_type,
            cmd: msg.genl_header().ok().map(|g| g.cmd),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "netlink I/O error: {error}"),
            Self::Netlink(error) => write!(f, "{error}"),
            Self::Kernel(error) => write!(f, "{error}"),
            Self::FamilyNotFound => write!(
                f,
                "the \"IPVS\" generic netlink family is not registered (is the ip_vs module loaded?)"
            ),
            Self::MissingAttribute { name } => {
                write!(f, "IPVS reply is missing the {name} attribute")
            }
            Self::UnexpectedReply {
                expected,
                nlmsg_type,
                cmd,
            } => {
                write!(f, "expected {expected}, got nlmsg_type {nlmsg_type}")?;
                if let Some(cmd) = cmd {
                    write!(f, " (command {cmd})")?;
                }
                Ok(())
            }
            Self::ValueTooLong { field, max, got } => write!(
                f,
                "{field} is {got} bytes long; the kernel accepts at most {max} bytes including the NUL"
            ),
            Self::InvalidNetmask => {
                write!(f, "netmask is not valid for the service address family")
            }
            Self::UnsupportedAddressFamily { af } => {
                write!(f, "unsupported address family {af}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Netlink(error) => Some(error),
            Self::Kernel(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<nl::Error> for Error {
    fn from(error: nl::Error) -> Self {
        Self::Netlink(error)
    }
}
