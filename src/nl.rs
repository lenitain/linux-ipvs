//! Generic netlink message layer: `nlmsghdr`, `genlmsghdr` and `nlattr`
//! encoding/decoding, 4-byte padding and nesting, attribute iteration, and
//! request construction.
//!
//! Everything in this module is a pure function over bytes: no socket is
//! opened and no kernel is required, so the exact wire format is covered by
//! expected-byte tests.
//!
//! Header fields are native endian (the kernel copies the C structures
//! as-is). Attribute payload byte order is defined by the subsystem and is
//! handled by the typed IPVS layer.

use std::error::Error as StdError;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants (from /usr/include/linux/netlink.h and genetlink.h)
// ---------------------------------------------------------------------------

/// `NETLINK_GENERIC` — the netlink protocol used for generic netlink (16).
pub const NETLINK_GENERIC: i32 = 16;

/// `NLMSG_NOOP`.
pub const NLMSG_NOOP: u16 = 0x1;
/// `NLMSG_ERROR` — an error (or success) acknowledgement.
pub const NLMSG_ERROR: u16 = 0x2;
/// `NLMSG_DONE` — end of a multipart dump.
pub const NLMSG_DONE: u16 = 0x3;
/// `NLMSG_OVERRUN`.
pub const NLMSG_OVERRUN: u16 = 0x4;

/// `NLM_F_REQUEST`.
pub const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_MULTI` — the message is part of a multipart dump.
pub const NLM_F_MULTI: u16 = 0x02;
/// `NLM_F_ACK` — request an acknowledgement.
pub const NLM_F_ACK: u16 = 0x04;
/// `NLM_F_DUMP_INTR` — the dump was inconsistent (a sequence change occurred).
pub const NLM_F_DUMP_INTR: u16 = 0x10;
/// `NLM_F_ROOT`.
pub const NLM_F_ROOT: u16 = 0x100;
/// `NLM_F_MATCH`.
pub const NLM_F_MATCH: u16 = 0x200;
/// `NLM_F_DUMP` = `NLM_F_ROOT | NLM_F_MATCH`.
pub const NLM_F_DUMP: u16 = 0x300;

/// `NLA_F_NESTED` — the attribute contains further attributes.
pub const NLA_F_NESTED: u16 = 1 << 15;
/// `NLA_F_NET_BYTEORDER` — the payload is in network byte order.
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
/// Mask of the flag bits in `nla_type`.
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

/// `NLMSG_HDRLEN` — size of `struct nlmsghdr`.
pub const NLMSG_HDRLEN: usize = 16;
/// `GENL_HDRLEN` — size of `struct genlmsghdr`.
pub const GENL_HDRLEN: usize = 4;
/// `NLA_HDRLEN` — size of `struct nlattr`.
pub const NLA_HDRLEN: usize = 4;
/// `NLMSG_ALIGNTO` / `NLA_ALIGNTO`.
pub const ALIGNTO: usize = 4;

/// `GENL_ID_CTRL` — the generic netlink controller family id.
pub const GENL_ID_CTRL: u16 = 0x10;
/// `CTRL_GENL_VERSION` — the controller family version.
pub const CTRL_GENL_VERSION: u8 = 0x2;
/// `CTRL_CMD_GETFAMILY`.
pub const CTRL_CMD_GETFAMILY: u8 = 3;
/// `CTRL_CMD_NEWFAMILY` — the command id of a `GETFAMILY` reply.
pub const CTRL_CMD_NEWFAMILY: u8 = 1;
/// `CTRL_ATTR_FAMILY_ID`.
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
/// `CTRL_ATTR_FAMILY_NAME`.
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
/// `CTRL_ATTR_VERSION`.
pub const CTRL_ATTR_VERSION: u16 = 3;

/// `NLMSGERR_ATTR_MSG` — human-readable error string inside `NLMSG_ERROR`.
pub const NLMSGERR_ATTR_MSG: u16 = 1;
/// `NLMSGERR_ATTR_OFFS` — offset of the offending attribute.
pub const NLMSGERR_ATTR_OFFS: u16 = 2;

// ---------------------------------------------------------------------------
// Alignment
// ---------------------------------------------------------------------------

/// Round `len` up to a multiple of `align` (`align` must be a power of two).
///
/// ```
/// use linux_ipvs::nl::align_to;
/// assert_eq!(align_to(5, 4), 8);
/// assert_eq!(align_to(4, 4), 4);
/// ```
pub fn align_to(len: usize, align: usize) -> usize {
    (len + align - 1) & !(align - 1)
}

/// `NLA_ALIGN(len)` — attribute length rounded up to 4 bytes.
///
/// ```
/// use linux_ipvs::nl::nla_align;
/// assert_eq!(nla_align(3), 4);
/// assert_eq!(nla_align(5), 8);
/// ```
pub fn nla_align(len: usize) -> usize {
    align_to(len, ALIGNTO)
}

/// `NLMSG_ALIGN(len)` — message length rounded up to 4 bytes.
///
/// ```
/// use linux_ipvs::nl::nlmsg_align;
/// assert_eq!(nlmsg_align(17), 20);
/// assert_eq!(nlmsg_align(20), 20);
/// ```
pub fn nlmsg_align(len: usize) -> usize {
    align_to(len, ALIGNTO)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced while decoding netlink bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A structure was shorter than required.
    Truncated {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        have: usize,
    },
    /// `nlmsg_len` is smaller than the header or larger than the buffer.
    BadMessageLength {
        /// Declared `nlmsg_len`.
        len: u32,
        /// Bytes available at the message start.
        available: usize,
    },
    /// A `nlattr` header declares a length smaller than the header itself.
    BadAttributeLength {
        /// Declared `nla_len`.
        len: u16,
    },
    /// Bytes are left over that do not form a complete message or attribute.
    TrailingBytes {
        /// Number of leftover bytes.
        available: usize,
    },
    /// An attribute payload does not have the length required by the type.
    BadPayload {
        /// Attribute type (flags removed).
        kind: u16,
        /// Payload length found.
        len: usize,
        /// Human-readable expected shape.
        expected: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, have } => {
                write!(f, "netlink: truncated: need {needed} bytes, have {have}")
            }
            Self::BadMessageLength { len, available } => write!(
                f,
                "netlink: bad nlmsg_len {len} with {available} bytes available"
            ),
            Self::BadAttributeLength { len } => {
                write!(f, "netlink: bad nla_len {len} (smaller than header)")
            }
            Self::TrailingBytes { available } => {
                write!(f, "netlink: {available} trailing bytes form no message")
            }
            Self::BadPayload {
                kind,
                len,
                expected,
            } => write!(
                f,
                "netlink: attribute {kind} has payload length {len}, expected {expected}"
            ),
        }
    }
}

impl StdError for Error {}

type NlResult<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------------------
// nlmsghdr / genlmsghdr
// ---------------------------------------------------------------------------

/// Decoded `struct nlmsghdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlMsgHeader {
    /// `nlmsg_len` — total length including this header (no padding).
    pub nlmsg_len: u32,
    /// `nlmsg_type` — family id or a reserved `NLMSG_*` value.
    pub nlmsg_type: u16,
    /// `nlmsg_flags` — `NLM_F_*`.
    pub nlmsg_flags: u16,
    /// `nlmsg_seq` — sequence number echoed from the request.
    pub nlmsg_seq: u32,
    /// `nlmsg_pid` — sender port id (0 for the kernel).
    pub nlmsg_pid: u32,
}

impl NlMsgHeader {
    /// Encode the 16-byte native-order header.
    ///
    /// ```
    /// use linux_ipvs::nl::NlMsgHeader;
    /// let h = NlMsgHeader {
    ///     nlmsg_len: 20,
    ///     nlmsg_type: 0x10,
    ///     nlmsg_flags: 0x05,
    ///     nlmsg_seq: 7,
    ///     nlmsg_pid: 0,
    /// };
    /// assert_eq!(h.encode(), [
    ///     20, 0, 0, 0, 0x10, 0, 0x05, 0, 7, 0, 0, 0, 0, 0, 0, 0,
    /// ]);
    /// ```
    pub fn encode(&self) -> [u8; NLMSG_HDRLEN] {
        let mut b = [0u8; NLMSG_HDRLEN];
        b[0..4].copy_from_slice(&self.nlmsg_len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.nlmsg_type.to_ne_bytes());
        b[6..8].copy_from_slice(&self.nlmsg_flags.to_ne_bytes());
        b[8..12].copy_from_slice(&self.nlmsg_seq.to_ne_bytes());
        b[12..16].copy_from_slice(&self.nlmsg_pid.to_ne_bytes());
        b
    }

    /// Decode a header from the first 16 bytes of `bytes` (extra bytes are
    /// ignored).
    ///
    /// ```
    /// use linux_ipvs::nl::NlMsgHeader;
    /// let h = NlMsgHeader::decode(&[
    ///     20, 0, 0, 0, 0x10, 0, 0x05, 0, 7, 0, 0, 0, 0, 0, 0, 0,
    /// ]).unwrap();
    /// assert_eq!(h.nlmsg_seq, 7);
    /// ```
    pub fn decode(bytes: &[u8]) -> NlResult<Self> {
        if bytes.len() < NLMSG_HDRLEN {
            return Err(Error::Truncated {
                needed: NLMSG_HDRLEN,
                have: bytes.len(),
            });
        }
        Ok(Self {
            nlmsg_len: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
            nlmsg_type: u16::from_ne_bytes([bytes[4], bytes[5]]),
            nlmsg_flags: u16::from_ne_bytes([bytes[6], bytes[7]]),
            nlmsg_seq: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
            nlmsg_pid: u32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
        })
    }
}

/// Decoded `struct genlmsghdr`, which follows the `nlmsghdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenlMsgHeader {
    /// `cmd` — family command or reply command.
    pub cmd: u8,
    /// `version` — family version.
    pub version: u8,
    /// `reserved` — must be zero.
    pub reserved: u16,
}

impl GenlMsgHeader {
    /// Encode the 4-byte header.
    ///
    /// ```
    /// use linux_ipvs::nl::GenlMsgHeader;
    /// let g = GenlMsgHeader { cmd: 3, version: 1, reserved: 0 };
    /// assert_eq!(g.encode(), [3, 1, 0, 0]);
    /// ```
    pub fn encode(&self) -> [u8; GENL_HDRLEN] {
        let mut b = [0u8; GENL_HDRLEN];
        b[0] = self.cmd;
        b[1] = self.version;
        b[2..4].copy_from_slice(&self.reserved.to_ne_bytes());
        b
    }

    /// Decode a header from the first 4 bytes of `bytes`.
    ///
    /// ```
    /// use linux_ipvs::nl::GenlMsgHeader;
    /// assert_eq!(GenlMsgHeader::decode(&[3, 2, 0, 0]).unwrap().cmd, 3);
    /// ```
    pub fn decode(bytes: &[u8]) -> NlResult<Self> {
        if bytes.len() < GENL_HDRLEN {
            return Err(Error::Truncated {
                needed: GENL_HDRLEN,
                have: bytes.len(),
            });
        }
        Ok(Self {
            cmd: bytes[0],
            version: bytes[1],
            reserved: u16::from_ne_bytes([bytes[2], bytes[3]]),
        })
    }
}

// ---------------------------------------------------------------------------
// nlattr
// ---------------------------------------------------------------------------

/// An attribute that this crate does not model, kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttr {
    /// Attribute type with `NLA_F_*` flags removed.
    pub kind: u16,
    /// Raw payload bytes (padding excluded).
    pub data: Vec<u8>,
}

/// A decoded `struct nlattr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlAttr {
    nla_type: u16,
    data: Vec<u8>,
}

impl NlAttr {
    /// Maximum payload length of a single attribute.
    pub const MAX_PAYLOAD: usize = u16::MAX as usize - NLA_HDRLEN;

    /// Build a raw attribute. The encoded form is padded to 4 bytes.
    ///
    /// # Panics
    ///
    /// Panics when the payload exceeds [`NlAttr::MAX_PAYLOAD`] bytes; the
    /// `nla_len` field cannot represent more.
    ///
    /// ```
    /// use linux_ipvs::nl::NlAttr;
    /// let a = NlAttr::new(1, [0xaa]);
    /// assert_eq!(a.encode(), [0x05, 0x00, 0x01, 0x00, 0xaa, 0x00, 0x00, 0x00]);
    /// ```
    pub fn new(kind: u16, payload: impl AsRef<[u8]>) -> Self {
        Self::with_vec(kind, payload.as_ref().to_vec())
    }

    fn with_vec(nla_type: u16, data: Vec<u8>) -> Self {
        assert!(
            data.len() <= Self::MAX_PAYLOAD,
            "netlink attribute payload exceeds {} bytes",
            Self::MAX_PAYLOAD
        );
        Self { nla_type, data }
    }

    /// Build a nested attribute (sets `NLA_F_NESTED`).
    ///
    /// ```
    /// use linux_ipvs::nl::NlAttr;
    /// let a = NlAttr::nested(1, [0, 0, 0, 0]);
    /// assert!(a.is_nested());
    /// assert_eq!(a.kind(), 1);
    /// ```
    pub fn nested(kind: u16, payload: impl AsRef<[u8]>) -> Self {
        Self::new(kind | NLA_F_NESTED, payload)
    }

    /// Build an attribute with a `u8` payload.
    pub fn u8(kind: u16, value: u8) -> Self {
        Self::new(kind, [value])
    }

    /// Build an attribute with a native-order `u16` payload.
    pub fn u16(kind: u16, value: u16) -> Self {
        Self::new(kind, value.to_ne_bytes())
    }

    /// Build an attribute with a native-order `u32` payload.
    pub fn u32(kind: u16, value: u32) -> Self {
        Self::new(kind, value.to_ne_bytes())
    }

    /// Build an attribute with a native-order `u64` payload.
    pub fn u64(kind: u16, value: u64) -> Self {
        Self::new(kind, value.to_ne_bytes())
    }

    /// Build an attribute with a native-order `i32` payload.
    pub fn i32(kind: u16, value: i32) -> Self {
        Self::new(kind, value.to_ne_bytes())
    }

    /// Build an attribute with a network-order `u16` payload.
    pub fn be16(kind: u16, value: u16) -> Self {
        Self::new(kind, value.to_be_bytes())
    }

    /// Build an attribute with a network-order `u32` payload.
    pub fn be32(kind: u16, value: u32) -> Self {
        Self::new(kind, value.to_be_bytes())
    }

    /// Build a NUL-terminated string attribute.
    pub fn string(kind: u16, value: &str) -> Self {
        let mut data = Vec::with_capacity(value.len() + 1);
        data.extend_from_slice(value.as_bytes());
        data.push(0);
        Self::new(kind, data)
    }

    /// The attribute type with `NLA_F_*` flags removed.
    pub fn kind(&self) -> u16 {
        self.nla_type & NLA_TYPE_MASK
    }

    /// The raw `nla_type` field, including flags.
    pub fn raw_type(&self) -> u16 {
        self.nla_type
    }

    /// Whether `NLA_F_NESTED` is set. The kernel does not set this flag on
    /// every container, so parsers must not rely on it.
    pub fn is_nested(&self) -> bool {
        self.nla_type & NLA_F_NESTED != 0
    }

    /// Payload length (excluding header and padding).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Raw payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.data
    }

    /// Encode the attribute (header, payload, zero padding).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(nla_align(NLA_HDRLEN + self.data.len()));
        self.encode_into(&mut out);
        out
    }

    /// Encode into an existing buffer.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let len = NLA_HDRLEN + self.data.len();
        let start = out.len();
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&self.nla_type.to_ne_bytes());
        out.extend_from_slice(&self.data);
        out.resize(start + nla_align(len), 0);
    }

    fn check(&self, expected_len: usize, expected: &'static str) -> NlResult<()> {
        if self.data.len() != expected_len {
            return Err(Error::BadPayload {
                kind: self.kind(),
                len: self.data.len(),
                expected,
            });
        }
        Ok(())
    }

    /// Read a `u8` payload.
    pub fn as_u8(&self) -> NlResult<u8> {
        self.check(1, "1 byte")?;
        Ok(self.data[0])
    }

    /// Read a native-order `u16` payload.
    pub fn as_u16(&self) -> NlResult<u16> {
        self.check(2, "2 bytes")?;
        Ok(u16::from_ne_bytes([self.data[0], self.data[1]]))
    }

    /// Read a native-order `u32` payload.
    pub fn as_u32(&self) -> NlResult<u32> {
        self.check(4, "4 bytes")?;
        Ok(u32::from_ne_bytes(self.data[..4].try_into().unwrap()))
    }

    /// Read a native-order `u64` payload.
    pub fn as_u64(&self) -> NlResult<u64> {
        self.check(8, "8 bytes")?;
        Ok(u64::from_ne_bytes(self.data[..8].try_into().unwrap()))
    }

    /// Read a native-order `i32` payload.
    pub fn as_i32(&self) -> NlResult<i32> {
        self.check(4, "4 bytes")?;
        Ok(i32::from_ne_bytes(self.data[..4].try_into().unwrap()))
    }

    /// Read a network-order `u16` payload.
    pub fn as_be16(&self) -> NlResult<u16> {
        self.check(2, "2 bytes")?;
        Ok(u16::from_be_bytes([self.data[0], self.data[1]]))
    }

    /// Read a network-order `u32` payload.
    pub fn as_be32(&self) -> NlResult<u32> {
        self.check(4, "4 bytes")?;
        Ok(u32::from_be_bytes(self.data[..4].try_into().unwrap()))
    }

    /// Read a NUL-terminated string payload. Trailing NUL bytes are removed;
    /// invalid UTF-8 is replaced lossily instead of failing.
    pub fn as_str(&self) -> String {
        let end = self
            .data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len());
        String::from_utf8_lossy(&self.data[..end]).into_owned()
    }
}

/// A parsed attribute list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Attrs {
    list: Vec<NlAttr>,
}

impl Attrs {
    /// Parse a sequence of attributes.
    ///
    /// ```
    /// use linux_ipvs::nl::{Attrs, NlAttr};
    /// let bytes = NlAttr::u32(7, 42).encode();
    /// let attrs = Attrs::parse(&bytes).unwrap();
    /// assert_eq!(attrs.get(7).unwrap().as_u32().unwrap(), 42);
    /// ```
    pub fn parse(bytes: &[u8]) -> NlResult<Self> {
        let mut list = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            if remaining.iter().all(|&b| b == 0) {
                break;
            }
            if remaining.len() < NLA_HDRLEN {
                if remaining.iter().all(|&b| b == 0) {
                    break;
                }
                return Err(Error::TrailingBytes {
                    available: remaining.len(),
                });
            }
            let nla_len = u16::from_ne_bytes([remaining[0], remaining[1]]) as usize;
            if nla_len < NLA_HDRLEN {
                return Err(Error::BadAttributeLength {
                    len: nla_len as u16,
                });
            }
            if nla_len > remaining.len() {
                return Err(Error::Truncated {
                    needed: nla_len,
                    have: remaining.len(),
                });
            }
            let nla_type = u16::from_ne_bytes([remaining[2], remaining[3]]);
            list.push(NlAttr::with_vec(
                nla_type,
                remaining[NLA_HDRLEN..nla_len].to_vec(),
            ));
            let advance = nla_align(nla_len);
            if advance >= remaining.len() {
                break;
            }
            offset += advance;
        }
        Ok(Self { list })
    }

    /// Find the first attribute of `kind`.
    pub fn get(&self, kind: u16) -> Option<&NlAttr> {
        self.list.iter().find(|a| a.kind() == kind)
    }

    /// Iterate over all attributes.
    pub fn iter(&self) -> impl Iterator<Item = &NlAttr> {
        self.list.iter()
    }

    /// Whether no attributes were parsed.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Number of attributes.
    pub fn len(&self) -> usize {
        self.list.len()
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A single decoded netlink message, owning its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlMsg {
    header: NlMsgHeader,
    raw: Vec<u8>,
}

impl NlMsg {
    /// Decode exactly one message from `bytes` (which must not contain a
    /// second message).
    ///
    /// ```
    /// use linux_ipvs::nl::NlMsg;
    /// let mut bytes = vec![20, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
    /// bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    /// let msg = NlMsg::decode(&bytes).unwrap();
    /// assert_eq!(msg.header().nlmsg_type, 2);
    /// assert_eq!(msg.payload().len(), 4);
    /// ```
    pub fn decode(bytes: &[u8]) -> NlResult<Self> {
        let header = NlMsgHeader::decode(bytes)?;
        let len = header.nlmsg_len as usize;
        if len < NLMSG_HDRLEN {
            return Err(Error::BadMessageLength {
                len: header.nlmsg_len,
                available: bytes.len(),
            });
        }
        if len > bytes.len() {
            return Err(Error::Truncated {
                needed: len,
                have: bytes.len(),
            });
        }
        Ok(Self {
            header,
            raw: bytes[..len].to_vec(),
        })
    }

    /// Parse every message in a datagram.
    ///
    /// ```
    /// use linux_ipvs::nl::{NlMsg, NlMsgHeader};
    /// let header = NlMsgHeader {
    ///     nlmsg_len: 16, nlmsg_type: 3, nlmsg_flags: 2, nlmsg_seq: 1, nlmsg_pid: 0,
    /// };
    /// assert_eq!(NlMsg::parse_messages(&header.encode()).unwrap().len(), 1);
    /// ```
    pub fn parse_messages(datagram: &[u8]) -> NlResult<Vec<Self>> {
        let mut messages = Vec::new();
        let mut offset = 0;
        while offset < datagram.len() {
            let remaining = &datagram[offset..];
            if remaining.iter().all(|&b| b == 0) {
                break;
            }
            if remaining.len() < NLMSG_HDRLEN {
                if remaining.iter().all(|&b| b == 0) {
                    break;
                }
                return Err(Error::TrailingBytes {
                    available: remaining.len(),
                });
            }
            let msg = Self::decode(remaining)?;
            let advance = nlmsg_align(msg.header.nlmsg_len as usize);
            messages.push(msg);
            if advance >= remaining.len() {
                break;
            }
            offset += advance;
        }
        Ok(messages)
    }

    /// The decoded header.
    pub fn header(&self) -> NlMsgHeader {
        self.header
    }

    /// The payload after the 16-byte `nlmsghdr`.
    pub fn payload(&self) -> &[u8] {
        &self.raw[NLMSG_HDRLEN..]
    }

    /// The complete message bytes (`nlmsg_len` bytes, without padding).
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The `genlmsghdr` at the start of the payload.
    pub fn genl_header(&self) -> NlResult<GenlMsgHeader> {
        GenlMsgHeader::decode(self.payload())
    }

    /// The generic netlink command of this message.
    pub fn cmd(&self) -> NlResult<u8> {
        Ok(self.genl_header()?.cmd)
    }

    /// Parse the attributes following the `genlmsghdr`.
    pub fn attrs(&self) -> NlResult<Attrs> {
        let payload = self.payload();
        if payload.len() < GENL_HDRLEN {
            return Err(Error::Truncated {
                needed: GENL_HDRLEN,
                have: payload.len(),
            });
        }
        Attrs::parse(&payload[GENL_HDRLEN..])
    }

    /// For a `NLMSG_DONE` message, the embedded error (0 for success).
    /// Returns `None` when the message carries no error field.
    pub fn done_error(&self) -> NlResult<Option<i32>> {
        if self.header.nlmsg_type != NLMSG_DONE {
            return Ok(None);
        }
        let payload = self.payload();
        if payload.len() < 4 {
            return Ok(None);
        }
        Ok(Some(i32::from_ne_bytes(payload[..4].try_into().unwrap())))
    }
}

/// Encode a sequence of attributes into one payload buffer, as expected by
/// a nested attribute or a set of top-level attributes.
///
/// ```
/// use linux_ipvs::nl::{encode_attrs, Attrs, NlAttr};
/// let bytes = encode_attrs(&[NlAttr::u16(1, 7), NlAttr::string(2, "rr")]);
/// let attrs = Attrs::parse(&bytes).unwrap();
/// assert_eq!(attrs.get(1).unwrap().as_u16().unwrap(), 7);
/// ```
pub fn encode_attrs(attrs: &[NlAttr]) -> Vec<u8> {
    let mut out = Vec::new();
    for attr in attrs {
        attr.encode_into(&mut out);
    }
    out
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

/// A generic netlink request under construction.
///
/// ```
/// use linux_ipvs::nl::{NLM_F_REQUEST, Request};
/// let bytes = Request::new(0x10, 3, 2).seq(1).flags(NLM_F_REQUEST).encode();
/// assert_eq!(bytes.len(), 20);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    nlmsg_type: u16,
    nlmsg_flags: u16,
    seq: u32,
    cmd: u8,
    version: u8,
    attrs: Vec<NlAttr>,
}

impl Request {
    /// Start a request with `NLM_F_REQUEST` already set.
    pub fn new(nlmsg_type: u16, cmd: u8, version: u8) -> Self {
        Self {
            nlmsg_type,
            nlmsg_flags: NLM_F_REQUEST,
            seq: 0,
            cmd,
            version,
            attrs: Vec::new(),
        }
    }

    /// Replace the message flags.
    pub fn flags(mut self, flags: u16) -> Self {
        self.nlmsg_flags = flags;
        self
    }

    /// Set the sequence number.
    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    /// Append one attribute.
    pub fn attr(mut self, attr: NlAttr) -> Self {
        self.attrs.push(attr);
        self
    }

    /// Append several attributes.
    pub fn attrs(mut self, attrs: impl IntoIterator<Item = NlAttr>) -> Self {
        self.attrs.extend(attrs);
        self
    }

    /// Encode the complete message (header, `genlmsghdr`, attributes).
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(
            &GenlMsgHeader {
                cmd: self.cmd,
                version: self.version,
                reserved: 0,
            }
            .encode(),
        );
        for attr in &self.attrs {
            attr.encode_into(&mut payload);
        }
        let header = NlMsgHeader {
            nlmsg_len: (NLMSG_HDRLEN + payload.len()) as u32,
            nlmsg_type: self.nlmsg_type,
            nlmsg_flags: self.nlmsg_flags,
            nlmsg_seq: self.seq,
            nlmsg_pid: 0,
        };
        let mut out = header.encode().to_vec();
        out.extend_from_slice(&payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlmsghdr_expected_bytes() {
        let h = NlMsgHeader {
            nlmsg_len: 32,
            nlmsg_type: 0x18,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: 0x0102_0304,
            nlmsg_pid: 0,
        };
        assert_eq!(
            h.encode(),
            [
                0x20, 0, 0, 0, // len = 32
                0x18, 0, // type
                0x05, 0, // flags
                0x04, 0x03, 0x02, 0x01, // seq (native)
                0, 0, 0, 0, // pid
            ]
        );
        assert_eq!(NlMsgHeader::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn genlmsghdr_expected_bytes() {
        let g = GenlMsgHeader {
            cmd: 16,
            version: 1,
            reserved: 0,
        };
        assert_eq!(g.encode(), [16, 1, 0, 0]);
        assert_eq!(GenlMsgHeader::decode(&g.encode()).unwrap(), g);
    }

    #[test]
    fn attr_padding_expected_bytes() {
        let a = NlAttr::u8(1, 0xaa);
        assert_eq!(a.encode(), [0x05, 0x00, 0x01, 0x00, 0xaa, 0x00, 0x00, 0x00]);
        let b = NlAttr::u32(2, 0x1122_3344);
        assert_eq!(b.encode(), [0x08, 0x00, 0x02, 0x00, 0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn nested_flag_is_set_but_not_required_when_parsing() {
        let inner = NlAttr::u16(1, 2).encode();
        let outer = NlAttr::nested(7, &inner);
        assert_eq!(outer.raw_type(), 7 | NLA_F_NESTED);
        assert_eq!(outer.kind(), 7);
        let parsed = Attrs::parse(&outer.encode()).unwrap();
        let inner_attrs = Attrs::parse(parsed.get(7).unwrap().payload()).unwrap();
        assert_eq!(inner_attrs.get(1).unwrap().as_u16().unwrap(), 2);

        // The kernel's nla_nest_start_noflag() omits the flag; parsing is
        // unchanged.
        let unflagged = NlAttr::new(7, &inner);
        let parsed = Attrs::parse(&unflagged.encode()).unwrap();
        let inner_attrs = Attrs::parse(parsed.get(7).unwrap().payload()).unwrap();
        assert_eq!(inner_attrs.get(1).unwrap().as_u16().unwrap(), 2);
    }

    #[test]
    fn parse_attrs_rejects_bad_lengths() {
        assert_eq!(
            Attrs::parse(&[0x03, 0x00, 0x00, 0x00]).unwrap_err(),
            Error::BadAttributeLength { len: 3 }
        );
        assert_eq!(
            Attrs::parse(&[0x08, 0x00, 0x01, 0x00, 0x00]).unwrap_err(),
            Error::Truncated { needed: 8, have: 5 }
        );
    }

    #[test]
    fn parse_attrs_accepts_missing_final_padding() {
        // nla_len 5 with exactly 5 bytes available: padding omitted.
        let attrs = Attrs::parse(&[0x05, 0x00, 0x01, 0x00, 0xaa]).unwrap();
        assert_eq!(attrs.get(1).unwrap().as_u8().unwrap(), 0xaa);
    }

    #[test]
    fn parse_messages_multipart() {
        let a = NlMsgHeader {
            nlmsg_len: 20,
            nlmsg_type: 0x18,
            nlmsg_flags: NLM_F_MULTI,
            nlmsg_seq: 9,
            nlmsg_pid: 0,
        }
        .encode()
        .to_vec();
        let mut first = a.clone();
        first.extend_from_slice(&[1, 2, 3, 4]);
        let second = NlMsgHeader {
            nlmsg_len: NLMSG_HDRLEN as u32,
            nlmsg_type: 0x18,
            nlmsg_flags: NLM_F_MULTI,
            nlmsg_seq: 9,
            nlmsg_pid: 0,
        };

        let mut datagram = first.clone();
        datagram.extend_from_slice(&second.encode());
        let msgs = NlMsg::parse_messages(&datagram).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].payload(), &[1, 2, 3, 4]);
        assert_eq!(msgs[0].header().nlmsg_seq, 9);
        assert_eq!(msgs[1].header().nlmsg_len, 16);
    }

    #[test]
    fn parse_messages_rejects_truncated_message() {
        let mut bytes = NlMsgHeader {
            nlmsg_len: 20,
            nlmsg_type: 0x18,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        }
        .encode()
        .to_vec();
        bytes.extend_from_slice(&[0, 0]);
        assert_eq!(
            NlMsg::parse_messages(&bytes).unwrap_err(),
            Error::Truncated {
                needed: 20,
                have: 18
            }
        );
    }

    #[test]
    fn getfamily_request_expected_bytes() {
        let bytes = Request::new(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_GENL_VERSION)
            .seq(1)
            .attr(NlAttr::string(CTRL_ATTR_FAMILY_NAME, "IPVS"))
            .encode();
        assert_eq!(
            bytes,
            [
                0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32
                0x10, 0x00, // nlmsg_type = GENL_ID_CTRL
                0x01, 0x00, // NLM_F_REQUEST
                0x01, 0x00, 0x00, 0x00, // seq = 1
                0x00, 0x00, 0x00, 0x00, // pid
                0x03, 0x02, 0x00, 0x00, // cmd = GETFAMILY, version = 2
                0x09, 0x00, 0x02, 0x00, // attr: len 9, type 2
                b'I', b'P', b'V', b'S', 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn request_round_trips_attributes() {
        let bytes = Request::new(0x18, 1, 1)
            .flags(NLM_F_REQUEST | NLM_F_ACK)
            .seq(7)
            .attr(NlAttr::u16(1, 2))
            .attr(NlAttr::string(6, "rr"))
            .encode();
        let msg = NlMsg::decode(&bytes).unwrap();
        assert_eq!(msg.header().nlmsg_seq, 7);
        assert_eq!(msg.header().nlmsg_flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(msg.cmd().unwrap(), 1);
        let attrs = msg.attrs().unwrap();
        assert_eq!(attrs.get(1).unwrap().as_u16().unwrap(), 2);
        assert_eq!(attrs.get(6).unwrap().as_str(), "rr");
    }

    #[test]
    fn string_accessor_strips_nul_and_tolerates_missing_nul() {
        assert_eq!(NlAttr::new(1, b"IPVS\0").as_str(), "IPVS");
        assert_eq!(NlAttr::new(1, b"IPVS").as_str(), "IPVS");
        assert_eq!(NlAttr::new(1, b"IP\0VS").as_str(), "IP");
    }

    #[test]
    fn done_error_is_parsed() {
        let mut bytes = NlMsgHeader {
            nlmsg_len: 20,
            nlmsg_type: NLMSG_DONE,
            nlmsg_flags: NLM_F_MULTI,
            nlmsg_seq: 3,
            nlmsg_pid: 0,
        }
        .encode()
        .to_vec();
        bytes.extend_from_slice(&0i32.to_ne_bytes());
        let msg = NlMsg::decode(&bytes).unwrap();
        assert_eq!(msg.done_error().unwrap(), Some(0));
    }

    #[test]
    fn encode_attrs_matches_individual_encoding() {
        let attrs = [NlAttr::u32(1, 2), NlAttr::string(3, "rr")];
        let mut expected = Vec::new();
        for attr in &attrs {
            expected.extend_from_slice(&attr.encode());
        }
        assert_eq!(encode_attrs(&attrs), expected);
    }

    #[test]
    fn trailing_zero_padding_is_tolerated() {
        let attr = NlAttr::u32(1, 1).encode();
        let mut padded = attr.clone();
        padded.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Attrs::parse(&padded).unwrap().len(), 1);
    }
}
