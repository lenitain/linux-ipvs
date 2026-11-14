//! Transport, family resolution, and the IPVS request/reply state machine.
//!
//! [`Ipvs`] owns a [`NetlinkTransport`] (the real socket with the `std`
//! feature, an injected double in tests) and the resolved `"IPVS"` family
//! id. Requests are matched by sequence number; multipart dumps are
//! collected until `NLMSG_DONE`, with per-message degradation into
//! [`Dump::rejected`] so a single malformed entry never discards the rest.

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Write as _;
use std::io;
use std::os::fd::BorrowedFd;
#[cfg(feature = "std")]
use std::os::fd::{AsFd, AsRawFd, FromRawFd};

use crate::error::{Error, KernelError, Result};
use crate::nl::{self, Attrs, NlAttr, NlMsg, Request};
use crate::proto;

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The send/receive boundary of the IPVS control plane.
///
/// [`NetlinkSocket`] implements it for real kernels; tests (and callers with
/// their own transport) implement it directly. `recv` replaces the contents
/// of the buffer with exactly one netlink datagram and returns its length;
/// zero length means end of file.
pub trait NetlinkTransport {
    /// Send one complete netlink message.
    fn send(&mut self, message: &[u8]) -> io::Result<()>;

    /// Receive one datagram, replacing `datagram`.
    fn recv(&mut self, datagram: &mut Vec<u8>) -> io::Result<usize>;

    /// The underlying file descriptor, when this transport has one. This is
    /// the escape hatch for socket options (for example `SO_RCVTIMEO`) and
    /// for integrating the socket into an external event loop.
    fn as_fd(&self) -> Option<BorrowedFd<'_>> {
        None
    }
}

/// The real `NETLINK_GENERIC` transport (feature `std`).
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct NetlinkSocket {
    fd: std::os::fd::OwnedFd,
}

#[cfg(feature = "std")]
impl NetlinkSocket {
    /// Open `socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC)`
    /// and enable extended acknowledgements (`NETLINK_EXT_ACK`) on a
    /// best-effort basis.
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::NetlinkSocket;
    /// let socket = NetlinkSocket::open().expect("open a generic netlink socket");
    /// let _fd = socket.as_fd();
    /// # }
    /// ```
    pub fn open() -> io::Result<Self> {
        // SAFETY: plain syscalls with valid arguments; the returned fd is
        // owned by the `OwnedFd` wrapper.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                nl::NETLINK_GENERIC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly opened fd that nobody else owns.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };

        // `SOL_NETLINK` and `NETLINK_EXT_ACK` are stable kernel ABI but are
        // not present in every libc release.
        const SOL_NETLINK: libc::c_int = 270;
        const NETLINK_EXT_ACK: libc::c_int = 11;
        let enable: libc::c_int = 1;
        // SAFETY: pointer to a live `c_int` with the matching length. Failure
        // only means no extended acknowledgement text; the socket still
        // works, so the result is deliberately ignored.
        unsafe {
            libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                SOL_NETLINK,
                NETLINK_EXT_ACK,
                std::ptr::from_ref(&enable).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        Ok(Self { fd })
    }

    /// Borrow the raw fd (escape hatch).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::NetlinkSocket;
    /// let socket = NetlinkSocket::open().expect("open a generic netlink socket");
    /// let _fd = socket.as_fd();
    /// # }
    /// ```
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(feature = "std")]
impl NetlinkTransport for NetlinkSocket {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        // `sockaddr_nl`'s padding field is private in some libc releases;
        // build the all-zero address and fill in the family.
        // SAFETY: `sockaddr_nl` is plain old data.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        loop {
            // SAFETY: the message slice and the sockaddr are valid for the
            // duration of the call; the kernel copies them.
            let sent = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    message.as_ptr().cast(),
                    message.len(),
                    0,
                    std::ptr::from_ref(&addr).cast(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if sent as usize != message.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short netlink send",
                ));
            }
            return Ok(());
        }
    }

    fn recv(&mut self, datagram: &mut Vec<u8>) -> io::Result<usize> {
        // `MSG_PEEK | MSG_TRUNC` reports the real size without consuming the
        // datagram, so a too-small buffer is grown instead of silently
        // truncating messages.
        let mut capacity = datagram.capacity().max(64 * 1024);
        loop {
            datagram.resize(capacity, 0);
            // SAFETY: the buffer is writable for `capacity` bytes.
            let peeked = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    datagram.as_mut_ptr().cast(),
                    capacity,
                    libc::MSG_PEEK | libc::MSG_TRUNC,
                )
            };
            if peeked < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let len = peeked as usize;
            if len > capacity {
                capacity = len;
                continue;
            }
            // SAFETY: same buffer, now known to fit the whole datagram.
            let received = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    datagram.as_mut_ptr().cast(),
                    capacity,
                    0,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            datagram.truncate(received as usize);
            return Ok(received as usize);
        }
    }

    fn as_fd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }
}

// ---------------------------------------------------------------------------
// Dump results
// ---------------------------------------------------------------------------

/// A message that arrived during a dump but could not be decoded.
///
/// The raw bytes are kept so no information is lost; `error` explains why
/// the message was rejected.
pub struct Rejected {
    /// Generic netlink command, or 0 when the message was too broken to
    /// expose one.
    pub cmd: u8,
    /// The undecoded message bytes (or the malformed remainder of a
    /// datagram).
    pub raw: Vec<u8>,
    /// Why decoding failed.
    pub error: Error,
}

impl fmt::Debug for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rejected")
            .field("cmd", &self.cmd)
            .field("raw", &hex(&self.raw))
            .field("error", &self.error)
            .finish()
    }
}

impl Rejected {
    pub(crate) fn from_message(message: &NlMsg, error: Error) -> Self {
        Self {
            cmd: message.cmd().unwrap_or(0),
            raw: message.raw().to_vec(),
            error,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The result of a multipart dump.
///
/// A malformed message never fails the whole dump: it lands in
/// [`Dump::rejected`] with its raw bytes. The kernel's `NLM_F_DUMP_INTR`
/// flag is surfaced as [`Dump::interrupted`] instead of being silently
/// dropped, so callers can decide whether to retry.
pub struct Dump<T> {
    /// Successfully decoded entries.
    pub entries: Vec<T>,
    /// Messages that could not be decoded, with their raw bytes.
    pub rejected: Vec<Rejected>,
    /// `true` when the kernel flagged the dump as inconsistent
    /// (`NLM_F_DUMP_INTR`, for example because a hash table resized).
    pub interrupted: bool,
}

impl<T> Dump<T> {
    /// An empty, complete dump.
    ///
    /// ```
    /// use linux_ipvs::Dump;
    /// let dump: Dump<u8> = Dump::new();
    /// assert!(dump.is_empty());
    /// assert_eq!(dump.len(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            rejected: Vec::new(),
            interrupted: false,
        }
    }

    /// Whether no entries were decoded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of decoded entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<T> Default for Dump<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for Dump<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dump")
            .field("entries", &self.entries)
            .field("rejected", &self.rejected)
            .field("interrupted", &self.interrupted)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Request / reply machinery
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Expect a `NLMSG_ERROR` acknowledgement with errno 0.
    Ack,
    /// Expect exactly one data message.
    Single,
    /// Collect `NLM_F_MULTI` messages until `NLMSG_DONE`.
    Dump,
}

pub(crate) struct Replies {
    pub(crate) messages: Vec<NlMsg>,
    pub(crate) rejected: Vec<Rejected>,
    pub(crate) interrupted: bool,
}

enum Event {
    Message(NlMsg),
    Rejected(Rejected),
}

/// The kernel's `struct nlmsgerr` payload, including any extended-ack
/// attributes.
fn kernel_error(message: &NlMsg) -> Result<KernelError> {
    let payload = message.payload();
    if payload.len() < 4 {
        return Err(nl::Error::Truncated {
            needed: 4,
            have: payload.len(),
        }
        .into());
    }
    let raw = i32::from_ne_bytes(payload[..4].try_into().unwrap());
    let errno = if raw < 0 { raw.wrapping_neg() } else { raw };

    let mut error = KernelError {
        errno,
        message: None,
        offset: None,
        extack: Vec::new(),
    };
    // `struct nlmsgerr` is 4 bytes of errno plus the echoed 16-byte header.
    // Extended-ack attributes follow it (we never set NETLINK_CAP_ACK).
    if payload.len() >= nl::NLMSG_HDRLEN + 4 {
        let attrs = Attrs::parse(&payload[nl::NLMSG_HDRLEN + 4..])?;
        for attr in attrs.iter() {
            match attr.kind() {
                nl::NLMSGERR_ATTR_MSG => error.message = Some(attr.as_str()),
                nl::NLMSGERR_ATTR_OFFS => error.offset = attr.as_u32().ok(),
                kind => error.extack.push(nl::RawAttr {
                    kind,
                    data: attr.payload().to_vec(),
                }),
            }
        }
    }
    Ok(error)
}

// ---------------------------------------------------------------------------
// Ipvs
// ---------------------------------------------------------------------------

/// A client for the Linux IPVS generic netlink family.
///
/// Construction opens a socket (feature `std`) or wraps an injected
/// [`NetlinkTransport`], then resolves the `"IPVS"` family id with
/// `CTRL_CMD_GETFAMILY`. The family id is cached for the lifetime of the
/// socket; IPVS state lives in the kernel, so this type performs no caching
/// of services and destinations.
///
/// ```no_run
/// # #[cfg(feature = "std")]
/// # {
/// use linux_ipvs::Ipvs;
///
/// // Requires CAP_NET_ADMIN and a kernel with the ip_vs module.
/// let mut ipvs = Ipvs::new().expect("open the IPVS control plane");
/// println!("IPVS version {:#x}", ipvs.info().unwrap().version);
/// # }
/// ```
pub struct Ipvs {
    transport: Box<dyn NetlinkTransport>,
    family_id: u16,
    seq: u32,
    inbox: VecDeque<Event>,
    pending: VecDeque<NlMsg>,
    scratch: Vec<u8>,
}

impl Ipvs {
    /// Open a `NETLINK_GENERIC` socket and resolve the `"IPVS"` family
    /// (feature `std`).
    ///
    /// Fails with [`Error::FamilyNotFound`] when the kernel has no IPVS
    /// family registered (module not loaded or `CONFIG_IP_VS` disabled).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// # let _ = &mut ipvs;
    /// # }
    /// ```
    #[cfg(feature = "std")]
    pub fn new() -> Result<Self> {
        Self::with_transport(Box::new(NetlinkSocket::open()?))
    }

    /// Resolve the family over an already-open [`NetlinkSocket`]
    /// (feature `std`).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::{Ipvs, NetlinkSocket};
    /// let socket = NetlinkSocket::open().unwrap();
    /// let mut ipvs = Ipvs::new_with_sock(socket).unwrap();
    /// # let _ = &mut ipvs;
    /// # }
    /// ```
    #[cfg(feature = "std")]
    pub fn new_with_sock(socket: NetlinkSocket) -> Result<Self> {
        Self::with_transport(Box::new(socket))
    }

    /// Resolve the family over an injected transport.
    ///
    /// This is the injection point used by tests and by callers that bring
    /// their own transport.
    ///
    /// ```
    /// use std::io;
    /// use linux_ipvs::nl::{self, GenlMsgHeader, NlAttr, NlMsgHeader};
    /// use linux_ipvs::{Ipvs, NetlinkTransport};
    ///
    /// /// Answers GETFAMILY with family id 0x18.
    /// struct Scripted;
    /// impl NetlinkTransport for Scripted {
    ///     fn send(&mut self, _message: &[u8]) -> io::Result<()> { Ok(()) }
    ///     fn recv(&mut self, datagram: &mut Vec<u8>) -> io::Result<usize> {
    ///         let mut payload = GenlMsgHeader {
    ///             cmd: nl::CTRL_CMD_NEWFAMILY, version: nl::CTRL_GENL_VERSION, reserved: 0,
    ///         }.encode().to_vec();
    ///         payload.extend_from_slice(&NlAttr::u16(nl::CTRL_ATTR_FAMILY_ID, 0x18).encode());
    ///         let header = NlMsgHeader {
    ///             nlmsg_len: (nl::NLMSG_HDRLEN + payload.len()) as u32,
    ///             nlmsg_type: nl::GENL_ID_CTRL, nlmsg_flags: 0,
    ///             nlmsg_seq: 1, nlmsg_pid: 0,
    ///         };
    ///         datagram.clear();
    ///         datagram.extend_from_slice(&header.encode());
    ///         datagram.extend_from_slice(&payload);
    ///         Ok(datagram.len())
    ///     }
    /// }
    ///
    /// let ipvs = Ipvs::with_transport(Box::new(Scripted)).unwrap();
    /// assert_eq!(ipvs.family_id(), 0x18);
    /// ```
    pub fn with_transport(transport: Box<dyn NetlinkTransport>) -> Result<Self> {
        let mut this = Self {
            transport,
            family_id: 0,
            seq: 0,
            inbox: VecDeque::new(),
            pending: VecDeque::new(),
            scratch: Vec::new(),
        };
        this.resolve_family()?;
        Ok(this)
    }

    /// The resolved generic netlink family id.
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let ipvs = Ipvs::new().unwrap();
    /// println!("IPVS family id {}", ipvs.family_id());
    /// # }
    /// ```
    pub fn family_id(&self) -> u16 {
        self.family_id
    }

    /// Borrow the underlying fd, when the transport has one (escape hatch
    /// for socket options and external event loops).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let ipvs = Ipvs::new().unwrap();
    /// let _fd = ipvs.as_fd();
    /// # }
    /// ```
    pub fn as_fd(&self) -> Option<BorrowedFd<'_>> {
        self.transport.as_fd()
    }

    /// Send raw netlink bytes without sequence tracking (escape hatch).
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// use linux_ipvs::nl::Request;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let request = Request::new(ipvs.family_id(), 15, 1).seq(1).encode();
    /// ipvs.send_raw(&request).unwrap();
    /// let _reply = ipvs.recv_raw().unwrap();
    /// # }
    /// ```
    pub fn send_raw(&mut self, message: &[u8]) -> Result<()> {
        self.transport.send(message)?;
        Ok(())
    }

    /// Receive one raw netlink message (escape hatch). Messages queued by a
    /// previous request whose sequence number did not match are returned
    /// first; a datagram that could not be split into messages is returned
    /// as its raw bytes.
    ///
    /// ```no_run
    /// # #[cfg(feature = "std")]
    /// # {
    /// use linux_ipvs::Ipvs;
    /// let mut ipvs = Ipvs::new().unwrap();
    /// let message = ipvs.recv_raw().unwrap();
    /// println!("{} raw bytes", message.len());
    /// # }
    /// ```
    pub fn recv_raw(&mut self) -> Result<Vec<u8>> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(message.raw().to_vec());
        }
        match self.poll()? {
            Event::Message(message) => Ok(message.raw().to_vec()),
            Event::Rejected(rejected) => Ok(rejected.raw),
        }
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        self.seq
    }

    fn resolve_family(&mut self) -> Result<()> {
        let seq = self.next_seq();
        let request = Request::new(
            nl::GENL_ID_CTRL,
            nl::CTRL_CMD_GETFAMILY,
            nl::CTRL_GENL_VERSION,
        )
        .seq(seq)
        .attr(NlAttr::string(
            nl::CTRL_ATTR_FAMILY_NAME,
            proto::FAMILY_NAME,
        ))
        .encode();
        self.transport.send(&request)?;

        loop {
            match self.poll()? {
                Event::Message(message) => {
                    if message.header().nlmsg_seq != seq {
                        self.pending.push_back(message);
                        continue;
                    }
                    if message.header().nlmsg_type == nl::NLMSG_ERROR {
                        let error = kernel_error(&message)?;
                        if error.is_not_found() {
                            return Err(Error::FamilyNotFound);
                        }
                        return Err(Error::Kernel(error));
                    }
                    let attrs = message.attrs()?;
                    let id = attrs
                        .get(nl::CTRL_ATTR_FAMILY_ID)
                        .ok_or(Error::MissingAttribute {
                            name: "CTRL_ATTR_FAMILY_ID",
                        })?;
                    self.family_id = id.as_u16()?;
                    return Ok(());
                }
                Event::Rejected(rejected) => return Err(rejected.error),
            }
        }
    }

    /// Feed a datagram into the inbox, degrading unparsable remainders
    /// instead of discarding earlier messages.
    fn ingest(&mut self, datagram: &[u8]) {
        let mut offset = 0;
        while offset < datagram.len() {
            let remaining = &datagram[offset..];
            if remaining.len() < nl::NLMSG_HDRLEN {
                if remaining.iter().any(|&b| b != 0) {
                    self.inbox.push_back(Event::Rejected(Rejected {
                        cmd: 0,
                        raw: remaining.to_vec(),
                        error: nl::Error::TrailingBytes {
                            available: remaining.len(),
                        }
                        .into(),
                    }));
                }
                return;
            }
            match NlMsg::decode(remaining) {
                Ok(message) => {
                    let advance = nl::nlmsg_align(message.header().nlmsg_len as usize);
                    self.inbox.push_back(Event::Message(message));
                    if advance >= remaining.len() {
                        return;
                    }
                    offset += advance;
                }
                Err(error) => {
                    self.inbox.push_back(Event::Rejected(Rejected {
                        cmd: 0,
                        raw: remaining.to_vec(),
                        error: error.into(),
                    }));
                    return;
                }
            }
        }
    }

    fn poll(&mut self) -> Result<Event> {
        loop {
            if let Some(event) = self.inbox.pop_front() {
                return Ok(event);
            }
            let mut datagram = std::mem::take(&mut self.scratch);
            datagram.clear();
            let received = self.transport.recv(&mut datagram)?;
            if received == 0 {
                self.scratch = datagram;
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            datagram.truncate(received);
            self.ingest(&datagram);
            self.scratch = datagram;
        }
    }

    fn transact(
        &mut self,
        family: u16,
        version: u8,
        cmd: u8,
        attrs: Vec<NlAttr>,
        mode: Mode,
    ) -> Result<Replies> {
        let seq = self.next_seq();
        let flags = match mode {
            Mode::Ack => nl::NLM_F_REQUEST | nl::NLM_F_ACK,
            Mode::Single => nl::NLM_F_REQUEST,
            Mode::Dump => nl::NLM_F_REQUEST | nl::NLM_F_DUMP,
        };
        let request = Request::new(family, cmd, version)
            .flags(flags)
            .seq(seq)
            .attrs(attrs)
            .encode();
        self.transport.send(&request)?;

        let mut replies = Replies {
            messages: Vec::new(),
            rejected: Vec::new(),
            interrupted: false,
        };
        loop {
            match self.poll()? {
                Event::Rejected(rejected) => {
                    if mode == Mode::Dump {
                        replies.rejected.push(rejected);
                    } else {
                        return Err(rejected.error);
                    }
                }
                Event::Message(message) => {
                    if message.header().nlmsg_seq != seq {
                        self.pending.push_back(message);
                        continue;
                    }
                    match message.header().nlmsg_type {
                        nl::NLMSG_ERROR => {
                            let error = kernel_error(&message)?;
                            if error.errno != 0 {
                                return Err(Error::Kernel(error));
                            }
                            if mode == Mode::Ack {
                                return Ok(replies);
                            }
                            // A stray success ack for a getter: keep waiting.
                        }
                        nl::NLMSG_DONE => {
                            if let Some(code) = message.done_error()? {
                                if code != 0 {
                                    return Err(Error::Kernel(KernelError {
                                        errno: code.checked_neg().unwrap_or(i32::MAX),
                                        message: None,
                                        offset: None,
                                        extack: Vec::new(),
                                    }));
                                }
                            }
                            replies.interrupted =
                                message.header().nlmsg_flags & nl::NLM_F_DUMP_INTR != 0;
                            if mode != Mode::Dump {
                                return Err(Error::unexpected("a data reply", &message));
                            }
                            return Ok(replies);
                        }
                        _ => match mode {
                            Mode::Ack => {
                                return Err(Error::unexpected("an acknowledgement", &message));
                            }
                            Mode::Single => {
                                replies.messages.push(message);
                                return Ok(replies);
                            }
                            Mode::Dump => replies.messages.push(message),
                        },
                    }
                }
            }
        }
    }

    pub(crate) fn ack(&mut self, cmd: u8, attrs: Vec<NlAttr>) -> Result<()> {
        self.transact(self.family_id, proto::FAMILY_VERSION, cmd, attrs, Mode::Ack)?;
        Ok(())
    }

    pub(crate) fn single(&mut self, cmd: u8, attrs: Vec<NlAttr>) -> Result<NlMsg> {
        let replies = self.transact(
            self.family_id,
            proto::FAMILY_VERSION,
            cmd,
            attrs,
            Mode::Single,
        )?;
        replies
            .messages
            .into_iter()
            .next()
            .ok_or(Error::UnexpectedReply {
                expected: "a data reply",
                nlmsg_type: nl::NLMSG_DONE,
                cmd: None,
            })
    }

    pub(crate) fn dump(&mut self, cmd: u8, attrs: Vec<NlAttr>) -> Result<Replies> {
        self.transact(
            self.family_id,
            proto::FAMILY_VERSION,
            cmd,
            attrs,
            Mode::Dump,
        )
    }
}

impl fmt::Debug for Ipvs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipvs")
            .field("family_id", &self.family_id)
            .field("seq", &self.seq)
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}
