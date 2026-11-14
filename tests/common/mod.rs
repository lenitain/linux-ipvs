#![allow(dead_code)]

//! Scripted, injectable netlink transport shared by the integration tests.
//!
//! The mock answers `CTRL_CMD_GETFAMILY` automatically (family id `0x18`),
//! replays one scripted set of datagrams per IPVS request, and patches the
//! requested sequence number into every scripted message unless the script
//! is explicitly raw.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::rc::Rc;

use linux_ipvs::nl::{self, GenlMsgHeader, NlAttr, NlMsg, NlMsgHeader};
use linux_ipvs::{Ipvs, NetlinkTransport};

/// Family id reported for the `"IPVS"` family.
pub const FAMILY_ID: u16 = 0x18;

struct Script {
    datagrams: Vec<Vec<u8>>,
    patch_seq: bool,
}

/// Observable state of the mock transport.
#[derive(Default)]
pub struct MockState {
    /// Every message passed to `send`, in order (including `GETFAMILY`).
    pub sent: Vec<Vec<u8>>,
    /// When set, `CTRL_CMD_GETFAMILY` is answered with this errno instead of
    /// the family description.
    pub family_error: Option<i32>,
    scripts: VecDeque<Script>,
    replies: VecDeque<Vec<u8>>,
}

impl MockState {
    /// Script one datagram containing `messages`, answered to the next
    /// non-controller request. Sequence numbers are patched in.
    pub fn script(&mut self, messages: impl IntoIterator<Item = Vec<u8>>) {
        let datagram = messages.into_iter().flatten().collect();
        self.scripts.push_back(Script {
            datagrams: vec![datagram],
            patch_seq: true,
        });
    }

    /// Script several datagrams (each may contain several messages).
    pub fn script_datagrams(&mut self, datagrams: impl IntoIterator<Item = Vec<u8>>) {
        self.scripts.push_back(Script {
            datagrams: datagrams.into_iter().collect(),
            patch_seq: true,
        });
    }

    /// Put a datagram into the receive queue immediately, without touching
    /// its sequence numbers.
    pub fn push_raw(&mut self, datagram: Vec<u8>) {
        self.replies.push_back(datagram);
    }

    /// Queue a datagram immediately, patching `seq` into its messages.
    pub fn push_for(&mut self, mut datagram: Vec<u8>, seq: u32) {
        patch_seq(&mut datagram, seq);
        self.replies.push_back(datagram);
    }
}

/// Scripted transport handed to [`Ipvs::with_transport`].
pub struct Mock {
    state: Rc<RefCell<MockState>>,
}

impl Mock {
    /// Create the transport together with its observable state.
    pub fn new() -> (Self, Rc<RefCell<MockState>>) {
        let state = Rc::new(RefCell::new(MockState::default()));
        (
            Self {
                state: Rc::clone(&state),
            },
            state,
        )
    }
}

/// Build an `Ipvs` over the mock transport.
pub fn connect() -> (Ipvs, Rc<RefCell<MockState>>) {
    let (mock, state) = Mock::new();
    let ipvs = Ipvs::with_transport(Box::new(mock)).expect("resolve the scripted IPVS family");
    (ipvs, state)
}

impl NetlinkTransport for Mock {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.sent.push(message.to_vec());
        let Ok(decoded) = NlMsg::decode(message) else {
            // The raw escape hatch is allowed to send arbitrary bytes.
            return Ok(());
        };
        let seq = decoded.header().nlmsg_seq;

        if decoded.header().nlmsg_type == nl::GENL_ID_CTRL {
            match state.family_error {
                Some(errno) => {
                    let mut datagram = error(errno);
                    patch_seq(&mut datagram, seq);
                    state.replies.push_back(datagram);
                }
                None => state.replies.push_back(family_reply(seq)),
            }
            return Ok(());
        }

        if let Some(script) = state.scripts.pop_front() {
            for mut datagram in script.datagrams {
                if script.patch_seq {
                    patch_seq(&mut datagram, seq);
                }
                state.replies.push_back(datagram);
            }
        }
        Ok(())
    }

    fn recv(&mut self, datagram: &mut Vec<u8>) -> io::Result<usize> {
        match self.state.borrow_mut().replies.pop_front() {
            Some(reply) => {
                *datagram = reply;
                Ok(datagram.len())
            }
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

fn patch_seq(datagram: &mut [u8], seq: u32) {
    let mut offset = 0;
    while offset + nl::NLMSG_HDRLEN <= datagram.len() {
        let len = u32::from_ne_bytes(datagram[offset..offset + 4].try_into().unwrap()) as usize;
        if len < nl::NLMSG_HDRLEN || offset + len > datagram.len() {
            break;
        }
        datagram[offset + 8..offset + 12].copy_from_slice(&seq.to_ne_bytes());
        let advance = nl::nlmsg_align(len);
        offset += advance;
    }
}

/// A generic netlink message with the given type, flags, command and
/// attributes.
pub fn genl_message(nlmsg_type: u16, flags: u16, seq: u32, cmd: u8, attrs: &[NlAttr]) -> Vec<u8> {
    let mut payload = GenlMsgHeader {
        cmd,
        version: 1,
        reserved: 0,
    }
    .encode()
    .to_vec();
    payload.extend_from_slice(&nl::encode_attrs(attrs));
    nlmsg(nlmsg_type, flags, seq, payload)
}

fn nlmsg(nlmsg_type: u16, flags: u16, seq: u32, payload: Vec<u8>) -> Vec<u8> {
    let header = NlMsgHeader {
        nlmsg_len: (nl::NLMSG_HDRLEN + payload.len()) as u32,
        nlmsg_type,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };
    let mut out = header.encode().to_vec();
    out.extend_from_slice(&payload);
    out
}

/// Concatenate messages into one datagram.
pub fn concat(messages: &[Vec<u8>]) -> Vec<u8> {
    messages.iter().flatten().copied().collect()
}

/// A single (non-multipart) IPVS reply.
pub fn reply(cmd: u8, attrs: &[NlAttr]) -> Vec<u8> {
    genl_message(FAMILY_ID, 0, 0, cmd, attrs)
}

/// One message of a multipart dump.
pub fn dump_message(cmd: u8, attrs: &[NlAttr]) -> Vec<u8> {
    genl_message(FAMILY_ID, nl::NLM_F_MULTI, 0, cmd, attrs)
}

/// The `NLMSG_DONE` terminator of a dump.
pub fn done(extra_flags: u16) -> Vec<u8> {
    nlmsg(
        nl::NLMSG_DONE,
        nl::NLM_F_MULTI | extra_flags,
        0,
        0i32.to_ne_bytes().to_vec(),
    )
}

/// An `NLMSG_DONE` carrying a negative errno (a dump that failed midway).
pub fn done_error(errno: i32) -> Vec<u8> {
    nlmsg(
        nl::NLMSG_DONE,
        nl::NLM_F_MULTI,
        0,
        (-errno).to_ne_bytes().to_vec(),
    )
}

fn family_reply(seq: u32) -> Vec<u8> {
    genl_message(
        nl::GENL_ID_CTRL,
        0,
        seq,
        nl::CTRL_CMD_NEWFAMILY,
        &[
            NlAttr::u16(nl::CTRL_ATTR_FAMILY_ID, FAMILY_ID),
            NlAttr::string(nl::CTRL_ATTR_FAMILY_NAME, "IPVS"),
            NlAttr::u32(nl::CTRL_ATTR_VERSION, 1),
        ],
    )
}

fn error_message(code: i32, extack: &[NlAttr]) -> Vec<u8> {
    let mut payload = code.to_ne_bytes().to_vec();
    payload.extend_from_slice(&[0u8; nl::NLMSG_HDRLEN]);
    payload.extend_from_slice(&nl::encode_attrs(extack));
    nlmsg(nl::NLMSG_ERROR, 0, 0, payload)
}

/// A success acknowledgement (`NLMSG_ERROR` with errno 0).
pub fn ack() -> Vec<u8> {
    error_message(0, &[])
}

/// An error acknowledgement for `errno` (positive).
pub fn error(errno: i32) -> Vec<u8> {
    error_message(-errno, &[])
}

/// An error acknowledgement carrying extended-ack message and offset.
pub fn error_with_extack(errno: i32, message: &str, offset: u32) -> Vec<u8> {
    error_message(
        -errno,
        &[
            NlAttr::string(nl::NLMSGERR_ATTR_MSG, message),
            NlAttr::u32(nl::NLMSGERR_ATTR_OFFS, offset),
        ],
    )
}
