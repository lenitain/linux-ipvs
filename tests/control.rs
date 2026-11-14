//! Command behaviour against a scripted kernel: replies, errors, dumps,
//! degradation and the raw escape hatches.

mod common;

use std::net::Ipv4Addr;

use linux_ipvs::nl::{self, NlAttr, NlMsg, RawAttr};
use linux_ipvs::proto::{self, Protocol};
use linux_ipvs::{
    DaemonState, DestId, Error, ForwardMethod, Ipvs, Netmask, ServiceFlags, ServiceId, ServiceSpec,
    TunnelFlags, TunnelType,
};

fn flags_payload(flags: u32) -> Vec<u8> {
    let mut bytes = flags.to_ne_bytes().to_vec();
    bytes.extend_from_slice(&u32::MAX.to_ne_bytes());
    bytes
}

/// Simulates `nla_put_u64_64bit`: a zero-length `PAD` attribute before every
/// 64-bit value whose offset needs 8-byte alignment.
fn stats64_attr(kind: u16) -> NlAttr {
    let mut payload = Vec::new();
    for field in 1u16..=10 {
        if field >= 4 {
            NlAttr::new(proto::STATS_ATTR_PAD, b"").encode_into(&mut payload);
        }
        NlAttr::u64(field, u64::from(field)).encode_into(&mut payload);
    }
    NlAttr::new(kind, payload)
}

/// The kernel's 32-bit stats container: u32 counters and rates, u64 bytes.
fn stats32_attr(kind: u16) -> NlAttr {
    let mut payload = Vec::new();
    for field in 1u16..=10 {
        if matches!(field, 4 | 5) {
            NlAttr::new(proto::STATS_ATTR_PAD, b"").encode_into(&mut payload);
            NlAttr::u64(field, 1000 + u64::from(field)).encode_into(&mut payload);
        } else {
            NlAttr::u32(field, u32::from(field) + 100).encode_into(&mut payload);
        }
    }
    NlAttr::new(kind, payload)
}

fn service_attrs() -> Vec<NlAttr> {
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[192, 0, 2, 100]);
    vec![
        NlAttr::u16(proto::SVC_ATTR_AF, 2),
        NlAttr::u16(proto::SVC_ATTR_PROTOCOL, 6),
        NlAttr::new(proto::SVC_ATTR_ADDR, addr),
        NlAttr::be16(proto::SVC_ATTR_PORT, 80),
        NlAttr::string(proto::SVC_ATTR_SCHED_NAME, "wrr"),
        NlAttr::new(
            proto::SVC_ATTR_FLAGS,
            flags_payload(proto::SVC_F_PERSISTENT | proto::SVC_F_HASHED),
        ),
        NlAttr::u32(proto::SVC_ATTR_TIMEOUT, 600),
        NlAttr::be32(proto::SVC_ATTR_NETMASK, 0xffff_ff00),
        stats32_attr(proto::SVC_ATTR_STATS),
        stats64_attr(proto::SVC_ATTR_STATS64),
        NlAttr::string(proto::SVC_ATTR_PE_NAME, "sip"),
        NlAttr::new(99, [0xaa, 0xbb]),
    ]
}

fn minimal_service_attrs() -> Vec<NlAttr> {
    vec![
        NlAttr::u16(proto::SVC_ATTR_AF, 2),
        NlAttr::u16(proto::SVC_ATTR_PROTOCOL, 6),
        NlAttr::new(proto::SVC_ATTR_ADDR, [192, 0, 2, 50]),
        NlAttr::be16(proto::SVC_ATTR_PORT, 443),
    ]
}

fn service_reply(attrs: &[NlAttr]) -> Vec<u8> {
    common::reply(
        proto::CMD_NEW_SERVICE,
        &[NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            nl::encode_attrs(attrs),
        )],
    )
}

fn service_dump_message(attrs: &[NlAttr]) -> Vec<u8> {
    common::dump_message(
        proto::CMD_NEW_SERVICE,
        &[NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            nl::encode_attrs(attrs),
        )],
    )
}

fn service_id() -> ServiceId {
    ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp)
}

#[test]
fn family_resolution_failure_is_typed() {
    let (mock, state) = common::Mock::new();
    state.borrow_mut().family_error = Some(2); // ENOENT
    let error = Ipvs::with_transport(Box::new(mock)).unwrap_err();
    assert!(matches!(error, Error::FamilyNotFound), "{error:?}");
}

#[test]
fn family_is_resolved_and_cached() {
    let (ipvs, state) = common::connect();
    assert_eq!(ipvs.family_id(), common::FAMILY_ID);
    assert!(ipvs.as_fd().is_none());
    // GETFAMILY targeted the controller family with the family name.
    let request = NlMsg::decode(&state.borrow().sent[0]).unwrap();
    assert_eq!(request.header().nlmsg_type, nl::GENL_ID_CTRL);
    assert_eq!(request.cmd().unwrap(), nl::CTRL_CMD_GETFAMILY);
    assert_eq!(
        request
            .attrs()
            .unwrap()
            .get(nl::CTRL_ATTR_FAMILY_NAME)
            .unwrap()
            .as_str(),
        "IPVS"
    );
}

#[test]
fn kernel_error_carries_errno_and_extack() {
    let (mut ipvs, state) = common::connect();
    state
        .borrow_mut()
        .script([common::error_with_extack(1, "Operation not permitted", 8)]);
    let error = ipvs.add_service(&service_spec()).unwrap_err();
    match error {
        Error::Kernel(kernel) => {
            assert_eq!(kernel.errno, 1);
            assert_eq!(kernel.message.as_deref(), Some("Operation not permitted"));
            assert_eq!(kernel.offset, Some(8));
            assert!(kernel.is_permission_denied());
            assert!(!kernel.is_not_found());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn get_service_decodes_a_kernel_shaped_reply() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([service_reply(&service_attrs())]);
    let service = ipvs.get_service(&service_id()).unwrap();

    assert_eq!(
        service.id,
        ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp)
    );
    assert_eq!(service.sched_name, "wrr");
    assert!(service.flags.contains(ServiceFlags::PERSISTENT));
    assert!(service.flags.contains(ServiceFlags::HASHED));
    assert_eq!(service.timeout, 600);
    assert_eq!(
        service.netmask,
        Netmask::Mask(Ipv4Addr::new(255, 255, 255, 0))
    );
    assert_eq!(service.pe_name.as_deref(), Some("sip"));
    assert_eq!(
        service.unknown,
        vec![RawAttr {
            kind: 99,
            data: vec![0xaa, 0xbb]
        }]
    );

    // STATS64 wins over STATS; padding attributes are skipped.
    let stats = service.stats.expect("stats");
    assert_eq!(stats.conns, 1);
    assert_eq!(stats.inbytes, 4);
    assert_eq!(stats.outbps, 10);
}

#[test]
fn get_service_accepts_a_short_ipv4_address() {
    let (mut ipvs, state) = common::connect();
    state
        .borrow_mut()
        .script([service_reply(&minimal_service_attrs())]);
    let service = ipvs.get_service(&service_id()).unwrap();
    assert_eq!(
        service.id,
        ServiceId::addr(Ipv4Addr::new(192, 0, 2, 50), 443, Protocol::Tcp)
    );
    assert_eq!(service.sched_name, "none");
    assert_eq!(service.netmask, Netmask::Mask(Ipv4Addr::BROADCAST));
    assert!(service.stats.is_none());
}

#[test]
fn stats32_is_a_fallback() {
    let (mut ipvs, state) = common::connect();
    let mut attrs = minimal_service_attrs();
    attrs.push(stats32_attr(proto::SVC_ATTR_STATS));
    state.borrow_mut().script([service_reply(&attrs)]);
    let stats = ipvs.get_service(&service_id()).unwrap().stats.unwrap();
    assert_eq!(stats.conns, 101);
    assert_eq!(stats.inbytes, 1004);
}

#[test]
fn service_dump_keeps_bad_entries_verbatim() {
    let (mut ipvs, state) = common::connect();
    let good = service_dump_message(&minimal_service_attrs());
    let bad = common::dump_message(proto::CMD_NEW_SERVICE, &[]);
    state.borrow_mut().script([good, bad, common::done(0)]);

    let dump = ipvs.list_services().unwrap();
    assert_eq!(dump.entries.len(), 1);
    assert_eq!(dump.rejected.len(), 1);
    assert!(!dump.interrupted);
    assert!(!dump.is_empty());
    assert!(matches!(
        dump.rejected[0].error,
        Error::MissingAttribute {
            name: "IPVS_CMD_ATTR_SERVICE"
        }
    ));
    assert!(!dump.rejected[0].raw.is_empty());
}

#[test]
fn malformed_datagram_does_not_abort_the_dump() {
    let (mut ipvs, state) = common::connect();
    // Six bytes cannot hold a message header.
    let truncated = vec![0x20, 0x00, 0x00, 0x00, 0x18, 0x00];
    state
        .borrow_mut()
        .script_datagrams([truncated, common::done(0)]);
    let dump = ipvs.list_services().unwrap();
    assert!(dump.entries.is_empty());
    assert_eq!(dump.rejected.len(), 1);
}

#[test]
fn dump_spanning_multiple_datagrams_is_concatenated() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script_datagrams([
        common::concat(&[
            service_dump_message(&minimal_service_attrs()),
            service_dump_message(&minimal_service_attrs()),
        ]),
        common::concat(&[
            service_dump_message(&minimal_service_attrs()),
            common::done(0),
        ]),
    ]);
    let dump = ipvs.list_services().unwrap();
    assert_eq!(dump.entries.len(), 3);
    assert!(!dump.interrupted);
}

#[test]
fn interrupted_dump_is_surfaced() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([
        service_dump_message(&minimal_service_attrs()),
        common::done(nl::NLM_F_DUMP_INTR),
    ]);
    let dump = ipvs.list_services().unwrap();
    assert_eq!(dump.entries.len(), 1);
    assert!(dump.interrupted);
}

#[test]
fn empty_dump_is_not_an_error() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::done(0)]);
    let dump = ipvs.list_services().unwrap();
    assert!(dump.entries.is_empty());
    assert!(dump.rejected.is_empty());
    assert!(!dump.interrupted);
}

#[test]
fn dump_kernel_error_is_returned() {
    let (mut ipvs, state) = common::connect();
    state
        .borrow_mut()
        .script([common::error_with_extack(13, "Permission denied", 20)]);
    match ipvs.list_services() {
        Err(Error::Kernel(kernel)) => {
            assert_eq!(kernel.errno, 13);
            assert_eq!(kernel.message.as_deref(), Some("Permission denied"));
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn done_with_an_error_payload_is_returned() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::done_error(3)]); // -ESRCH

    match ipvs.list_services() {
        Err(Error::Kernel(kernel)) => assert_eq!(kernel.errno, 3),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn unexpected_reply_command_is_rejected() {
    let (mut ipvs, state) = common::connect();
    state
        .borrow_mut()
        .script([common::reply(proto::CMD_NEW_DEST, &[])]);
    match ipvs.get_service(&service_id()) {
        Err(Error::UnexpectedReply {
            expected,
            cmd: Some(cmd),
            ..
        }) => {
            assert_eq!(expected, "a NEW_SERVICE reply");
            assert_eq!(cmd, proto::CMD_NEW_DEST);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn pending_sequence_is_available_through_recv_raw() {
    let (mut ipvs, state) = common::connect();
    let stray = common::genl_message(common::FAMILY_ID, 0, 4242, proto::CMD_NEW_SERVICE, &[]);
    state.borrow_mut().push_raw(stray);
    state.borrow_mut().script([common::ack()]);
    ipvs.del_service(&service_id()).unwrap();

    let raw = ipvs.recv_raw().unwrap();
    assert_eq!(NlMsg::decode(&raw).unwrap().header().nlmsg_seq, 4242);
}

#[test]
fn raw_escape_hatches_forward_bytes_untouched() {
    let (mut ipvs, state) = common::connect();
    ipvs.send_raw(b"not-a-netlink-message").unwrap();
    assert_eq!(
        state.borrow().sent.last().unwrap().as_slice(),
        b"not-a-netlink-message"
    );

    state.borrow_mut().push_raw(common::ack());
    assert_eq!(ipvs.recv_raw().unwrap(), common::ack());
}

#[test]
fn scheduler_name_length_is_checked_before_sending() {
    let (mut ipvs, state) = common::connect();
    let sent_before = state.borrow().sent.len();
    let error = ipvs
        .add_service(&ServiceSpec::addr(
            Ipv4Addr::new(192, 0, 2, 1),
            80,
            Protocol::Tcp,
            "a".repeat(15),
        ))
        .unwrap_err();
    assert!(matches!(
        error,
        Error::ValueTooLong {
            field: "IPVS_SVC_ATTR_SCHED_NAME",
            max: 15,
            got: 15
        }
    ));
    assert_eq!(state.borrow().sent.len(), sent_before);

    // 14 bytes + NUL is the maximum accepted by the kernel policy.
    state.borrow_mut().script([common::ack()]);
    ipvs.add_service(&ServiceSpec::addr(
        Ipv4Addr::new(192, 0, 2, 1),
        80,
        Protocol::Tcp,
        "a".repeat(14),
    ))
    .unwrap();
}

#[test]
fn netmask_family_mismatch_is_rejected() {
    let (mut ipvs, _state) = common::connect();
    let mut spec = ServiceSpec::addr(Ipv4Addr::new(192, 0, 2, 1), 80, Protocol::Tcp, "rr");
    spec.netmask = Netmask::Prefix(64);
    assert!(matches!(
        ipvs.add_service(&spec).unwrap_err(),
        Error::InvalidNetmask
    ));
}

#[test]
fn set_service_uses_the_set_command() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    ipvs.set_service(&service_spec()).unwrap();
    let request = NlMsg::decode(state.borrow().sent.last().unwrap()).unwrap();
    assert_eq!(request.cmd().unwrap(), proto::CMD_SET_SERVICE);
}

fn service_spec() -> ServiceSpec {
    ServiceSpec::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp, "rr")
}

#[test]
fn dest_dump_parses_a_kernel_reply() {
    let (mut ipvs, state) = common::connect();
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[198, 51, 100, 10]);
    let attrs = [
        NlAttr::new(proto::DEST_ATTR_ADDR, addr),
        NlAttr::be16(proto::DEST_ATTR_PORT, 8080),
        NlAttr::u32(proto::DEST_ATTR_FWD_METHOD, 3),
        NlAttr::i32(proto::DEST_ATTR_WEIGHT, 5),
        NlAttr::u32(proto::DEST_ATTR_U_THRESH, 1000),
        NlAttr::u32(proto::DEST_ATTR_L_THRESH, 10),
        NlAttr::u8(proto::DEST_ATTR_TUN_TYPE, 2),
        NlAttr::be16(proto::DEST_ATTR_TUN_PORT, 6081),
        NlAttr::u16(proto::DEST_ATTR_TUN_FLAGS, 3),
        NlAttr::u32(proto::DEST_ATTR_ACTIVE_CONNS, 4),
        NlAttr::u32(proto::DEST_ATTR_INACT_CONNS, 1),
        NlAttr::u32(proto::DEST_ATTR_PERSIST_CONNS, 2),
        NlAttr::u16(proto::DEST_ATTR_ADDR_FAMILY, 2),
        stats64_attr(proto::DEST_ATTR_STATS64),
    ];
    state.borrow_mut().script([
        common::dump_message(
            proto::CMD_NEW_DEST,
            &[NlAttr::nested(
                proto::CMD_ATTR_DEST,
                nl::encode_attrs(&attrs),
            )],
        ),
        common::done(0),
    ]);

    let dump = ipvs.list_dests(&service_id()).unwrap();
    assert_eq!(dump.entries.len(), 1);
    let dest = &dump.entries[0];
    assert_eq!(
        dest.spec.id,
        DestId::new(Ipv4Addr::new(198, 51, 100, 10), 8080)
    );
    assert_eq!(dest.spec.fwd_method, ForwardMethod::DirectRoute);
    assert_eq!(dest.spec.weight, 5);
    assert_eq!(dest.spec.u_threshold, 1000);
    assert_eq!(dest.spec.l_threshold, 10);
    assert_eq!(dest.spec.tun_type, Some(TunnelType::Gre));
    assert_eq!(dest.spec.tun_port, Some(6081));
    assert_eq!(
        dest.spec.tun_flags,
        TunnelFlags::CSUM | TunnelFlags::REMCSUM
    );
    assert_eq!(dest.active_conns, 4);
    assert_eq!(dest.inact_conns, 1);
    assert_eq!(dest.persist_conns, 2);
    assert_eq!(dest.stats.unwrap().conns, 1);
}

#[test]
fn missing_service_error_is_typed() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::error(3)]); // ESRCH
    match ipvs.list_dests(&service_id()) {
        Err(Error::Kernel(kernel)) => assert!(kernel.is_not_found()),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn daemon_dump_parses_ipv4_and_ipv6_groups() {
    let (mut ipvs, state) = common::connect();
    let v4 = [
        NlAttr::u32(proto::DAEMON_ATTR_STATE, 1),
        NlAttr::string(proto::DAEMON_ATTR_MCAST_IFN, "eth0"),
        NlAttr::u32(proto::DAEMON_ATTR_SYNC_ID, 7),
        NlAttr::u16(proto::DAEMON_ATTR_SYNC_MAXLEN, 1400),
        NlAttr::new(proto::DAEMON_ATTR_MCAST_GROUP, [239, 0, 0, 1]),
        NlAttr::u16(proto::DAEMON_ATTR_MCAST_PORT, 8848),
        NlAttr::u8(proto::DAEMON_ATTR_MCAST_TTL, 1),
    ];
    let v6 = [
        NlAttr::u32(proto::DAEMON_ATTR_STATE, 2),
        NlAttr::string(proto::DAEMON_ATTR_MCAST_IFN, "eth1"),
        NlAttr::u32(proto::DAEMON_ATTR_SYNC_ID, 8),
        NlAttr::new(
            proto::DAEMON_ATTR_MCAST_GROUP6,
            "ff05::1".parse::<std::net::Ipv6Addr>().unwrap().octets(),
        ),
    ];
    state.borrow_mut().script([
        common::dump_message(
            proto::CMD_NEW_DAEMON,
            &[NlAttr::nested(
                proto::CMD_ATTR_DAEMON,
                nl::encode_attrs(&v4),
            )],
        ),
        common::dump_message(
            proto::CMD_NEW_DAEMON,
            &[NlAttr::nested(
                proto::CMD_ATTR_DAEMON,
                nl::encode_attrs(&v6),
            )],
        ),
        common::done(0),
    ]);

    let dump = ipvs.list_daemons().unwrap();
    assert_eq!(dump.entries.len(), 2);
    assert_eq!(dump.entries[0].state, DaemonState::Master);
    assert_eq!(
        dump.entries[0].mcast_group,
        Some("239.0.0.1".parse().unwrap())
    );
    assert_eq!(dump.entries[0].mcast_port, Some(8848));
    assert_eq!(dump.entries[0].sync_maxlen, Some(1400));
    assert_eq!(dump.entries[1].state, DaemonState::Backup);
    assert_eq!(
        dump.entries[1].mcast_group,
        Some("ff05::1".parse().unwrap())
    );
    assert_eq!(dump.entries[1].mcast_port, None);
}

#[test]
fn info_reply_uses_set_info_command() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::reply(
        proto::CMD_SET_INFO,
        &[
            NlAttr::u32(proto::INFO_ATTR_VERSION, 0x010201),
            NlAttr::u32(proto::INFO_ATTR_CONN_TAB_SIZE, 4096),
        ],
    )]);
    let info = ipvs.info().unwrap();
    assert_eq!(info.version, 0x010201);
    assert_eq!(info.conn_tab_size, 4096);
}

#[test]
fn timeouts_reply_uses_set_config_command_and_keeps_absent_fields_empty() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::reply(
        proto::CMD_SET_CONFIG,
        &[
            NlAttr::u32(proto::CMD_ATTR_TIMEOUT_TCP, 600),
            NlAttr::u32(proto::CMD_ATTR_TIMEOUT_TCP_FIN, 120),
        ],
    )]);
    let timeouts = ipvs.timeouts().unwrap();
    assert_eq!(timeouts.tcp, Some(600));
    assert_eq!(timeouts.tcp_fin, Some(120));
    assert_eq!(timeouts.udp, None);
}

#[test]
fn transport_failure_is_an_io_error() {
    let (mut ipvs, _state) = common::connect();
    match ipvs.info() {
        Err(Error::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        }
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn unsupported_address_family_is_reported() {
    let (mut ipvs, state) = common::connect();
    let attrs = [
        NlAttr::u16(proto::SVC_ATTR_AF, 99),
        NlAttr::u16(proto::SVC_ATTR_PROTOCOL, 6),
        NlAttr::new(proto::SVC_ATTR_ADDR, [192, 0, 2, 1]),
        NlAttr::be16(proto::SVC_ATTR_PORT, 80),
    ];
    state.borrow_mut().script([service_reply(&attrs)]);
    match ipvs.get_service(&service_id()) {
        Err(Error::UnsupportedAddressFamily { af: 99 }) => {}
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn family_id_is_visible_for_raw_requests() {
    let (ipvs, _state) = common::connect();
    assert_eq!(ipvs.family_id(), 0x18);
}
