//! Wire-format fixtures: every request is checked against the shape the
//! kernel's `ip_vs_ctl.c` expects, including padding, nesting, byte order and
//! attribute order.

mod common;

use std::cell::RefCell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use common::MockState;
use linux_ipvs::nl::{self, Attrs, NlAttr, NlMsg};
use linux_ipvs::proto::{self, AddressFamily, Protocol};
use linux_ipvs::{
    DaemonConfig, DaemonState, DestSpec, ForwardMethod, Netmask, ServiceFlags, ServiceId,
    ServiceSpec, Timeouts, TunnelFlags, TunnelType,
};

fn last_request(state: &Rc<RefCell<MockState>>) -> NlMsg {
    let sent = state.borrow().sent.clone();
    NlMsg::decode(sent.last().expect("a request was sent")).unwrap()
}

fn nested(message: &NlMsg, kind: u16) -> Attrs {
    let outer = message.attrs().unwrap();
    Attrs::parse(outer.get(kind).expect("nested attribute").payload()).unwrap()
}

fn service_identity() -> ServiceId {
    ServiceId::addr(Ipv4Addr::new(192, 0, 2, 100), 80, Protocol::Tcp)
}

#[test]
fn add_service_ipv4_has_the_exact_kernel_wire_shape() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    let spec = ServiceSpec::addr(Ipv4Addr::new(192, 0, 2, 1), 80, Protocol::Tcp, "rr");
    ipvs.add_service(&spec).unwrap();

    // nlmsghdr(16) + genlmsghdr(4) + SERVICE attr(72) = 92.
    // The nested payload is: AF(8) PROTOCOL(8) ADDR(8) PORT(8)
    // SCHED_NAME(8) FLAGS(12) TIMEOUT(8) NETMASK(8) = 68.
    #[rustfmt::skip]
    let expected: &[u8] = &[
        0x5c, 0x00, 0x00, 0x00, // nlmsg_len = 92
        0x18, 0x00,             // nlmsg_type = family id
        0x05, 0x00,             // NLM_F_REQUEST | NLM_F_ACK
        0x02, 0x00, 0x00, 0x00, // nlmsg_seq = 2 (1 was GETFAMILY)
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid
        0x01, 0x01, 0x00, 0x00, // NEW_SERVICE, version 1
        0x48, 0x00, 0x01, 0x80, // nested SERVICE, 72 bytes

        0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, // AF_INET
        0x06, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, // IPPROTO_TCP
        0x08, 0x00, 0x03, 0x00, 0xc0, 0x00, 0x02, 0x01, // 192.0.2.1
        0x06, 0x00, 0x04, 0x00, 0x00, 0x50, 0x00, 0x00, // port 80 (be16)
        0x07, 0x00, 0x06, 0x00, b'r', b'r', 0x00, 0x00, // "rr\0"
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, // flags = 0
        0xff, 0xff, 0xff, 0xff,                         // mask = !0
        0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // timeout = 0
        0x08, 0x00, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, // netmask /32
    ];

    assert_eq!(&state.borrow().sent[1], expected);
}

#[test]
fn ipv6_service_uses_16_byte_address_and_prefix_netmask() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let mut spec = ServiceSpec::addr(addr, 443, Protocol::Tcp, "rr");
    spec.netmask = Netmask::Prefix(64);
    ipvs.add_service(&spec).unwrap();

    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_NEW_SERVICE);
    let attrs = nested(&message, proto::CMD_ATTR_SERVICE);
    assert_eq!(attrs.get(proto::SVC_ATTR_AF).unwrap().as_u16().unwrap(), 10);
    assert_eq!(
        attrs.get(proto::SVC_ATTR_ADDR).unwrap().payload(),
        addr.octets()
    );
    // IPv6 netmasks are host-order prefix lengths, not network-order masks.
    assert_eq!(
        attrs.get(proto::SVC_ATTR_NETMASK).unwrap().payload(),
        u32::from(64u8).to_ne_bytes()
    );
}

#[test]
fn fwmark_service_omits_address_protocol_and_port() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    let spec = ServiceSpec::fwmark(AddressFamily::Inet, 42, "wrr");
    ipvs.add_service(&spec).unwrap();

    let attrs = nested(&last_request(&state), proto::CMD_ATTR_SERVICE);
    assert_eq!(
        attrs.get(proto::SVC_ATTR_FWMARK).unwrap().as_u32().unwrap(),
        42
    );
    assert!(attrs.get(proto::SVC_ATTR_ADDR).is_none());
    assert!(attrs.get(proto::SVC_ATTR_PORT).is_none());
    assert!(attrs.get(proto::SVC_ATTR_PROTOCOL).is_none());
}

#[test]
fn service_flags_are_sent_as_ip_vs_flags_struct() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    let mut spec = ServiceSpec::addr(Ipv4Addr::new(192, 0, 2, 1), 80, Protocol::Tcp, "rr");
    spec.flags = ServiceFlags::PERSISTENT | ServiceFlags::ONE_PACKET;
    spec.timeout = 600;
    ipvs.add_service(&spec).unwrap();

    let attrs = nested(&last_request(&state), proto::CMD_ATTR_SERVICE);
    let flags = attrs.get(proto::SVC_ATTR_FLAGS).unwrap().payload();
    assert_eq!(flags.len(), 8);
    assert_eq!(
        u32::from_ne_bytes(flags[..4].try_into().unwrap()),
        proto::SVC_F_PERSISTENT | proto::SVC_F_ONEPACKET
    );
    assert_eq!(u32::from_ne_bytes(flags[4..].try_into().unwrap()), u32::MAX);
    assert_eq!(
        attrs
            .get(proto::SVC_ATTR_TIMEOUT)
            .unwrap()
            .as_u32()
            .unwrap(),
        600
    );
}

#[test]
fn delete_service_sends_identity_only() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    ipvs.del_service(&service_identity()).unwrap();

    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_DEL_SERVICE);
    let attrs = nested(&message, proto::CMD_ATTR_SERVICE);
    assert_eq!(attrs.len(), 4); // AF, PROTOCOL, ADDR, PORT
    assert!(attrs.get(proto::SVC_ATTR_SCHED_NAME).is_none());
    assert!(attrs.get(proto::SVC_ATTR_FLAGS).is_none());
}

#[test]
fn get_service_and_zero_use_the_get_and_zero_commands() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::reply(
        proto::CMD_NEW_SERVICE,
        &[NlAttr::nested(
            proto::CMD_ATTR_SERVICE,
            nl::encode_attrs(&[
                NlAttr::u16(proto::SVC_ATTR_AF, 2),
                NlAttr::u16(proto::SVC_ATTR_PROTOCOL, 6),
                NlAttr::new(proto::SVC_ATTR_ADDR, [192, 0, 2, 100]),
                NlAttr::be16(proto::SVC_ATTR_PORT, 80),
            ]),
        )],
    )]);
    ipvs.get_service(&service_identity()).unwrap();
    assert_eq!(last_request(&state).cmd().unwrap(), proto::CMD_GET_SERVICE);
    assert_eq!(last_request(&state).header().nlmsg_flags, nl::NLM_F_REQUEST);

    for (command, call) in [
        (proto::CMD_ZERO, 0u8),
        (proto::CMD_FLUSH, 1),
        (proto::CMD_ZERO, 2),
    ] {
        state.borrow_mut().script([common::ack()]);
        match call {
            0 => ipvs.zero_service(&service_identity()).unwrap(),
            1 => ipvs.flush().unwrap(),
            _ => ipvs.zero_services().unwrap(),
        }
        assert_eq!(last_request(&state).cmd().unwrap(), command);
    }

    // FLUSH and whole-table ZERO carry no attributes.
    state.borrow_mut().script([common::ack()]);
    ipvs.flush().unwrap();
    let message = last_request(&state);
    assert_eq!(
        message.payload().len(),
        nl::GENL_HDRLEN,
        "FLUSH must not carry attributes"
    );
}

#[test]
fn add_dest_sends_service_and_destination_attributes() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    let mut dest = DestSpec::new(
        Ipv4Addr::new(198, 51, 100, 10),
        8080,
        ForwardMethod::DirectRoute,
    );
    dest.weight = 5;
    dest.u_threshold = 1000;
    dest.l_threshold = 10;
    dest.tun_type = Some(TunnelType::Gre);
    dest.tun_port = Some(6081);
    dest.tun_flags = TunnelFlags::CSUM;
    ipvs.add_dest(&service_identity(), &dest).unwrap();

    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_NEW_DEST);
    let outer = message.attrs().unwrap();
    assert!(outer.get(proto::CMD_ATTR_SERVICE).is_some());
    let attrs = Attrs::parse(outer.get(proto::CMD_ATTR_DEST).unwrap().payload()).unwrap();

    assert_eq!(
        attrs.get(proto::DEST_ATTR_ADDR).unwrap().payload(),
        [198, 51, 100, 10]
    );
    assert_eq!(
        attrs.get(proto::DEST_ATTR_PORT).unwrap().as_be16().unwrap(),
        8080
    );
    assert_eq!(
        attrs
            .get(proto::DEST_ATTR_FWD_METHOD)
            .unwrap()
            .as_u32()
            .unwrap(),
        3
    );
    assert_eq!(
        attrs
            .get(proto::DEST_ATTR_WEIGHT)
            .unwrap()
            .as_i32()
            .unwrap(),
        5
    );
    assert_eq!(
        attrs
            .get(proto::DEST_ATTR_TUN_TYPE)
            .unwrap()
            .as_u8()
            .unwrap(),
        2
    );
    assert_eq!(
        attrs
            .get(proto::DEST_ATTR_TUN_PORT)
            .unwrap()
            .as_be16()
            .unwrap(),
        6081
    );
    assert_eq!(
        attrs
            .get(proto::DEST_ATTR_TUN_FLAGS)
            .unwrap()
            .as_u16()
            .unwrap(),
        1
    );
}

#[test]
fn del_dest_sends_only_addr_port_and_family() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    let dest = linux_ipvs::DestId::new(Ipv4Addr::new(198, 51, 100, 10), 8080);
    ipvs.del_dest(&service_identity(), &dest).unwrap();

    let attrs = nested(&last_request(&state), proto::CMD_ATTR_DEST);
    assert!(attrs.get(proto::DEST_ATTR_ADDR).is_some());
    assert!(attrs.get(proto::DEST_ATTR_PORT).is_some());
    assert!(attrs.get(proto::DEST_ATTR_WEIGHT).is_none());
    assert!(attrs.get(proto::DEST_ATTR_FWD_METHOD).is_none());
}

#[test]
fn daemon_request_attributes() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    let mut config = DaemonConfig::new(DaemonState::Master, "eth0", 7);
    config.sync_maxlen = Some(1400);
    config.mcast_group = Some("239.0.0.1".parse().unwrap());
    config.mcast_port = Some(8848);
    config.mcast_ttl = Some(1);
    ipvs.add_daemon(&config).unwrap();

    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_NEW_DAEMON);
    let attrs = nested(&message, proto::CMD_ATTR_DAEMON);
    assert_eq!(
        attrs
            .get(proto::DAEMON_ATTR_STATE)
            .unwrap()
            .as_u32()
            .unwrap(),
        1
    );
    assert_eq!(
        attrs.get(proto::DAEMON_ATTR_MCAST_IFN).unwrap().as_str(),
        "eth0"
    );
    assert_eq!(
        attrs
            .get(proto::DAEMON_ATTR_SYNC_ID)
            .unwrap()
            .as_u32()
            .unwrap(),
        7
    );
    assert_eq!(
        attrs.get(proto::DAEMON_ATTR_MCAST_GROUP).unwrap().payload(),
        [239, 0, 0, 1]
    );

    state.borrow_mut().script([common::ack()]);
    ipvs.del_daemon(DaemonState::Master).unwrap();
    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_DEL_DAEMON);
    let attrs = nested(&message, proto::CMD_ATTR_DAEMON);
    assert_eq!(attrs.len(), 1);
}

#[test]
fn set_timeouts_only_sends_present_fields() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::ack()]);
    ipvs.set_timeouts(&Timeouts {
        tcp: Some(600),
        tcp_fin: None,
        udp: Some(300),
    })
    .unwrap();

    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_SET_CONFIG);
    let attrs = message.attrs().unwrap();
    assert_eq!(
        attrs
            .get(proto::CMD_ATTR_TIMEOUT_TCP)
            .unwrap()
            .as_u32()
            .unwrap(),
        600
    );
    assert!(attrs.get(proto::CMD_ATTR_TIMEOUT_TCP_FIN).is_none());
    assert_eq!(
        attrs
            .get(proto::CMD_ATTR_TIMEOUT_UDP)
            .unwrap()
            .as_u32()
            .unwrap(),
        300
    );
}

#[test]
fn list_dests_and_daemons_use_dump_flags() {
    let (mut ipvs, state) = common::connect();
    state.borrow_mut().script([common::done(0)]);
    ipvs.list_dests(&service_identity()).unwrap();
    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_GET_DEST);
    assert_eq!(
        message.header().nlmsg_flags & nl::NLM_F_DUMP,
        nl::NLM_F_DUMP
    );
    assert!(
        message
            .attrs()
            .unwrap()
            .get(proto::CMD_ATTR_SERVICE)
            .is_some()
    );

    state.borrow_mut().script([common::done(0)]);
    ipvs.list_daemons().unwrap();
    let message = last_request(&state);
    assert_eq!(message.cmd().unwrap(), proto::CMD_GET_DAEMON);
    assert_eq!(
        message.header().nlmsg_flags & nl::NLM_F_DUMP,
        nl::NLM_F_DUMP
    );
    assert_eq!(message.payload().len(), nl::GENL_HDRLEN);
}
