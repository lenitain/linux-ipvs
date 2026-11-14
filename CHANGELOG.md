# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-14

Initial release: a complete userspace mechanism layer for the Linux IPVS generic netlink interface, with a zero-dependency core (`default-features = false` builds with no dependencies).

### Added

- **Generic netlink message layer** (`nl`): `nlmsghdr` / `genlmsghdr` / `nlattr` encode/decode with `NLA_ALIGN` and `NLA_F_NESTED`, attribute iteration, multipart message splitting, `NLMSG_DONE` parsing, and request construction, all covered by expected-byte tests.
- **Transport and family resolution** (`ipvs`): RAII `NETLINK_GENERIC` socket with `NETLINK_EXT_ACK`, `CTRL_CMD_GETFAMILY "IPVS"` resolution, sequence matching, typed errno mapping with extended-ack message/offset, and injectable `NetlinkTransport` for root-free testing.
- **Virtual services** (`service`): `NEW`/`SET`/`DEL`/`GET_SERVICE`, the service dump, address/port/protocol and firewall-mark identities, `ip_vs_flags` with mask, persistence netmask (IPv4 mask / IPv6 prefix), scheduler and persistence-engine names, statistics.
- **Real servers** (`dest`): `NEW`/`SET`/`DEL`/`GET_DEST`, destination dumps, forwarding methods, weights, thresholds, tunnel type/port/flags, and connection counters.
- **Statistics and information** (`stats`): 32-bit and 64-bit statistics containers (the 64-bit form is preferred), connection rates, and `GET_INFO`.
- **Synchronization daemon** (`daemon`): `NEW`/`DEL`/`GET_DAEMON` with state, interface, sync ID, payload size, IPv4/IPv6 multicast group, port and TTL.
- **Timeouts** (`timeout`): `GET`/`SET_CONFIG` with partial updates.
- **Dump degradation**: malformed entries are returned in `Dump::rejected` with their raw bytes; `NLM_F_DUMP_INTR` is surfaced as `Dump::interrupted`.
- **Escape hatches**: `as_fd`, `send_raw`, `recv_raw`, and the public `proto` constant table.
- Example: `list_services`.

### Tested

- Expected-byte request fixtures (IPv4/IPv6/firewall-mark services, destinations, daemon, timeouts).
- Scripted-transport integration tests for family resolution, acknowledgements, extack, every command, multipart dumps, empty/interrupted/degraded dumps, sequence parking and raw hatches.
- Both feature sets (`cargo test` and `cargo test --no-default-features`).
