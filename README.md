# linux-ipvs

Complete mechanism layer for Linux IPVS via netlink: virtual service and destination management with typed statistics.

[![crates.io](https://img.shields.io/crates/v/linux-ipvs.svg)](https://crates.io/crates/linux-ipvs)
[![docs.rs](https://docs.rs/linux-ipvs/badge.svg)](https://docs.rs/linux-ipvs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/lenitain/linux-ipvs/actions/workflows/ci.yml/badge.svg)](https://github.com/lenitain/linux-ipvs/actions/workflows/ci.yml)

## Overview

`linux-ipvs` is the missing Rust mechanism layer for the Linux IPVS (IP Virtual Server) generic netlink interface — the protocol used by `ipvsadm`, `keepalived` and load-balancer control planes to program virtual services and real servers.

The crate implements the correctness layer completely: `nlmsghdr` / `genlmsghdr` / `nlattr` encoding with 4-byte padding and nesting, family resolution (`CTRL_CMD_GETFAMILY "IPVS"`), service and destination management, statistics, the synchronization daemon, connection timeouts, multipart dumps terminated by `NLMSG_DONE`, byte order (network-order addresses and ports, host-order scalars), typed kernel errors with extended acknowledgements, and per-entry dump degradation that preserves unparsable messages verbatim.

It stops at the mechanism layer: scheduling algorithms, health checks, HA state machines, keepalived-style configuration and event loops belong to the caller. Raw escape hatches (`as_fd`, `send_raw`, `recv_raw`) and an injectable transport keep the crate out of the way.

The core builds with zero external dependencies (`default-features = false`); the `std` feature adds the real `NETLINK_GENERIC` socket. Because the transport is injectable, every command, error path and dump shape is testable without root, `CAP_NET_ADMIN` or a loaded kernel module.

## Example

```rust
use std::net::Ipv4Addr;
use linux_ipvs::{DestSpec, ForwardMethod, Ipvs, Protocol, ServiceSpec};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ipvs = Ipvs::new()?;                // open socket + resolve the IPVS family

    let service = ServiceSpec::addr(
        Ipv4Addr::new(192, 0, 2, 100),
        80,
        Protocol::Tcp,
        "rr",                                   // the crate deliberately chooses no scheduler
    );
    ipvs.add_service(&service)?;                // NEW_SERVICE

    let dest = DestSpec::new(
        Ipv4Addr::new(198, 51, 100, 10),
        8080,
        ForwardMethod::DirectRoute,
    );
    ipvs.add_dest(service.id(), &dest)?;        // NEW_DEST

    for entry in ipvs.list_services()?.entries {   // GET_SERVICE + NLM_F_DUMP
        println!("{:?}", entry.id);
    }

    ipvs.del_service(service.id())?;            // explicit, never implicit
    Ok(())
}
```

## Scope

Implemented: generic netlink transport and family resolution; the pure message layer; `NEW`/`SET`/`DEL`/`GET_SERVICE` and `NEW`/`SET`/`DEL`/`GET_DEST`; `GET_INFO`; `NEW`/`DEL`/`GET_DAEMON`; `GET`/`SET_CONFIG` (timeouts); `ZERO` and `FLUSH`; service and destination dumps with statistics.

Not implemented on purpose: load-balancing schedulers, health checks, keepalived configuration parsing, high-availability state machines, the legacy `setsockopt` interface, and any threading or async runtime.

## License

MIT.
