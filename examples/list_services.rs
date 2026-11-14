//! Dump every IPVS service and its real servers.
//!
//! Requires `CAP_NET_ADMIN` (or root) and a kernel with the `ip_vs` module.
//!
//! ```text
//! cargo run --example list_services
//! ```

use linux_ipvs::Ipvs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ipvs = Ipvs::new()?;
    let info = ipvs.info()?;
    println!(
        "IPVS version {:#x}, connection table size {}",
        info.version, info.conn_tab_size
    );

    for service in ipvs.list_services()?.entries {
        println!(
            "{:?} scheduler={} flags={} timeout={}",
            service.id, service.sched_name, service.flags, service.timeout
        );
        for dest in ipvs.list_dests(&service.id)?.entries {
            println!(
                "  {:?} fwd={:?} weight={} active={} inactive={}",
                dest.spec.id,
                dest.spec.fwd_method,
                dest.spec.weight,
                dest.active_conns,
                dest.inact_conns
            );
        }
    }
    Ok(())
}
