use std::net::Ipv4Addr;
use anyhow::Context;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya::maps::HashMap;
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-hello"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-hello"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Point to the xdp_hello program!
    let program: &mut Xdp = bpf.program_mut("xdp_hello").unwrap().try_into()?;

    // Load onto Kernel
    program.load()?;

    // Attach to interface
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;


    let mut blocking_ip_list: HashMap<_, u32,u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;

    let first_blocked_ip: u32 = Ipv4Addr::new(34,193,132,77).try_into()?;
    let second_blocked_ip: u32 = Ipv4Addr::new(3,230,204,70).try_into()?;
    blocking_ip_list.insert(first_blocked_ip, 0, 0)?;
    blocking_ip_list.insert(second_blocked_ip, 0, 0)?;


    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
