#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// Our ebpf program
#[xdp(name = "xdp_hello")]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match { try_xdp_firewall(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// With eBPF - data is transferred between the user space and kernel space via Maps
#[map(name = "BLOCKLIST")]
static mut BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    // Reading parts of the data (e.g. going straight to a field of a struct, instead of an entire struct then field)
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    // We use unsafe because we're reading _from_ XdpContext (kernel event), not because we're switching off
    // Rust's safety features. We (human) know that at this point,a packet has been received based on some
    // event so we're not at risk of checking invalid (null) references. This is a human check and hence, the unsafe keyword.
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS), // ignore (but do not fail) non IPV4
    }

    // For each packet in the context, read <LEN> bytes ahead for the next field in the XdpContext
    // struct. This will keep eBPF's verifier happy (i.e. no out-of-bounds access)
    // LEN is 14 bytes and in this case will include the IPV4 header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    // We are reading bytes and are forcing the ordering of bytes to make sure we don't make up
    // a silly IP address.
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let action = if block_ip(source_addr) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    info!(&ctx, "SRC IP: {:ipv4}, ACTION: {}", source_addr, action);

    Ok(action)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
