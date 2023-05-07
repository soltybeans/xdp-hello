# eBPF and XDP
This repo follows a hands-on guide to using [aya-rs](https://github.com/aya-rs/aya) to write an eBPF program in the
`Rust` language. eBPF provides an abstract virtual machine that runs in the Kernel. These sandboxed environments provide
a safe way to extend low level, Linux capabilities (e.g. receiving/sending network packets). 

This toy example blocks
traffic to a hard-coded list of IP addresses (some subset of the `httpbin` endpoint). More on eBPF can be found 
[here](https://ebpf.io/).

To be able to inspect packets within this eBPF application, the `eXpress Data Path (XDP)` framework is used. More on
XDP can be found [here](https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/).


## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## Test dropping packets
Using an `eBPF` map (called `BLOCKLIST`) to transfer data between user and kernel space, the
[httpbin](https://httpbin.org/) endpoint will be used as a guinea pig. Two IP addresses will be blocked. If the IP is in this map, our program will drop this packet. Otherwise, the outgoing request will proceed as normal.

### Get IP addresses behind httpbin.org
```sh
dig httpbin.org
```
This looks something like (IPs may be subject to change):

```sh
ANSWER SECTION:
httpbin.org.            0       IN      A       34.227.35.160
httpbin.org.            0       IN      A       34.193.132.77   # Blocked IP
httpbin.org.            0       IN      A       3.230.204.70    # Blocked IP
httpbin.org.            0       IN      A       34.235.32.249
```

In another terminal (while the xdp program is running), randomly calling against the httpbin endpoint multiple times should see some requests succeeding (those with IPs not in the `BLOCKLIST`).

### Output
Blocking calls will show the following (where xdp is running):
```sh
[2023-05-07T12:51:27Z INFO  xdp_hello] SRC IP: 3.230.204.70, ACTION: 1 
```

while succeeding calls:
```shell
[2023-05-07T12:51:25Z INFO  xdp_hello] SRC IP: 34.227.35.160, ACTION: 2 
```

Action `1` maps to [XDP_DROP](https://github.com/aya-rs/aya/blob/main/bpf/aya-bpf-bindings/src/aarch64/bindings.rs#L1426)
while `2` corresponds to [XPD_PASS](https://github.com/aya-rs/aya/blob/main/bpf/aya-bpf-bindings/src/aarch64/bindings.rs#L1427) 

## Notes
* eBPF programs (written in Rust via `aya-rs`) do NOT have a `main` function.
* The `std` library is also not allowed. Only the `core` library.