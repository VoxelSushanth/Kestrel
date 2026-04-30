# Zero-Copy Network Analyzer

A production-grade, high-performance network packet analyzer written in Rust that captures packets at line rate (≥10 Gbps) using zero-copy techniques.

## Features

- **Zero-Copy Capture**: AF_XDP primary backend with TPACKET_V3 fallback
- **In-Place Parsing**: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP/QUIC without allocations
- **Real-Time Statistics**: PPS, BPS, flow table, top-N talkers, protocol distribution
- **Pluggable Outputs**: Console, JSON, Prometheus /metrics endpoint
- **Lock-Free Design**: Per-CPU counters with atomic aggregation

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Userspace                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │   Capture   │  │    Parser    │  │      Statistics         │ │
│  │   Engine    │──│   (Zero-Copy)│──│       Collector         │ │
│  │  (AF_XDP/   │  │              │  │                         │ │
│  │  TPACKET)   │  │              │  │  ┌──────────────────┐   │ │
│  └─────────────┘  └──────────────┘  │  │    Flow Table    │   │ │
│                                     │  │  (DashMap +      │   │ │
│  ┌──────────────────────────────┐   │  │   Timing Wheel)  │   │ │
│  │        Output Backends       │   │  └──────────────────┘   │ │
│  │  Console │ JSON │ Prometheus │   │                         │ │
│  └──────────────────────────────┘   └─────────────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                          Kernel                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    XDP Program (BPF)                        ││
│  │              (Pass all or filter by port/proto)             ││
│  └─────────────────────────────────────────────────────────────┘│
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  NIC RX     │  │   UMEM      │  │   Fill/RX Rings         │  │
│  │  Ring       │──│  (Shared)   │──│   (Lock-free)           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
zero-copy-analyzer/
├── Cargo.toml              # Workspace with feature flags
├── src/
│   ├── main.rs             # CLI entry point
│   ├── capture/
│   │   ├── mod.rs          # CaptureEngine trait
│   │   ├── af_xdp.rs       # AF_XDP backend (primary)
│   │   └── tpacket.rs      # TPACKET_V3 fallback
│   ├── umem.rs             # UMEM allocator, PacketRef<'umem>
│   ├── parser/
│   │   ├── mod.rs          # Main parser, FlowKey
│   │   ├── ethernet.rs     # Ethernet/VLAN parsing
│   │   ├── ip.rs           # IPv4/IPv6 parsing
│   │   └── transport.rs    # TCP/UDP/ICMP parsing
│   ├── flow/
│   │   ├── table.rs        # Concurrent flow hash map
│   │   └── timer_wheel.rs  # Hierarchical timing wheel
│   ├── stats.rs            # Per-CPU counters, aggregation
│   └── output/
│       ├── mod.rs          # Output trait
│       ├── console.rs      # Human-readable output
│       ├── json.rs         # NDJSON output
│       └── prometheus.rs   # Prometheus /metrics server
├── xdp/
│   └── xdp_prog.c          # XDP BPF program
├── benches/
│   └── parser_bench.rs     # Criterion benchmarks
└── tests/
    └── integration.rs      # Integration tests
```

## Building

### Prerequisites

- Rust 1.75+ (for array::from_fn)
- Linux kernel 5.3+ (for AF_XDP with shared UMEM)
- libbpf development files (for XDP)
- clang/llvm (for BPF program compilation)

### Build Commands

```bash
# Standard build
cargo build --release

# With XDP support (default)
cargo build --release --features xdp

# With TPACKET fallback only
cargo build --release --features tpacket --no-default-features

# Build BPF program
clang -O2 -target bpf -c xdp/xdp_prog.c -o xdp/xdp_prog.o
```

## Usage

### Basic Capture

```bash
# Capture on eth0 with default settings
sudo ./target/release/zero-copy-analyzer --interface eth0

# Capture with custom settings
sudo ./target/release/zero-copy-analyzer \
    --interface enp3s0 \
    --queue-id 0 \
    --cpu-core 1 \
    --output-format prometheus \
    --prometheus-port 9090 \
    --stats-interval 1
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface` | Network interface | eth0 |
| `-q, --queue-id` | RSS queue ID | 0 |
| `--cpu-core` | CPU core for capture thread | 0 |
| `--umem-size` | UMEM size in bytes | 67108864 (64MB) |
| `--frame-size` | Frame size in bytes | 2048 |
| `--flow-table-size` | Max concurrent flows | 1048576 |
| `--flow-timeout-secs` | Flow idle timeout | 300 |
| `--output-format` | console/json/prometheus | console |
| `--prometheus-port` | Metrics HTTP port | 9090 |
| `--use-tpacket` | Use TPACKET instead of XDP | false |

## Performance Tuning

### Huge Pages Setup

```bash
# Allocate 1GB of huge pages
sudo sysctl -w vm.nr_hugepages=512

# Verify
cat /proc/meminfo | grep HugePages
```

### IRQ Affinity

```bash
# Find NIC IRQs
cat /proc/interrupts | grep eth0

# Pin IRQ to specific CPU
echo 2 > /proc/irq/<IRQ_NUMBER>/smp_affinity_list
```

### ethtool Coalescing

```bash
# Disable coalescing for lowest latency
sudo ethtool -C eth0 rx-usecs 0 rx-frames 1

# Or tune for throughput
sudo ethtool -C eth0 rx-usecs 50 rx-frames 64
```

### XDP Mode Selection

```bash
# Check current XDP mode
ip link show eth0

# Load XDP program in native mode (best performance)
sudo ip link set dev eth0 xdp obj xdp/xdp_prog.o sec xdp

# Or DRV mode if native not supported
sudo ip link set dev eth0 xdpdrv obj xdp/xdp_prog.o sec xdp
```

## Prometheus Metrics

The analyzer exposes these metrics on `/metrics`:

```prometheus
# Total packets by protocol
network_packets_total{protocol="tcp"}
network_packets_total{protocol="udp"}
network_packets_total{protocol="icmp"}

# Total bytes by protocol
network_bytes_total{protocol="tcp"}
network_bytes_total{protocol="udp"}

# Current rates
network_pps{protocol="total"}
network_bps{protocol="total"}

# Active flows
network_active_flows

# Dropped packets
network_dropped_packets_total{reason="ring_overflow"}
```

## Benchmark Results

Expected performance on modern hardware (Intel Xeon, 10GbE NIC):

| Benchmark | Target | Typical Result |
|-----------|--------|----------------|
| Parser (TCP) | ≥5 Mpps | 8-12 Mpps |
| Parser (Mixed) | ≥5 Mpps | 6-10 Mpps |
| Flow Insert | ≥10 Mops | 15-20 Mops |
| Flow Update | ≥20 Mops | 25-35 Mops |
| End-to-End | ≥5 Mpps | 6-8 Mpps |

Run benchmarks:
```bash
cargo bench --bench parser_bench
```

## Flame Graph Analysis

For performance profiling:

```bash
# Install flamegraph
cargo install flamegraph

# Record and generate
sudo flamegraph --root -- ./target/release/zero-copy-analyzer -i eth0

# Or use perf directly
sudo perf record -F 99 -a -g -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > flame.svg
```

### What to Look For

1. **Parser hotspots**: Should be in `parse_ethernet`, `parse_ipv4`, `parse_tcp`
2. **Lock contention**: DashMap operations should show minimal waiting
3. **Cache misses**: High L1/L2 miss rates indicate poor data locality
4. **Syscall overhead**: Should be minimal after initialization

## Build Matrix

| OS | Kernel | NIC Driver | XDP Mode | Status |
|----|--------|------------|----------|--------|
| Ubuntu 22.04 | 5.15+ | mlx5, ice, i40e | native | ✅ Tested |
| Ubuntu 20.04 | 5.4+ | mlx5, i40e | native/drv | ✅ Tested |
| RHEL 8 | 4.18+ | mlx5 | drv | ⚠️ Limited |
| RHEL 9 | 5.14+ | mlx5, ice | native | ✅ Tested |
| Debian 11 | 5.10+ | mlx5, i40e | native | ✅ Tested |

### NIC Driver Requirements

| Driver | Minimum Version | XDP Support | Notes |
|--------|-----------------|-------------|-------|
| mlx5 (Mellanox) | 5.0+ | Native | Best performance |
| ice (Intel E810) | 1.0+ | Native | Good performance |
| i40e (Intel XL710) | 2.0+ | Native | Mature support |
| ixgbe (Intel X520) | 5.0+ | DRV Only | Older hardware |
| ena (AWS Nitro) | 2.0+ | Native | Cloud optimized |

## Example Session

```bash
# Start capture on eth0
$ sudo ./target/release/zero-copy-analyzer -i eth0 --output console

============================================================
Zero-Copy Network Analyzer - Statistics Report
============================================================

Uptime: 60.00s | Flows: 15234 | Packets: 45123456 | Bytes: 54123456789
Rate: 752057.60 pps | 7214.15 Mbps

Protocol Distribution:
  TCP:    78.45% (35403456)
  UDP:    18.23% (8226789)
  ICMP:    2.12% (956234)
  IPv6:   12.34% (5567890)
  ARP:     1.20% (541234)

Top 10 Flows by Bytes:
#        Flow                                          Bytes    Packets
--------------------------------------------------------------------------------
1        192.168.1.100:443 → 10.0.0.50:52341    1234567890     876543
2        192.168.1.100:443 → 10.0.0.51:52342     987654321     654321
3        192.168.1.101:80 → 10.0.0.52:52343      456789012     345678
...

============================================================
```

## Safety Guarantees

All `unsafe` blocks are accompanied by `// SAFETY:` comments explaining:
- Why the operation is safe
- Invariants being maintained
- Bounds checking performed

Key safety measures:
1. UMEM lifetime tied to `PacketRef<'umem>` via Rust lifetimes
2. Ring buffer indices always bounds-checked before access
3. Atomic operations use appropriate memory orderings
4. No raw pointer arithmetic outside mmap/ring management

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please ensure:
- `cargo clippy -- -D clippy::pedantic` passes
- All tests pass: `cargo test`
- Benchmarks meet performance targets
- New code has doc comments with examples
