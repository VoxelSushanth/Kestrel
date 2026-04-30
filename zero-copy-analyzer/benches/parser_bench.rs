//! Parser and flow table benchmarks using Criterion.
//!
//! These benchmarks measure the performance of the zero-copy packet parser
//! and flow table operations to ensure we meet the ≥5 Mpps target.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::net::Ipv4Addr;
use std::time::Instant;

use zero_copy_analyzer::flow::{FlowTable, TimingWheel};
use zero_copy_analyzer::parser::{FlowKey, IpAddr, PacketParser, ParsedPacket, Protocol};

/// Create a realistic TCP SYN packet for benchmarking
fn create_tcp_syn_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    
    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC (broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00, // EtherType: IPv4
    ]);
    
    // IPv4 header (20 bytes)
    packet.extend_from_slice(&[
        0x45, 0x00, // Version/IHL, TOS
        0x00, 0x28, // Total length (40 bytes)
        0x00, 0x01, // ID
        0x40, 0x00, // Flags/Fragment (DF set)
        0x40, // TTL (64)
        0x06, // Protocol (TCP)
        0x00, 0x00, // Checksum (placeholder)
        0xc0, 0xa8, 0x01, 0x01, // Src IP: 192.168.1.1
        0x0a, 0x00, 0x00, 0x01, // Dst IP: 10.0.0.1
    ]);
    
    // TCP header (20 bytes) - SYN packet
    packet.extend_from_slice(&[
        0x00, 0x50, // Src port: 80 (HTTP)
        0xc0, 0xa8, // Dst port: 49320
        0x00, 0x00, 0x00, 0x01, // Seq number
        0x00, 0x00, 0x00, 0x00, // Ack number
        0x50, 0x02, // Data offset (5), Flags: SYN
        0xff, 0xff, // Window size
        0x00, 0x00, // Checksum
        0x00, 0x00, // Urgent pointer
    ]);
    
    packet
}

/// Create a UDP DNS query packet
fn create_udp_dns_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    
    // Ethernet header
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
    ]);
    
    // IPv4 header
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0x08, 0x08, 0x08, 0x08,
    ]);
    
    // UDP header (DNS query to 8.8.8.8:53)
    packet.extend_from_slice(&[
        0xc0, 0xa8, // Src port: 49320
        0x00, 0x35, // Dst port: 53 (DNS)
        0x00, 0x18, // Length
        0x00, 0x00, // Checksum
    ]);
    
    // Minimal DNS query payload
    packet.extend_from_slice(&[0x00, 0x01, 0x01, 0x00, 0x00, 0x01]);
    
    packet
}

/// Create an IPv6 TCP packet
fn create_ipv6_tcp_packet() -> Vec<u8> {
    let mut packet = Vec::with_capacity(74);
    
    // Ethernet header
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x86, 0xdd, // EtherType: IPv6
    ]);
    
    // IPv6 header (40 bytes)
    packet.extend_from_slice(&[
        0x60, 0x00, 0x00, 0x00, // Version/Traffic class/Flow label
        0x00, 0x14, // Payload length (20 bytes for TCP)
        0x06, // Next header: TCP
        0x40, // Hop limit (64)
        // Source address (fe80::1)
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest address (fe80::2)
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ]);
    
    // TCP header
    packet.extend_from_slice(&[
        0x01, 0xbb, // Src port: 443 (HTTPS)
        0xc0, 0xa8, // Dst port: 49320
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x10, // Data offset, Flags: ACK
        0xff, 0xff,
        0x00, 0x00,
        0x00, 0x00,
    ]);
    
    packet
}

/// Benchmark the packet parser with TCP SYN packets
fn bench_parser_tcp(c: &mut Criterion) {
    let packet = create_tcp_syn_packet();
    let mut parser = PacketParser::new();
    
    let mut group = c.benchmark_group("parser/tcp");
    group.throughput(Throughput::Elements(1));
    
    group.bench_function("parse_tcp_syn", |b| {
        b.iter(|| {
            let result = parser.parse(black_box(&packet));
            black_box(result)
        })
    });
    
    group.finish();
}

/// Benchmark the packet parser with mixed traffic
fn bench_parser_mixed(c: &mut Criterion) {
    let tcp_packet = create_tcp_syn_packet();
    let udp_packet = create_udp_dns_packet();
    let ipv6_packet = create_ipv6_tcp_packet();
    
    let mut parser = PacketParser::new();
    let mut idx = 0;
    let packets = [tcp_packet, udp_packet, ipv6_packet];
    
    let mut group = c.benchmark_group("parser/mixed");
    group.throughput(Throughput::Elements(1));
    
    group.bench_function("parse_mixed_traffic", |b| {
        b.iter(|| {
            let packet = &packets[idx % packets.len()];
            idx += 1;
            let result = parser.parse(black_box(packet));
            black_box(result)
        })
    });
    
    group.finish();
}

/// Benchmark raw parsing throughput (packets per second simulation)
fn bench_parser_throughput(c: &mut Criterion) {
    let packet = create_tcp_syn_packet();
    let mut parser = PacketParser::new();
    
    let mut group = c.benchmark_group("parser/throughput");
    group.throughput(Throughput::Elements(1_000_000)); // Report in Mpps
    
    group.bench_function("parse_1m_packets", |b| {
        b.iter(|| {
            for _ in 0..1_000_000 {
                let _ = parser.parse(black_box(&packet));
            }
        })
    });
    
    group.finish();
}

/// Benchmark flow table insertion
fn bench_flow_table_insert(c: &mut Criterion) {
    let table = FlowTable::new(1_048_576);
    
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        12345,
        80,
        Protocol::Tcp,
    );
    
    let mut group = c.benchmark_group("flow_table");
    
    group.bench_function("insert_new_flow", |b| {
        b.iter(|| {
            let key = FlowKey::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, black_box(1))),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                black_box(12345),
                80,
                Protocol::Tcp,
            );
            table.insert_or_update(key, 1500, 0x02, None, None)
        })
    });
    
    group.finish();
}

/// Benchmark flow table update (existing flow)
fn bench_flow_table_update(c: &mut Criterion) {
    let table = FlowTable::new(1_048_576);
    
    // Pre-populate with a flow
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        12345,
        80,
        Protocol::Tcp,
    );
    table.insert_or_update(key, 1500, 0x02, None, None);
    
    let mut group = c.benchmark_group("flow_table");
    
    group.bench_function("update_existing_flow", |b| {
        b.iter(|| {
            table.insert_or_update(key, 100, 0x10, None, None)
        })
    });
    
    group.finish();
}

/// Benchmark flow table lookup
fn bench_flow_table_lookup(c: &mut Criterion) {
    let table = FlowTable::new(1_048_576);
    
    // Pre-populate with flows
    for i in 0..10000 {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i % 256) as u8)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345 + i as u16,
            80,
            Protocol::Tcp,
        );
        table.insert_or_update(key, 1500, 0x02, None, None);
    }
    
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        12445,
        80,
        Protocol::Tcp,
    );
    
    let mut group = c.benchmark_group("flow_table");
    
    group.bench_function("lookup_flow", |b| {
        b.iter(|| {
            black_box(table.get(&key))
        })
    });
    
    group.finish();
}

/// Benchmark timing wheel operations
fn bench_timing_wheel(c: &mut Criterion) {
    let wheel = TimingWheel::new();
    
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        12345,
        80,
        Protocol::Tcp,
    );
    
    let mut group = c.benchmark_group("timing_wheel");
    
    group.bench_function("schedule_timer", |b| {
        b.iter(|| {
            wheel.schedule(key, std::time::Duration::from_secs(300))
        })
    });
    
    group.bench_function("tick_wheel", |b| {
        b.iter(|| {
            wheel.tick(std::time::Duration::from_millis(10))
        })
    });
    
    group.finish();
}

/// Combined benchmark: parse and track flows
fn bench_parse_and_track(c: &mut Criterion) {
    let packet = create_tcp_syn_packet();
    let mut parser = PacketParser::new();
    let table = FlowTable::new(1_048_576);
    
    let mut group = c.benchmark_group("pipeline");
    group.throughput(Throughput::Elements(1));
    
    group.bench_function("parse_and_track_flow", |b| {
        b.iter(|| {
            if let Ok(parsed) = parser.parse(black_box(&packet)) {
                if let Some(flow_key) = parsed.flow_key {
                    let tcp_flags = parsed.tcp.map(|t| {
                        let mut flags = 0u8;
                        if t.syn { flags |= 0x02; }
                        if t.ack_flag { flags |= 0x10; }
                        flags
                    }).unwrap_or(0);
                    
                    table.insert_or_update(
                        flow_key,
                        parsed.capture_len,
                        tcp_flags,
                        parsed.tcp.map(|t| t.seq),
                        parsed.tcp.map(|t| t.ack),
                    );
                }
            }
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_parser_tcp,
    bench_parser_mixed,
    bench_parser_throughput,
    bench_flow_table_insert,
    bench_flow_table_update,
    bench_flow_table_lookup,
    bench_timing_wheel,
    bench_parse_and_track,
);

criterion_main!(benches);
