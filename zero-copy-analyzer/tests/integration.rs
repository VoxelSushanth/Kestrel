//! Integration tests for the zero-copy network analyzer.
//!
//! These tests replay captured packets and verify correct flow tracking,
//! statistics aggregation, and output generation.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use zero_copy_analyzer::flow::{FlowTable, TimingWheel};
use zero_copy_analyzer::output::{ConsoleOutput, OutputBackend};
use zero_copy_analyzer::parser::{FlowKey, IpAddr, PacketParser, ParsedPacket, Protocol};
use zero_copy_analyzer::stats::StatsCollector;

/// Create a test TCP SYN packet
fn create_test_tcp_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    
    // Ethernet header
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src MAC
        0x08, 0x00, // EtherType: IPv4
    ]);
    
    // IPv4 header
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01, // Src: 192.168.1.1
        0x0a, 0x00, 0x00, 0x01, // Dst: 10.0.0.1
    ]);
    
    // TCP header (SYN)
    packet.extend_from_slice(&[
        (src_port >> 8) as u8, (src_port & 0xFF) as u8,
        (dst_port >> 8) as u8, (dst_port & 0xFF) as u8,
        0x00, 0x00, 0x00, 0x01, // Seq
        0x00, 0x00, 0x00, 0x00, // Ack
        0x50, 0x02, 0xff, 0xff, // Offset/Flags, Window
        0x00, 0x00, 0x00, 0x00, // Checksum, Urgent
    ]);
    
    packet
}

/// Create a test UDP packet
fn create_test_udp_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);
    
    // Ethernet header
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
    ]);
    
    // IPv4 header
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0x08, 0x08, 0x08, 0x08,
    ]);
    
    // UDP header
    packet.extend_from_slice(&[
        (src_port >> 8) as u8, (src_port & 0xFF) as u8,
        (dst_port >> 8) as u8, (dst_port & 0xFF) as u8,
        0x00, 0x08, 0x00, 0x00,
    ]);
    
    packet
}

#[test]
fn test_parser_basic_tcp() {
    let packet = create_test_tcp_packet(12345, 80);
    let mut parser = PacketParser::new();
    
    let result = parser.parse(&packet);
    assert!(result.is_ok());
    
    let parsed = result.unwrap();
    assert_eq!(parsed.protocol, Protocol::Tcp);
    assert!(parsed.tcp.is_some());
    assert_eq!(parsed.tcp.unwrap().src_port, 12345);
    assert_eq!(parsed.tcp.unwrap().dst_port, 80);
}

#[test]
fn test_parser_basic_udp() {
    let packet = create_test_udp_packet(54321, 53);
    let mut parser = PacketParser::new();
    
    let result = parser.parse(&packet);
    assert!(result.is_ok());
    
    let parsed = result.unwrap();
    assert_eq!(parsed.protocol, Protocol::Udp);
    assert!(parsed.udp.is_some());
    assert_eq!(parsed.udp.unwrap().src_port, 54321);
    assert_eq!(parsed.udp.unwrap().dst_port, 53);
}

#[test]
fn test_flow_key_generation() {
    let packet = create_test_tcp_packet(12345, 80);
    let mut parser = PacketParser::new();
    
    let parsed = parser.parse(&packet).unwrap();
    assert!(parsed.flow_key.is_some());
    
    let flow_key = parsed.flow_key.unwrap();
    assert_eq!(flow_key.src_port, 12345);
    assert_eq!(flow_key.dst_port, 80);
    assert_eq!(flow_key.protocol, Protocol::Tcp);
}

#[test]
fn test_flow_table_insert_and_update() {
    let table = FlowTable::new(1000);
    
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        12345,
        80,
        Protocol::Tcp,
    );
    
    // First insert
    let is_new = table.insert_or_update(key, 1500, 0x02, None, None);
    assert!(is_new);
    assert_eq!(table.len(), 1);
    
    // Update existing
    let is_new = table.insert_or_update(key, 100, 0x10, None, None);
    assert!(!is_new);
    assert_eq!(table.len(), 1);
    
    // Verify state
    let state = table.get(&key).unwrap();
    assert_eq!(state.packet_count, 2);
    assert_eq!(state.byte_count, 1600);
}

#[test]
fn test_flow_table_multiple_flows() {
    let table = FlowTable::new(1000);
    
    // Insert multiple flows
    for i in 0..100 {
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i % 256) as u8)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            10000 + i as u16,
            80,
            Protocol::Tcp,
        );
        table.insert_or_update(key, 1500, 0x02, None, None);
    }
    
    assert_eq!(table.len(), 100);
    
    // Get top flows
    let top = table.top_n_by_bytes(10);
    assert_eq!(top.len(), 10);
}

#[test]
fn test_stats_collector() {
    let collector = StatsCollector::new(1000, 300);
    
    // Simulate some packets
    for i in 0..100 {
        let packet = create_test_tcp_packet(10000 + i as u16, 80);
        let mut parser = PacketParser::new();
        
        if let Ok(parsed) = parser.parse(&packet) {
            collector.record_packet(&parsed, packet.len());
        }
    }
    
    // Aggregate stats
    let stats = collector.aggregate();
    assert!(stats.total_packets >= 100);
    assert!(stats.tcp_packets >= 100);
}

#[test]
fn test_timing_wheel_schedule_expire() {
    use std::thread;
    
    let wheel = TimingWheel::new();
    
    let key = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        12345,
        80,
        Protocol::Tcp,
    );
    
    // Schedule for very soon
    wheel.schedule(key, Duration::from_millis(5));
    assert_eq!(wheel.pending_count(), 1);
    
    // Wait and tick
    thread::sleep(Duration::from_millis(10));
    let expired = wheel.tick(Duration::from_millis(20));
    
    assert!(!expired.is_empty());
    assert_eq!(wheel.pending_count(), 0);
}

#[test]
fn test_console_output() {
    let mut output = ConsoleOutput::new(Vec::new());
    
    let packet = create_test_tcp_packet(12345, 80);
    let mut parser = PacketParser::new();
    let parsed = parser.parse(&packet).unwrap();
    
    output.emit(&parsed);
    output.flush().unwrap();
    
    // Verify no errors occurred
    assert_eq!(output.name(), "console");
}

#[test]
fn test_full_pipeline() {
    let table = FlowTable::new(1000);
    let mut parser = PacketParser::new();
    
    // Simulate a TCP handshake
    let syn = create_test_tcp_packet(12345, 80);
    let syn_ack = create_test_tcp_packet(80, 12345);
    let ack = create_test_tcp_packet(12345, 80);
    
    // Parse and track SYN
    let parsed_syn = parser.parse(&syn).unwrap();
    if let Some(key) = parsed_syn.flow_key {
        table.insert_or_update(key, syn.len(), 0x02, parsed_syn.tcp.map(|t| t.seq), None);
    }
    
    // Parse and track SYN-ACK
    let parsed_syn_ack = parser.parse(&syn_ack).unwrap();
    if let Some(key) = parsed_syn_ack.flow_key.reverse() {
        table.insert_or_update(key, syn_ack.len(), 0x12, parsed_syn_ack.tcp.map(|t| t.seq), None);
    }
    
    // Parse and track ACK
    let parsed_ack = parser.parse(&ack).unwrap();
    if let Some(key) = parsed_ack.flow_key {
        table.insert_or_update(key, ack.len(), 0x10, None, None);
    }
    
    // Verify flow was tracked
    assert_eq!(table.len(), 2); // Forward and reverse flows
    
    // Check TCP flags were recorded
    let stats = table.stats();
    assert!(stats.total_flows >= 1);
}

#[test]
fn test_ipv6_parsing() {
    let mut packet = Vec::with_capacity(74);
    
    // Ethernet header with IPv6 EtherType
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x86, 0xdd, // IPv6
    ]);
    
    // IPv6 header
    packet.extend_from_slice(&[
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x14,
        0x06, // TCP
        0x40,
        // Source: fe80::1
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest: fe80::2
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ]);
    
    // TCP header
    packet.extend_from_slice(&[
        0x00, 0x50, 0xc0, 0xa8,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    ]);
    
    let mut parser = PacketParser::new();
    let result = parser.parse(&packet);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.protocol, Protocol::Tcp);
    assert!(parsed.ip.is_some());
    assert!(parsed.ip.as_ref().unwrap().version().is_v6());
}

#[test]
fn test_vlan_parsing() {
    let mut packet = Vec::with_capacity(68);
    
    // Ethernet header with VLAN
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x81, 0x00, // VLAN EtherType
        0x00, 0x01, // VLAN ID 1
        0x08, 0x00, // IPv4
    ]);
    
    // IPv4 header
    packet.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0x0a, 0x00, 0x00, 0x01,
    ]);
    
    // TCP header
    packet.extend_from_slice(&[
        0x00, 0x50, 0xc0, 0xa8,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00,
    ]);
    
    let mut parser = PacketParser::new();
    let result = parser.parse(&packet);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert!(!parsed.vlan_tags.is_empty());
    assert_eq!(parsed.vlan_tags[0], 1);
}
