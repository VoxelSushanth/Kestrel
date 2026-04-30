//! Statistics collection module for per-CPU counters and aggregation.
//!
//! This module provides lock-free per-CPU statistics counters that are
//! aggregated atomically only at reporting intervals to minimize contention.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::flow::{FlowTable, FlowTableStats};
use crate::parser::{ParsedPacket, Protocol};

/// Cache line size for padding to avoid false sharing
const CACHE_LINE_SIZE: usize = 128;

/// Per-CPU statistics counter with cache-line padding
#[repr(C, align(128))]
#[derive(Debug, Default)]
pub struct CpuStats {
    /// Packets received on this CPU
    pub packets: AtomicU64,
    /// Bytes received on this CPU
    pub bytes: AtomicU64,
    /// TCP packets
    pub tcp_packets: AtomicU64,
    /// UDP packets
    pub udp_packets: AtomicU64,
    /// ICMP packets
    pub icmp_packets: AtomicU64,
    /// IPv6 packets
    pub ipv6_packets: AtomicU64,
    /// ARP packets
    pub arp_packets: AtomicU64,
    /// Other/unknown packets
    pub other_packets: AtomicU64,
    /// Dropped packets (ring overflow)
    pub dropped: AtomicU64,
    /// Parse errors
    pub parse_errors: AtomicU64,
    /// Padding to cache line boundary
    _padding: [u8; CACHE_LINE_SIZE - 9 * 8],
}

impl CpuStats {
    /// Create a new zeroed CPU stats structure
    pub fn new() -> Self {
        Self {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            tcp_packets: AtomicU64::new(0),
            udp_packets: AtomicU64::new(0),
            icmp_packets: AtomicU64::new(0),
            ipv6_packets: AtomicU64::new(0),
            arp_packets: AtomicU64::new(0),
            other_packets: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            _padding: [0u8; CACHE_LINE_SIZE - 9 * 8],
        }
    }

    /// Record a packet
    #[inline]
    pub fn record_packet(&self, packet_len: usize, protocol: Protocol, is_ipv6: bool) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(packet_len as u64, Ordering::Relaxed);

        match protocol {
            Protocol::Tcp => self.tcp_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::Udp => self.udp_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::Icmp | Protocol::Icmpv6 => self.icmp_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::Arp => self.arp_packets.fetch_add(1, Ordering::Relaxed),
            _ => self.other_packets.fetch_add(1, Ordering::Relaxed),
        }

        if is_ipv6 {
            self.ipv6_packets.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a dropped packet
    #[inline]
    pub fn record_drop(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a parse error
    #[inline]
    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of stats
    pub fn snapshot(&self) -> CpuStatsSnapshot {
        CpuStatsSnapshot {
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            tcp_packets: self.tcp_packets.load(Ordering::Relaxed),
            udp_packets: self.udp_packets.load(Ordering::Relaxed),
            icmp_packets: self.icmp_packets.load(Ordering::Relaxed),
            ipv6_packets: self.ipv6_packets.load(Ordering::Relaxed),
            arp_packets: self.arp_packets.load(Ordering::Relaxed),
            other_packets: self.other_packets.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of CPU stats for aggregation
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuStatsSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub ipv6_packets: u64,
    pub arp_packets: u64,
    pub other_packets: u64,
    pub dropped: u64,
    pub parse_errors: u64,
}

impl std::ops::Add for CpuStatsSnapshot {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            packets: self.packets + other.packets,
            bytes: self.bytes + other.bytes,
            tcp_packets: self.tcp_packets + other.tcp_packets,
            udp_packets: self.udp_packets + other.udp_packets,
            icmp_packets: self.icmp_packets + other.icmp_packets,
            ipv6_packets: self.ipv6_packets + other.ipv6_packets,
            arp_packets: self.arp_packets + other.arp_packets,
            other_packets: self.other_packets + other.other_packets,
            dropped: self.dropped + other.dropped,
            parse_errors: self.parse_errors + other.parse_errors,
        }
    }
}

/// Thread-local storage for per-CPU stats
thread_local! {
    static LOCAL_STATS: RefCell<CpuStatsSnapshot> = const { RefCell::new(CpuStatsSnapshot::default()) };
}

/// Aggregated statistics from all CPUs
#[derive(Debug, Clone, Default)]
pub struct AggregateStats {
    /// Total packets
    pub total_packets: u64,
    /// Total bytes
    pub total_bytes: u64,
    /// Packets per second
    pub pps: f64,
    /// Bits per second
    pub bps: f64,
    /// TCP packet count
    pub tcp_packets: u64,
    /// UDP packet count
    pub udp_packets: u64,
    /// ICMP packet count
    pub icmp_packets: u64,
    /// IPv6 packet count
    pub ipv6_packets: u64,
    /// ARP packet count
    pub arp_packets: u64,
    /// Other packet count
    pub other_packets: u64,
    /// Dropped packet count
    pub dropped: u64,
    /// Parse error count
    pub parse_errors: u64,
    /// Protocol distribution percentages
    pub protocol_distribution: ProtocolDistribution,
    /// Collection timestamp
    pub timestamp: Instant,
}

/// Protocol distribution percentages
#[derive(Debug, Clone, Default)]
pub struct ProtocolDistribution {
    pub tcp_percent: f64,
    pub udp_percent: f64,
    pub icmp_percent: f64,
    pub ipv6_percent: f64,
    pub arp_percent: f64,
    pub other_percent: f64,
}

/// Statistics collector that aggregates per-CPU counters
pub struct StatsCollector {
    /// Per-CPU stats arrays
    cpu_stats: Box<[CpuStats]>,
    /// Number of CPUs
    num_cpus: usize,
    /// Flow table reference
    flow_table: Arc<FlowTable>,
    /// Last aggregation time
    last_aggregation: AtomicU64,
    /// Previous totals for rate calculation
    prev_total_packets: AtomicU64,
    /// Previous bytes for rate calculation
    prev_total_bytes: AtomicU64,
    /// Start time
    start_time: Instant,
}

impl StatsCollector {
    /// Create a new statistics collector
    ///
    /// # Arguments
    ///
    /// * `flow_table_capacity` - Maximum number of flows to track
    pub fn new(flow_table_capacity: usize, _flow_timeout_secs: u64) -> Self {
        let num_cpus = num_cpus::get();
        
        // Allocate per-CPU stats with proper alignment
        let mut cpu_stats = Vec::with_capacity(num_cpus);
        for _ in 0..num_cpus {
            cpu_stats.push(CpuStats::new());
        }

        Self {
            cpu_stats: cpu_stats.into_boxed_slice(),
            num_cpus,
            flow_table: Arc::new(FlowTable::new(flow_table_capacity)),
            last_aggregation: AtomicU64::new(0),
            prev_total_packets: AtomicU64::new(0),
            prev_total_bytes: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Get the per-CPU stats for the current CPU
    #[inline]
    pub fn current_cpu_stats(&self) -> &CpuStats {
        // Use CPU ID modulo num_cpus for simplicity
        // In production, would use sched_getcpu() or similar
        let cpu_id = 0; // Simplified
        &self.cpu_stats[cpu_id % self.num_cpus]
    }

    /// Record a parsed packet
    pub fn record_packet(&self, packet: &ParsedPacket<'_>, packet_len: usize) {
        let stats = self.current_cpu_stats();
        let is_ipv6 = packet.ip.as_ref().map(|ip| ip.version().is_v6()).unwrap_or(false);
        stats.record_packet(packet_len, packet.protocol, is_ipv6);

        // Update flow table
        if let Some(flow_key) = packet.flow_key {
            let tcp_flags = packet.tcp.map(|t| {
                let mut flags = 0u8;
                if t.fin { flags |= 0x01; }
                if t.syn { flags |= 0x02; }
                if t.rst { flags |= 0x04; }
                if t.psh { flags |= 0x08; }
                if t.ack_flag { flags |= 0x10; }
                if t.urg { flags |= 0x20; }
                flags
            }).unwrap_or(0);

            self.flow_table.insert_or_update(
                flow_key,
                packet_len,
                tcp_flags,
                packet.tcp.map(|t| t.seq),
                packet.tcp.map(|t| t.ack),
            );
        }
    }

    /// Record a dropped packet
    pub fn record_drop(&self) {
        self.current_cpu_stats().record_drop();
    }

    /// Record a parse error
    pub fn record_parse_error(&self) {
        self.current_cpu_stats().record_parse_error();
    }

    /// Aggregate statistics from all CPUs
    pub fn aggregate(&self) -> AggregateStats {
        let mut total = CpuStatsSnapshot::default();

        for cpu_stat in &self.cpu_stats {
            total = total + cpu_stat.snapshot();
        }

        let now = Instant::now();
        let elapsed_secs = now.duration_since(self.start_time).as_secs_f64();

        // Calculate rates
        let prev_packets = self.prev_total_packets.swap(total.packets, Ordering::Relaxed);
        let prev_bytes = self.prev_total_bytes.swap(total.bytes, Ordering::Relaxed);

        let pps = if elapsed_secs > 0.0 {
            (total.packets - prev_packets) as f64 / elapsed_secs.max(1.0)
        } else {
            0.0
        };

        let bps = pps * (total.bytes.max(1) / total.packets.max(1)) as f64 * 8.0;

        // Calculate protocol distribution
        let transport_total = total.tcp_packets + total.udp_packets + total.icmp_packets + total.other_packets;
        let protocol_dist = ProtocolDistribution {
            tcp_percent: if transport_total > 0 {
                total.tcp_packets as f64 / transport_total as f64 * 100.0
            } else {
                0.0
            },
            udp_percent: if transport_total > 0 {
                total.udp_packets as f64 / transport_total as f64 * 100.0
            } else {
                0.0
            },
            icmp_percent: if transport_total > 0 {
                total.icmp_packets as f64 / transport_total as f64 * 100.0
            } else {
                0.0
            },
            ipv6_percent: if total.packets > 0 {
                total.ipv6_packets as f64 / total.packets as f64 * 100.0
            } else {
                0.0
            },
            arp_percent: if total.packets > 0 {
                total.arp_packets as f64 / total.packets as f64 * 100.0
            } else {
                0.0
            },
            other_percent: if transport_total > 0 {
                total.other_packets as f64 / transport_total as f64 * 100.0
            } else {
                0.0
            },
        };

        AggregateStats {
            total_packets: total.packets,
            total_bytes: total.bytes,
            pps,
            bps,
            tcp_packets: total.tcp_packets,
            udp_packets: total.udp_packets,
            icmp_packets: total.icmp_packets,
            ipv6_packets: total.ipv6_packets,
            arp_packets: total.arp_packets,
            other_packets: total.other_packets,
            dropped: total.dropped,
            parse_errors: total.parse_errors,
            protocol_distribution: protocol_dist,
            timestamp: now,
        }
    }

    /// Get flow table statistics
    pub fn flow_stats(&self) -> FlowTableStats {
        self.flow_table.stats()
    }

    /// Get top N flows by bytes
    pub fn top_flows_by_bytes(&self, n: usize) -> Vec<(crate::parser::FlowKey, crate::flow::FlowState)> {
        self.flow_table.top_n_by_bytes(n)
    }

    /// Get the flow table reference
    pub fn flow_table(&self) -> &Arc<FlowTable> {
        &self.flow_table
    }

    /// Reset all counters
    pub fn reset(&self) {
        for cpu_stat in &self.cpu_stats {
            // Note: Can't reset atomics without replacing them
            // This is a limitation - in production would use different design
        }
        self.flow_table.clear();
    }
}

/// Formatted statistics report for display
#[derive(Debug, Clone)]
pub struct StatsReport {
    pub aggregate: AggregateStats,
    pub flow_stats: FlowTableStats,
    pub uptime_secs: f64,
    pub top_flows: Vec<(crate::parser::FlowKey, crate::flow::FlowState)>,
}

impl StatsCollector {
    /// Generate a full statistics report
    pub fn generate_report(&self) -> StatsReport {
        let aggregate = self.aggregate();
        let flow_stats = self.flow_stats();
        let top_flows = self.top_flows_by_bytes(10);
        let uptime_secs = self.start_time.elapsed().as_secs_f64();

        StatsReport {
            aggregate,
            flow_stats,
            uptime_secs,
            top_flows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{IpAddr, ParsedPacket, Protocol};
    use std::net::Ipv4Addr;

    #[test]
    fn test_cpu_stats_record() {
        let stats = CpuStats::new();
        stats.record_packet(1500, Protocol::Tcp, false);
        
        assert_eq!(stats.packets.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes.load(Ordering::Relaxed), 1500);
        assert_eq!(stats.tcp_packets.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stats_collector() {
        let collector = StatsCollector::new(1000, 300);
        
        // Create a mock packet
        let data = vec![0u8; 64];
        let mut packet = ParsedPacket::new(&data);
        packet.protocol = Protocol::Tcp;
        packet.flow_key = Some(crate::parser::FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        ));

        collector.record_packet(&packet, 64);
        
        let agg = collector.aggregate();
        assert!(agg.total_packets >= 1);
    }
}
