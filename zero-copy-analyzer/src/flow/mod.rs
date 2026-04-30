//! Flow tracking module for network flow state management.
//!
//! This module provides a concurrent flow hash table with efficient
//! lookup, insertion, and expiration using a hierarchical timing wheel.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use ahash::AHashMap;
use dashmap::DashMap;
use smallvec::SmallVec;

use crate::parser::{FlowKey, IpAddr, Protocol};

pub mod table;
pub mod timer_wheel;

pub use table::FlowTable;
pub use timer_wheel::TimingWheel;

/// Flow state information
#[derive(Debug, Clone)]
pub struct FlowState {
    /// Number of packets in this flow
    pub packet_count: u64,
    /// Total bytes in this flow
    pub byte_count: u64,
    /// First packet timestamp (nanoseconds since epoch)
    pub first_seen_ns: u64,
    /// Last packet timestamp (nanoseconds since epoch)
    pub last_seen_ns: u64,
    /// TCP flags seen (bitmask)
    pub tcp_flags: u8,
    /// Initial sequence number (for RTT estimation)
    pub initial_seq: Option<u32>,
    /// Last acknowledgment number (for RTT estimation)
    pub last_ack: Option<u32>,
}

impl Default for FlowState {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowState {
    /// Create a new flow state
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            packet_count: 0,
            byte_count: 0,
            first_seen_ns: now,
            last_seen_ns: now,
            tcp_flags: 0,
            initial_seq: None,
            last_ack: None,
        }
    }

    /// Update flow state with a new packet
    pub fn update(&mut self, packet_len: usize, tcp_flags: u8, seq: Option<u32>, ack: Option<u32>) {
        self.packet_count += 1;
        self.byte_count += packet_len as u64;
        
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.last_seen_ns = now;

        // Merge TCP flags
        self.tcp_flags |= tcp_flags;

        // Track sequence/ack for RTT estimation
        if let Some(s) = seq {
            if self.initial_seq.is_none() {
                self.initial_seq = Some(s);
            }
        }
        self.last_ack = ack;
    }

    /// Check if flow is idle beyond timeout
    pub fn is_idle(&self, timeout_ns: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        now.saturating_sub(self.last_seen_ns) > timeout_ns
    }

    /// Get flow duration in nanoseconds
    pub fn duration_ns(&self) -> u64 {
        self.last_seen_ns.saturating_sub(self.first_seen_ns)
    }

    /// Get average packet rate (packets per second)
    pub fn packets_per_second(&self) -> f64 {
        let duration_secs = self.duration_ns() as f64 / 1_000_000_000.0;
        if duration_secs > 0.0 {
            self.packet_count as f64 / duration_secs
        } else {
            self.packet_count as f64
        }
    }

    /// Get average bit rate
    pub fn bits_per_second(&self) -> f64 {
        self.packets_per_second() * (self.byte_count as f64 * 8.0)
    }

    /// Check if this is a complete TCP connection (SYN, SYN-ACK, ACK, FIN/RST)
    pub fn is_complete_tcp_connection(&self) -> bool {
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        const FIN: u8 = 0x01;
        const RST: u8 = 0x04;

        let has_syn = (self.tcp_flags & SYN) != 0;
        let has_ack = (self.tcp_flags & ACK) != 0;
        let has_fin = (self.tcp_flags & FIN) != 0;
        let has_rst = (self.tcp_flags & RST) != 0;

        has_syn && has_ack && (has_fin || has_rst)
    }
}

/// Statistics about the flow table
#[derive(Debug, Default)]
pub struct FlowTableStats {
    /// Total number of flows
    pub total_flows: u64,
    /// Active flows (not expired)
    pub active_flows: u64,
    /// Flows expired this interval
    pub expired_flows: u64,
    /// Total packets tracked
    pub total_packets: u64,
    /// Total bytes tracked
    pub total_bytes: u64,
    /// Hash collisions
    pub collisions: u64,
    /// Load factor (0.0 - 1.0)
    pub load_factor: f64,
}

/// Flow entry with metadata
pub struct FlowEntry {
    /// Flow key
    pub key: FlowKey,
    /// Flow state
    pub state: FlowState,
    /// Hash value (cached for rehashing)
    pub hash: u64,
}

impl FlowEntry {
    /// Create a new flow entry
    pub fn new(key: FlowKey, hash: u64) -> Self {
        Self {
            key,
            state: FlowState::new(),
            hash,
        }
    }
}
