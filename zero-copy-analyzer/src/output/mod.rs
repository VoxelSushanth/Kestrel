//! Output backend module for emitting statistics and parsed packets.
//!
//! This module provides pluggable output backends including console, JSON,
//! and Prometheus metrics endpoints.

use std::io::{self, Write};
use std::sync::Arc;

use thiserror::Error;

use crate::parser::ParsedPacket;
use crate::stats::{AggregateStats, StatsReport};

pub mod console;
pub mod json;
pub mod prometheus;

pub use console::ConsoleOutput;
pub use json::JsonOutput;
pub use prometheus::PrometheusOutput;

/// Errors that can occur during output operations
#[derive(Debug, Error)]
pub enum OutputError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// HTTP server error
    #[error("HTTP server error: {0}")]
    Http(String),

    /// Channel send error
    #[error("Channel send error: {0}")]
    ChannelSend(String),
}

/// Result type for output operations
pub type OutputResult<T> = Result<T, OutputError>;

/// Trait for output backends
///
/// Implementors provide different ways to emit parsed packet data
/// and statistics (console, JSON, Prometheus, etc.)
///
/// # Examples
///
/// ```no_run
/// use zero_copy_analyzer::output::{OutputBackend, ConsoleOutput};
/// use zero_copy_analyzer::parser::ParsedPacket;
///
/// let mut output = ConsoleOutput::new(std::io::stdout());
/// // Emit packets and stats...
/// ```
pub trait OutputBackend: Send + Sync {
    /// Emit a parsed packet
    ///
    /// # Arguments
    ///
    /// * `packet` - Parsed packet to emit
    fn emit(&mut self, packet: &ParsedPacket<'_>);

    /// Emit aggregated statistics
    ///
    /// # Arguments
    ///
    /// * `stats` - Aggregated statistics to report
    fn report_stats(&mut self, stats: &AggregateStats) -> OutputResult<()>;

    /// Flush any buffered output
    fn flush(&mut self) -> OutputResult<()>;

    /// Get the output name/description
    fn name(&self) -> &str;
}

/// Packet record for serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PacketRecord {
    /// Timestamp in nanoseconds since epoch
    pub timestamp_ns: u64,
    /// Capture length
    pub capture_len: usize,
    /// Protocol
    pub protocol: String,
    /// Source IP (if available)
    pub src_ip: Option<String>,
    /// Destination IP (if available)
    pub dst_ip: Option<String>,
    /// Source port (if available)
    pub src_port: Option<u16>,
    /// Destination port (if available)
    pub dst_port: Option<u16>,
    /// TCP flags (if TCP)
    pub tcp_flags: Option<u8>,
    /// Payload length
    pub payload_len: usize,
}

impl From<&ParsedPacket<'_>> for PacketRecord {
    fn from(packet: &ParsedPacket<'_>) -> Self {
        use std::time::SystemTime;
        
        let timestamp_ns = packet.timestamp_ns.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64
        });

        let src_ip = packet.src_ip().map(|ip| ip.to_string());
        let dst_ip = packet.dst_ip().map(|ip| ip.to_string());
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();
        let tcp_flags = packet.tcp.map(|t| {
            let mut flags = 0u8;
            if t.fin { flags |= 0x01; }
            if t.syn { flags |= 0x02; }
            if t.rst { flags |= 0x04; }
            if t.psh { flags |= 0x08; }
            if t.ack_flag { flags |= 0x10; }
            if t.urg { flags |= 0x20; }
            flags
        });

        Self {
            timestamp_ns,
            capture_len: packet.capture_len,
            protocol: format!("{:?}", packet.protocol),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            tcp_flags,
            payload_len: packet.payload_len,
        }
    }
}

/// Statistics record for serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatsRecord {
    /// Timestamp
    pub timestamp: String,
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
    /// Dropped packet count
    pub dropped: u64,
    /// Flow count
    pub flow_count: u64,
    /// Protocol distribution
    pub protocol_distribution: ProtocolDistributionRecord,
}

/// Protocol distribution percentages
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtocolDistributionRecord {
    pub tcp_percent: f64,
    pub udp_percent: f64,
    pub icmp_percent: f64,
    pub ipv6_percent: f64,
}

impl From<&StatsReport> for StatsRecord {
    fn from(report: &StatsReport) -> Self {
        use chrono::{DateTime, Utc};
        
        let now: DateTime<Utc> = Utc::now();
        
        Self {
            timestamp: now.to_rfc3339(),
            total_packets: report.aggregate.total_packets,
            total_bytes: report.aggregate.total_bytes,
            pps: report.aggregate.pps,
            bps: report.aggregate.bps,
            tcp_packets: report.aggregate.tcp_packets,
            udp_packets: report.aggregate.udp_packets,
            icmp_packets: report.aggregate.icmp_packets,
            ipv6_packets: report.aggregate.ipv6_packets,
            dropped: report.aggregate.dropped,
            flow_count: report.flow_stats.total_flows,
            protocol_distribution: ProtocolDistributionRecord {
                tcp_percent: report.aggregate.protocol_distribution.tcp_percent,
                udp_percent: report.aggregate.protocol_distribution.udp_percent,
                icmp_percent: report.aggregate.protocol_distribution.icmp_percent,
                ipv6_percent: report.aggregate.protocol_distribution.ipv6_percent,
            },
        }
    }
}
