//! Console output backend for human-readable statistics.
//!
//! This module provides a simple console-based output that formats
//! and displays statistics in a human-readable format.

use std::io::{self, Stdout, Write};
use std::time::Instant;

use crate::output::{OutputBackend, OutputError, OutputResult};
use crate::parser::ParsedPacket;
use crate::stats::{AggregateStats, StatsReport};

/// Console output backend
pub struct ConsoleOutput<W: Write> {
    /// Output writer
    writer: W,
    /// Last stats report time
    last_report: Option<Instant>,
    /// Report interval
    report_interval_secs: u64,
    /// Packet counter for sampling
    packet_count: u64,
    /// Whether to print every packet (debug mode)
    verbose: bool,
}

impl ConsoleOutput<Stdout> {
    /// Create a new console output writing to stdout
    pub fn new_stdout() -> Self {
        Self::new(io::stdout())
    }
}

impl<W: Write> ConsoleOutput<W> {
    /// Create a new console output with the specified writer
    ///
    /// # Arguments
    ///
    /// * `writer` - Output writer (e.g., stdout, file)
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            last_report: None,
            report_interval_secs: 1,
            packet_count: 0,
            verbose: false,
        }
    }

    /// Set the stats report interval in seconds
    pub fn with_report_interval(mut self, secs: u64) -> Self {
        self.report_interval_secs = secs;
        self
    }

    /// Enable verbose mode (print every packet)
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Format and write a statistics report
    fn write_report(&mut self, report: &StatsReport) -> OutputResult<()> {
        let now = Instant::now();
        
        // Check if we should report
        if let Some(last) = self.last_report {
            if now.duration_since(last).as_secs() < self.report_interval_secs {
                return Ok(());
            }
        }
        self.last_report = Some(now);

        writeln!(self.writer, "\n{}", "=".repeat(60))?;
        writeln!(self.writer, "Zero-Copy Network Analyzer - Statistics Report")?;
        writeln!(self.writer, "{}", "=".repeat(60))?;
        writeln!(self.writer)?;

        // Overall stats
        writeln!(
            self.writer,
            "Uptime: {:.2}s | Flows: {} | Packets: {} | Bytes: {}",
            report.uptime_secs,
            report.flow_stats.total_flows,
            report.aggregate.total_packets,
            report.aggregate.total_bytes
        )?;
        writeln!(
            self.writer,
            "Rate: {:.2} pps | {:.2} Mbps",
            report.aggregate.pps,
            report.aggregate.bps / 1_000_000.0
        )?;
        writeln!(self.writer)?;

        // Protocol distribution
        writeln!(self.writer, "Protocol Distribution:")?;
        writeln!(
            self.writer,
            "  TCP:  {:7.2}% ({})",
            report.aggregate.protocol_distribution.tcp_percent,
            report.aggregate.tcp_packets
        )?;
        writeln!(
            self.writer,
            "  UDP:  {:7.2}% ({})",
            report.aggregate.protocol_distribution.udp_percent,
            report.aggregate.udp_packets
        )?;
        writeln!(
            self.writer,
            "  ICMP: {:7.2}% ({})",
            report.aggregate.protocol_distribution.icmp_percent,
            report.aggregate.icmp_packets
        )?;
        writeln!(
            self.writer,
            "  IPv6: {:7.2}% ({})",
            report.aggregate.protocol_distribution.ipv6_percent,
            report.aggregate.ipv6_packets
        )?;
        writeln!(
            self.writer,
            "  ARP:  {:7.2}% ({})",
            report.aggregate.protocol_distribution.arp_percent,
            report.aggregate.arp_packets
        )?;
        writeln!(self.writer)?;

        // Top flows
        if !report.top_flows.is_empty() {
            writeln!(self.writer, "Top 10 Flows by Bytes:")?;
            writeln!(self.writer, "{:<8} {:<44} {:>12} {:>10}", "#", "Flow", "Bytes", "Packets")?;
            writeln!(self.writer, "{}", "-".repeat(80))?;
            
            for (i, (key, state)) in report.top_flows.iter().take(10).enumerate() {
                let flow_str = format!(
                    "{}:{} → {}:{}",
                    key.src_ip, key.src_port, key.dst_ip, key.dst_port
                );
                writeln!(
                    self.writer,
                    "{:<8} {:<44} {:>12} {:>10}",
                    i + 1,
                    flow_str,
                    state.byte_count,
                    state.packet_count
                )?;
            }
            writeln!(self.writer)?;
        }

        // Errors
        if report.aggregate.dropped > 0 || report.aggregate.parse_errors > 0 {
            writeln!(self.writer, "Errors:")?;
            writeln!(self.writer, "  Dropped:      {}", report.aggregate.dropped)?;
            writeln!(self.writer, "  Parse errors: {}", report.aggregate.parse_errors)?;
            writeln!(self.writer)?;
        }

        writeln!(self.writer, "{}", "=".repeat(60))?;
        self.writer.flush()?;

        Ok(())
    }
}

impl<W: Write> OutputBackend for ConsoleOutput<W> {
    fn emit(&mut self, packet: &ParsedPacket<'_>) {
        self.packet_count += 1;

        if self.verbose {
            let _ = writeln!(
                self.writer,
                "[{}] {}:{} → {}:{} ({:?}, {} bytes)",
                self.packet_count,
                packet.src_ip().map(|ip| ip.to_string()).unwrap_or_else(|| "-".to_string()),
                packet.src_port().map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
                packet.dst_ip().map(|ip| ip.to_string()).unwrap_or_else(|| "-".to_string()),
                packet.dst_port().map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
                packet.protocol,
                packet.capture_len
            );
        }
    }

    fn report_stats(&mut self, stats: &AggregateStats) -> OutputResult<()> {
        // For console, we create a minimal report
        let report = StatsReport {
            aggregate: stats.clone(),
            flow_stats: Default::default(),
            uptime_secs: 0.0,
            top_flows: Vec::new(),
        };
        self.write_report(&report)
    }

    fn flush(&mut self) -> OutputResult<()> {
        self.writer.flush()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "console"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{IpAddr, Protocol};
    use std::net::Ipv4Addr;

    #[test]
    fn test_console_output_creation() {
        let output = ConsoleOutput::new(Vec::new());
        assert_eq!(output.name(), "console");
    }

    #[test]
    fn test_console_output_emit() {
        let mut output = ConsoleOutput::new(Vec::new());
        
        let data = vec![0u8; 64];
        let mut packet = ParsedPacket::new(&data);
        packet.protocol = Protocol::Tcp;
        
        output.emit(&packet);
        assert_eq!(output.packet_count, 1);
    }
}
