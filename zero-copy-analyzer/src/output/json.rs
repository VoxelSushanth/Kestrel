//! JSON output backend for machine-readable statistics.
//!
//! This module provides JSON-formatted output suitable for logging
//! pipelines and downstream processing.

use std::io::{self, Stdout, Write};
use std::time::Instant;

use crate::output::{OutputBackend, OutputError, OutputResult, PacketRecord, StatsRecord};
use crate::parser::ParsedPacket;
use crate::stats::{AggregateStats, FlowTableStats, StatsReport};

/// JSON output backend
pub struct JsonOutput<W: Write> {
    /// Output writer
    writer: W,
    /// Last stats report time
    last_report: Option<Instant>,
    /// Report interval in seconds
    report_interval_secs: u64,
    /// Whether to output packets as NDJSON
    emit_packets: bool,
}

impl JsonOutput<Stdout> {
    /// Create a new JSON output writing to stdout
    pub fn new_stdout() -> Self {
        Self::new(io::stdout())
    }
}

impl<W: Write> JsonOutput<W> {
    /// Create a new JSON output with the specified writer
    ///
    /// # Arguments
    ///
    /// * `writer` - Output writer (e.g., stdout, file)
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            last_report: None,
            report_interval_secs: 1,
            emit_packets: false,
        }
    }

    /// Set the stats report interval in seconds
    pub fn with_report_interval(mut self, secs: u64) -> Self {
        self.report_interval_secs = secs;
        self
    }

    /// Enable packet emission (NDJSON format)
    pub fn with_packets(mut self, emit: bool) -> Self {
        self.emit_packets = emit;
        self
    }

    /// Emit a packet record as JSON line
    fn emit_packet_json(&mut self, packet: &ParsedPacket<'_>) -> OutputResult<()> {
        if !self.emit_packets {
            return Ok(());
        }

        let record = PacketRecord::from(packet);
        let json = serde_json::to_string(&record)?;
        writeln!(self.writer, "{}", json)?;
        Ok(())
    }

    /// Emit a stats report as JSON
    fn emit_stats_json(&mut self, report: &StatsReport) -> OutputResult<()> {
        let now = Instant::now();

        // Check if we should report
        if let Some(last) = self.last_report {
            if now.duration_since(last).as_secs() < self.report_interval_secs {
                return Ok(());
            }
        }
        self.last_report = Some(now);

        let record = StatsRecord::from(report);
        let json = serde_json::to_string(&record)?;
        writeln!(self.writer, "{}", json)?;
        self.writer.flush()?;

        Ok(())
    }
}

impl<W: Write> OutputBackend for JsonOutput<W> {
    fn emit(&mut self, packet: &ParsedPacket<'_>) {
        let _ = self.emit_packet_json(packet);
    }

    fn report_stats(&mut self, stats: &AggregateStats) -> OutputResult<()> {
        let report = StatsReport {
            aggregate: stats.clone(),
            flow_stats: FlowTableStats::default(),
            uptime_secs: 0.0,
            top_flows: Vec::new(),
        };
        self.emit_stats_json(&report)
    }

    fn flush(&mut self) -> OutputResult<()> {
        self.writer.flush()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "json"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{IpAddr, Protocol};
    use std::net::Ipv4Addr;

    #[test]
    fn test_json_output_creation() {
        let output = JsonOutput::new(Vec::new());
        assert_eq!(output.name(), "json");
    }

    #[test]
    fn test_json_packet_serialization() {
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
        packet.capture_len = 64;

        let record = PacketRecord::from(&packet);
        let json = serde_json::to_string(&record).unwrap();

        assert!(json.contains("tcp"));
        assert!(json.contains("192.168.1.1"));
    }
}
