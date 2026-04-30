//! Prometheus metrics output backend.
//!
//! This module provides a Prometheus-compatible HTTP server that exposes
//! network statistics as metrics on the /metrics endpoint.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use prometheus::{CounterVec, Encoder, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::output::{OutputBackend, OutputError, OutputResult};
use crate::parser::ParsedPacket;
use crate::stats::AggregateStats;

/// Default Prometheus metrics port
const DEFAULT_PROMETHEUS_PORT: u16 = 9090;

/// Prometheus metrics registry wrapper
pub struct PrometheusMetrics {
    /// Prometheus registry
    pub registry: Registry,
    /// Total packets counter by protocol
    pub packets_total: CounterVec,
    /// Total bytes counter by protocol
    pub bytes_total: CounterVec,
    /// Active flows gauge
    pub active_flows: IntGauge,
    /// Dropped packets counter
    pub dropped_packets: IntCounterVec,
    /// Packets per second gauge by protocol
    pub pps_gauge: IntGaugeVec,
    /// Bytes per second gauge by protocol
    pub bps_gauge: IntGaugeVec,
}

impl PrometheusMetrics {
    /// Create a new Prometheus metrics registry
    pub fn new() -> Result<Self, OutputError> {
        let registry = Registry::new();

        // Packets total counter
        let packets_total_opts = Opts::new(
            "network_packets_total",
            "Total number of packets received",
        );
        let packets_total = CounterVec::new(packets_total_opts, &["protocol"])?;
        registry.register(Box::new(packets_total.clone()))?;

        // Bytes total counter
        let bytes_total_opts = Opts::new(
            "network_bytes_total",
            "Total number of bytes received",
        );
        let bytes_total = CounterVec::new(bytes_total_opts, &["protocol"])?;
        registry.register(Box::new(bytes_total.clone()))?;

        // Active flows gauge
        let active_flows = IntGauge::new(
            "network_active_flows",
            "Current number of active flows",
        )?;
        registry.register(Box::new(active_flows.clone()))?;

        // Dropped packets counter
        let dropped_opts = Opts::new(
            "network_dropped_packets_total",
            "Total number of dropped packets",
        );
        let dropped_packets = IntCounterVec::new(dropped_opts, &["reason"])?;
        registry.register(Box::new(dropped_packets.clone()))?;

        // PPS gauge
        let pps_opts = Opts::new("network_pps", "Packets per second");
        let pps_gauge = IntGaugeVec::new(pps_opts, &["protocol"])?;
        registry.register(Box::new(pps_gauge.clone()))?;

        // BPS gauge
        let bps_opts = Opts::new("network_bps", "Bytes per second");
        let bps_gauge = IntGaugeVec::new(bps_opts, &["protocol"])?;
        registry.register(Box::new(bps_gauge.clone()))?;

        Ok(Self {
            registry,
            packets_total,
            bytes_total,
            active_flows,
            dropped_packets,
            pps_gauge,
            bps_gauge,
        })
    }

    /// Update metrics from aggregated stats
    pub fn update(&self, stats: &AggregateStats) {
        // Update packet counters
        self.packets_total
            .with_label_values(&["tcp"])
            .inc_by(stats.tcp_packets);
        self.packets_total
            .with_label_values(&["udp"])
            .inc_by(stats.udp_packets);
        self.packets_total
            .with_label_values(&["icmp"])
            .inc_by(stats.icmp_packets);
        self.packets_total
            .with_label_values(&["ipv6"])
            .inc_by(stats.ipv6_packets);
        self.packets_total
            .with_label_values(&["arp"])
            .inc_by(stats.arp_packets);
        self.packets_total
            .with_label_values(&["other"])
            .inc_by(stats.other_packets);

        // Update byte counters (approximate based on protocol distribution)
        let total_packets = stats.total_packets.max(1);
        self.bytes_total
            .with_label_values(&["tcp"])
            .inc_by((stats.tcp_packets as f64 / total_packets as f64 * stats.total_bytes as f64) as u64);
        self.bytes_total
            .with_label_values(&["udp"])
            .inc_by((stats.udp_packets as f64 / total_packets as f64 * stats.total_bytes as f64) as u64);
        self.bytes_total
            .with_label_values(&["icmp"])
            .inc_by((stats.icmp_packets as f64 / total_packets as f64 * stats.total_bytes as f64) as u64);

        // Update gauges
        self.pps_gauge
            .with_label_values(&["total"])
            .set(stats.pps as i64);
        self.bps_gauge
            .with_label_values(&["total"])
            .set((stats.bps / 8.0) as i64);

        // Update dropped counter
        if stats.dropped > 0 {
            self.dropped_packets
                .with_label_values(&["ring_overflow"])
                .inc_by(stats.dropped);
        }
    }

    /// Get metrics in Prometheus text format
    pub fn gather(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            error!("Failed to encode metrics: {}", e);
            return String::new();
        }

        String::from_utf8_lossy(&buffer).to_string()
    }
}

impl Default for PrometheusMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create Prometheus metrics")
    }
}

/// State for the Prometheus HTTP server
#[derive(Clone)]
pub struct PrometheusState {
    pub metrics: Arc<PrometheusMetrics>,
}

/// Prometheus output backend
pub struct PrometheusOutput {
    /// Metrics registry
    metrics: Arc<PrometheusMetrics>,
    /// Last report time
    last_report: Option<Instant>,
    /// Report interval
    report_interval_secs: u64,
    /// Server handle for shutdown
    _server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl PrometheusOutput {
    /// Create a new Prometheus output with the specified port
    ///
    /// # Arguments
    ///
    /// * `port` - Port to listen on for Prometheus scrapes
    pub fn new(port: u16) -> Result<Self, OutputError> {
        let metrics = Arc::new(PrometheusMetrics::new()?);
        let state = PrometheusState {
            metrics: Arc::clone(&metrics),
        };

        // Build router
        let app = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(|| async { StatusCode::OK }))
            .with_state(state);

        // Start server in background
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        
        let server_handle = tokio::spawn(async move {
            info!("Starting Prometheus metrics server on port {}", port);
            
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, app).await {
                        error!("Prometheus server error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to bind Prometheus server: {}", e);
                }
            }
        });

        Ok(Self {
            metrics,
            last_report: None,
            report_interval_secs: 1,
            _server_handle: Some(server_handle),
        })
    }

    /// Set the report interval
    pub fn with_report_interval(mut self, secs: u64) -> Self {
        self.report_interval_secs = secs;
        self
    }
}

/// Handler for /metrics endpoint
async fn metrics_handler(State(state): State<PrometheusState>) -> impl IntoResponse {
    let metrics_text = state.metrics.gather();
    metrics_text
}

impl OutputBackend for PrometheusOutput {
    fn emit(&mut self, _packet: &ParsedPacket<'_>) {
        // Individual packets are not emitted to Prometheus
        // Only aggregated stats are exposed
    }

    fn report_stats(&mut self, stats: &AggregateStats) -> OutputResult<()> {
        let now = Instant::now();

        // Check if we should update
        if let Some(last) = self.last_report {
            if now.duration_since(last).as_secs() < self.report_interval_secs {
                return Ok(());
            }
        }
        self.last_report = Some(now);

        // Update Prometheus metrics
        self.metrics.update(stats);

        Ok(())
    }

    fn flush(&mut self) -> OutputResult<()> {
        // No flushing needed for Prometheus
        Ok(())
    }

    fn name(&self) -> &str {
        "prometheus"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_metrics_creation() {
        let metrics = PrometheusMetrics::new().unwrap();
        assert!(metrics.gather().contains("network_packets_total"));
    }

    #[test]
    fn test_prometheus_metrics_update() {
        let metrics = PrometheusMetrics::new().unwrap();
        
        let stats = AggregateStats {
            total_packets: 1000,
            total_bytes: 1500000,
            pps: 1000.0,
            bps: 12000000.0,
            tcp_packets: 800,
            udp_packets: 150,
            icmp_packets: 50,
            ipv6_packets: 100,
            arp_packets: 0,
            other_packets: 0,
            dropped: 0,
            parse_errors: 0,
            protocol_distribution: Default::default(),
            timestamp: Instant::now(),
        };

        metrics.update(&stats);
        
        let output = metrics.gather();
        assert!(output.contains("network_packets_total"));
        assert!(output.contains("network_bytes_total"));
    }
}
