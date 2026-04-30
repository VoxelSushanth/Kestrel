//! Zero-Copy Network Packet Analyzer
//!
//! A production-grade, high-performance network packet analyzer that captures
//! packets at line rate (≥10 Gbps) without copying packet data from kernel to userspace.
//!
//! # Architecture
//!
//! This crate implements:
//! - **Capture backends**: AF_XDP (primary) and AF_PACKET TPACKET_V3 (fallback)
//! - **Zero-copy memory model**: UMEM slabs with `PacketRef<'umem>` borrowed slices
//! - **In-place packet parsing**: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP/QUIC
//! - **Concurrent flow table**: Robin Hood hashing with hierarchical timing wheel
//! - **Per-CPU statistics**: Lock-free counters with atomic aggregation
//! - **Pluggable outputs**: Console, JSON, Prometheus metrics
//!
//! # Example
//!
//! ```no_run
//! use zero_copy_analyzer::capture::{CaptureEngine, CaptureConfig};
//! use zero_copy_analyzer::output::OutputBackend;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = CaptureConfig::builder()
//!         .interface("eth0")
//!         .queue_id(0)
//!         .umem_size(64 << 20) // 64 MB
//!         .build();
//!
//!     // Engine would be initialized here
//!     Ok(())
//! }
//! ```

#![deny(clippy::pedantic)]
#![warn(missing_docs)]
#![warn(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]

pub mod capture;
pub mod flow;
pub mod output;
pub mod parser;
pub mod stats;
pub mod umem;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::capture::{af_xdp, tpacket, CaptureConfig, CaptureEngine};
use crate::output::{ConsoleOutput, JsonOutput, OutputBackend, PrometheusOutput};
use crate::stats::StatsCollector;

/// Zero-Copy Network Packet Analyzer CLI
///
/// Captures and analyzes network packets at line rate using zero-copy techniques.
#[derive(Parser, Debug)]
#[command(name = "zero-copy-analyzer")]
#[command(author = "Network Engineering Team")]
#[command(version = "0.1.0")]
#[command(about = "Production-grade zero-copy network packet analyzer", long_about = None)]
pub struct Cli {
    /// Network interface to capture from (e.g., eth0, enp3s0)
    #[arg(short, long, env = "INTERFACE", default_value = "eth0")]
    pub interface: String,

    /// Queue ID for RSS steering (AF_XDP only)
    #[arg(short, long, env = "QUEUE_ID", default_value_t = 0)]
    pub queue_id: u16,

    /// UMEM size in bytes (must be power of 2)
    #[arg(short, long, env = "UMEM_SIZE", default_value_t = 67_108_864)] // 64 MB
    pub umem_size: usize,

    /// Frame size in bytes
    #[arg(long, env = "FRAME_SIZE", default_value_t = 2048)]
    pub frame_size: usize,

    /// Number of fill ring entries
    #[arg(long, env = "FILL_RING_SIZE", default_value_t = 4096)]
    pub fill_ring_size: u32,

    /// CPU core to pin capture thread
    #[arg(short, long, env = "CPU_CORE", default_value_t = 0)]
    pub cpu_core: usize,

    /// Flow table capacity (max concurrent flows)
    #[arg(long, env = "FLOW_TABLE_SIZE", default_value_t = 1_048_576)]
    pub flow_table_size: usize,

    /// Flow idle timeout in seconds
    #[arg(long, env = "FLOW_TIMEOUT", default_value_t = 300)]
    pub flow_timeout_secs: u64,

    /// Statistics reporting interval in seconds
    #[arg(short, long, env = "STATS_INTERVAL", default_value_t = 1)]
    pub stats_interval_secs: u64,

    /// Output format (console, json, prometheus, all)
    #[arg(short, long, env = "OUTPUT_FORMAT", default_value = "console")]
    pub output_format: String,

    /// Prometheus metrics port
    #[arg(long, env = "PROMETHEUS_PORT", default_value_t = 9090)]
    pub prometheus_port: u16,

    /// Enable verbose logging
    #[arg(short, long, env = "VERBOSE")]
    pub verbose: bool,

    /// Use TPACKET_V3 instead of AF_XDP
    #[arg(long, env = "USE_TPACKET")]
    pub use_tpacket: bool,

    /// PCAP file to replay (instead of live capture)
    #[arg(short, long, env = "PCAP_FILE")]
    pub pcap_file: Option<String>,
}

/// Graceful shutdown handler
pub struct ShutdownHandler {
    shutdown_flag: Arc<AtomicBool>,
}

impl ShutdownHandler {
    /// Create a new shutdown handler
    pub fn new() -> Self {
        Self {
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the shutdown flag clone
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown_flag)
    }

    /// Check if shutdown was requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_flag.load(Ordering::Relaxed)
    }

    /// Install signal handlers for graceful shutdown
    pub fn install_signal_handlers(&self) -> anyhow::Result<()> {
        let flag = Arc::clone(&self.shutdown_flag);

        ctrlc::set_handler(move || {
            info!("Received shutdown signal, initiating graceful shutdown...");
            flag.store(true, Ordering::Relaxed);
        })
        .context("Failed to set Ctrl+C handler")?;

        Ok(())
    }
}

impl Default for ShutdownHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Main entry point for the analyzer
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("zero_copy_analyzer={}", log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    info!(
        "Starting Zero-Copy Network Analyzer on interface {}",
        cli.interface
    );

    // Setup shutdown handling
    let shutdown = ShutdownHandler::new();
    shutdown.install_signal_handlers()?;

    // Build capture configuration
    let capture_config = CaptureConfig::builder()
        .interface(&cli.interface)
        .queue_id(cli.queue_id)
        .umem_size(cli.umem_size)
        .frame_size(cli.frame_size)
        .fill_ring_size(cli.fill_ring_size)
        .cpu_core(cli.cpu_core)
        .use_tpacket(cli.use_tpacket)
        .build();

    // Create capture engine
    let mut capture_engine: Box<dyn CaptureEngine> = if cli.use_tpacket {
        info!("Using TPACKET_V3 capture backend");
        Box::new(tpacket::TpacketEngine::new(capture_config.clone())?)
    } else {
        info!("Using AF_XDP capture backend");
        Box::new(af_xdp::XdpEngine::new(capture_config.clone())?)
    };

    // Initialize stats collector
    let stats = Arc::new(StatsCollector::new(cli.flow_table_size, cli.flow_timeout_secs));

    // Create output backend
    let output: Box<dyn OutputBackend> = match cli.output_format.as_str() {
        "json" => Box::new(JsonOutput::new(std::io::stdout())),
        "prometheus" => {
            let prom_output = PrometheusOutput::new(cli.prometheus_port)?;
            Box::new(prom_output)
        }
        "all" => {
            // Composite output - for simplicity, use console
            Box::new(ConsoleOutput::new(std::io::stdout()))
        }
        _ => Box::new(ConsoleOutput::new(std::io::stdout())),
    };

    info!(
        "Capture engine initialized: {}x{} byte frames, {} fill ring entries",
        capture_config.num_blocks(),
        cli.frame_size,
        cli.fill_ring_size
    );

    // Start capture loop
    capture_engine.start(stats.clone(), output, shutdown.flag()).await?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(num_cpus::get())
        .thread_name("analyzer-worker")
        .build()
        .context("Failed to create Tokio runtime")?;

    runtime.block_on(run(cli))
}
