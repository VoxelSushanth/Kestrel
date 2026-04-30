//! Capture engine module providing trait abstraction for packet capture backends.
//!
//! This module defines the `CaptureEngine` trait and configuration types that allow
//! swappable capture backends (AF_XDP, AF_PACKET TPACKET_V3) at runtime.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Context;
use thiserror::Error;

use crate::output::OutputBackend;
use crate::stats::StatsCollector;

/// Errors that can occur during packet capture
#[derive(Debug, Error)]
pub enum CaptureError {
    /// Failed to create socket
    #[error("Failed to create socket: {0}")]
    SocketCreation(#[source] std::io::Error),

    /// Failed to bind socket
    #[error("Failed to bind socket: {0}")]
    BindError(#[source] std::io::Error),

    /// Failed to set socket options
    #[error("Failed to set socket option: {0}")]
    SocketOption(#[source] std::io::Error),

    /// Interface not found
    #[error("Network interface '{0}' not found")]
    InterfaceNotFound(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Ring buffer overflow
    #[error("Ring buffer overflow - packets dropped")]
    RingOverflow,

    /// XDP program load failed
    #[error("Failed to load XDP program: {0}")]
    XdpLoadError(String),

    /// Memory mapping failed
    #[error("Failed to mmap memory: {0}")]
    MmapError(#[source] std::io::Error),

    /// Channel send error
    #[error("Channel send error: {0}")]
    ChannelSend(String),
}

/// Configuration for capture engine initialization
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface name (e.g., "eth0")
    pub interface: String,
    /// Queue ID for RSS steering
    pub queue_id: u16,
    /// UMEM size in bytes
    pub umem_size: usize,
    /// Frame size in bytes
    pub frame_size: usize,
    /// Fill ring size (number of descriptors)
    pub fill_ring_size: u32,
    /// Completion ring size
    pub completion_ring_size: u32,
    /// CPU core to pin capture thread
    pub cpu_core: usize,
    /// Number of blocks for TPACKET_V3
    pub num_blocks: u32,
    /// Block size for TPACKET_V3
    pub block_size: u32,
    /// Use TPACKET_V3 instead of AF_XDP
    pub use_tpacket: bool,
}

impl CaptureConfig {
    /// Create a new builder for CaptureConfig
    pub fn builder() -> CaptureConfigBuilder {
        CaptureConfigBuilder::default()
    }

    /// Calculate number of frames that fit in UMEM
    pub fn num_frames(&self) -> usize {
        self.umem_size / self.frame_size
    }

    /// Get the chunk size for UMEM registration
    pub fn chunk_size(&self) -> usize {
        self.frame_size
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), CaptureError> {
        if self.interface.is_empty() {
            return Err(CaptureError::InvalidConfig(
                "Interface name cannot be empty".to_string(),
            ));
        }

        if !self.umem_size.is_power_of_two() {
            return Err(CaptureError::InvalidConfig(
                "UMEM size must be a power of 2".to_string(),
            ));
        }

        if self.umem_size < 1 << 20 {
            return Err(CaptureError::InvalidConfig(
                "UMEM size must be at least 1 MB".to_string(),
            ));
        }

        if self.frame_size < 64 || self.frame_size > 65536 {
            return Err(CaptureError::InvalidConfig(
                "Frame size must be between 64 and 65536 bytes".to_string(),
            ));
        }

        if !self.fill_ring_size.is_power_of_two() {
            return Err(CaptureError::InvalidConfig(
                "Fill ring size must be a power of 2".to_string(),
            ));
        }

        Ok(())
    }

    /// Calculate number of blocks for TPACKET_V3
    pub fn num_blocks(&self) -> u32 {
        self.num_blocks
    }
}

/// Builder for CaptureConfig
#[derive(Default)]
pub struct CaptureConfigBuilder {
    interface: String,
    queue_id: u16,
    umem_size: usize,
    frame_size: usize,
    fill_ring_size: u32,
    cpu_core: usize,
    use_tpacket: bool,
}

impl CaptureConfigBuilder {
    /// Set the network interface name
    pub fn interface(mut self, iface: &str) -> Self {
        self.interface = iface.to_string();
        self
    }

    /// Set the queue ID for RSS steering
    pub fn queue_id(mut self, id: u16) -> Self {
        self.queue_id = id;
        self
    }

    /// Set the UMEM size in bytes
    pub fn umem_size(mut self, size: usize) -> Self {
        self.umem_size = size;
        self
    }

    /// Set the frame size in bytes
    pub fn frame_size(mut self, size: usize) -> Self {
        self.frame_size = size;
        self
    }

    /// Set the fill ring size
    pub fn fill_ring_size(mut self, size: u32) -> Self {
        self.fill_ring_size = size;
        self
    }

    /// Set the CPU core to pin the capture thread
    pub fn cpu_core(mut self, core: usize) -> Self {
        self.cpu_core = core;
        self
    }

    /// Set whether to use TPACKET_V3
    pub fn use_tpacket(mut self, use_tpacket: bool) -> Self {
        self.use_tpacket = use_tpacket;
        self
    }

    /// Build the CaptureConfig
    ///
    /// # Panics
    ///
    /// Panics if default values are invalid (should never happen with sensible defaults)
    pub fn build(self) -> CaptureConfig {
        let umem_size = if self.umem_size == 0 {
            64 << 20 // 64 MB default
        } else {
            self.umem_size
        };

        let frame_size = if self.frame_size == 0 {
            2048 // Default frame size
        } else {
            self.frame_size
        };

        let fill_ring_size = if self.fill_ring_size == 0 {
            4096 // Default fill ring size
        } else {
            self.fill_ring_size
        };

        // TPACKET_V3 defaults: 4 MB blocks, 64 blocks
        let block_size = 1 << 22; // 4 MB
        let num_blocks = 64;

        CaptureConfig {
            interface: self.interface,
            queue_id: self.queue_id,
            umem_size,
            frame_size,
            fill_ring_size,
            completion_ring_size: fill_ring_size,
            cpu_core: self.cpu_core,
            num_blocks,
            block_size,
            use_tpacket: self.use_tpacket,
        }
    }
}

/// Trait for packet capture engines
///
/// Implementors provide the low-level packet capture functionality.
/// The trait is designed for zero-copy operation where packet data
/// is accessed directly from kernel-mapped memory regions.
///
/// # Example
///
/// ```no_run
/// use zero_copy_analyzer::capture::{CaptureEngine, CaptureConfig};
/// use zero_copy_analyzer::stats::StatsCollector;
/// use zero_copy_analyzer::output::ConsoleOutput;
/// use std::sync::Arc;
/// use std::sync::atomic::AtomicBool;
///
/// async fn example() -> anyhow::Result<()> {
///     let config = CaptureConfig::builder()
///         .interface("eth0")
///         .build();
///
///     // Engine implementation would go here
///     Ok(())
/// }
/// ```
#[async_trait::async_trait]
pub trait CaptureEngine: Send + Sync {
    /// Initialize the capture engine
    ///
    /// # Arguments
    ///
    /// * `config` - Capture configuration
    ///
    /// # Returns
    ///
    /// Result indicating success or capture error
    async fn init(&mut self, config: &CaptureConfig) -> Result<(), CaptureError>;

    /// Start the capture loop
    ///
    /// This method starts capturing packets and processing them through
    /// the stats collector and output backend. It runs until the shutdown
    /// flag is set.
    ///
    /// # Arguments
    ///
    /// * `stats` - Shared statistics collector
    /// * `output` - Output backend for emitting results
    /// * `shutdown_flag` - Atomic flag to signal shutdown
    ///
    /// # Returns
    ///
    /// Result indicating success or capture error
    async fn start(
        &mut self,
        stats: Arc<StatsCollector>,
        output: Box<dyn OutputBackend>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<(), CaptureError>;

    /// Stop the capture engine gracefully
    ///
    /// This method should flush any pending packets and release resources.
    async fn stop(&mut self) -> Result<(), CaptureError>;

    /// Get capture statistics
    ///
    /// Returns the number of packets received, dropped, and processed.
    fn stats(&self) -> CaptureStats;

    /// Check if the engine is running
    fn is_running(&self) -> bool;
}

/// Statistics for capture engine
#[derive(Debug, Default, Clone)]
pub struct CaptureStats {
    /// Total packets received
    pub packets_received: u64,
    /// Total packets dropped (ring overflow)
    pub packets_dropped: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Packets currently in flight (being processed)
    pub packets_in_flight: u64,
}

// Re-export backend implementations
pub mod af_xdp;
pub mod tpacket;
