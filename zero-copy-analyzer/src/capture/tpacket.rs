//! TPACKET_V3 capture backend implementation.
//!
//! This module implements AF_PACKET with TPACKET_V3 ring buffer as a fallback
//! for kernels that don't support AF_XDP. TPACKET_V3 uses block-based ring buffers
//! with variable-length packets, providing good performance (though not quite XDP levels).
//!
//! # Architecture
//!
//! TPACKET_V3 uses:
//! - **Blocks**: Large contiguous memory regions (default 4 MB)
//! - **Frames**: Variable-length packets within blocks
//! - **Ring buffer**: Circular queue of blocks shared with kernel
//!
//! # Example
//!
//! ```no_run
//! use zero_copy_analyzer::capture::{tpacket::TpacketEngine, CaptureConfig};
//!
//! async fn example() -> anyhow::Result<()> {
//!     let config = CaptureConfig::builder()
//!         .interface("eth0")
//!         .use_tpacket(true)
//!         .build();
//!
//!     let mut engine = TpacketEngine::new(config)?;
//!     // Start capture...
//!     Ok(())
//! }
//! ```

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libc::{c_int, c_void, sockaddr, socklen_t};
use tracing::{debug, error, info, warn};

use crate::capture::{CaptureConfig, CaptureError, CaptureEngine, CaptureStats};
use crate::output::OutputBackend;
use crate::parser::{PacketParser, ParsedPacket};
use crate::stats::StatsCollector;
use crate::umem::UMem;

/// AF_PACKET protocol
const ETH_P_ALL: u16 = 0x0003;

/// TPACKET_V3 version
const TPACKET_V3: c_int = 2;

/// TP_STATUS_USER flag
const TP_STATUS_USER: c_int = 1;

/// SOL_PACKET level
const SOL_PACKET: c_int = 263;

/// PACKET_RX_RING option
const PACKET_RX_RING: c_int = 5;

/// PACKET_VERSION option
const PACKET_VERSION: c_int = 10;

/// PACKET_VNET_HDR option
const PACKET_VNET_HDR: c_int = 15;

/// PACKET_ADD_MEMBERSHIP option
const PACKET_ADD_MEMBERSHIP: c_int = 1;

/// PACKET_MR_PKTGEN option
const PACKET_MR_PKTGEN: c_int = 5;

/// SOCK_RAW socket type
const SOCK_RAW: c_int = 3;

/// AF_PACKET address family
const AF_PACKET: c_int = 17;

/// Packet socket address structure
#[repr(C)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: c_int,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

/// TPACKET_V3 header structure
#[repr(C)]
struct Tpacket3Header {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [u8; 4],
}

/// TPACKET_V3 block header
#[repr(C)]
struct TpacketBlockDesc {
    version: u32,
    offset_to_priv: u32,
    bh1: TpacketBlockDescV1,
}

#[repr(C)]
struct TpacketBlockDescV1 {
    block_size: u32,
    num_blocks: u32,
    block_num: u32,
    flags: u32,
    opt_offset: u32,
    header_to_offset: u32,
    data_to_offset: u32,
    blk_len: u32,
    slot_cnt: u32,
    slot_next_offset: u32,
    slot_reserved: u32,
}

/// Ring configuration for TPACKET_V3
#[repr(C)]
struct PacketReq3 {
    block_size: u32,
    block_nr: u32,
    frame_size: u32,
    frame_nr: u32,
    retire_blk_tov: u32,
    size_of_priv: u32,
    feature_req_word: u32,
}

/// TPACKET_V3 capture engine
pub struct TpacketEngine {
    config: CaptureConfig,
    socket_fd: Option<RawFd>,
    mmap_region: Option<*mut c_void>,
    mmap_size: usize,
    running: Arc<AtomicBool>,
    stats: Arc<CaptureStatsInner>,
    thread_handle: Option<JoinHandle<()>>,
}

/// Inner stats for atomic updates
#[derive(Default)]
struct CaptureStatsInner {
    packets_received: AtomicU64,
    packets_dropped: AtomicU64,
    bytes_received: AtomicU64,
}

// SAFETY: TpacketEngine manages raw pointers but ensures thread safety
unsafe impl Send for TpacketEngine {}
unsafe impl Sync for TpacketEngine {}

impl TpacketEngine {
    /// Create a new TPACKET_V3 engine
    ///
    /// # Arguments
    ///
    /// * `config` - Capture configuration
    ///
    /// # Returns
    ///
    /// Result containing the engine or capture error
    pub fn new(config: CaptureConfig) -> Result<Self, CaptureError> {
        config.validate()?;

        Ok(Self {
            config,
            socket_fd: None,
            mmap_region: None,
            mmap_size: 0,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(CaptureStatsInner::default()),
            thread_handle: None,
        })
    }

    /// Create AF_PACKET socket
    fn create_socket(&self) -> Result<RawFd, CaptureError> {
        // SAFETY: socket() is safe FFI
        let fd = unsafe { libc::socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as i32).to_be()) };
        if fd < 0 {
            return Err(CaptureError::SocketCreation(io::Error::last_os_error()));
        }
        Ok(fd)
    }

    /// Set TPACKET_V3 version
    fn set_version(&self, fd: RawFd) -> Result<(), CaptureError> {
        let version: c_int = TPACKET_V3;
        // SAFETY: setsockopt is safe with valid arguments
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_VERSION,
                &version as *const c_int as *const c_void,
                mem::size_of::<c_int>() as socklen_t,
            )
        };
        if ret != 0 {
            return Err(CaptureError::SocketOption(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Configure and map the RX ring
    fn setup_ring(&mut self, fd: RawFd) -> Result<(), CaptureError> {
        // Use configured values or defaults
        let block_size = if self.config.block_size > 0 {
            self.config.block_size
        } else {
            1 << 22 // 4 MB default
        };

        let num_blocks = if self.config.num_blocks > 0 {
            self.config.num_blocks
        } else {
            64 // 64 blocks default
        };

        let frame_size = self.config.frame_size as u32;
        let total_size = (block_size * num_blocks) as usize;

        // Configure ring parameters
        let req = PacketReq3 {
            block_size,
            block_nr: num_blocks,
            frame_size,
            frame_nr: (block_size / frame_size) * num_blocks,
            retire_blk_tov: 10, // 10ms timeout
            size_of_priv: 0,
            feature_req_word: 0,
        };

        // Set RX ring configuration
        // SAFETY: setsockopt with PACKET_RX_RING is safe
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_RX_RING,
                &req as *const PacketReq3 as *const c_void,
                mem::size_of::<PacketReq3>() as socklen_t,
            )
        };
        if ret != 0 {
            return Err(CaptureError::SocketOption(io::Error::last_os_error()));
        }

        // Map the ring buffer
        // SAFETY: mmap is safe with correct parameters
        let mmap_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_LOCKED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if mmap_ptr == libc::MAP_FAILED {
            return Err(CaptureError::MmapError(io::Error::last_os_error()));
        }

        self.mmap_region = Some(mmap_ptr);
        self.mmap_size = total_size;

        Ok(())
    }

    /// Bind socket to interface
    fn bind_to_interface(&self, fd: RawFd, iface: &str) -> Result<(), CaptureError> {
        let iface_c = CString::new(iface).map_err(|_| {
            CaptureError::InvalidConfig(format!("Invalid interface name: {}", iface))
        })?;

        // SAFETY: if_nametoindex is safe
        let ifindex = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
        if ifindex == 0 {
            return Err(CaptureError::InterfaceNotFound(iface.to_string()));
        }

        let addr = SockaddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_ALL as u16).to_be(),
            sll_ifindex: ifindex as c_int,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        // SAFETY: bind is safe with valid address
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const SockaddrLl as *const sockaddr,
                mem::size_of::<SockaddrLl>() as socklen_t,
            )
        };

        if ret != 0 {
            return Err(CaptureError::BindError(io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Process packets from the ring buffer
    fn process_packets(
        &self,
        stats_collector: &Arc<StatsCollector>,
        output: &mut dyn OutputBackend,
        shutdown_flag: &AtomicBool,
    ) -> usize {
        let mmap_ptr = match self.mmap_region {
            Some(p) => p as *mut u8,
            None => return 0,
        };

        let mut processed = 0;
        let mut parser = PacketParser::new();
        let block_size = self.config.block_size.max(1 << 22) as usize;
        let num_blocks = self.config.num_blocks.max(64) as usize;

        // Iterate through blocks
        for block_idx in 0..num_blocks {
            if shutdown_flag.load(Ordering::Relaxed) {
                break;
            }

            let block_offset = block_idx * block_size;
            let block_ptr = unsafe { mmap_ptr.add(block_offset) };

            // Get block header
            // SAFETY: We're accessing valid mmap'd memory
            let bd = unsafe { &*(block_ptr as *const TpacketBlockDesc) };
            let bh1 = &bd.bh1;

            if bh1.block_size == 0 {
                continue;
            }

            // Iterate through slots in block
            let mut slot_offset = bh1.header_to_offset as usize;
            while slot_offset < block_size {
                let hdr_ptr = unsafe { block_ptr.add(slot_offset) as *const Tpacket3Header };
                // SAFETY: Accessing valid memory within block
                let hdr = unsafe { &*hdr_ptr };

                if hdr.tp_status & TP_STATUS_USER as u32 == 0 {
                    break; // No more packets in this block
                }

                if hdr.tp_len > 0 {
                    let data_offset = slot_offset + bh1.data_to_offset as usize;
                    // SAFETY: Data is within block bounds
                    let data = unsafe {
                        std::slice::from_raw_parts(block_ptr.add(data_offset), hdr.tp_len as usize)
                    };

                    // Parse packet
                    let mut parser = PacketParser::new();
                    match parser.parse(data) {
                        Ok(parsed) => {
                            stats_collector.record_packet(&parsed, hdr.tp_len as usize);
                            self.stats
                                .bytes_received
                                .fetch_add(hdr.tp_len as u64, Ordering::Relaxed);
                            output.emit(&parsed);
                            processed += 1;
                        }
                        Err(e) => {
                            debug!("Failed to parse packet: {:?}", e);
                        }
                    }

                    self.stats
                        .packets_received
                        .fetch_add(1, Ordering::Relaxed);
                }

                // Clear status and move to next slot
                unsafe {
                    let hdr_mut = block_ptr.add(slot_offset) as *mut Tpacket3Header;
                    (*hdr_mut).tp_status = 0;
                }

                slot_offset += bh1.slot_next_offset as usize;
                if slot_offset >= block_size {
                    break;
                }
            }
        }

        processed
    }

    /// Main capture loop
    fn capture_loop(
        &mut self,
        stats_collector: Arc<StatsCollector>,
        mut output: Box<dyn OutputBackend>,
        shutdown_flag: Arc<AtomicBool>,
    ) {
        info!(
            "TPACKET_V3 capture loop started on core {}",
            self.config.cpu_core
        );

        // Pin thread to CPU
        if let Err(e) = pin_thread_to_cpu(self.config.cpu_core) {
            warn!(
                "Failed to pin thread to CPU {}: {:?}",
                self.config.cpu_core, e
            );
        }

        while !shutdown_flag.load(Ordering::Relaxed) {
            let processed = self.process_packets(&stats_collector, &mut *output, &shutdown_flag);

            if processed == 0 {
                thread::yield_now();
            }
        }

        info!("TPACKET_V3 capture loop shutting down");
    }
}

#[async_trait::async_trait]
impl CaptureEngine for TpacketEngine {
    async fn init(&mut self, config: &CaptureConfig) -> Result<(), CaptureError> {
        self.config = config.clone();
        
        let fd = self.create_socket()?;
        self.set_version(fd)?;
        self.setup_ring(fd)?;
        self.bind_to_interface(fd, &self.config.interface)?;
        self.socket_fd = Some(fd);

        Ok(())
    }

    async fn start(
        &mut self,
        stats_collector: Arc<StatsCollector>,
        output: Box<dyn OutputBackend>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<(), CaptureError> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(CaptureError::InvalidConfig(
                "Engine already running".to_string(),
            ));
        }

        let mut capture_self = Self {
            config: self.config.clone(),
            socket_fd: self.socket_fd.take(),
            mmap_region: self.mmap_region.take(),
            mmap_size: self.mmap_size,
            running: Arc::clone(&self.running),
            stats: Arc::clone(&self.stats),
            thread_handle: None,
        };

        let handle = thread::spawn(move || {
            capture_self.capture_loop(stats_collector, output, shutdown_flag);
        });

        self.thread_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), CaptureError> {
        self.running.store(false, Ordering::SeqCst);

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }

        // Unmap and close socket
        if let Some(ptr) = self.mmap_region.take() {
            // SAFETY: munmap with valid pointer
            unsafe { libc::munmap(ptr, self.mmap_size) };
        }

        if let Some(fd) = self.socket_fd.take() {
            // SAFETY: close with valid fd
            unsafe { libc::close(fd) };
        }

        Ok(())
    }

    fn stats(&self) -> CaptureStats {
        CaptureStats {
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            packets_in_flight: 0,
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

impl Drop for TpacketEngine {
    fn drop(&mut self) {
        if let Some(ptr) = self.mmap_region {
            // SAFETY: munmap with valid pointer
            unsafe { libc::munmap(ptr, self.mmap_size) };
        }
        if let Some(fd) = self.socket_fd {
            // SAFETY: close with valid fd
            unsafe { libc::close(fd) };
        }
    }
}

/// Pin current thread to a specific CPU core
fn pin_thread_to_cpu(core_id: usize) -> Result<(), io::Error> {
    let mut cpu_set: libc::cpu_set_t;
    // SAFETY: cpu_set_t is plain data
    unsafe {
        cpu_set = mem::zeroed();
        libc::CPU_SET(core_id, &mut cpu_set);
    }

    // SAFETY: pthread_setaffinity_np is safe
    let ret = unsafe {
        libc::pthread_setaffinity_np(
            libc::pthread_self(),
            mem::size_of::<libc::cpu_set_t>(),
            &cpu_set,
        )
    };

    if ret != 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }

    Ok(())
}
