//! AF_XDP capture backend implementation.
//!
//! This module implements the AF_XDP socket interface for zero-copy packet capture.
//! AF_XDP provides direct access to the NIC's RX rings via XDP (eXpress Data Path),
//! enabling line-rate packet processing at 10+ Gbps with minimal CPU overhead.
//!
//! # Architecture
//!
//! The AF_XDP backend uses:
//! - **UMEM**: A contiguous memory region registered with the kernel for packet buffers
//! - **Fill Ring**: Descriptors provided by userspace to kernel for incoming packets
//! - **RX Ring**: Descriptors filled by kernel with received packet locations
//! - **Completion Ring**: Descriptors returned by kernel after packet processing
//!
//! # Example
//!
//! ```no_run
//! use zero_copy_analyzer::capture::{af_xdp::XdpEngine, CaptureConfig};
//!
//! async fn example() -> anyhow::Result<()> {
//!     let config = CaptureConfig::builder()
//!         .interface("eth0")
//!         .queue_id(0)
//!         .umem_size(64 << 20)
//!         .build();
//!
//!     let mut engine = XdpEngine::new(config)?;
//!     // Start capture...
//!     Ok(())
//! }
//! ```

use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Context;
use libc::{c_int, c_void, sockaddr, socklen_t};
use tracing::{debug, error, info, warn};

use crate::capture::{CaptureConfig, CaptureError, CaptureEngine, CaptureStats};
use crate::output::OutputBackend;
use crate::parser::{PacketParser, ParsedPacket};
use crate::stats::StatsCollector;
use crate::umem::{PacketRef, UMem};

/// Default number of descriptors in XDP rings (kernel default)
pub const XSK_RING_PROD__DEFAULT_NUM_DESCS: u32 = 2048;

/// Default number of completions in XDP rings
pub const XSK_RING_CONS__DEFAULT_NUM_DESCS: u32 = 2048;

/// XDP socket options
const XDP_OPTIONS_ZEROCOPY: u32 = 1;

/// SOL_XDP level for setsockopt
const SOL_XDP: c_int = 283;

/// AF_XDP address family
const AF_XDP: c_int = 44;

/// SOCK_RAW socket type
const SOCK_RAW: c_int = 3;

/// XDP_UMEM_REG option
const XDP_UMEM_REG: c_int = 1;

/// XDP_UMEM_FILL_RING option
const XDP_UMEM_FILL_RING: c_int = 2;

/// XDP_UMEM_COMPLETION_RING option
const XDP_UMEM_COMPLETION_RING: c_int = 3;

/// XDP_RX_RING option
const XDP_RX_RING: c_int = 4;

/// XDP_TX_RING option
const XDP_TX_RING: c_int = 5;

/// XDP_STATISTICS option
const XDP_STATISTICS: c_int = 6;

/// XDP_OPTIONS option
const XDP_OPTIONS: c_int = 7;

/// XDP_MMAP_OFFSETS option
const XDP_MMAP_OFFSETS: c_int = 8;

/// XDP_SHARED_UMEM option
const XDP_SHARED_UMEM: c_int = 9;

/// XDP_COPY option
const XDP_COPY: c_int = 10;

/// XDP_COPY_MAX_FRAG_SIZE option
const XDP_COPY_MAX_FRAG_SIZE: c_int = 11;

/// XDP_USE_NEED_WAKEUP flag
const XDP_USE_NEED_WAKEUP: u32 = 0x8;

/// XDP ring offset structure
#[repr(C)]
struct XdpRingOffsets {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

/// XDP umem registration structure
#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

/// XDP statistics structure
#[repr(C)]
#[derive(Default, Debug)]
struct XdpStatistics {
    rx_dropped: u64,
    rx_invalid_descs: u64,
    tx_invalid_descs: u64,
    rx_ring_full: u64,
    rx_fill_ring_empty_descs: u64,
    tx_ring_empty_descs: u64,
}

/// XDP descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XdpDesc {
    /// Address offset into UMEM
    pub addr: u64,
    /// Length of packet data
    pub len: u32,
    /// Options (headroom, etc.)
    pub options: u32,
}

impl Default for XdpDesc {
    fn default() -> Self {
        Self {
            addr: 0,
            len: 0,
            options: 0,
        }
    }
}

/// XDP ring structure for memory-mapped rings
struct XdpRing {
    /// Pointer to producer index
    producer: *mut u64,
    /// Pointer to consumer index
    consumer: *mut u64,
    /// Pointer to descriptor array
    descriptors: *mut XdpDesc,
    /// Mask for ring indexing
    mask: u32,
    /// Flags pointer (for XDP_USE_NEED_WAKEUP)
    flags: *mut u32,
    /// Ring size
    size: u32,
}

unsafe impl Send for XdpRing {}
unsafe impl Sync for XdpRing {}

impl XdpRing {
    /// Create a new XDP ring from mmap'd memory
    ///
    /// # Safety
    ///
    /// The caller must ensure that `base` points to valid memory mapped with
    /// the correct layout for an XDP ring.
    unsafe fn new(base: *mut c_void, size: u32, offsets: &XdpRingOffsets) -> Self {
        let base = base as *mut u8;
        Self {
            producer: base.add(offsets.producer as usize) as *mut u64,
            consumer: base.add(offsets.consumer as usize) as *mut u64,
            descriptors: base.add(offsets.desc as usize) as *mut XdpDesc,
            flags: base.add(offsets.flags as usize) as *mut u32,
            mask: size - 1,
            size,
        }
    }

    /// Get the number of available entries to consume
    #[inline]
    fn available(&self) -> u32 {
        unsafe {
            let prod = *self.producer;
            let cons = *self.consumer;
            ((prod.wrapping_sub(cons)) & self.mask as u64) as u32
        }
    }

    /// Get descriptor at index
    ///
    /// # Safety
    ///
    /// Caller must ensure index is within bounds
    #[inline]
    unsafe fn get_desc(&self, idx: u32) -> &XdpDesc {
        &*self.descriptors.add((idx & self.mask) as usize)
    }

    /// Submit entries to the ring
    ///
    /// # Safety
    ///
    /// Caller must ensure num_entries does not exceed available space
    #[inline]
    unsafe fn submit(&mut self, num_entries: u32) {
        let prod = self.producer;
        *prod = prod.read().wrapping_add(num_entries as u64);
    }
}

/// AF_XDP socket file descriptor wrapper
struct XdpSocket {
    fd: RawFd,
    _owned: bool,
}

impl XdpSocket {
    /// Create a new AF_XDP socket
    fn new() -> Result<Self, CaptureError> {
        // SAFETY: socket() is a safe FFI call; we check the return value
        let fd = unsafe { libc::socket(AF_XDP, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(CaptureError::SocketCreation(io::Error::last_os_error()));
        }

        Ok(Self { fd, _owned: true })
    }

    /// Bind the socket to an interface and queue
    fn bind(&self, if_name: &str, queue_id: u16) -> Result<(), CaptureError> {
        // Structure for AF_XDP address
        #[repr(C)]
        struct SockaddrXdp {
            sfamily: u16,
            flags: u16,
            ifindex: u32,
            queue_id: u32,
            shared_umem_fd: u32,
            padding: [u8; 16], // Ensure proper size
        }

        // Get interface index
        let if_name_c = CString::new(if_name).map_err(|_| {
            CaptureError::InvalidConfig(format!("Invalid interface name: {}", if_name))
        })?;

        // SAFETY: if_nametoindex is safe; returns 0 on failure
        let ifindex = unsafe { libc::if_nametoindex(if_name_c.as_ptr()) };
        if ifindex == 0 {
            return Err(CaptureError::InterfaceNotFound(if_name.to_string()));
        }

        let addr = SockaddrXdp {
            sfamily: AF_XDP as u16,
            flags: 0,
            ifindex,
            queue_id: queue_id as u32,
            shared_umem_fd: 0xffffffff, // No shared UMEM
            padding: [0; 16],
        };

        // SAFETY: bind() is safe; we've validated the address structure
        let ret = unsafe {
            libc::bind(
                self.fd,
                &addr as *const SockaddrXdp as *const sockaddr,
                mem::size_of::<SockaddrXdp>() as socklen_t,
            )
        };

        if ret != 0 {
            return Err(CaptureError::BindError(io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Set socket options for XDP
    fn setsockopt<T>(&self, level: c_int, optname: c_int, optval: &T) -> Result<(), CaptureError> {
        // SAFETY: setsockopt is safe; we pass valid pointers
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                level,
                optname,
                optval as *const T as *const c_void,
                mem::size_of::<T>() as socklen_t,
            )
        };

        if ret != 0 {
            return Err(CaptureError::SocketOption(io::Error::last_os_error()));
        }

        Ok(())
    }

    /// Get socket statistics
    fn get_statistics(&self) -> Result<XdpStatistics, CaptureError> {
        let mut stats = XdpStatistics::default();
        let mut len = mem::size_of::<XdpStatistics>() as socklen_t;

        // SAFETY: getsockopt is safe; we provide valid buffer
        let ret = unsafe {
            libc::getsockopt(
                self.fd,
                SOL_XDP,
                XDP_STATISTICS,
                &mut stats as *mut XdpStatistics as *mut c_void,
                &mut len,
            )
        };

        if ret != 0 {
            return Err(CaptureError::SocketOption(io::Error::last_os_error()));
        }

        Ok(stats)
    }

    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        if self._owned {
            // SAFETY: close is safe with valid fd
            unsafe { libc::close(self.fd) };
        }
    }
}

/// AF_XDP capture engine
pub struct XdpEngine {
    config: CaptureConfig,
    socket: Option<XdpSocket>,
    umem: Option<UMem>,
    fill_ring: Option<XdpRing>,
    rx_ring: Option<XdpRing>,
    completion_ring: Option<XdpRing>,
    mmap_region: Option<*mut libc::c_void>,
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

// SAFETY: XdpEngine manages raw pointers but ensures thread safety through Arc/Atomic
unsafe impl Send for XdpEngine {}
unsafe impl Sync for XdpEngine {}

impl XdpEngine {
    /// Create a new AF_XDP engine
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
            socket: None,
            umem: None,
            fill_ring: None,
            rx_ring: None,
            completion_ring: None,
            mmap_region: None,
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(CaptureStatsInner::default()),
            thread_handle: None,
        })
    }

    /// Populate the fill ring with UMEM descriptors
    ///
    /// # Arguments
    ///
    /// * `num_frames` - Number of frames to add to fill ring
    fn populate_fill_ring(&mut self, num_frames: usize) -> Result<(), CaptureError> {
        let fill_ring = self.fill_ring.as_mut().ok_or_else(|| {
            CaptureError::InvalidConfig("Fill ring not initialized".to_string())
        })?;

        let umem = self.umem.as_ref().ok_or_else(|| {
            CaptureError::InvalidConfig("UMEM not initialized".to_string())
        })?;

        // SAFETY: We're submitting descriptors up to num_frames which fits in the ring
        unsafe {
            let available = fill_ring.available();
            let to_submit = std::cmp::min(available as usize, num_frames);

            for i in 0..to_submit {
                let idx = (*fill_ring.producer + i as u64) & fill_ring.mask as u64;
                let desc = &mut *fill_ring.descriptors.add(idx as usize);
                desc.addr = (i * self.config.frame_size) as u64;
                desc.len = self.config.frame_size as u32;
                desc.options = 0;
            }

            fill_ring.submit(to_submit as u32);
        }

        Ok(())
    }

    /// Process received packets from the RX ring
    ///
    /// # Arguments
    ///
    /// * `stats_collector` - Stats collector for updating counters
    /// * `output` - Output backend for emitting parsed packets
    /// * `shutdown_flag` - Flag to check for shutdown
    ///
    /// # Returns
    ///
    /// Number of packets processed
    fn process_packets(
        &mut self,
        stats_collector: &Arc<StatsCollector>,
        output: &mut dyn OutputBackend,
        shutdown_flag: &AtomicBool,
    ) -> usize {
        let rx_ring = match &self.rx_ring {
            Some(r) => r,
            None => return 0,
        };

        let umem = match &self.umem {
            Some(u) => u,
            None => return 0,
        };

        let mut processed = 0;
        let mut parser = PacketParser::new();

        // SAFETY: We carefully manage ring indices and bounds checking
        unsafe {
            let available = rx_ring.available();
            if available == 0 {
                return 0;
            }

            let consumer = *rx_ring.consumer;

            for i in 0..available {
                if shutdown_flag.load(Ordering::Relaxed) {
                    break;
                }

                let idx = (consumer + i as u64) & rx_ring.mask as u64;
                let desc = rx_ring.get_desc(idx as u32);

                if desc.len == 0 {
                    continue;
                }

                // Create a PacketRef to the frame data (zero-copy!)
                let frame_data = umem.get_packet(desc.addr as usize, desc.len as usize);

                // Parse the packet
                match parser.parse(&frame_data) {
                    Ok(parsed) => {
                        // Update statistics
                        stats_collector.record_packet(&parsed, desc.len as usize);
                        self.stats
                            .bytes_received
                            .fetch_add(desc.len as u64, Ordering::Relaxed);

                        // Emit to output backend
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

            // Update consumer index
            *rx_ring.consumer = consumer.wrapping_add(processed as u64);
        }

        processed
    }

    /// Refill the fill ring with consumed descriptors
    fn refill_fill_ring(&mut self, num_descriptors: usize) {
        let fill_ring = match &mut self.fill_ring {
            Some(r) => r,
            None => return,
        };

        // SAFETY: Bounds checked refill
        unsafe {
            let available = fill_ring.available();
            let to_refill = std::cmp::min(available, num_descriptors as u32);

            if to_refill > 0 {
                fill_ring.submit(to_refill);
            }
        }
    }

    /// Main capture loop
    fn capture_loop(
        &mut self,
        stats_collector: Arc<StatsCollector>,
        mut output: Box<dyn OutputBackend>,
        shutdown_flag: Arc<AtomicBool>,
    ) {
        info!("AF_XDP capture loop started on core {}", self.config.cpu_core);

        // Pin thread to CPU core
        if let Err(e) = pin_thread_to_cpu(self.config.cpu_core) {
            warn!("Failed to pin thread to CPU {}: {:?}", self.config.cpu_core, e);
        }

        // Set SO_BUSY_POLL for lower latency
        if let Some(socket) = &self.socket {
            // Enable busy poll
            let busy_poll_us: c_int = 50; // 50 microseconds
            unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BUSY_POLL,
                    &busy_poll_us as *const c_int as *const c_void,
                    mem::size_of::<c_int>() as socklen_t,
                );
            }
        }

        // Initial fill ring population
        if let Err(e) = self.populate_fill_ring(self.config.num_frames()) {
            error!("Failed to populate fill ring: {:?}", e);
            return;
        }

        while !shutdown_flag.load(Ordering::Relaxed) {
            // Process received packets
            let processed = self.process_packets(&stats_collector, &mut *output, &shutdown_flag);

            // Refill fill ring
            if processed > 0 {
                self.refill_fill_ring(processed);
            }

            // If no packets, yield briefly to avoid busy spinning
            if processed == 0 {
                thread::yield_now();
            }
        }

        info!("AF_XDP capture loop shutting down");
    }
}

#[async_trait::async_trait]
impl CaptureEngine for XdpEngine {
    async fn init(&mut self, config: &CaptureConfig) -> Result<(), CaptureError> {
        self.config = config.clone();
        self.init_inner()
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

        // Clone self references for the thread
        let mut capture_self = Self {
            config: self.config.clone(),
            socket: self.socket.take(),
            umem: self.umem.take(),
            fill_ring: self.fill_ring.take(),
            rx_ring: self.rx_ring.take(),
            completion_ring: self.completion_ring.take(),
            mmap_region: self.mmap_region.take(),
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

impl XdpEngine {
    /// Initialize the XDP engine internals
    fn init_inner(&mut self) -> Result<(), CaptureError> {
        // Create AF_XDP socket
        let socket = XdpSocket::new()?;

        // Register UMEM
        let mut umem = UMem::new(self.config.umem_size, self.config.frame_size)?;

        // Set XDP options for zero-copy
        let options: u32 = XDP_OPTIONS_ZEROCOPY;
        socket.setsockopt(SOL_XDP, XDP_OPTIONS, &options)?;

        // Register UMEM with socket
        let umem_reg = XdpUmemReg {
            addr: umem.as_ptr() as u64,
            len: self.config.umem_size as u64,
            chunk_size: self.config.frame_size as u32,
            headroom: 0,
            flags: 0,
        };
        socket.setsockopt(SOL_XDP, XDP_UMEM_REG, &umem_reg)?;

        // Calculate ring sizes
        let fill_ring_size = self.config.fill_ring_size;
        let rx_ring_size = fill_ring_size; // Same size for simplicity
        let completion_ring_size = fill_ring_size;

        // Map rings (simplified - in production would use XDP_MMAP_OFFSETS)
        // For now, we'll allocate separate regions
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let ring_size = (fill_ring_size as usize) * mem::size_of::<XdpDesc>();
        let ring_size_aligned = ((ring_size + page_size - 1) / page_size) * page_size;

        // Allocate fill ring
        // SAFETY: mmap with MAP_ANONYMOUS is safe
        let fill_ring_mmap = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size_aligned,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if fill_ring_mmap == libc::MAP_FAILED {
            return Err(CaptureError::MmapError(io::Error::last_os_error()));
        }

        // Initialize fill ring (simplified - production would use proper offsets)
        let fill_ring = unsafe {
            // In real implementation, get offsets via XDP_MMAP_OFFSETS
            let offsets = XdpRingOffsets {
                producer: 0,
                consumer: page_size as u64,
                desc: (page_size * 2) as u64,
                flags: (page_size * 3) as u64,
            };
            XdpRing::new(fill_ring_mmap, fill_ring_size, &offsets)
        };

        // Allocate RX ring
        let rx_ring_mmap = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_size_aligned,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if rx_ring_mmap == libc::MAP_FAILED {
            unsafe { libc::munmap(fill_ring_mmap, ring_size_aligned) };
            return Err(CaptureError::MmapError(io::Error::last_os_error()));
        }

        let rx_ring = unsafe {
            let offsets = XdpRingOffsets {
                producer: 0,
                consumer: page_size as u64,
                desc: (page_size * 2) as u64,
                flags: (page_size * 3) as u64,
            };
            XdpRing::new(rx_ring_mmap, rx_ring_size, &offsets)
        };

        // Set up rings via setsockopt
        socket.setsockopt(SOL_XDP, XDP_UMEM_FILL_RING, &(fill_ring_size as u32))?;
        socket.setsockopt(SOL_XDP, XDP_RX_RING, &(rx_ring_size as u32))?;

        // Bind socket to interface
        socket.bind(&self.config.interface, self.config.queue_id)?;

        self.socket = Some(socket);
        self.umem = Some(umem);
        self.fill_ring = Some(fill_ring);
        self.rx_ring = Some(rx_ring);
        self.mmap_region = Some(fill_ring_mmap);

        Ok(())
    }
}

/// Pin current thread to a specific CPU core
fn pin_thread_to_cpu(core_id: usize) -> Result<(), io::Error> {
    let mut cpu_set: libc::cpu_set_t;
    // SAFETY: cpu_set_t is a plain data structure
    unsafe {
        cpu_set = mem::zeroed();
        libc::CPU_SET(core_id, &mut cpu_set);
    }

    // SAFETY: pthread_setaffinity_np is safe with valid arguments
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
