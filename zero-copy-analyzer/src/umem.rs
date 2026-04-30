//! UMEM (User Memory) allocator for zero-copy packet buffers.
//!
//! This module manages a contiguous memory region that is shared with the kernel
//! for AF_XDP or TPACKET_V3 packet capture. The key design principle is zero-copy:
//! packet data is accessed directly from kernel-mapped memory without copying.
//!
//! # Memory Model
//!
//! - **UMEM**: A large contiguous allocation (typically 64MB-1GB) using mmap
//! - **Frames**: Fixed-size slots within UMEM for individual packets
//! - **PacketRef**: Borrowed slice tied to UMEM lifetime for type-safe zero-copy access
//!
//! # Example
//!
//! ```no_run
//! use zero_copy_analyzer::umem::UMem;
//!
//! fn example() -> anyhow::Result<()> {
//!     let mut umem = UMem::new(64 << 20, 2048)?; // 64MB, 2KB frames
//!     
//!     // Get a packet reference (zero-copy!)
//!     let packet = umem.get_packet(0, 1500);
//!     println!("Packet length: {}", packet.len());
//!     
//!     Ok(())
//! }
//! ```

use std::io;
use std::mem;
use std::ptr::NonNull;
use std::slice;
use std::sync::Arc;

use thiserror::Error;

/// Errors that can occur during UMEM operations
#[derive(Debug, Error)]
pub enum UMemError {
    /// Memory mapping failed
    #[error("Failed to map memory: {0}")]
    MmapFailed(#[source] io::Error),

    /// Invalid size (not power of 2, too small, etc.)
    #[error("Invalid UMEM size: {0}")]
    InvalidSize(String),

    /// Invalid frame size
    #[error("Invalid frame size: {0}")]
    InvalidFrameSize(String),

    /// Out of bounds access
    #[error("Access out of bounds: offset={0}, len={1}, umem_size={2}")]
    OutOfBounds(usize, usize, usize),
}

/// A borrowed reference to packet data within UMEM.
///
/// `PacketRef` provides safe, zero-copy access to packet data by borrowing
/// from the parent `UMem`. The lifetime parameter ensures the reference
/// cannot outlive the UMEM allocation.
///
/// # Examples
///
/// ```no_run
/// use zero_copy_analyzer::umem::UMem;
///
/// let umem = UMem::new(64 << 20, 2048).unwrap();
/// let packet = umem.get_packet(0, 1500);
///
/// // Access packet data without copying
/// if packet.len() >= 14 {
///     let dst_mac = &packet[0..6];
///     let src_mac = &packet[6..12];
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PacketRef<'umem> {
    data: &'umem [u8],
}

impl<'umem> PacketRef<'umem> {
    /// Create a new PacketRef from a slice
    ///
    /// # Safety
    ///
    /// Caller must ensure the slice points to valid UMEM memory
    pub unsafe fn from_slice(data: &'umem [u8]) -> Self {
        Self { data }
    }

    /// Get the raw packet data as a slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.data
    }

    /// Get the packet length
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the packet is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the first n bytes of the packet
    ///
    /// Returns None if the packet is shorter than n bytes
    #[inline]
    pub fn get_bytes(&self, n: usize) -> Option<&'umem [u8]> {
        if n <= self.data.len() {
            Some(&self.data[..n])
        } else {
            None
        }
    }

    /// Split the packet at an offset
    ///
    /// Returns (before, after) slices
    #[inline]
    pub fn split_at(&self, offset: usize) -> (&'umem [u8], &'umem [u8]) {
        self.data.split_at(offset)
    }
}

impl<'umem> AsRef<[u8]> for PacketRef<'umem> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

impl<'umem> std::ops::Deref for PacketRef<'umem> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

/// User Memory allocator for zero-copy packet capture.
///
/// `UMem` allocates a large contiguous memory region using mmap that can be
/// shared with the kernel for AF_XDP or TPACKET_V3 packet capture. The memory
/// is organized into fixed-size frames for efficient packet storage.
///
/// # Memory Layout
///
/// ```text
/// UMEM (64 MB)
/// ├─────────────┬─────────────┬─────────────┬─────────────┬───
/// │   Frame 0   │   Frame 1   │   Frame 2   │   Frame 3   │ ...
/// │  (2048 B)   │  (2048 B)   │  (2048 B)   │  (2048 B)   │
/// └─────────────┴─────────────┴─────────────┴─────────────┴───
/// ```
///
/// # Thread Safety
///
/// `UMem` is `Send + Sync` and can be safely shared across threads.
/// However, concurrent access to the same frame is not synchronized.
///
/// # Examples
///
/// ```no_run
/// use zero_copy_analyzer::umem::UMem;
///
/// // Allocate 64 MB UMEM with 2 KB frames
/// let umem = UMem::new(64 << 20, 2048)?;
///
/// println!("UMEM size: {} bytes", umem.size());
/// println!("Frame count: {}", umem.num_frames());
/// println!("Frame size: {} bytes", umem.frame_size());
///
/// # Ok::<(), zero_copy_analyzer::umem::UMemError>(())
/// ```
pub struct UMem {
    /// Pointer to the mapped memory region
    ptr: NonNull<u8>,
    /// Total size of the UMEM region in bytes
    size: usize,
    /// Size of each frame in bytes
    frame_size: usize,
    /// Number of frames in the UMEM
    num_frames: usize,
    /// Whether we own the memory (for Drop)
    owned: bool,
}

// SAFETY: UMem can be sent between threads as long as access is synchronized
unsafe impl Send for UMem {}
unsafe impl Sync for UMem {}

impl UMem {
    /// Create a new UMEM allocation.
    ///
    /// Allocates a contiguous memory region using mmap with the specified size
    /// and organizes it into fixed-size frames.
    ///
    /// # Arguments
    ///
    /// * `size` - Total UMEM size in bytes (must be power of 2, min 1 MB)
    /// * `frame_size` - Size of each frame in bytes (typically 2048 or 4096)
    ///
    /// # Returns
    ///
    /// Result containing the UMEM or an error
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zero_copy_analyzer::umem::UMem;
    ///
    /// let umem = UMem::new(64 << 20, 2048)?;
    /// # Ok::<(), zero_copy_analyzer::umem::UMemError>(())
    /// ```
    pub fn new(size: usize, frame_size: usize) -> Result<Self, UMemError> {
        // Validate size
        if !size.is_power_of_two() {
            return Err(UMemError::InvalidSize(
                "Size must be a power of 2".to_string(),
            ));
        }
        if size < 1 << 20 {
            return Err(UMemError::InvalidSize(
                "Size must be at least 1 MB".to_string(),
            ));
        }

        // Validate frame size
        if frame_size < 64 || frame_size > 65536 {
            return Err(UMemError::InvalidFrameSize(
                "Frame size must be between 64 and 65536 bytes".to_string(),
            ));
        }

        let num_frames = size / frame_size;

        // Allocate memory using mmap
        // SAFETY: mmap with MAP_ANONYMOUS | MAP_PRIVATE is safe
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_LOCKED,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(UMemError::MmapFailed(io::Error::last_os_error()));
        }

        // Initialize memory to zero (helps with debugging)
        unsafe {
            libc::memset(ptr, 0, size);
        }

        Ok(Self {
            ptr: NonNull::new(ptr as *mut u8).ok_or_else(|| {
                UMemError::MmapFailed(io::Error::new(io::ErrorKind::Other, "NULL pointer"))
            })?,
            size,
            frame_size,
            num_frames,
            owned: true,
        })
    }

    /// Create a UMEM from an existing memory region.
    ///
    /// # Safety
    ///
    /// Caller must ensure:
    /// - `ptr` points to valid, page-aligned memory of at least `size` bytes
    /// - The memory remains valid for the lifetime of the UMEM
    /// - The memory is not freed while UMEM owns it
    pub unsafe fn from_raw(
        ptr: *mut u8,
        size: usize,
        frame_size: usize,
    ) -> Result<Self, UMemError> {
        let num_frames = size / frame_size;

        Ok(Self {
            ptr: NonNull::new(ptr).ok_or_else(|| {
                UMemError::InvalidSize("NULL pointer".to_string())
            })?,
            size,
            frame_size,
            num_frames,
            owned: false,
        })
    }

    /// Get the total UMEM size in bytes
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the frame size in bytes
    #[inline]
    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Get the number of frames
    #[inline]
    pub fn num_frames(&self) -> usize {
        self.num_frames
    }

    /// Get the raw pointer to the UMEM region
    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Get a packet reference at the specified offset.
    ///
    /// Returns a `PacketRef` that borrows from this UMEM, providing
    /// zero-copy access to the packet data.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset into the UMEM region
    /// * `len` - Length of the packet data
    ///
    /// # Panics
    ///
    /// Panics if the offset + len exceeds the UMEM bounds
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use zero_copy_analyzer::umem::UMem;
    ///
    /// let umem = UMem::new(64 << 20, 2048)?;
    /// let packet = umem.get_packet(0, 1500);
    /// assert_eq!(packet.len(), 1500);
    /// # Ok::<(), zero_copy_analyzer::umem::UMemError>(())
    /// ```
    pub fn get_packet(&self, offset: usize, len: usize) -> PacketRef<'_> {
        if offset + len > self.size {
            panic!(
                "Packet access out of bounds: offset={}, len={}, umem_size={}",
                offset, len, self.size
            );
        }

        // SAFETY: We've validated bounds, and ptr is valid
        let slice = unsafe {
            slice::from_raw_parts(self.ptr.as_ptr().add(offset), len)
        };

        PacketRef { data: slice }
    }

    /// Get a packet reference by frame index.
    ///
    /// Similar to `get_packet` but calculates the offset from the frame index.
    ///
    /// # Arguments
    ///
    /// * `frame_idx` - Index of the frame (0..num_frames)
    /// * `len` - Actual packet length within the frame
    ///
    /// # Panics
    ///
    /// Panics if frame_idx >= num_frames or len > frame_size
    pub fn get_frame(&self, frame_idx: usize, len: usize) -> PacketRef<'_> {
        if frame_idx >= self.num_frames {
            panic!(
                "Frame index out of bounds: idx={}, num_frames={}",
                frame_idx, self.num_frames
            );
        }
        if len > self.frame_size {
            panic!(
                "Packet length exceeds frame size: len={}, frame_size={}",
                len, self.frame_size
            );
        }

        let offset = frame_idx * self.frame_size;
        self.get_packet(offset, len)
    }

    /// Zero-fill a frame
    ///
    /// # Arguments
    ///
    /// * `frame_idx` - Index of the frame to clear
    pub fn clear_frame(&self, frame_idx: usize) {
        if frame_idx >= self.num_frames {
            return;
        }

        let offset = frame_idx * self.frame_size;
        // SAFETY: Bounds checked above
        unsafe {
            libc::memset(self.ptr.as_ptr().add(offset), 0, self.frame_size);
        }
    }

    /// Copy data into a frame
    ///
    /// # Arguments
    ///
    /// * `frame_idx` - Index of the frame
    /// * `data` - Data to copy
    ///
    /// # Returns
    ///
    /// Number of bytes copied (min of data.len() and frame_size)
    pub fn write_frame(&self, frame_idx: usize, data: &[u8]) -> usize {
        if frame_idx >= self.num_frames {
            return 0;
        }

        let copy_len = std::cmp::min(data.len(), self.frame_size);
        let offset = frame_idx * self.frame_size;

        // SAFETY: Bounds checked
        unsafe {
            libc::memcpy(self.ptr.as_ptr().add(offset), data.as_ptr(), copy_len);
        }

        copy_len
    }
}

impl Drop for UMem {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: munmap with valid pointer from our mmap
            unsafe {
                libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.size);
            }
        }
    }
}

impl std::fmt::Debug for UMem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UMem")
            .field("size", &self.size)
            .field("frame_size", &self.frame_size)
            .field("num_frames", &self.num_frames)
            .field("ptr", &format!("{:p}", self.ptr))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_umem_creation() {
        let umem = UMem::new(1 << 20, 2048).unwrap();
        assert_eq!(umem.size(), 1 << 20);
        assert_eq!(umem.frame_size(), 2048);
        assert_eq!(umem.num_frames(), 512);
    }

    #[test]
    fn test_invalid_size() {
        let result = UMem::new(1000, 2048); // Not power of 2
        assert!(result.is_err());
    }

    #[test]
    fn test_get_packet() {
        let umem = UMem::new(1 << 20, 2048).unwrap();
        let packet = umem.get_packet(0, 100);
        assert_eq!(packet.len(), 100);
    }

    #[test]
    fn test_get_frame() {
        let umem = UMem::new(1 << 20, 2048).unwrap();
        let packet = umem.get_frame(5, 1500);
        assert_eq!(packet.len(), 1500);
    }

    #[test]
    fn test_write_and_read_frame() {
        let umem = UMem::new(1 << 20, 2048).unwrap();
        let data = b"Hello, World!";
        umem.write_frame(0, data);
        
        let packet = umem.get_frame(0, data.len());
        assert_eq!(packet.as_slice(), data);
    }
}
