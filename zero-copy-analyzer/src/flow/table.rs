//! Concurrent flow hash table implementation.
//!
//! This module implements a fixed-capacity concurrent hash map using DashMap
//! for thread-safe flow tracking with Robin Hood hashing characteristics.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use ahash::AHasher;
use dashmap::{DashMap, SharedValue};
use xxhash_rust::xxh3::xxh3_64;

use crate::flow::{FlowEntry, FlowState, FlowTableStats};
use crate::parser::FlowKey;

/// Default load factor threshold (75%)
const DEFAULT_LOAD_FACTOR: f64 = 0.75;

/// A concurrent flow table for tracking network flows.
///
/// Uses DashMap for lock-free concurrent access and supports
/// efficient lookup, insertion, and iteration.
///
/// # Examples
///
/// ```no_run
/// use zero_copy_analyzer::flow::table::FlowTable;
/// use zero_copy_analyzer::parser::{FlowKey, IpAddr, Protocol};
/// use std::net::Ipv4Addr;
///
/// let table = FlowTable::new(1_048_576); // 1M flows
///
/// let key = FlowKey::new(
///     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
///     IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
///     12345,
///     80,
///     Protocol::Tcp,
/// );
///
/// table.insert_or_update(key, 1500, 0x02, None, None);
/// ```
pub struct FlowTable {
    /// The underlying concurrent hash map
    map: DashMap<FlowKey, FlowState, ahash::RandomState>,
    /// Maximum capacity before eviction
    capacity: usize,
    /// Load factor threshold
    load_factor: f64,
    /// Total packets processed
    total_packets: AtomicU64,
    /// Total bytes processed
    total_bytes: AtomicU64,
    /// Expired flow count
    expired_count: AtomicU64,
    /// Collision counter
    collisions: AtomicU64,
}

impl FlowTable {
    /// Create a new flow table with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of flows to track
    ///
    /// # Returns
    ///
    /// A new FlowTable instance
    pub fn new(capacity: usize) -> Self {
        let hasher = ahash::RandomState::new();
        
        Self {
            map: DashMap::with_hasher(hasher),
            capacity,
            load_factor: DEFAULT_LOAD_FACTOR,
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            expired_count: AtomicU64::new(0),
            collisions: AtomicU64::new(0),
        }
    }

    /// Create a new flow table with custom load factor.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of flows
    /// * `load_factor` - Load factor threshold (0.0 - 1.0)
    pub fn with_load_factor(capacity: usize, load_factor: f64) -> Self {
        let load_factor = load_factor.clamp(0.1, 0.95);
        
        Self {
            map: DashMap::with_capacity_and_hasher(
                (capacity as f64 * load_factor) as usize,
                ahash::RandomState::new(),
            ),
            capacity,
            load_factor,
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            expired_count: AtomicU64::new(0),
            collisions: AtomicU64::new(0),
        }
    }

    /// Hash a flow key using xxHash3.
    ///
    /// # Arguments
    ///
    /// * `key` - Flow key to hash
    ///
    /// # Returns
    ///
    /// 64-bit hash value
    #[inline]
    pub fn hash_key(&self, key: &FlowKey) -> u64 {
        // Create a compact representation for hashing
        let mut buf = [0u8; 36];
        
        match key.src_ip {
            crate::parser::IpAddr::V4(v4) => {
                buf[0..4].copy_from_slice(&v4.octets());
                buf[4] = 4; // IPv4 marker
            }
            crate::parser::IpAddr::V6(v6) => {
                buf[0..16].copy_from_slice(&v6);
                buf[4] = 6; // IPv6 marker
            }
        }
        
        match key.dst_ip {
            crate::parser::IpAddr::V4(v4) => {
                buf[16..20].copy_from_slice(&v4.octets());
            }
            crate::parser::IpAddr::V6(v6) => {
                buf[16..32].copy_from_slice(&v6);
            }
        }
        
        buf[32..34].copy_from_slice(&key.src_port.to_be_bytes());
        buf[34..36].copy_from_slice(&key.dst_port.to_be_bytes());
        
        xxh3_64(&buf)
    }

    /// Insert or update a flow entry.
    ///
    /// # Arguments
    ///
    /// * `key` - Flow key
    /// * `packet_len` - Length of the packet in bytes
    /// * `tcp_flags` - TCP flags bitmask (0 for non-TCP)
    /// * `seq` - TCP sequence number (for RTT estimation)
    /// * `ack` - TCP acknowledgment number
    ///
    /// # Returns
    ///
    /// True if this was a new flow, false if existing flow was updated
    pub fn insert_or_update(
        &self,
        key: FlowKey,
        packet_len: usize,
        tcp_flags: u8,
        seq: Option<u32>,
        ack: Option<u32>,
    ) -> bool {
        let hash = self.hash_key(&key);
        
        match self.map.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                // Update existing flow
                let state = entry.get_mut();
                state.update(packet_len, tcp_flags, seq, ack);
                false
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                // Check capacity
                if self.map.len() >= self.capacity {
                    // Simple eviction: don't add new flow
                    // In production, would evict oldest/least active
                    self.collisions.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                
                // Create new flow
                let mut state = FlowState::new();
                state.update(packet_len, tcp_flags, seq, ack);
                entry.insert(state);
                true
            }
        }
    }

    /// Get a flow by key.
    ///
    /// # Arguments
    ///
    /// * `key` - Flow key to look up
    ///
    /// # Returns
    ///
    /// Clone of the flow state if found
    pub fn get(&self, key: &FlowKey) -> Option<FlowState> {
        self.map.get(key).map(|ref| ref.value().clone())
    }

    /// Get a reference to a flow's state.
    ///
    /// # Arguments
    ///
    /// * `key` - Flow key
    ///
    /// # Returns
    ///
    /// DashMap reference guard (holds read lock)
    pub fn get_ref(&self, key: &FlowKey) -> Option<dashmap::mapref::one::Ref<FlowKey, FlowState>> {
        self.map.get(key)
    }

    /// Remove a flow from the table.
    ///
    /// # Arguments
    ///
    /// * `key` - Flow key to remove
    ///
    /// # Returns
    ///
    /// The removed flow state if it existed
    pub fn remove(&self, key: &FlowKey) -> Option<FlowState> {
        self.map.remove(key).map(|(_, v)| v)
    }

    /// Remove and return expired flows.
    ///
    /// # Arguments
    ///
    /// * `timeout_ns` - Idle timeout in nanoseconds
    ///
    /// # Returns
    ///
    /// Vector of expired flow keys and their states
    pub fn remove_expired(&self, timeout_ns: u64) -> Vec<(FlowKey, FlowState)> {
        let mut expired = Vec::new();
        
        // Collect keys to remove (can't modify while iterating)
        let keys_to_remove: Vec<_> = self
            .map
            .iter()
            .filter(|entry| entry.value().is_idle(timeout_ns))
            .map(|entry| *entry.key())
            .collect();
        
        // Remove and collect
        for key in keys_to_remove {
            if let Some(state) = self.remove(&key) {
                expired.push((key, state));
                self.expired_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        
        expired
    }

    /// Get the number of flows in the table.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get the current load factor.
    pub fn load_factor(&self) -> f64 {
        self.map.len() as f64 / self.capacity as f64
    }

    /// Check if the table is at capacity.
    pub fn is_full(&self) -> bool {
        self.load_factor() >= self.load_factor
    }

    /// Get statistics about the flow table.
    pub fn stats(&self) -> FlowTableStats {
        let len = self.map.len();
        
        FlowTableStats {
            total_flows: len as u64,
            active_flows: len as u64,
            expired_flows: self.expired_count.load(Ordering::Relaxed),
            total_packets: self.total_packets.load(Ordering::Relaxed),
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            collisions: self.collisions.load(Ordering::Relaxed),
            load_factor: self.load_factor(),
        }
    }

    /// Iterate over all flows.
    ///
    /// # Warning
    ///
    /// This acquires a read lock on the entire table. Use sparingly.
    pub fn iter<F>(&self, mut f: F)
    where
        F: FnMut(&FlowKey, &FlowState),
    {
        for entry in self.map.iter() {
            f(entry.key(), entry.value());
        }
    }

    /// Get top N flows by byte count.
    ///
    /// # Arguments
    ///
    /// * `n` - Number of top flows to return
    ///
    /// # Returns
    ///
    /// Vector of (FlowKey, FlowState) pairs sorted by byte count
    pub fn top_n_by_bytes(&self, n: usize) -> Vec<(FlowKey, FlowState)> {
        let mut flows: Vec<_> = self
            .map
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();
        
        flows.sort_by(|a, b| b.1.byte_count.cmp(&a.1.byte_count));
        flows.truncate(n);
        flows
    }

    /// Get top N flows by packet count.
    pub fn top_n_by_packets(&self, n: usize) -> Vec<(FlowKey, FlowState)> {
        let mut flows: Vec<_> = self
            .map
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();
        
        flows.sort_by(|a, b| b.1.packet_count.cmp(&a.1.packet_count));
        flows.truncate(n);
        flows
    }

    /// Clear all flows from the table.
    pub fn clear(&self) {
        self.map.clear();
    }

    /// Reserve capacity for expected number of flows.
    pub fn reserve(&self, additional: usize) {
        self.map.reserve(additional);
    }
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new(1_048_576) // 1M default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{IpAddr, Protocol};
    use std::net::Ipv4Addr;

    #[test]
    fn test_flow_table_insert() {
        let table = FlowTable::new(1000);
        
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        );
        
        let is_new = table.insert_or_update(key, 1500, 0x02, None, None);
        assert!(is_new);
        
        let is_new = table.insert_or_update(key, 100, 0x10, None, None);
        assert!(!is_new);
        
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_flow_table_get() {
        let table = FlowTable::new(1000);
        
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        );
        
        table.insert_or_update(key, 1500, 0x02, None, None);
        
        let state = table.get(&key).unwrap();
        assert_eq!(state.packet_count, 1);
        assert_eq!(state.byte_count, 1500);
    }

    #[test]
    fn test_flow_table_top_n() {
        let table = FlowTable::new(1000);
        
        for i in 0..10 {
            let key = FlowKey::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                12345,
                80,
                Protocol::Tcp,
            );
            table.insert_or_update(key, (i + 1) * 1000, 0, None, None);
        }
        
        let top = table.top_n_by_bytes(3);
        assert_eq!(top.len(), 3);
        assert!(top[0].1.byte_count >= top[1].1.byte_count);
    }
}
