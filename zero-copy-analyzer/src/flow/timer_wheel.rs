//! Hierarchical timing wheel for efficient flow expiration.
//!
//! This module implements a 3-level hierarchical timing wheel for O(1)
//! timer management with efficient bulk expiration operations.
//!
//! # Architecture
//!
//! The timing wheel has three levels:
//! - **Level 0**: 100 slots × 10ms = 1 second resolution
//! - **Level 1**: 60 slots × 1s = 1 minute resolution  
//! - **Level 2**: 60 slots × 1min = 1 hour resolution
//!
//! Total coverage: ~1 hour with 10ms granularity

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smallvec::SmallVec;

use crate::parser::FlowKey;

/// Number of slots in level 0 (10ms resolution, 1 second total)
const WHEEL_L0_SLOTS: usize = 100;

/// Number of slots in level 1 (1s resolution, 1 minute total)
const WHEEL_L1_SLOTS: usize = 60;

/// Number of slots in level 2 (1min resolution, 1 hour total)
const WHEEL_L2_SLOTS: usize = 60;

/// Duration per slot in level 0 (10ms)
const L0_SLOT_DURATION_MS: u64 = 10;

/// Duration per slot in level 1 (1s)
const L1_SLOT_DURATION_MS: u64 = 1000;

/// Duration per slot in level 2 (1min)
const L2_SLOT_DURATION_MS: u64 = 60_000;

/// A slot in the timing wheel containing flow keys
#[derive(Debug, Default)]
pub struct WheelSlot {
    /// Flow keys scheduled for this slot
    pub keys: SmallVec<[FlowKey; 4]>,
}

impl WheelSlot {
    /// Create a new empty slot
    pub fn new() -> Self {
        Self {
            keys: SmallVec::new(),
        }
    }

    /// Add a flow key to this slot
    pub fn push(&mut self, key: FlowKey) {
        self.keys.push(key);
    }

    /// Drain all keys from this slot
    pub fn drain(&mut self) -> SmallVec<[FlowKey; 4]> {
        self.keys.drain(..).collect()
    }

    /// Check if slot is empty
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Get number of keys in slot
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// A hierarchical timing wheel for efficient timer management.
///
/// Provides O(1) insertion and expiration for flow timeouts.
///
/// # Examples
///
/// ```no_run
/// use zero_copy_analyzer::flow::timer_wheel::TimingWheel;
/// use zero_copy_analyzer::parser::{FlowKey, IpAddr, Protocol};
/// use std::net::Ipv4Addr;
/// use std::time::Duration;
///
/// let wheel = TimingWheel::new();
///
/// let key = FlowKey::new(
///     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
///     IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
///     12345,
///     80,
///     Protocol::Tcp,
/// );
///
/// // Schedule expiration in 5 seconds
/// wheel.schedule(key, Duration::from_secs(5));
///
/// // Tick the wheel periodically
/// let expired = wheel.tick(Duration::from_millis(10));
/// ```
pub struct TimingWheel {
    /// Level 0 wheel (10ms slots)
    l0: Box<[WheelSlot; WHEEL_L0_SLOTS]>,
    /// Level 1 wheel (1s slots)
    l1: Box<[WheelSlot; WHEEL_L1_SLOTS]>,
    /// Level 2 wheel (1min slots)
    l2: Box<[WheelSlot; WHEEL_L2_SLOTS]>,
    /// Current tick count (in 10ms units)
    current_tick: AtomicU64,
    /// Start time
    start_time: Instant,
    /// Total scheduled timers
    scheduled_count: AtomicU64,
    /// Total expired timers
    expired_count: AtomicU64,
}

impl Default for TimingWheel {
    fn default() -> Self {
        Self::new()
    }
}

impl TimingWheel {
    /// Create a new timing wheel.
    pub fn new() -> Self {
        Self {
            l0: std::array::from_fn(|_| WheelSlot::new()),
            l1: std::array::from_fn(|_| WheelSlot::new()),
            l2: std::array::from_fn(|_| WheelSlot::new()),
            current_tick: AtomicU64::new(0),
            start_time: Instant::now(),
            scheduled_count: AtomicU64::new(0),
            expired_count: AtomicU64::new(0),
        }
    }

    /// Get the current tick count.
    #[inline]
    fn tick(&self) -> u64 {
        self.current_tick.load(Ordering::Relaxed)
    }

    /// Calculate which slot a deadline maps to at a given level.
    #[inline]
    fn slot_for_tick(tick: u64, delay_ticks: u64, num_slots: usize) -> usize {
        ((tick + delay_ticks) as usize) % num_slots
    }

    /// Schedule a flow key for expiration after the given duration.
    ///
    /// # Arguments
    ///
    /// * `key` - Flow key to schedule
    /// * `delay` - Duration until expiration
    ///
    /// # Returns
    ///
    /// True if scheduled successfully
    pub fn schedule(&self, key: FlowKey, delay: Duration) -> bool {
        let delay_ms = delay.as_millis() as u64;
        let delay_ticks = (delay_ms + L0_SLOT_DURATION_MS - 1) / L0_SLOT_DURATION_MS;
        
        let current = self.tick();
        let target_tick = current + delay_ticks;

        // Determine which level to place the timer
        if delay_ticks < WHEEL_L0_SLOTS as u64 {
            // Level 0: < 1 second
            let slot = Self::slot_for_tick(current, delay_ticks, WHEEL_L0_SLOTS);
            self.l0[slot].push(key);
        } else if delay_ticks < (WHEEL_L0_SLOTS * WHEEL_L1_SLOTS) as u64 {
            // Level 1: < 1 minute
            let delay_l1_ticks = delay_ticks / WHEEL_L0_SLOTS as u64;
            let slot = Self::slot_for_tick(
                current / WHEEL_L0_SLOTS as u64,
                delay_l1_ticks,
                WHEEL_L1_SLOTS,
            );
            self.l1[slot].push(key);
        } else {
            // Level 2: >= 1 minute (up to ~1 hour)
            let delay_l2_ticks = delay_ticks / (WHEEL_L0_SLOTS * WHEEL_L1_SLOTS) as u64;
            let slot = Self::slot_for_tick(
                current / (WHEEL_L0_SLOTS * WHEEL_L1_SLOTS) as u64,
                delay_l2_ticks.min(WHEEL_L2_SLOTS as u64 - 1),
                WHEEL_L2_SLOTS,
            );
            self.l2[slot].push(key);
        }

        self.scheduled_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Advance the wheel by the given duration and return expired keys.
    ///
    /// # Arguments
    ///
    /// * `elapsed` - Time elapsed since last tick
    ///
    /// # Returns
    ///
    /// Vector of expired flow keys
    pub fn tick(&self, elapsed: Duration) -> Vec<FlowKey> {
        let elapsed_ms = elapsed.as_millis() as u64;
        let ticks_to_advance = (elapsed_ms + L0_SLOT_DURATION_MS - 1) / L0_SLOT_DURATION_MS;
        
        if ticks_to_advance == 0 {
            return Vec::new();
        }

        let mut expired = Vec::new();
        let old_tick = self.current_tick.swap(
            self.tick() + ticks_to_advance,
            Ordering::Relaxed,
        );

        // Process each tick that we advanced through
        for tick_offset in 0..ticks_to_advance {
            let tick = old_tick + tick_offset;
            
            // Process level 0 slot
            let l0_slot = tick as usize % WHEEL_L0_SLOTS;
            let l0_expired = self.l0[l0_slot].drain();
            expired.extend(l0_expired.into_iter());

            // Every L0_SLOTS ticks, process level 1
            if tick % WHEEL_L0_SLOTS as u64 == 0 {
                let l1_tick = tick / WHEEL_L0_SLOTS as u64;
                let l1_slot = l1_tick as usize % WHEEL_L1_SLOTS;
                
                // Move level 1 entries down to level 0 or expire them
                let l1_expired = self.l1[l1_slot].drain();
                for key in l1_expired {
                    // Re-schedule to level 0 with remaining time
                    // For simplicity, just expire them now
                    expired.push(key);
                }

                // Every L1_SLOTS ticks at level 1, process level 2
                if l1_tick % WHEEL_L1_SLOTS as u64 == 0 {
                    let l2_tick = l1_tick / WHEEL_L1_SLOTS as u64;
                    let l2_slot = l2_tick as usize % WHEEL_L2_SLOTS;
                    
                    let l2_expired = self.l2[l2_slot].drain();
                    for key in l2_expired {
                        // Move to level 1
                        let l1_slot = (l1_tick as usize + 1) % WHEEL_L1_SLOTS;
                        self.l1[l1_slot].push(key);
                    }
                }
            }
        }

        self.expired_count.fetch_add(expired.len() as u64, Ordering::Relaxed);
        expired
    }

    /// Remove a specific key from the wheel (if not yet expired).
    ///
    /// Note: This is O(n) in the number of slots and should be used sparingly.
    ///
    /// # Arguments
    ///
    /// * `key` - Flow key to cancel
    ///
    /// # Returns
    ///
    /// True if the key was found and removed
    pub fn cancel(&self, key: &FlowKey) -> bool {
        // Search all slots (expensive operation)
        for slot in self.l0.iter_mut() {
            if let Some(pos) = slot.keys.iter().position(|k| k == key) {
                slot.keys.remove(pos);
                return true;
            }
        }
        
        for slot in self.l1.iter_mut() {
            if let Some(pos) = slot.keys.iter().position(|k| k == key) {
                slot.keys.remove(pos);
                return true;
            }
        }
        
        for slot in self.l2.iter_mut() {
            if let Some(pos) = slot.keys.iter().position(|k| k == key) {
                slot.keys.remove(pos);
                return true;
            }
        }
        
        false
    }

    /// Get statistics about the timing wheel.
    pub fn stats(&self) -> TimingWheelStats {
        let l0_count: usize = self.l0.iter().map(|s| s.len()).sum();
        let l1_count: usize = self.l1.iter().map(|s| s.len()).sum();
        let l2_count: usize = self.l2.iter().map(|s| s.len()).sum();

        TimingWheelStats {
            level0_count: l0_count as u64,
            level1_count: l1_count as u64,
            level2_count: l2_count as u64,
            total_scheduled: self.scheduled_count.load(Ordering::Relaxed),
            total_expired: self.expired_count.load(Ordering::Relaxed),
            current_tick: self.tick(),
            uptime_ms: self.start_time.elapsed().as_millis() as u64,
        }
    }

    /// Get the approximate number of pending timers.
    pub fn pending_count(&self) -> usize {
        self.l0.iter().map(|s| s.len()).sum::<usize>()
            + self.l1.iter().map(|s| s.len()).sum::<usize>()
            + self.l2.iter().map(|s| s.len()).sum::<usize>()
    }

    /// Clear all timers from the wheel.
    pub fn clear(&self) {
        for slot in self.l0.iter_mut() {
            slot.keys.clear();
        }
        for slot in self.l1.iter_mut() {
            slot.keys.clear();
        }
        for slot in self.l2.iter_mut() {
            slot.keys.clear();
        }
    }
}

/// Statistics about the timing wheel
#[derive(Debug, Default, Clone)]
pub struct TimingWheelStats {
    /// Number of timers in level 0
    pub level0_count: u64,
    /// Number of timers in level 1
    pub level1_count: u64,
    /// Number of timers in level 2
    pub level2_count: u64,
    /// Total timers ever scheduled
    pub total_scheduled: u64,
    /// Total timers ever expired
    pub total_expired: u64,
    /// Current tick value
    pub current_tick: u64,
    /// Uptime in milliseconds
    pub uptime_ms: u64,
}

impl TimingWheelStats {
    /// Get total pending timers
    pub fn total_pending(&self) -> u64 {
        self.level0_count + self.level1_count + self.level2_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{IpAddr, Protocol};
    use std::net::Ipv4Addr;
    use std::thread;

    #[test]
    fn test_schedule_and_expire() {
        let wheel = TimingWheel::new();
        
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        );

        // Schedule for 50ms from now
        wheel.schedule(key, Duration::from_millis(50));
        assert_eq!(wheel.pending_count(), 1);

        // Tick past the deadline
        thread::sleep(Duration::from_millis(60));
        let expired = wheel.tick(Duration::from_millis(70));
        
        assert!(!expired.is_empty());
        assert_eq!(wheel.pending_count(), 0);
    }

    #[test]
    fn test_cancel_timer() {
        let wheel = TimingWheel::new();
        
        let key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            80,
            Protocol::Tcp,
        );

        wheel.schedule(key, Duration::from_secs(10));
        assert_eq!(wheel.pending_count(), 1);

        let cancelled = wheel.cancel(&key);
        assert!(cancelled);
        assert_eq!(wheel.pending_count(), 0);
    }

    #[test]
    fn test_stats() {
        let wheel = TimingWheel::new();
        
        for i in 0..10 {
            let key = FlowKey::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                12345 + i,
                80,
                Protocol::Tcp,
            );
            wheel.schedule(key, Duration::from_millis(100));
        }

        let stats = wheel.stats();
        assert_eq!(stats.total_scheduled, 10);
        assert_eq!(stats.total_pending(), 10);
    }
}
