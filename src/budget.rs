//! Relay budgets and neighbour penalties (MSH-10).
//!
//! Two independent token buckets gate every admitted packet: one per claimed
//! origin and one per sending link. Both use the per-class hourly budgets in
//! ADR-0001, so Direct has the largest allowance and Telemetry the smallest.
//! A packet is relayed only when both buckets have enough tokens; local
//! delivery is never suppressed by a budget. Class buckets do not borrow from
//! each other, which is what makes the class ordering in ADR-0001 meaningful
//! under load.
//!
//! State is bounded by configuration. Origin buckets are evicted
//! least-recently-used first, with `NodeId` order as a deterministic tie-break;
//! neighbour state disappears on `LinkDown`. Time is caller-supplied
//! milliseconds, and backwards clocks never mint tokens.

use ao_idents::NodeId;
use ao_network::LinkId;
use std::collections::BTreeMap;

use crate::packet::PacketClass;

/// Fixed-point scale for token fractions. Telemetry's 32 KiB/hour is about
/// 9 units per millisecond at this scale, so integer refill does not round a
/// normal tick down to zero.
const SCALE: u128 = 1024;
const MS_PER_HOUR: u128 = 3_600_000;

/// Relay allowance and burst for one traffic class.
///
/// The array index is the class's position in
/// [`crate::PacketClass::all`]: Direct, Broadcast, Presence, Telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassRate {
    /// Sustained allowance in bytes per hour (ADR-0001).
    pub bytes_per_hour: u64,
    /// Refill window represented by a full bucket, in seconds.
    ///
    /// A shorter window bounds a single burst; a longer one tolerates a
    /// chattier but honest node. The default is ten minutes.
    pub burst_seconds: u64,
}

/// Bounds, rates and penalty tuning for [`BudgetTracker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetConfig {
    /// Whether budgets and penalties are enforced.
    ///
    /// The simulator sets this to false only for ablation runs that measure
    /// what a flood would do without MSH-10; production engines leave it on.
    pub enforce: bool,
    /// Maximum distinct claimed origins tracked at once.
    pub max_origins: usize,
    /// Maximum distinct sending links tracked at once.
    pub max_neighbors: usize,
    /// Class rates in Direct, Broadcast, Presence, Telemetry order.
    pub rates: [ClassRate; 4],
    /// Penalty for a structurally invalid packet from a link.
    pub penalty_invalid: u32,
    /// Penalty for a packet from a link whose hello did not verify.
    pub penalty_unverified: u32,
    /// Penalty for a packet its bucket could not admit.
    pub penalty_excess: u32,
    /// Penalty threshold at which the link is released once.
    pub penalty_release_at: u32,
    /// Penalty removed per decay interval.
    pub penalty_decay: u32,
    /// Length of one penalty decay interval in milliseconds.
    pub penalty_decay_ms: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            enforce: true,
            max_origins: 1024,
            max_neighbors: 32,
            rates: [
                ClassRate {
                    bytes_per_hour: 1024 * 1024,
                    burst_seconds: 600,
                },
                ClassRate {
                    bytes_per_hour: 256 * 1024,
                    burst_seconds: 600,
                },
                ClassRate {
                    bytes_per_hour: 64 * 1024,
                    burst_seconds: 600,
                },
                ClassRate {
                    bytes_per_hour: 32 * 1024,
                    burst_seconds: 600,
                },
            ],
            penalty_invalid: 3,
            penalty_unverified: 2,
            penalty_excess: 1,
            penalty_release_at: 12,
            penalty_decay: 1,
            penalty_decay_ms: 60_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    tokens: u64,
    capacity: u64,
    last_ms: u64,
}

impl Bucket {
    fn new(now: u64, capacity: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_ms: now,
        }
    }

    fn refill(&mut self, now: u64, rate: ClassRate) {
        if now <= self.last_ms {
            return;
        }
        let elapsed = (now - self.last_ms) as u128;
        let added = elapsed
            .saturating_mul(rate.bytes_per_hour as u128)
            .saturating_mul(SCALE)
            / MS_PER_HOUR;
        self.tokens = (self.tokens as u128)
            .saturating_add(added)
            .min(self.capacity as u128) as u64;
        self.last_ms = now;
    }

    fn take(&mut self, cost: u64) -> bool {
        if self.tokens < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClassBuckets {
    slots: [Bucket; 4],
    last_ms: u64,
}

impl ClassBuckets {
    fn new(now: u64, rates: &[ClassRate; 4]) -> Self {
        Self {
            slots: [
                Bucket::new(now, capacity(rates[0])),
                Bucket::new(now, capacity(rates[1])),
                Bucket::new(now, capacity(rates[2])),
                Bucket::new(now, capacity(rates[3])),
            ],
            last_ms: now,
        }
    }

    fn try_take(&mut self, now: u64, rates: &[ClassRate; 4], index: usize, cost: u64) -> bool {
        self.last_ms = now;
        let bucket = &mut self.slots[index];
        bucket.refill(now, rates[index]);
        bucket.take(cost)
    }
}

fn rate_index(class: PacketClass) -> usize {
    match class {
        PacketClass::Direct => 0,
        PacketClass::Broadcast => 1,
        PacketClass::Presence => 2,
        PacketClass::Telemetry => 3,
    }
}

fn capacity(rate: ClassRate) -> u64 {
    let value = (rate.bytes_per_hour as u128)
        .saturating_mul(rate.burst_seconds as u128)
        .saturating_mul(SCALE)
        / 3_600;
    value.min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NeighborBudget {
    buckets: ClassBuckets,
    penalty: u32,
    penalty_at_ms: u64,
    released: bool,
}

impl NeighborBudget {
    fn new(now: u64, rates: &[ClassRate; 4]) -> Self {
        Self {
            buckets: ClassBuckets::new(now, rates),
            penalty: 0,
            penalty_at_ms: now,
            released: false,
        }
    }
}

/// Deterministic, bounded relay-budget and penalty state.
///
/// The engine owns one tracker; callers only read it through
/// [`crate::MeshEngine::budgets`].
#[derive(Debug)]
pub struct BudgetTracker {
    config: BudgetConfig,
    origins: BTreeMap<NodeId, ClassBuckets>,
    neighbors: BTreeMap<LinkId, NeighborBudget>,
}

impl BudgetTracker {
    pub(crate) fn new(config: BudgetConfig) -> Self {
        Self {
            config,
            origins: BTreeMap::new(),
            neighbors: BTreeMap::new(),
        }
    }

    /// Whether one received packet fits both the origin and neighbour
    /// allowance. On success both buckets are debited exactly once.
    pub fn admit(
        &mut self,
        now: u64,
        link: LinkId,
        origin: NodeId,
        class: PacketClass,
        bytes: usize,
    ) -> bool {
        if !self.config.enforce {
            return true;
        }
        if self.config.max_origins == 0 || self.config.max_neighbors == 0 {
            return false;
        }
        if !self.origins.contains_key(&origin) && self.origins.len() >= self.config.max_origins {
            let victim = self
                .origins
                .iter()
                .min_by_key(|(id, buckets)| (buckets.last_ms, **id))
                .map(|(id, _)| *id);
            if let Some(victim) = victim {
                self.origins.remove(&victim);
            }
        }
        if !self.neighbors.contains_key(&link) && self.neighbors.len() >= self.config.max_neighbors
        {
            return false;
        }
        let rates = self.config.rates;
        let index = rate_index(class);
        let cost = (bytes as u128).saturating_mul(SCALE).min(u64::MAX as u128) as u64;
        let origin_buckets = self
            .origins
            .entry(origin)
            .or_insert_with(|| ClassBuckets::new(now, &rates));
        let neighbor = self
            .neighbors
            .entry(link)
            .or_insert_with(|| NeighborBudget::new(now, &rates));
        neighbor.buckets.last_ms = now;
        let origin_ok = origin_buckets.try_take(now, &rates, index, cost);
        if !origin_ok {
            return false;
        }
        if !neighbor.buckets.try_take(now, &rates, index, cost) {
            // The origin was debited, so refund it: a denied packet must
            // not consume allowance the neighbour's bucket cannot cover.
            let refund = origin_buckets.slots[index];
            let mut restored = refund;
            restored.tokens = refund.tokens.saturating_add(cost).min(refund.capacity);
            origin_buckets.slots[index] = restored;
            return false;
        }
        true
    }

    /// Adds `amount` to a link's penalty after decaying old score.
    ///
    /// Returns true exactly once, on the transition over the release
    /// threshold, so the adapter does not disconnect the same link on every
    /// subsequent packet.
    pub fn penalize(&mut self, now: u64, link: LinkId, amount: u32) -> bool {
        if !self.config.enforce || self.config.max_neighbors == 0 {
            return false;
        }
        let rates = self.config.rates;
        let neighbor = self
            .neighbors
            .entry(link)
            .or_insert_with(|| NeighborBudget::new(now, &rates));
        if self.config.penalty_decay_ms > 0 && now > neighbor.penalty_at_ms {
            let steps = (now - neighbor.penalty_at_ms) / self.config.penalty_decay_ms;
            let decay = steps
                .saturating_mul(self.config.penalty_decay as u64)
                .min(u32::MAX as u64) as u32;
            neighbor.penalty = neighbor.penalty.saturating_sub(decay);
            neighbor.penalty_at_ms = neighbor
                .penalty_at_ms
                .saturating_add(steps.saturating_mul(self.config.penalty_decay_ms));
        }
        neighbor.penalty = neighbor.penalty.saturating_add(amount);
        if neighbor.penalty >= self.config.penalty_release_at && !neighbor.released {
            neighbor.released = true;
            return true;
        }
        false
    }

    /// Whether this link has already been asked to disconnect.
    ///
    /// The engine stops acting on its traffic until `LinkDown` removes the
    /// entry; aoNetwork remains responsible for completing the disconnect.
    pub fn is_released(&self, link: LinkId) -> bool {
        self.neighbors
            .get(&link)
            .is_some_and(|neighbor| neighbor.released)
    }

    /// Current penalty for a tracked link, for tests and observability.
    pub fn penalty(&self, link: LinkId) -> u32 {
        self.neighbors
            .get(&link)
            .map_or(0, |neighbor| neighbor.penalty)
    }

    /// Number of claimed origins with live bucket state.
    pub fn origins(&self) -> usize {
        self.origins.len()
    }

    pub(crate) fn link_down(&mut self, link: LinkId) {
        self.neighbors.remove(&link);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK_A: LinkId = LinkId::new(1);
    const LINK_B: LinkId = LinkId::new(2);
    const ORIGIN_A: NodeId = NodeId::from_bytes([1; 16]);
    const ORIGIN_B: NodeId = NodeId::from_bytes([2; 16]);

    fn small() -> BudgetConfig {
        BudgetConfig {
            enforce: true,
            max_origins: 2,
            max_neighbors: 2,
            rates: [ClassRate {
                bytes_per_hour: 3_600,
                burst_seconds: 600,
            }; 4],
            penalty_release_at: 3,
            penalty_invalid: 1,
            penalty_unverified: 1,
            penalty_excess: 1,
            penalty_decay: 1,
            penalty_decay_ms: 1_000,
        }
    }

    #[test]
    fn a_bucket_starts_with_ten_minutes_of_allowance() {
        // 3600 bytes/hour over 600 s is 600 bytes of burst.
        let tracker = BudgetTracker::new(small());
        let mut buckets = ClassBuckets::new(0, &small().rates);
        assert_eq!(buckets.slots[0].tokens, 600 * SCALE as u64);
        assert!(buckets.try_take(0, &tracker.config.rates, 0, 600 * SCALE as u64));
        assert!(!buckets.try_take(0, &tracker.config.rates, 0, 1));
    }

    #[test]
    fn both_origin_and_neighbour_must_admit() {
        let config = small();
        let mut tracker = BudgetTracker::new(config);
        assert!(tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 10));
        // Origin A is now over its burst; a different neighbour cannot
        // rescue it, so flooding is throttled network-wide.
        let mut flood = BudgetTracker::new(config);
        assert!(flood.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 600));
        assert!(!flood.admit(0, LINK_B, ORIGIN_A, PacketClass::Direct, 1));
        // The same neighbour flooding many origins is caught by its own
        // bucket even when each origin still has tokens.
        let mut neighbor = BudgetTracker::new(config);
        assert!(neighbor.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 600));
        assert!(!neighbor.admit(0, LINK_A, ORIGIN_B, PacketClass::Direct, 1));
    }

    #[test]
    fn denied_packet_does_not_consume_the_other_bucket() {
        let config = small();
        let mut tracker = BudgetTracker::new(config);
        assert!(tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 600));
        assert!(!tracker.admit(0, LINK_B, ORIGIN_A, PacketClass::Direct, 1));
        // Refunded origin can still send one small packet from a fresh link.
        assert!(tracker.admit(0, LINK_B, ORIGIN_B, PacketClass::Direct, 1));
    }

    #[test]
    fn clock_going_backwards_never_mints_tokens() {
        let config = small();
        let mut tracker = BudgetTracker::new(config);
        assert!(tracker.admit(10_000, LINK_A, ORIGIN_A, PacketClass::Direct, 600));
        assert!(!tracker.admit(0, LINK_B, ORIGIN_A, PacketClass::Direct, 1));
    }

    #[test]
    fn least_recently_used_origin_is_evicted() {
        let mut config = small();
        config.max_origins = 2;
        let mut tracker = BudgetTracker::new(config);
        assert!(tracker.admit(10, LINK_A, ORIGIN_A, PacketClass::Direct, 1));
        assert!(tracker.admit(20, LINK_A, ORIGIN_B, PacketClass::Direct, 1));
        let third = NodeId::from_bytes([3; 16]);
        assert!(tracker.admit(30, LINK_A, third, PacketClass::Direct, 1));
        assert_eq!(tracker.origins(), 2);
        assert!(tracker.admit(40, LINK_A, ORIGIN_A, PacketClass::Direct, 1));
    }

    #[test]
    fn penalty_crosses_release_threshold_once_and_decays() {
        let config = small();
        let mut tracker = BudgetTracker::new(config);
        assert!(!tracker.penalize(0, LINK_A, 2));
        assert!(tracker.penalize(1, LINK_A, 1));
        assert_eq!(tracker.penalty(LINK_A), 3);
        assert!(!tracker.penalize(2, LINK_A, 1), "no repeated release");
        assert!(tracker.is_released(LINK_A));
        assert!(!tracker.is_released(LINK_B));
        // Two decay intervals have elapsed since the last penalty update.
        assert!(!tracker.penalize(2_001, LINK_A, 0));
        assert_eq!(tracker.penalty(LINK_A), 2);
    }

    #[test]
    fn disabled_budgets_are_an_ablation_not_a_silent_zero_rate() {
        let mut config = small();
        config.enforce = false;
        config.max_origins = 0;
        config.max_neighbors = 0;
        let mut tracker = BudgetTracker::new(config);
        assert!(tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Telemetry, 4096));
        assert!(!tracker.penalize(0, LINK_A, 1_000));
    }

    #[test]
    fn link_down_forgets_neighbour_penalty() {
        let mut tracker = BudgetTracker::new(small());
        assert!(tracker.penalize(0, LINK_A, 3));
        tracker.link_down(LINK_A);
        assert_eq!(tracker.penalty(LINK_A), 0);
    }
}
