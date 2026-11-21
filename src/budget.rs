//! Relay budgets and neighbour penalties (MSH-10).
//!
//! Two independent token buckets gate every admitted packet: one per claimed
//! origin and one per (sending link, claimed origin) pair. Both use the
//! per-class hourly budgets in ADR-0001, so Direct has the largest allowance
//! and Telemetry the smallest. Keying the link bucket by origin prevents a
//! flooding origin from consuming the allowance honest origins need on the
//! same link.
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

impl ClassRate {
    /// Full bucket for this rate in bytes, before the fixed-point scale.
    ///
    /// Used by reports and gates that compare measured channel traffic with
    /// the Broadcast allowance; it is the calculation the token buckets use
    /// at construction.
    #[must_use]
    pub fn burst_bytes(&self) -> u64 {
        capacity(*self) / SCALE as u64
    }
}

/// Which bucket, if any, refused a relay (MSH-10).
///
/// The distinction matters for blame: an exhausted origin is that origin's
/// fault and must not disconnect the neighbour that merely forwarded it. An
/// exhausted sending link is local to that neighbour and feeds its penalty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetOutcome {
    /// Both buckets accepted the packet; the relay may proceed.
    Admitted,
    /// The claimed origin has no allowance left.
    OriginDenied,
    /// The sending link has no allowance left.
    NeighborDenied,
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
    /// Maximum distinct origins tracked inside one sending link.
    ///
    /// Bounds the per-link bucket map independently of the global origin
    /// table. An overfull link evicts its least-recently-used origin.
    pub max_origins_per_neighbor: usize,
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
            max_origins_per_neighbor: 64,
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
    buckets: BTreeMap<NodeId, ClassBuckets>,
    penalty: u32,
    penalty_at_ms: u64,
    released: bool,
}

impl NeighborBudget {
    fn new(now: u64) -> Self {
        Self {
            buckets: BTreeMap::new(),
            penalty: 0,
            penalty_at_ms: now,
            released: false,
        }
    }

    fn buckets(
        &mut self,
        now: u64,
        rates: &[ClassRate; 4],
        origin: NodeId,
        limit: usize,
    ) -> &mut ClassBuckets {
        if !self.buckets.contains_key(&origin) && self.buckets.len() >= limit {
            let victim = self
                .buckets
                .iter()
                .min_by_key(|(id, buckets)| (buckets.last_ms, **id))
                .map(|(id, _)| *id);
            if let Some(victim) = victim {
                self.buckets.remove(&victim);
            }
        }
        self.buckets
            .entry(origin)
            .or_insert_with(|| ClassBuckets::new(now, rates))
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

    /// Checks one packet against the origin and neighbour allowances.
    ///
    /// On [`BudgetOutcome::Admitted`] both buckets are debited exactly once.
    /// A refused packet debits neither bucket: if the origin bucket accepted
    /// but the neighbour bucket did not, the origin debit is refunded.
    pub fn admit(
        &mut self,
        now: u64,
        link: LinkId,
        origin: NodeId,
        class: PacketClass,
        bytes: usize,
    ) -> BudgetOutcome {
        if !self.config.enforce {
            return BudgetOutcome::Admitted;
        }
        if self.config.max_origins == 0 {
            return BudgetOutcome::OriginDenied;
        }
        if self.config.max_neighbors == 0 || self.config.max_origins_per_neighbor == 0 {
            return BudgetOutcome::NeighborDenied;
        }
        if !self.neighbors.contains_key(&link) && self.neighbors.len() >= self.config.max_neighbors
        {
            return BudgetOutcome::NeighborDenied;
        }
        // Copy config before taking disjoint mutable field borrows; the
        // neighbour map and origin table never alias each other.
        let rates = self.config.rates;
        let max_origins_per_neighbor = self.config.max_origins_per_neighbor;
        let index = rate_index(class);
        let cost = (bytes as u128).saturating_mul(SCALE).min(u64::MAX as u128) as u64;
        let origin_buckets = match Self::origin_bucket(
            &mut self.origins,
            self.config.max_origins,
            &rates,
            now,
            origin,
        ) {
            Some(buckets) => buckets,
            None => return BudgetOutcome::OriginDenied,
        };
        let neighbor = self
            .neighbors
            .entry(link)
            .or_insert_with(|| NeighborBudget::new(now));
        let neighbor_buckets = neighbor.buckets(now, &rates, origin, max_origins_per_neighbor);
        neighbor_buckets.last_ms = now;
        let origin_ok = origin_buckets.try_take(now, &rates, index, cost);
        if !origin_ok {
            return BudgetOutcome::OriginDenied;
        }
        if !neighbor_buckets.try_take(now, &rates, index, cost) {
            // The origin was debited, so refund it: a denied packet must
            // not consume allowance the neighbour's bucket cannot cover.
            let refund = origin_buckets.slots[index];
            let mut restored = refund;
            restored.tokens = refund.tokens.saturating_add(cost).min(refund.capacity);
            origin_buckets.slots[index] = restored;
            return BudgetOutcome::NeighborDenied;
        }
        BudgetOutcome::Admitted
    }

    /// Debits one origin-style bucket without charging a link.
    ///
    /// Local submissions (MSH-23) pay their per-origin allowance here. A
    /// submission has no receiving link, so inventing a sentinel neighbour
    /// would consume one of the bounded link slots; this uses the same
    /// origin table and class rate as [`Self::admit`] instead.
    pub(crate) fn admit_origin(
        &mut self,
        now: u64,
        origin: NodeId,
        class: PacketClass,
        bytes: usize,
    ) -> BudgetOutcome {
        if !self.config.enforce {
            return BudgetOutcome::Admitted;
        }
        let rates = self.config.rates;
        let cost = (bytes as u128).saturating_mul(SCALE).min(u64::MAX as u128) as u64;
        let Some(buckets) = Self::origin_bucket(
            &mut self.origins,
            self.config.max_origins,
            &rates,
            now,
            origin,
        ) else {
            return BudgetOutcome::OriginDenied;
        };
        if buckets.try_take(now, &rates, rate_index(class), cost) {
            BudgetOutcome::Admitted
        } else {
            BudgetOutcome::OriginDenied
        }
    }

    /// Restores an origin debit after a paired admission failed.
    ///
    /// A local channel submission needs both its origin and its channel to
    /// admit the same bytes. If the second bucket refuses, the first must not
    /// keep tokens for a packet that was never emitted (MSH-10's refund rule).
    pub(crate) fn refund_origin(
        &mut self,
        now: u64,
        origin: NodeId,
        class: PacketClass,
        bytes: usize,
    ) {
        if !self.config.enforce {
            return;
        }
        let rates = self.config.rates;
        let cost = (bytes as u128).saturating_mul(SCALE).min(u64::MAX as u128) as u64;
        // Re-create the entry if the paired channel admission evicted it from
        // a very small LRU table; otherwise a denied packet silently burns
        // tokens for an origin that never emitted one. The table stays bounded
        // because this uses the same insertion path as admission.
        let Some(buckets) = Self::origin_bucket(
            &mut self.origins,
            self.config.max_origins,
            &rates,
            now,
            origin,
        ) else {
            return;
        };
        let slot = &mut buckets.slots[rate_index(class)];
        slot.refill(now, rates[rate_index(class)]);
        slot.tokens = slot.tokens.saturating_add(cost).min(slot.capacity);
    }

    /// Debits only an origin-style bucket, for MSH-23's per-channel key.
    ///
    /// Public channels reuse the same class rates and the same bounded
    /// LRU token-bucket table as [`Self::admit`]; the synthetic key comes
    /// from `channel::channel_budget_origin`. No second budget table, timer
    /// or config knob is introduced, and the link bucket is not charged
    /// twice for one packet. A denial is always reported as
    /// [`BudgetOutcome::OriginDenied`]: it is never the neighbour's fault.
    pub(crate) fn admit_channel(
        &mut self,
        now: u64,
        channel: NodeId,
        class: PacketClass,
        bytes: usize,
    ) -> BudgetOutcome {
        if !self.config.enforce {
            return BudgetOutcome::Admitted;
        }
        let rates = self.config.rates;
        let cost = (bytes as u128).saturating_mul(SCALE).min(u64::MAX as u128) as u64;
        let Some(buckets) = Self::origin_bucket(
            &mut self.origins,
            self.config.max_origins,
            &rates,
            now,
            channel,
        ) else {
            return BudgetOutcome::OriginDenied;
        };
        if buckets.try_take(now, &rates, rate_index(class), cost) {
            BudgetOutcome::Admitted
        } else {
            BudgetOutcome::OriginDenied
        }
    }

    fn origin_bucket<'a>(
        origins: &'a mut BTreeMap<NodeId, ClassBuckets>,
        max_origins: usize,
        rates: &[ClassRate; 4],
        now: u64,
        origin: NodeId,
    ) -> Option<&'a mut ClassBuckets> {
        if max_origins == 0 {
            return None;
        }
        if !origins.contains_key(&origin) && origins.len() >= max_origins {
            let victim = origins
                .iter()
                .min_by_key(|(id, buckets)| (buckets.last_ms, **id))
                .map(|(id, _)| *id);
            if let Some(victim) = victim {
                origins.remove(&victim);
            }
        }
        Some(
            origins
                .entry(origin)
                .or_insert_with(|| ClassBuckets::new(now, rates)),
        )
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
        let neighbor = self
            .neighbors
            .entry(link)
            .or_insert_with(|| NeighborBudget::new(now));
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
            max_origins_per_neighbor: 2,
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
        assert_eq!(
            tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 10),
            BudgetOutcome::Admitted
        );
        // Origin A is now over its burst; a different neighbour cannot
        // rescue it, so flooding is throttled network-wide.
        let mut flood = BudgetTracker::new(config);
        assert_eq!(
            flood.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 600),
            BudgetOutcome::Admitted
        );
        assert_eq!(
            flood.admit(0, LINK_B, ORIGIN_A, PacketClass::Direct, 1),
            BudgetOutcome::OriginDenied
        );
        // An origin that saturates one link cannot retry through it, but
        // a different origin has its own allowance on the same link.
        let mut neighbor = BudgetTracker::new(config);
        assert_eq!(
            neighbor.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 600),
            BudgetOutcome::Admitted
        );
        assert_eq!(
            neighbor.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 1),
            BudgetOutcome::OriginDenied
        );
        assert_eq!(
            neighbor.admit(0, LINK_A, ORIGIN_B, PacketClass::Direct, 1),
            BudgetOutcome::Admitted
        );
    }

    #[test]
    fn a_flooding_origin_does_not_starve_other_origins_on_one_link() {
        let mut tracker = BudgetTracker::new(small());
        for _ in 0..6 {
            assert_eq!(
                tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 100),
                BudgetOutcome::Admitted
            );
        }
        assert_eq!(
            tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 1),
            BudgetOutcome::OriginDenied
        );
        assert_eq!(
            tracker.admit(0, LINK_A, ORIGIN_B, PacketClass::Direct, 100),
            BudgetOutcome::Admitted
        );
    }

    #[test]
    fn per_neighbor_origin_buckets_are_bounded() {
        let mut config = small();
        config.max_origins = 3;
        config.max_origins_per_neighbor = 1;
        let mut tracker = BudgetTracker::new(config);
        assert_eq!(
            tracker.admit(10, LINK_A, ORIGIN_A, PacketClass::Direct, 100),
            BudgetOutcome::Admitted
        );
        assert_eq!(
            tracker.admit(20, LINK_A, ORIGIN_B, PacketClass::Direct, 100),
            BudgetOutcome::Admitted
        );
        // B evicted A from this link's bounded map, so A gets a fresh bucket.
        assert_eq!(
            tracker.admit(30, LINK_A, ORIGIN_A, PacketClass::Direct, 100),
            BudgetOutcome::Admitted
        );
        assert_eq!(tracker.origins(), 2);
    }

    #[test]
    fn default_origin_per_neighbor_bound_matches_the_adr() {
        assert_eq!(BudgetConfig::default().max_origins_per_neighbor, 64);
    }

    #[test]
    fn channel_key_reuses_the_origin_bucket_without_charging_a_link() {
        let config = small();
        let mut tracker = BudgetTracker::new(config);
        let channel = NodeId::from_bytes([42; 16]);
        assert_eq!(
            tracker.admit_channel(0, channel, PacketClass::Broadcast, 400),
            BudgetOutcome::Admitted
        );
        // The same channel is capped by the Broadcast allowance, while the
        // real origin and every link bucket are untouched.
        assert_eq!(
            tracker.admit_channel(0, channel, PacketClass::Broadcast, 201),
            BudgetOutcome::OriginDenied
        );
        assert_eq!(
            tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Broadcast, 400),
            BudgetOutcome::Admitted
        );
        assert_eq!(tracker.origins(), 2);
        let burst = config.rates[1].burst_bytes();
        assert!(burst > 0);
        assert_eq!(
            burst,
            config.rates[1].bytes_per_hour * config.rates[1].burst_seconds / 3_600
        );
    }

    #[test]
    fn refund_restores_an_origin_evicted_by_the_paired_channel_admission() {
        let config = BudgetConfig {
            max_origins: 1,
            ..small()
        };
        let mut tracker = BudgetTracker::new(config);
        let channel = NodeId::from_bytes([42; 16]);
        assert_eq!(
            tracker.admit_origin(0, ORIGIN_A, PacketClass::Broadcast, 200),
            BudgetOutcome::Admitted
        );
        // With one origin slot this evicts A before charging the channel.
        assert_eq!(
            tracker.admit_channel(0, channel, PacketClass::Broadcast, 500),
            BudgetOutcome::Admitted
        );
        tracker.refund_origin(0, ORIGIN_A, PacketClass::Broadcast, 200);
        // A was restored, evicting the nearly empty channel bucket; a fresh
        // channel bucket can therefore still admit the next packet.
        assert_eq!(
            tracker.admit_channel(0, channel, PacketClass::Broadcast, 200),
            BudgetOutcome::Admitted
        );
    }

    #[test]
    fn denied_packet_does_not_consume_the_other_bucket() {
        let config = small();
        let mut tracker = BudgetTracker::new(config);
        assert_eq!(
            tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Direct, 600),
            BudgetOutcome::Admitted
        );
        assert_eq!(
            tracker.admit(0, LINK_B, ORIGIN_A, PacketClass::Direct, 1),
            BudgetOutcome::OriginDenied
        );
        // An origin denial never touches the neighbour bucket, so a fresh
        // origin on that link is still admitted.
        assert_eq!(
            tracker.admit(0, LINK_B, ORIGIN_B, PacketClass::Direct, 1),
            BudgetOutcome::Admitted
        );
    }

    #[test]
    fn clock_going_backwards_never_mints_tokens() {
        let config = small();
        let mut tracker = BudgetTracker::new(config);
        assert_eq!(
            tracker.admit(10_000, LINK_A, ORIGIN_A, PacketClass::Direct, 600),
            BudgetOutcome::Admitted
        );
        assert_eq!(
            tracker.admit(0, LINK_B, ORIGIN_A, PacketClass::Direct, 1),
            BudgetOutcome::OriginDenied
        );
    }

    #[test]
    fn least_recently_used_origin_is_evicted() {
        let mut config = small();
        config.max_origins = 2;
        let mut tracker = BudgetTracker::new(config);
        assert_eq!(
            tracker.admit(10, LINK_A, ORIGIN_A, PacketClass::Direct, 1),
            BudgetOutcome::Admitted
        );
        assert_eq!(
            tracker.admit(20, LINK_A, ORIGIN_B, PacketClass::Direct, 1),
            BudgetOutcome::Admitted
        );
        let third = NodeId::from_bytes([3; 16]);
        assert_eq!(
            tracker.admit(30, LINK_A, third, PacketClass::Direct, 1),
            BudgetOutcome::Admitted
        );
        assert_eq!(tracker.origins(), 2);
        assert_eq!(
            tracker.admit(40, LINK_A, ORIGIN_A, PacketClass::Direct, 1),
            BudgetOutcome::Admitted
        );
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
        assert_eq!(
            tracker.admit(0, LINK_A, ORIGIN_A, PacketClass::Telemetry, 4096),
            BudgetOutcome::Admitted
        );
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
