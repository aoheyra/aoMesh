//! The forwarding dedupe cache: one bounded record per message.
//!
//! aoMesh owns forwarding dedupe (MSH-05). aoIdents' `ReplayGuard` is a
//! different thing on purpose: per-sender acceptance at the final
//! recipient (AGENTS section 9). This cache only decides whether a relay
//! has already forwarded a message.
//!
//! It is bounded in **size and time**, because every neighbour is
//! hostile: a flood of unique ids would otherwise pin memory for as long
//! as the traffic continues, and a pure time bound would never shed stale
//! records. Capacity evicts the oldest recording; every recording
//! expires after its class's lifetime from the routing ADR-0001 (MSH-02)
//! table. Decision record: `docs/adr/0003-seen-cache-bounds.md`.
//!
//! Time is unix milliseconds, as in [`crate::MeshEngine::handle`].

use std::collections::{BTreeMap, VecDeque};

use crate::observability::Counter;
use crate::packet::{MessageId, PacketClass};

/// Bounds and lifetimes for a [`SeenCache`].
///
/// Configuration is plain data; the defaults are the bounds this crate
/// documents (ADR-0003, ADR-0001's Lifetime column) and are enumerated
/// by a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenConfig {
    /// Maximum recordings held at once. When full, the oldest recording
    /// is evicted, so size pressure can end dedupe early for old traffic.
    /// `0` disables recording: every offer is fresh.
    pub capacity: usize,
    /// Dedupe window for recordings made for Direct packets (ADR-0001:
    /// 24 h).
    pub direct_lifetime_ms: u64,
    /// Dedupe window for recordings made for Broadcast packets
    /// (ADR-0001: 6 h).
    pub broadcast_lifetime_ms: u64,
    /// Dedupe window for recordings made for Presence packets (ADR-0001:
    /// 30 min).
    pub presence_lifetime_ms: u64,
    /// Dedupe window for recordings made for Telemetry packets
    /// (ADR-0001: 5 min).
    pub telemetry_lifetime_ms: u64,
}

impl SeenConfig {
    /// The dedupe window recordings are given under `class`.
    #[must_use]
    pub const fn lifetime_ms(&self, class: PacketClass) -> u64 {
        match class {
            PacketClass::Direct => self.direct_lifetime_ms,
            PacketClass::Broadcast => self.broadcast_lifetime_ms,
            PacketClass::Presence => self.presence_lifetime_ms,
            PacketClass::Telemetry => self.telemetry_lifetime_ms,
        }
    }
}

impl Default for SeenConfig {
    fn default() -> Self {
        Self {
            capacity: 4_096,
            direct_lifetime_ms: 24 * 60 * 60 * 1_000,
            broadcast_lifetime_ms: 6 * 60 * 60 * 1_000,
            presence_lifetime_ms: 30 * 60 * 1_000,
            telemetry_lifetime_ms: 5 * 60 * 1_000,
        }
    }
}

/// What [`SeenCache::check_and_insert`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// Not seen within its lifetime: recorded, subject to capacity;
    /// forward the packet.
    Fresh,
    /// Already seen within its lifetime: drop the packet.
    Duplicate,
}

/// The exact bounded state an MSH-29 snapshot carries.
///
/// Both structures are kept, including stale order slots: capacity eviction
/// is defined in terms of the deque, so dropping a stale slot would change
/// which recording is shed after a restart.
#[derive(Debug)]
pub(crate) struct SeenState {
    pub(crate) entries: BTreeMap<MessageId, u64>,
    pub(crate) order: VecDeque<MessageId>,
}

/// The forwarding dedupe cache (MSH-05), keyed by `msg_id`.
///
/// Both bounds always hold: [`SeenCache::len`] never exceeds
/// [`SeenConfig::capacity`], and a recording stops deduplicating once its
/// class's lifetime has passed. Capacity wins over time under pressure:
/// the oldest recording can expire early when the cache is full, which is
/// what keeps a hostile flood of unique ids inside the memory budget.
///
/// Expiry is checked at every lookup, so correctness never depends on
/// cleanup; the front sweep and capacity eviction merely reclaim memory
/// early.
///
/// ```
/// use ao_mesh::packet::{MessageId, PacketClass};
/// use ao_mesh::seen::{Offer, SeenCache};
///
/// let mut cache = SeenCache::default();
/// let id = MessageId::from_bytes([9; 16]);
/// // The first sighting records; a repeat inside the window is a duplicate.
/// assert_eq!(cache.check_and_insert(0, PacketClass::Broadcast, id), Offer::Fresh);
/// assert_eq!(cache.check_and_insert(1_000, PacketClass::Broadcast, id), Offer::Duplicate);
/// // After the class's window the same content is a legitimate new arrival.
/// let other = MessageId::from_bytes([8; 16]);
/// assert_eq!(cache.check_and_insert(0, PacketClass::Telemetry, other), Offer::Fresh);
/// assert_eq!(cache.check_and_insert(6 * 60 * 1_000, PacketClass::Telemetry, other), Offer::Fresh);
/// ```
///
/// # Memory
///
/// Both structures are strictly functions of `capacity`: the order deque
/// reserves `capacity` slots up front, and the map holds at most
/// `capacity` records, so a filled cache stops allocating and no input
/// can grow it further. `tests/seen_memory.rs` drives the default of
/// 4096 recordings through a million insertions and asserts the
/// documented ceiling of 512 KiB at every step (measured peak: 263,560
/// bytes).
#[derive(Debug)]
pub struct SeenCache {
    config: SeenConfig,
    /// Duplicate verdicts (MSH-30). The cache owns this count because it owns
    /// the dedupe decision: no second state can disagree with it.
    duplicates: Counter,
    /// `msg_id` to its expiry instant (unix ms).
    entries: BTreeMap<MessageId, u64>,
    /// Recording order, oldest first; never longer than `config.capacity`.
    order: VecDeque<MessageId>,
}

impl SeenCache {
    /// Creates an empty cache bounded by `config`: the order deque
    /// reserves its `capacity` slots up front, and the map allocates as
    /// recordings arrive but can hold at most `config.capacity` of them.
    #[must_use]
    pub fn new(config: SeenConfig) -> Self {
        Self {
            config,
            duplicates: Counter::new(),
            entries: BTreeMap::new(),
            order: VecDeque::with_capacity(config.capacity),
        }
    }

    /// Copies the bounded recordings and their order into snapshot state.
    pub(crate) fn export_state(&self) -> SeenState {
        SeenState {
            entries: self.entries.clone(),
            order: self.order.clone(),
        }
    }

    /// Installs a validated snapshot without changing this cache's bounds.
    pub(crate) fn import_state(&mut self, state: SeenState) {
        self.entries = state.entries;
        self.order = state.order;
    }

    /// Offers a packet's `msg_id` and reports whether it was already seen
    /// within the lifetime recorded for `class`.
    ///
    /// `now` is unix milliseconds, as in [`crate::MeshEngine::handle`].
    /// A fresh recording expires at `now` plus the class's window; at or
    /// after that instant the same `msg_id` is fresh again, because the
    /// same content may legitimately reappear. A duplicate does not
    /// extend the original window, and the class of the recording is the
    /// class of the offer that first saw the message. Recording is
    /// subject to capacity: a full cache evicts its oldest recording, so
    /// `len` never exceeds the configured bound.
    ///
    /// At `now == u64::MAX` no later instant exists; a saturated expiry
    /// therefore reads as already expired and the offer is fresh.
    #[must_use]
    pub fn check_and_insert(&mut self, now: u64, class: PacketClass, msg_id: MessageId) -> Offer {
        self.sweep(now);
        if self.is_duplicate(now, &msg_id) {
            self.duplicates.add(1);
            return Offer::Duplicate;
        }
        // Expired: drop the stale record so the new recording below
        // gets the full window (a no-op when absent). Its old order
        // slot is reclaimed when the deque reaches it.
        self.entries.remove(&msg_id);
        self.record(now, class, msg_id);
        Offer::Fresh
    }

    /// Whether `msg_id` already has a fresh recording at `now`: a pure
    /// read, with no sweep, no recording and no window change.
    ///
    /// The delivery path (MSH-09) checks this before it spends
    /// cryptography, and the engine records only after its pipeline
    /// accepts a delivery, so a forgery that fails authentication can
    /// never consume the key the honest copy still needs.
    #[must_use]
    pub fn is_duplicate(&self, now: u64, msg_id: &MessageId) -> bool {
        self.entries
            .get(msg_id)
            .is_some_and(|&expires_at| expires_at > now)
    }

    /// The number of recordings held, expired ones included until they
    /// are reclaimed at lookup, by the front sweep, or by capacity. Never
    /// exceeds [`SeenConfig::capacity`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no recordings are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The configured capacity: the hard bound on [`SeenCache::len`].
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.config.capacity
    }

    /// Saturating duplicate verdicts recorded here (MSH-30).
    pub(crate) fn duplicates(&self) -> u64 {
        self.duplicates.get()
    }

    /// Counts one duplicate observed through the pure [`Self::is_duplicate`]
    /// peek. Called by the delivery and flooded-class gates, which must not
    /// extend a dedupe window but still need the event in the snapshot.
    pub(crate) fn note_duplicate(&mut self) {
        self.duplicates.add(1);
    }

    /// Records `msg_id` fresh for `class`'s window, evicting the oldest
    /// recordings to stay inside both bounds.
    fn record(&mut self, now: u64, class: PacketClass, msg_id: MessageId) {
        if self.config.capacity == 0 {
            return;
        }
        while self.entries.len() >= self.config.capacity && self.evict_oldest() {}
        if self.entries.len() >= self.config.capacity {
            // The order deque drained before an entry gave way (a
            // slot-less recording still held its window). Record
            // nothing; the packet is fresh regardless.
            return;
        }
        self.entries
            .insert(msg_id, now.saturating_add(self.config.lifetime_ms(class)));
        // The order deque has its own bound. A recording made while it is
        // full holds no slot and is reclaimed at expiry instead of by
        // eviction; nothing can grow past `capacity`.
        if self.order.len() < self.config.capacity {
            self.order.push_back(msg_id);
        }
    }

    /// Drops the oldest order slot, and the entry behind it when the slot
    /// is that recording's, evicting it. A stale slot left by an expired
    /// recording frees only itself; if its id was re-recorded since, the
    /// newer recording goes with the older slot, which keeps eviction
    /// oldest-first by original recording order (ADR-0003). Returns false
    /// when the deque was empty.
    fn evict_oldest(&mut self) -> bool {
        let Some(msg_id) = self.order.pop_front() else {
            return false;
        };
        self.entries.remove(&msg_id);
        true
    }

    /// Reclaims expired recordings and stale slots from the front, where
    /// the oldest recordings are, in amortised O(1). With per-class
    /// windows a long-lived front entry can hide expired ones behind it;
    /// those are reclaimed at their own lookup or by capacity, and the
    /// size bound does not depend on the sweep at all.
    fn sweep(&mut self, now: u64) {
        while let Some(msg_id) = self.order.front().copied() {
            let expires_at = self.entries.get(&msg_id).copied();
            match expires_at {
                // Stale slot: the recording was replaced or removed.
                None => {
                    self.order.pop_front();
                }
                Some(expires_at) if expires_at <= now => {
                    self.order.pop_front();
                    self.entries.remove(&msg_id);
                }
                Some(_) => break,
            }
        }
    }
}

impl Default for SeenCache {
    /// The documented default bounds: [`SeenConfig::default`].
    fn default() -> Self {
        Self::new(SeenConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> MessageId {
        MessageId::from_bytes(n.to_le_bytes())
    }

    fn config_with(capacity: usize, direct_lifetime_ms: u64) -> SeenConfig {
        SeenConfig {
            capacity,
            direct_lifetime_ms,
            ..SeenConfig::default()
        }
    }

    #[test]
    fn defaults_match_the_adr_table() {
        let config = SeenConfig::default();
        assert_eq!(config.capacity, 4_096);
        assert_eq!(config.direct_lifetime_ms, 24 * 60 * 60 * 1_000);
        assert_eq!(config.broadcast_lifetime_ms, 6 * 60 * 60 * 1_000);
        assert_eq!(config.presence_lifetime_ms, 30 * 60 * 1_000);
        assert_eq!(config.telemetry_lifetime_ms, 5 * 60 * 1_000);
        // The class selects its window.
        assert_eq!(
            config.lifetime_ms(PacketClass::Direct),
            24 * 60 * 60 * 1_000
        );
        assert_eq!(
            config.lifetime_ms(PacketClass::Broadcast),
            6 * 60 * 60 * 1_000
        );
        assert_eq!(config.lifetime_ms(PacketClass::Presence), 30 * 60 * 1_000);
        assert_eq!(config.lifetime_ms(PacketClass::Telemetry), 5 * 60 * 1_000);
    }

    #[test]
    fn duplicate_within_lifetime_then_fresh_at_expiry() {
        // The boundary is `expires_at > now`: fresh at the exact instant
        // the window runs out, duplicate one millisecond before it.
        for (class, lifetime_ms) in [
            (PacketClass::Direct, 24 * 60 * 60 * 1_000),
            (PacketClass::Broadcast, 6 * 60 * 60 * 1_000),
            (PacketClass::Presence, 30 * 60 * 1_000),
            (PacketClass::Telemetry, 5 * 60 * 1_000),
        ] {
            let mut cache = SeenCache::default();
            let msg_id = id(1);
            assert_eq!(cache.check_and_insert(1_000, class, msg_id), Offer::Fresh);
            assert_eq!(
                cache.check_and_insert(1_000, class, msg_id),
                Offer::Duplicate,
                "{class:?}: same instant"
            );
            assert_eq!(
                cache.check_and_insert(1_000 + lifetime_ms - 1, class, msg_id),
                Offer::Duplicate,
                "{class:?}: one ms before expiry"
            );
            assert_eq!(
                cache.check_and_insert(1_000 + lifetime_ms, class, msg_id),
                Offer::Fresh,
                "{class:?}: at expiry"
            );
            // The new recording starts its own window from that instant.
            assert_eq!(
                cache.check_and_insert(1_000 + lifetime_ms + lifetime_ms - 1, class, msg_id),
                Offer::Duplicate,
                "{class:?}: inside the second window"
            );
            assert_eq!(
                cache.check_and_insert(1_000 + lifetime_ms + lifetime_ms, class, msg_id),
                Offer::Fresh,
                "{class:?}: end of the second window"
            );
        }
    }

    #[test]
    fn is_duplicate_is_a_pure_freshness_read() {
        let mut cache = SeenCache::default();
        let msg_id = id(7);
        assert!(!cache.is_duplicate(0, &msg_id));
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert!(cache.is_duplicate(0, &msg_id));
        // The read neither records nor extends: at the window's end the
        // recording reads as gone while the entry is still held.
        let expiry = 24 * 60 * 60 * 1_000;
        assert!(!cache.is_duplicate(expiry, &msg_id));
        assert_eq!(cache.len(), 1);
        // Only an offer records again, and it sees the expired entry as
        // absent rather than as a duplicate.
        assert_eq!(
            cache.check_and_insert(expiry, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_duplicate_lookup_does_not_extend_the_window() {
        let mut cache = SeenCache::default();
        let msg_id = id(2);
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Telemetry, msg_id),
            Offer::Fresh
        );
        // Repeated sightings just before expiry leave the window where it was.
        for now in [299_999u64, 299_998, 200_000] {
            assert_eq!(
                cache.check_and_insert(now, PacketClass::Telemetry, msg_id),
                Offer::Duplicate
            );
        }
        assert_eq!(
            cache.check_and_insert(300_000, PacketClass::Telemetry, msg_id),
            Offer::Fresh,
            "the window was not extended by the duplicates"
        );
    }

    #[test]
    fn the_recordings_class_decides_the_window() {
        let mut cache = SeenCache::default();
        let msg_id = id(3);
        // First seen as Telemetry: a five-minute window.
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Telemetry, msg_id),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(360_000, PacketClass::Direct, msg_id),
            Offer::Fresh,
            "expired under the class it was recorded with"
        );
        // Re-recorded as Direct: now a 24-hour window, even when offered
        // as Telemetry.
        assert_eq!(
            cache.check_and_insert(720_000, PacketClass::Telemetry, msg_id),
            Offer::Duplicate
        );
        assert_eq!(
            cache.check_and_insert(86_400_000, PacketClass::Telemetry, msg_id),
            Offer::Duplicate
        );
    }

    #[test]
    fn capacity_evicts_the_oldest_recording_first() {
        let mut cache = SeenCache::new(config_with(2, 60_000));
        for n in [1u128, 2, 3] {
            assert_eq!(
                cache.check_and_insert(0, PacketClass::Direct, id(n)),
                Offer::Fresh
            );
        }
        // Recording 3 evicted 1, the oldest: 2 and 3 still deduplicate.
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, id(2)),
            Offer::Duplicate
        );
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, id(3)),
            Offer::Duplicate
        );
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, id(1)),
            Offer::Fresh
        );
        assert_eq!(cache.len(), 2);
        // Each fresh distinct recording takes the front slot out: a plain
        // oldest-first rotation under sustained pressure.
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, id(2)),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, id(3)),
            Offer::Fresh
        );
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, id(3)),
            Offer::Duplicate
        );
    }

    #[test]
    fn capacity_zero_never_records() {
        let mut cache = SeenCache::new(config_with(0, 60_000));
        let msg_id = id(4);
        assert_eq!(cache.capacity(), 0);
        assert!(cache.is_empty());
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(1, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn zero_lifetime_never_deduplicates() {
        let mut cache = SeenCache::new(config_with(4, 0));
        let msg_id = id(5);
        assert_eq!(
            cache.check_and_insert(7, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(7, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn an_expired_recording_is_replaced_by_a_fresh_one() {
        let mut cache = SeenCache::new(config_with(4, 1_000));
        let msg_id = id(6);
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(999, PacketClass::Direct, msg_id),
            Offer::Duplicate
        );
        assert_eq!(
            cache.check_and_insert(1_000, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        // One slot, one recording: the replacement reused it.
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.check_and_insert(1_999, PacketClass::Direct, msg_id),
            Offer::Duplicate
        );
        assert_eq!(
            cache.check_and_insert(2_000, PacketClass::Direct, msg_id),
            Offer::Fresh
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn an_old_slot_evicts_the_newer_recording_and_is_then_swept() {
        // One id recorded twice holds two order slots: at the re-record
        // the deque was full, so the old slot could not be reclaimed.
        // Evicting through that old slot drops the newer record with it;
        // the newer slot then reads as stale and the front sweep drops it
        // on the next offer. This is the oldest-first approximation
        // ADR-0003 documents: under capacity pressure dedupe for an id can
        // end before its window does, and both structures stay bounded.
        let config = SeenConfig {
            capacity: 3,
            ..SeenConfig::default()
        };
        let mut cache = SeenCache::new(config);
        let long = id(10); // Direct: holds the front live
        let twice = id(11); // Telemetry: expires while parked behind
        let filler = id(12);

        // The long-lived front, then the id that will be recorded twice.
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, long),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Telemetry, twice),
            Offer::Fresh
        );
        // Telemetry's five minutes pass behind the live front. The stale
        // record is replaced, and with deque room the new recording gets
        // its own slot: two slots for one id.
        assert_eq!(
            cache.check_and_insert(6 * 60 * 1_000, PacketClass::Telemetry, twice),
            Offer::Fresh
        );
        assert_eq!(cache.order.len(), 3, "old and new slot coexist");
        assert_eq!(cache.order.iter().filter(|&&m| m == twice).count(), 2);

        // The next id fills `entries` but holds no slot: the deque is at
        // capacity, so it is reclaimed at expiry instead.
        assert_eq!(
            cache.check_and_insert(6 * 60 * 1_000, PacketClass::Direct, filler),
            Offer::Fresh
        );
        assert_eq!(cache.order.len(), 3, "the deque never exceeds capacity");

        // Two more offers evict from the front: first `long`, then the
        // OLD slot of `twice`, which removes twice's newer record while
        // its new slot is still dequeued.
        assert_eq!(
            cache.check_and_insert(6 * 60 * 1_000, PacketClass::Direct, id(13)),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(6 * 60 * 1_000, PacketClass::Direct, id(14)),
            Offer::Fresh
        );
        assert!(
            !cache.entries.contains_key(&twice),
            "the old slot took the newer record with it"
        );

        // The next offer sweeps the now-stale slot from the front.
        assert_eq!(
            cache.check_and_insert(6 * 60 * 1_000, PacketClass::Direct, id(15)),
            Offer::Fresh
        );
        assert!(!cache.order.contains(&twice), "the stale slot is gone");
        assert_eq!(cache.len(), 3, "still exactly at the bound");

        // Public consequence of the approximation: `twice` deduplicates
        // no longer, though its window has not run out; once offered
        // again it re-records normally.
        assert_eq!(
            cache.check_and_insert(6 * 60 * 1_000, PacketClass::Direct, twice),
            Offer::Fresh
        );
        assert_eq!(
            cache.check_and_insert(6 * 60 * 1_000, PacketClass::Direct, twice),
            Offer::Duplicate
        );
    }

    #[test]
    fn both_bounds_hold_under_mixed_lifetime_churn() {
        // Few ids, mixed classes and advancing time exercise expiry at
        // lookup, front sweeps, stale slots and eviction together; the
        // recorded window comes from whichever class first saw the id in
        // each cycle.
        let config = SeenConfig {
            capacity: 3,
            ..SeenConfig::default()
        };
        let mut cache = SeenCache::new(config);
        let mut now = 0u64;
        for step in 0..500u64 {
            now += 60_000;
            let class = match step % 3 {
                0 => PacketClass::Direct,
                1 => PacketClass::Telemetry,
                _ => PacketClass::Presence,
            };
            let msg_id = id(u128::from(step % 7));
            // The verdict depends on each id's expiry history; this loop
            // asserts the bounds under churn, so it is discarded here.
            let _ = cache.check_and_insert(now, class, msg_id);
            assert!(
                cache.len() <= 3,
                "entries bounded at step {step}: {}",
                cache.len()
            );
            assert!(
                cache.order.len() <= 3,
                "order bounded at step {step}: {}",
                cache.order.len()
            );
        }
    }

    #[test]
    fn capacity_and_length_reporters_stay_consistent() {
        let cache = SeenCache::default();
        assert_eq!(cache.capacity(), 4_096);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn only_duplicate_verdicts_increment_the_counter() {
        let mut cache = SeenCache::new(config_with(2, 60_000));
        assert_eq!(cache.duplicates(), 0);
        assert_eq!(
            cache.check_and_insert(0, PacketClass::Direct, id(20)),
            Offer::Fresh
        );
        assert_eq!(
            cache.duplicates(),
            0,
            "a fresh recording is not a duplicate"
        );
        assert_eq!(
            cache.check_and_insert(1, PacketClass::Direct, id(20)),
            Offer::Duplicate
        );
        assert_eq!(cache.duplicates(), 1);
        // A pure peek does not change dedupe state; the caller's explicit
        // note is what makes the event visible.
        assert!(cache.is_duplicate(1, &id(20)));
        assert_eq!(cache.duplicates(), 1);
        cache.note_duplicate();
        assert_eq!(cache.duplicates(), 2);
        // An expired recording is fresh again, and does not count.
        assert_eq!(
            cache.check_and_insert(60_000, PacketClass::Direct, id(20)),
            Offer::Fresh
        );
        assert_eq!(cache.duplicates(), 2);
    }

    #[test]
    fn duplicate_counter_saturates() {
        let mut cache = SeenCache::default();
        cache.duplicates.set(u64::MAX - 1);
        let msg_id = id(21);
        let _ = cache.check_and_insert(0, PacketClass::Direct, msg_id);
        let _ = cache.check_and_insert(1, PacketClass::Direct, msg_id);
        let _ = cache.check_and_insert(2, PacketClass::Direct, msg_id);
        assert_eq!(cache.duplicates(), u64::MAX);
    }
}
