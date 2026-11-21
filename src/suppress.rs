//! Counter-based broadcast suppression (MSH-11).
//!
//! A flooded class is not relayed on sight. A node waits a short, seeded
//! assessment delay while counting distinct sending links that carry the same
//! content address. If at least `k` copies arrive, the mesh has already given
//! this node enough chances to hear the message and its own relay is cancelled;
//! otherwise it forwards once when the timer fires. `k` grows and the delay
//! shrinks with the observed degree, which is what keeps dense graphs from
//! retransmitting the same flood to everybody.
//!
//! State is keyed by the content-bound `MessageId`, bounded by configuration,
//! and evicted by earliest deadline. Time and randomness are caller-supplied,
//! so the engine stays deterministic. No timer thread or system clock is used.

use ao_network::LinkId;
use rand_core::RngCore;
use std::collections::{BTreeMap, BTreeSet};

use crate::packet::{MessageId, Packet, PacketClass};
use crate::sign::derive_msg_id;

/// Bounds, timer parameters and per-class TTLs for suppression.
///
/// The class TTLs are ADR-0001's table. The other defaults were chosen with
/// the MSH-27 50-node sweep recorded in the README: a reference degree of
/// four with three copies at that degree gives the measured 45% transmission
/// saving while the Direct delivery ratio stays level, and a 60-140 ms base
/// delay is short enough that a flood still finishes inside a normal contact
/// but long enough for neighbours' copies to arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppressionConfig {
    /// Whether counter-based suppression replaces immediate flooding.
    ///
    /// The simulator turns this off only for the naive-flooding ablation.
    pub enabled: bool,
    /// Maximum pending messages. Zero relays immediately without state.
    pub max_entries: usize,
    /// Degree at which `k_at_degree_ref` and the base delay are calibrated.
    pub degree_ref: usize,
    /// Copy threshold at `degree_ref`.
    pub k_at_degree_ref: usize,
    /// Configured lower bound for the degree-scaled copy threshold.
    ///
    /// The suppression table always requires at least two distinct sending
    /// links, because one copy cannot prove the flood reached this node's
    /// neighbours.
    pub min_k: usize,
    /// Upper bound for the degree-scaled copy threshold.
    pub max_k: usize,
    /// Minimum random base delay before degree scaling, in milliseconds.
    pub min_base_delay_ms: u64,
    /// Maximum random base delay before degree scaling, in milliseconds.
    pub max_base_delay_ms: u64,
    /// Lower bound for the final assessment delay, in milliseconds.
    pub min_delay_ms: u64,
    /// Upper bound for the final assessment delay, in milliseconds.
    pub max_delay_ms: u64,
    /// Submission/relay hop limit for Direct (ADR-0001).
    pub direct_ttl: u8,
    /// Submission/relay hop limit for Broadcast (ADR-0001).
    pub broadcast_ttl: u8,
    /// Submission/relay hop limit for Presence (ADR-0001).
    pub presence_ttl: u8,
    /// Submission/relay hop limit for Telemetry (ADR-0001).
    pub telemetry_ttl: u8,
}

impl Default for SuppressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 1_024,
            degree_ref: 4,
            k_at_degree_ref: 3,
            min_k: 1,
            max_k: 6,
            min_base_delay_ms: 60,
            max_base_delay_ms: 140,
            min_delay_ms: 20,
            max_delay_ms: 600,
            direct_ttl: 8,
            broadcast_ttl: 6,
            presence_ttl: 3,
            telemetry_ttl: 3,
        }
    }
}

impl SuppressionConfig {
    /// The ADR-0001 hop limit for `class`.
    #[must_use]
    pub const fn ttl(&self, class: PacketClass) -> u8 {
        match class {
            PacketClass::Direct => self.direct_ttl,
            PacketClass::Broadcast => self.broadcast_ttl,
            PacketClass::Presence => self.presence_ttl,
            PacketClass::Telemetry => self.telemetry_ttl,
        }
    }

    /// Distinct neighbour copies needed before a relay is cancelled.
    ///
    /// The degree-scaled threshold is fractional for most degrees. Rounding
    /// it up always keeps too many relays; rounding it down always loses
    /// reachability. The seeded fractional draw makes the expected threshold
    /// exactly the ADR value while keeping each individual decision an
    /// integer and the whole engine deterministic.
    #[must_use]
    pub fn copy_threshold<R: RngCore>(&self, degree: usize, rng: &mut R) -> usize {
        let degree = degree.max(1) as u128;
        let reference = self.degree_ref.max(1) as u128;
        let numerator = (self.k_at_degree_ref.max(1) as u128).saturating_mul(degree);
        let whole = numerator / reference;
        let fraction = numerator % reference;
        let extra = u128::from(fraction > 0 && u128::from(rng.next_u64()) % reference < fraction);
        let min = self.min_k.max(1) as u128;
        let max = self.max_k.max(min as usize) as u128;
        (whole + extra).clamp(min, max) as usize
    }

    /// Seeded assessment delay for `degree`, shrinking as degree grows.
    #[must_use]
    pub fn assessment_delay<R: RngCore>(&self, degree: usize, rng: &mut R) -> u64 {
        let low = self.min_base_delay_ms.min(self.max_base_delay_ms);
        let high = self.max_base_delay_ms.max(low);
        let span = high - low + 1;
        let base = low + (rng.next_u64() % span);
        let reference = self.degree_ref.max(1) as u128;
        let scaled = (base as u128)
            .saturating_mul(reference)
            .checked_div(degree.max(1) as u128)
            .unwrap_or(base as u128);
        let scaled = scaled.min(u64::MAX as u128) as u64;
        scaled.clamp(self.min_delay_ms, self.max_delay_ms.max(self.min_delay_ms))
    }
}

/// Whether a decoded packet's claimed content address matches its bytes.
#[must_use]
pub(crate) fn content_valid(packet: &Packet<'_>) -> bool {
    derive_msg_id(&packet.header, packet.payload) == packet.header.msg_id
}

/// Re-encodes a packet for the next hop, capped at its class TTL.
///
/// `None` means the class has no relay left. `ttl` and `hops` are outside the
/// signed immutable prefix, so this encoding stays verifiable (ADR-0002).
#[must_use]
pub(crate) fn relay_bytes(packet: Packet<'_>, class_ttl: u8) -> Option<Vec<u8>> {
    let ttl = packet.header.ttl.min(class_ttl);
    if ttl <= 1 {
        return None;
    }
    let mut relayed = packet;
    relayed.header.ttl = ttl - 1;
    relayed.header.hops = relayed.header.hops.saturating_add(1);
    Some(relayed.encode())
}

/// What one observed copy means for a pending message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observe {
    /// Wait for more copies or the deadline.
    Pending,
    /// Enough neighbours carried it; cancel this node's relay.
    Suppressed,
    /// No state was possible, so relay immediately.
    RelayNow(Due),
}

/// A relay whose assessment window ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Due {
    /// Content address being relayed.
    pub msg_id: MessageId,
    /// Class whose dedupe window the engine should record.
    pub class: PacketClass,
    /// Complete re-encoded packet.
    pub bytes: Vec<u8>,
    /// Links that already carried a copy; none receives it back.
    pub senders: BTreeSet<LinkId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending {
    class: PacketClass,
    deadline_ms: u64,
    threshold: usize,
    senders: BTreeSet<LinkId>,
    relay: Option<Vec<u8>>,
}

/// One observed copy and the relay bytes precomputed for its decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sighting {
    /// Caller-supplied time in milliseconds.
    pub now: u64,
    /// Content address being counted.
    pub msg_id: MessageId,
    /// Class whose dedupe window the engine should record.
    pub class: PacketClass,
    /// Link that carried this copy.
    pub sender: LinkId,
    /// Seeded copy threshold for the observed degree.
    pub threshold: usize,
    /// Millisecond deadline for this assessment window.
    pub deadline_ms: u64,
    /// Complete re-encoded packet if the timer wins.
    pub relay: Vec<u8>,
}

/// Deterministic, bounded pending-flood state.
#[derive(Debug)]
pub(crate) struct SuppressionTable {
    config: SuppressionConfig,
    entries: BTreeMap<MessageId, Pending>,
}

impl SuppressionTable {
    pub(crate) fn new(config: SuppressionConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Removes every window that ended at or before `now`.
    pub(crate) fn take_due(&mut self, now: u64) -> Vec<Due> {
        let due_ids: Vec<MessageId> = self
            .entries
            .iter()
            .filter(|(_, pending)| pending.deadline_ms <= now)
            .map(|(id, _)| *id)
            .collect();
        let mut due = Vec::with_capacity(due_ids.len());
        for id in due_ids {
            if let Some(pending) = self.entries.remove(&id) {
                if let Some(bytes) = pending.relay {
                    due.push(Due {
                        msg_id: id,
                        class: pending.class,
                        bytes,
                        senders: pending.senders,
                    });
                }
            }
        }
        due
    }

    /// Records one sighting. Relay bytes are precomputed so the timer can
    /// send without retaining borrowed input bytes.
    pub(crate) fn observe(&mut self, sighting: Sighting) -> Observe {
        let Sighting {
            now,
            msg_id,
            class,
            sender,
            threshold,
            deadline_ms,
            relay,
        } = sighting;
        if self.config.max_entries == 0 {
            return Observe::RelayNow(Due {
                msg_id,
                class,
                bytes: relay,
                senders: BTreeSet::from([sender]),
            });
        }
        if let Some(pending) = self.entries.get_mut(&msg_id) {
            // A late arrival can race the timer; the engine drains due
            // entries first, so anything still here has time to count.
            pending.senders.insert(sender);
            if pending.senders.len() >= pending.threshold {
                self.entries.remove(&msg_id);
                return Observe::Suppressed;
            }
            return Observe::Pending;
        }
        if self.entries.len() >= self.config.max_entries {
            let victim = self
                .entries
                .iter()
                .min_by(|(a_id, a), (b_id, b)| (a.deadline_ms, *a_id).cmp(&(b.deadline_ms, *b_id)))
                .map(|(id, _)| *id);
            if let Some(victim) = victim {
                self.entries.remove(&victim);
            }
        }
        // One copy proves only that this node heard the packet. Cancelling on
        // it would let suppression extinguish a flood at the first hop,
        // especially on a line or a small-degree graph. Every degree-scaled
        // threshold is therefore floored at two distinct sending links; if no
        // second copy arrives, `take_due` relays when the timer fires.
        let threshold = threshold.max(2);
        let mut senders = BTreeSet::new();
        senders.insert(sender);
        if senders.len() >= threshold {
            return Observe::Suppressed;
        }
        self.entries.insert(
            msg_id,
            Pending {
                class,
                deadline_ms: deadline_ms.max(now),
                threshold,
                senders,
                relay: Some(relay),
            },
        );
        Observe::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_packet;
    use ao_idents::{Identity, Signature};
    use rand::SeedableRng;

    const LINK_A: LinkId = LinkId::new(1);
    const LINK_B: LinkId = LinkId::new(2);
    const LINK_C: LinkId = LinkId::new(3);
    const ID: MessageId = MessageId::from_bytes([7; 16]);

    fn sight(
        now: u64,
        msg_id: MessageId,
        sender: LinkId,
        threshold: usize,
        deadline_ms: u64,
        relay: Vec<u8>,
    ) -> Sighting {
        Sighting {
            now,
            msg_id,
            class: PacketClass::Broadcast,
            sender,
            threshold,
            deadline_ms,
            relay,
        }
    }

    fn config() -> SuppressionConfig {
        SuppressionConfig {
            min_base_delay_ms: 10,
            max_base_delay_ms: 10,
            min_delay_ms: 10,
            max_delay_ms: 10,
            ..SuppressionConfig::default()
        }
    }

    fn wire(ttl: u8) -> Packet<'static> {
        let identity = Identity::from_seed([1; 32]);
        let mut header = crate::Header {
            class: PacketClass::Broadcast,
            dst: None,
            msg_id: [0; 16].into(),
            origin: [0; 16],
            created_ms: 100,
            lifetime_s: 600,
            payload_len: 3,
            ttl,
            hops: 0,
        };
        let signature = sign_packet(&identity, &mut header, b"abc").expect("fixed key signs");
        static PAYLOAD: &[u8] = b"abc";
        Packet::new(header, signature, PAYLOAD).expect("lengths agree")
    }

    #[test]
    fn threshold_and_delay_scale_with_degree() {
        let exact = SuppressionConfig {
            k_at_degree_ref: 4,
            degree_ref: 8,
            ..config()
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        assert_eq!(exact.copy_threshold(4, &mut rng), 2);
        assert_eq!(exact.copy_threshold(8, &mut rng), 4);
        assert_eq!(exact.copy_threshold(32, &mut rng), 6);

        // A fractional threshold is rounded probabilistically, never
        // outside its two neighbouring integers.
        let fractional = SuppressionConfig {
            min_k: 1,
            k_at_degree_ref: 3,
            degree_ref: 4,
            ..config()
        };
        let mut ones = 0;
        for _ in 0..200 {
            let threshold = fractional.copy_threshold(2, &mut rng);
            assert!(matches!(threshold, 1 | 2));
            ones += usize::from(threshold == 1);
        }
        assert!((60..=140).contains(&ones), "unbalanced rounding: {ones}");

        let scaling = SuppressionConfig {
            degree_ref: 8,
            min_delay_ms: 1,
            max_delay_ms: 600,
            ..config()
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        assert_eq!(scaling.assessment_delay(8, &mut rng), 10);
        assert_eq!(scaling.assessment_delay(2, &mut rng), 40);
    }

    #[test]
    fn class_ttls_match_the_adr() {
        let config = config();
        assert_eq!(config.ttl(PacketClass::Direct), 8);
        assert_eq!(config.ttl(PacketClass::Broadcast), 6);
        assert_eq!(config.ttl(PacketClass::Presence), 3);
        assert_eq!(config.ttl(PacketClass::Telemetry), 3);
    }

    #[test]
    fn copies_from_distinct_links_cancel_the_relay() {
        let mut table = SuppressionTable::new(config());
        assert_eq!(
            table.observe(sight(0, ID, LINK_A, 3, 100, vec![1])),
            Observe::Pending
        );
        assert_eq!(
            table.observe(sight(1, ID, LINK_A, 3, 100, vec![1])),
            Observe::Pending,
            "the same link is one copy"
        );
        assert_eq!(
            table.observe(sight(2, ID, LINK_B, 3, 100, vec![1])),
            Observe::Pending
        );
        assert_eq!(
            table.observe(sight(3, ID, LINK_C, 3, 100, vec![1])),
            Observe::Suppressed
        );
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn a_single_copy_is_never_enough_to_cancel_a_flood() {
        let mut table = SuppressionTable::new(config());
        assert_eq!(
            table.observe(sight(0, ID, LINK_A, 1, 100, vec![1])),
            Observe::Pending,
            "a degree-one neighbour must not extinguish the flood"
        );
        assert_eq!(
            table.observe(sight(1, ID, LINK_B, 1, 100, vec![1])),
            Observe::Suppressed
        );
    }

    #[test]
    fn deadline_produces_one_due_relay() {
        let mut table = SuppressionTable::new(config());
        assert_eq!(
            table.observe(sight(0, ID, LINK_A, 3, 100, vec![9])),
            Observe::Pending
        );
        assert!(table.take_due(99).is_empty());
        let due = table.take_due(100);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].bytes, vec![9]);
        assert!(due[0].senders.contains(&LINK_A));
        assert!(table.take_due(101).is_empty());
    }

    #[test]
    fn oldest_deadline_is_evicted_under_pressure() {
        let config = SuppressionConfig {
            max_entries: 2,
            ..config()
        };
        let mut table = SuppressionTable::new(config);
        let other = MessageId::from_bytes([8; 16]);
        assert_eq!(
            table.observe(sight(0, ID, LINK_A, 3, 100, vec![1])),
            Observe::Pending
        );
        assert_eq!(
            table.observe(sight(0, other, LINK_A, 3, 200, vec![2])),
            Observe::Pending
        );
        let third = MessageId::from_bytes([9; 16]);
        assert_eq!(
            table.observe(sight(0, third, LINK_A, 3, 300, vec![3])),
            Observe::Pending
        );
        assert_eq!(table.len(), 2);
        let due = table.take_due(400);
        assert_eq!(due.len(), 2);
        assert!(due.iter().any(|d| d.bytes == vec![2]));
        assert!(due.iter().any(|d| d.bytes == vec![3]));
    }

    #[test]
    fn zero_capacity_relays_immediately() {
        let config = SuppressionConfig {
            max_entries: 0,
            ..config()
        };
        let mut table = SuppressionTable::new(config);
        assert!(matches!(
            table.observe(sight(0, ID, LINK_A, 3, 100, vec![1])),
            Observe::RelayNow(_)
        ));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn relay_encoding_caps_ttl_and_keeps_the_content_address() {
        let packet = wire(255);
        assert!(content_valid(&packet));
        let relayed = relay_bytes(packet, 6).expect("relay exists");
        let decoded = Packet::decode(&relayed).expect("valid wire");
        assert_eq!(decoded.header.ttl, 5);
        assert_eq!(decoded.header.hops, 1);
        assert_eq!(decoded.header.msg_id, packet.header.msg_id);
        assert!(content_valid(&decoded));
        let signature: Signature = packet.signature;
        assert_eq!(decoded.signature, signature);
        assert!(relay_bytes(wire(1), 6).is_none());
    }
}
