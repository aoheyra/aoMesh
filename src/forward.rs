//! Baseline forwarding decisions for received packets (MSH-08).
//!
//! [`crate::MeshEngine`] owns the neighbour table and turns these
//! decisions into outputs; this module decides what one structurally
//! valid inbound packet means: the content-bound `msg_id` check, one
//! dedupe record per message, local delivery when `dst` is this node,
//! and the relay encoding. Only the Direct class arrives here; Broadcast
//! and Presence suppression is MSH-11, Presence gossip MSH-19 and
//! Telemetry handling MSH-22.
//!
//! The `msg_id` derivation is re-checked before any state changes on
//! purpose: without it a neighbour could claim an arbitrary key and
//! poison the dedupe cache against a future legitimate message.

use ao_idents::NodeId;

use crate::packet::{Header, Packet, PacketClass};
use crate::seen::{Offer, SeenCache};
use crate::sign::derive_msg_id;

/// What the engine does with one structurally valid inbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// Neither delivered nor relayed.
    Drop,
    /// Addressed to this node: hand the header and payload to the host.
    Deliver {
        /// The packet header, as received.
        header: Header,
        /// The opaque payload, copied out of the input buffer.
        payload: Vec<u8>,
    },
    /// Re-encoded for every verified neighbour except the sending link.
    Relay {
        /// The complete re-encoded packet with `ttl` decremented.
        bytes: Vec<u8>,
    },
}

/// Applies the MSH-08 rules to one decoded packet, recording a fresh
/// Direct message in `seen` on the way.
///
/// Delivery is structural only: the origin signature is verified in
/// MSH-09, not here. `local_id` is the engine's own node; a packet for
/// it delivers regardless of a worn `ttl`, while anything else relays
/// only while at least one hop of `ttl` remains (ADR-0001: TTL is the
/// hop limit).
pub(crate) fn on_data(
    local_id: NodeId,
    seen: &mut SeenCache,
    now: u64,
    packet: Packet<'_>,
) -> Action {
    if packet.header.class != PacketClass::Direct {
        return Action::Drop;
    }
    // The claimed id must match the content before it can key dedupe.
    if derive_msg_id(&packet.header, packet.payload) != packet.header.msg_id {
        return Action::Drop;
    }
    if seen.check_and_insert(now, packet.header.class, packet.header.msg_id) == Offer::Duplicate {
        return Action::Drop;
    }
    if packet.header.dst == Some(*local_id.as_bytes()) {
        return Action::Deliver {
            header: packet.header,
            payload: packet.payload.to_vec(),
        };
    }
    if packet.header.ttl <= 1 {
        return Action::Drop;
    }
    let mut relayed = packet;
    relayed.header.ttl -= 1;
    relayed.header.hops = relayed.header.hops.saturating_add(1);
    // The signature and `msg_id` cover the immutable prefix, which
    // excludes `ttl` and `hops`, so the re-encoding stays verifiable at
    // the next hop (the layout in ADR-0002 makes this possible).
    Action::Relay {
        bytes: relayed.encode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_packet;
    use ao_idents::Identity;

    const LOCAL: NodeId = NodeId::from_bytes([3; 16]);

    /// A wire packet from a fixed demonstration identity; `mutate`
    /// adjusts the header before signing so tests can build hostile
    /// or destined variants of the same message.
    fn wire(class: PacketClass, mutate: impl FnOnce(&mut Header), payload: &[u8]) -> Vec<u8> {
        let mut header = Header {
            class,
            dst: None,
            msg_id: [0; 16].into(),
            origin: [0; 16],
            created_ms: 100,
            lifetime_s: 600,
            payload_len: payload.len() as u64,
            ttl: 8,
            hops: 0,
        };
        mutate(&mut header);
        let identity = Identity::from_seed([1; 32]);
        let signature = sign_packet(&identity, &mut header, payload).expect("fixed key signs");
        Packet::new(header, signature, payload)
            .expect("lengths agree")
            .encode()
    }

    fn decode(bytes: &[u8]) -> Packet<'_> {
        Packet::decode(bytes).expect("wire is valid")
    }

    #[test]
    fn fresh_direct_for_this_node_delivers_exactly_once() {
        let bytes = wire(
            PacketClass::Direct,
            |h| h.dst = Some(*LOCAL.as_bytes()),
            b"hello",
        );
        let packet = decode(&bytes);
        let mut seen = SeenCache::default();
        assert_eq!(
            on_data(LOCAL, &mut seen, 0, packet),
            Action::Deliver {
                header: packet.header,
                payload: b"hello".to_vec(),
            }
        );
        // The second copy of the same message is a duplicate, so the
        // host never sees it twice.
        assert_eq!(on_data(LOCAL, &mut seen, 10, packet), Action::Drop);
    }

    #[test]
    fn fresh_direct_for_another_node_relays_with_ttl_and_hops() {
        let bytes = wire(PacketClass::Direct, |h| h.dst = Some([9; 16]), b"hop");
        let packet = decode(&bytes);
        let mut seen = SeenCache::default();
        let Action::Relay { bytes: relaid } = on_data(LOCAL, &mut seen, 0, packet) else {
            panic!("expected a relay");
        };
        let relayed = decode(&relaid);
        assert_eq!(relayed.header.ttl, 7);
        assert_eq!(relayed.header.hops, 1);
        assert_eq!(relayed.payload, b"hop");
        // The immutable prefix is untouched: next hop verifies.
        assert_eq!(relayed.header.msg_id, packet.header.msg_id);
        assert_eq!(relayed.signature, packet.signature);
        // The relay's own copy coming back is dropped, not re-relayed.
        assert_eq!(on_data(LOCAL, &mut seen, 10, relayed), Action::Drop);
    }

    #[test]
    fn exhausted_ttl_stops_relaying_but_never_blocks_delivery() {
        let mut seen = SeenCache::default();
        for (ttl, payload) in [(0, &b"zero"[..]), (1, &b"one"[..])] {
            let bytes = wire(PacketClass::Direct, |h| h.ttl = ttl, payload);
            assert_eq!(on_data(LOCAL, &mut seen, 0, decode(&bytes)), Action::Drop);
        }
        // A worn ttl still delivers at the destination itself.
        let bytes = wire(
            PacketClass::Direct,
            |h| {
                h.dst = Some(*LOCAL.as_bytes());
                h.ttl = 0;
            },
            b"last hop",
        );
        assert!(matches!(
            on_data(LOCAL, &mut seen, 0, decode(&bytes)),
            Action::Deliver { .. }
        ));
    }

    #[test]
    fn hostile_hops_saturate_instead_of_panicking() {
        let bytes = wire(PacketClass::Direct, |h| h.hops = 255, b"many");
        let mut seen = SeenCache::default();
        let Action::Relay { bytes: relaid } = on_data(LOCAL, &mut seen, 0, decode(&bytes)) else {
            panic!("expected a relay");
        };
        assert_eq!(decode(&relaid).header.hops, 255);
    }

    #[test]
    fn non_direct_classes_drop_before_delivery_and_dedupe() {
        for class in [
            PacketClass::Broadcast,
            PacketClass::Presence,
            PacketClass::Telemetry,
        ] {
            // Hostile: a flooded class claiming this node as its
            // destination must not deliver, and must not consume a
            // dedupe record its real owner (MSH-11/19/22) will need.
            let bytes = wire(class, |h| h.dst = Some(*LOCAL.as_bytes()), b"flooded");
            let mut seen = SeenCache::default();
            assert_eq!(on_data(LOCAL, &mut seen, 0, decode(&bytes)), Action::Drop);
            assert_eq!(seen.len(), 0, "{class:?}");
        }
    }

    #[test]
    fn content_tampering_never_reaches_delivery_or_dedupe() {
        let bytes = wire(
            PacketClass::Direct,
            |h| h.dst = Some(*LOCAL.as_bytes()),
            b"secret",
        );
        let mut tampered = bytes.clone();
        *tampered.last_mut().expect("payload byte") ^= 1;
        let mut seen = SeenCache::default();
        // The claimed msg_id no longer matches the content: dropped
        // before the cache is touched, so a flood of forgeries cannot
        // evict real recordings.
        assert_eq!(
            on_data(LOCAL, &mut seen, 0, decode(&tampered)),
            Action::Drop
        );
        assert_eq!(seen.len(), 0);
        // The untouched copy still delivers: nothing was poisoned.
        assert!(matches!(
            on_data(LOCAL, &mut seen, 10, decode(&bytes)),
            Action::Deliver { .. }
        ));
    }
}
