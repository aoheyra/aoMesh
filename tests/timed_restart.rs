//! Public-API restart evidence. Persistence is supplied by the host.
mod common;
use ao_idents::Identity;
use ao_mesh::{
    Header, MeshConfig, MeshEngine, MeshHello, MeshInput, MeshOutput, Packet, PacketClass,
    Snapshot, SnapshotError, TimedSnapshot, sign_packet,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::{SeedableRng, rngs::StdRng};
fn engine() -> MeshEngine<StdRng> {
    let mut config = MeshConfig::default();
    config.presence.enabled = false;
    config.spray.enabled = false;
    MeshEngine::with_config(StdRng::seed_from_u64(29), config)
}
fn up(e: &mut MeshEngine<StdRng>, id: &Identity, n: u64, now: u64) -> Vec<MeshOutput> {
    let hello = Hello {
        proto_min: 1,
        proto_max: 1,
        caps: ao_mesh::hello::CAPS,
        max_frame: 16384,
        tag: LocalTag::new([n as u8; 16]),
        app_hello: AppHello::new(
            MeshHello::sign(id, [0; 8], [0; 4])
                .unwrap()
                .encode()
                .to_vec(),
        )
        .unwrap(),
    };
    e.handle(
        now,
        MeshInput::LinkUp {
            link: LinkId::new(n),
            remote_hello: hello,
        },
    )
    .unwrap()
}
fn receive(e: &mut MeshEngine<StdRng>, own: &Identity, wire: &[u8], now: u64) -> Vec<MeshOutput> {
    e.handle(
        now,
        MeshInput::Data {
            link: LinkId::new(1),
            channel: Channel::Message,
            payload: wire,
            identity: own,
        },
    )
    .unwrap()
}
fn outgoing(out: &[MeshOutput]) -> usize {
    out.iter()
        .filter(|o| matches!(o, MeshOutput::Send { .. } | MeshOutput::Broadcast { .. }))
        .count()
}
fn relay_wire(sender: &Identity) -> Vec<u8> {
    let payload = b"opaque relay data";
    let mut header = Header {
        class: PacketClass::Direct,
        dst: Some([9; 16]),
        msg_id: [0; 16].into(),
        origin: [0; 16],
        created_ms: u64::MAX,
        lifetime_s: 3600,
        payload_len: payload.len() as u64,
        ttl: 8,
        hops: 0,
    };
    let sig = sign_packet(sender, &mut header, payload).unwrap();
    Packet::new(header, sig, payload).unwrap().encode()
}

#[test]
fn timed_restore_survives_both_forward_and_backward_clock_epoch_changes() {
    let sender = Identity::from_seed([1; 32]);
    let own = Identity::from_seed([2; 32]);
    let next = Identity::from_seed([3; 32]);
    let mut before = engine();
    up(&mut before, &sender, 1, 90_000);
    up(&mut before, &next, 2, 90_000);
    let wire = relay_wire(&sender);
    assert_eq!(outgoing(&receive(&mut before, &own, &wire, 90_001)), 1);
    let saved = before.snapshot_at(90_002, own.node_id()).unwrap();
    for epoch in [5, 1_000_000_000_000] {
        let mut after = engine();
        after
            .restore_at(epoch, own.node_id(), 1_000, &saved)
            .unwrap();
        assert!(after.neighbors().is_empty());
        up(&mut after, &sender, 1, epoch);
        up(&mut after, &next, 2, epoch);
        assert_eq!(outgoing(&receive(&mut after, &own, &wire, epoch + 1)), 0);
        let expiry = epoch + 86_400_000 - 1 - 1_000;
        assert_eq!(outgoing(&receive(&mut after, &own, &wire, expiry)), 1);
    }
}
#[test]
fn timed_receipt_restore_is_authenticated_atomic_and_ages_by_host_elapsed_time() {
    let sender = Identity::from_seed([4; 32]);
    let own = Identity::from_seed([5; 32]);
    let mut before = engine();
    up(&mut before, &sender, 1, 1_000);
    let wire = common::sealed(
        &sender,
        &own,
        1000,
        PacketClass::Direct,
        |_| {},
        b"restart receipt",
    );
    let out = receive(&mut before, &own, &wire, 1_001);
    assert!(out.iter().any(|o| matches!(o, MeshOutput::Deliver { .. })));
    let receipt = out
        .iter()
        .find_map(|o| match o {
            MeshOutput::Send { payload, .. }
                if payload.first() == Some(&ao_mesh::RECEIPT_MAGIC) =>
            {
                Some(payload)
            }
            _ => None,
        })
        .unwrap();
    let saved = before.snapshot_at(1_002, own.node_id()).unwrap();
    let mut after = engine();
    after.restore_at(50, own.node_id(), 5000, &saved).unwrap();
    let plain = after.snapshot().unwrap();
    assert_eq!(u32::from_le_bytes(plain[13..17].try_into().unwrap()), 1);
    // The saved sent-to LinkId must not suppress gossip to an unrelated
    // new peer whose transport happens to reuse that raw link number.
    assert!(!up(&mut after, &sender, 1, 50).is_empty());
    assert!(
        !receive(&mut after, &own, &wire, 51)
            .iter()
            .any(|o| matches!(o, MeshOutput::Deliver { .. }))
    );
    let mut bad = saved.clone();
    let position = bad
        .windows(receipt.len())
        .position(|bytes| bytes == receipt)
        .unwrap();
    bad[position + 10] ^= 1;
    let mut fresh = engine();
    assert!(fresh.restore_at(0, own.node_id(), 0, &bad).is_err());
    fresh.restore_at(0, own.node_id(), 0, &saved).unwrap();
    let mut expired = engine();
    expired
        .restore_at(0, own.node_id(), 300_000, &saved)
        .unwrap();
    let plain = expired.snapshot().unwrap();
    assert_eq!(u32::from_le_bytes(plain[13..17].try_into().unwrap()), 0);
}
#[test]
fn timed_restore_checks_owner_version_truncation_gate_and_overflow() {
    let sender = Identity::from_seed([6; 32]);
    let own = Identity::from_seed([7; 32]);
    let next = Identity::from_seed([8; 32]);
    let mut before = engine();
    up(&mut before, &sender, 1, 0);
    up(&mut before, &next, 2, 0);
    receive(&mut before, &own, &relay_wire(&sender), 1);
    let saved = before.snapshot_at(2, own.node_id()).unwrap();
    let mut fresh = engine();
    assert_eq!(
        fresh.restore_at(0, sender.node_id(), 0, &saved),
        Err(SnapshotError::OwnerMismatch)
    );
    let mut version = saved.clone();
    version[4] = 2;
    assert_eq!(
        fresh.restore_at(0, own.node_id(), 0, &version),
        Err(SnapshotError::UnsupportedVersion(2))
    );
    for cut in 0..saved.len() {
        assert!(
            fresh
                .restore_at(0, own.node_id(), 0, &saved[..cut])
                .is_err()
        );
    }
    assert_eq!(
        fresh.restore_at(u64::MAX, own.node_id(), 0, &saved),
        Err(SnapshotError::ClockOverflow)
    );
    fresh.restore_at(0, own.node_id(), 0, &saved).unwrap();
    assert_eq!(
        fresh.restore_at(0, own.node_id(), 0, &saved),
        Err(SnapshotError::AlreadyStarted)
    );
    let mut started = engine();
    up(&mut started, &own, 1, 0);
    assert_eq!(
        started.restore_at(0, own.node_id(), 0, &saved),
        Err(SnapshotError::AlreadyStarted)
    );
}
