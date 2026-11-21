//! MSH-13 evidence: identical stores share a digest and one change moves it.

use ao_mesh::store::{MemoryStore, MessageStore, StoreLimits, conformance};
use ao_mesh::{
    MeshConfig, MeshEngine, MeshInput, MeshOutput, MessageId, PacketClass, StoreSummary,
    SummaryConfig,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn id(byte: u8) -> MessageId {
    MessageId::from_bytes([byte; 16])
}

fn store(ids: &[u8]) -> MemoryStore {
    let mut store = MemoryStore::new(StoreLimits::default());
    for byte in ids {
        store
            .put(
                1_000,
                conformance::entry(*byte, *byte, PacketClass::Direct, 6, 1, 1_000),
            )
            .expect("fixture fits the default store");
    }
    store
}

#[test]
fn identical_stores_have_equal_digests_and_one_change_moves_it() {
    let first = store(&[1, 2]);
    let reordered = store(&[2, 1]);
    let changed = store(&[1, 3]);
    let now = 1_000;

    let expected = StoreSummary::from_store(&first, now).digest();
    assert_eq!(StoreSummary::from_store(&reordered, now).digest(), expected);
    assert_ne!(StoreSummary::from_store(&changed, now).digest(), expected);
}

#[test]
fn store_summary_changes_emit_one_debounced_beacon() {
    let mut engine = MeshEngine::with_config(
        StdRng::seed_from_u64(1),
        MeshConfig {
            summary: SummaryConfig {
                debounce_ms: 100,
                beacon_hint: [4; 8],
            },
            ..MeshConfig::default()
        },
    );
    let first = StoreSummary::from_ids(&[id(1)]).digest();
    let second = StoreSummary::from_ids(&[id(2)]).digest();

    assert!(
        engine
            .handle(10, MeshInput::StoreSummary { ids: &[id(1)] })
            .expect("summary input is valid")
            .is_empty()
    );
    assert_eq!(engine.published_store_digest(), None);

    let out = engine
        .handle(110, MeshInput::StoreSummary { ids: &[id(1)] })
        .expect("summary input is valid");
    let [
        MeshOutput::SetBeacon {
            hint,
            digest,
            flags,
        },
    ] = out.as_slice()
    else {
        panic!("expected one beacon, got {out:?}")
    };
    assert_eq!(*hint, [4; 8]);
    assert_eq!(*digest, first);
    assert!(flags.accepting && flags.relay_willing && !flags.low_battery);
    assert_eq!(
        engine
            .handle(120, MeshInput::StoreSummary { ids: &[id(1)] })
            .expect("summary input is valid")
            .len(),
        0
    );

    assert!(
        engine
            .handle(150, MeshInput::StoreSummary { ids: &[id(2)] })
            .expect("summary input is valid")
            .is_empty()
    );
    let out = engine
        .handle(251, MeshInput::StoreSummary { ids: &[id(2)] })
        .expect("summary input is valid");
    let [MeshOutput::SetBeacon { digest, .. }] = out.as_slice() else {
        panic!("expected one beacon, got {out:?}")
    };
    assert_eq!(*digest, second);
    assert_ne!(first, second);
}
