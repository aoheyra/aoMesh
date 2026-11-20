//! MeshHello through the public API (MSH-07): the 256-byte `app_hello`
//! fit and codec properties on hostile bytes.

use ao_idents::Identity;
use ao_mesh::{MeshHello, hello};
use ao_network::{AppHello, MAX_APP_HELLO};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, MapFailurePersistence, RngSeed};

fn config() -> Config {
    let mut config = Config::with_cases(256);
    config.rng_seed = RngSeed::Fixed(0x4D53_0007);
    // File persistence calls getcwd, which Miri's isolated runner forbids
    // (CI runs cargo miri test). In-memory persistence with a fixed seed
    // keeps every run reproducible; promote a reported minimal failing
    // input to a regression test when one appears.
    config.failure_persistence = Some(Box::new(MapFailurePersistence::default()));
    config
}

/// Done when: the encoded hello is asserted to fit in 256 bytes.
#[test]
fn encoded_hello_fits_the_256_byte_app_hello_limit() {
    let identity = Identity::from_seed([0x07; 32]);
    let hello = MeshHello::sign(&identity, [1; 8], [2; 4]).unwrap();
    // The wire length itself: a layout change must update this, the
    // ADR and the protocol doc together.
    assert_eq!(hello.encode().len(), 161);
    assert!(hello.encode().len() <= MAX_APP_HELLO);
    let blob = AppHello::new(hello.encode().to_vec()).unwrap();
    // What the engine verifies on LinkUp is byte-identical to what was
    // signed: fixed-width fields, no normalisation on the way.
    let verified = hello::verified_node_id(blob.as_bytes()).unwrap();
    assert_eq!(verified, identity.node_id());
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn decode_never_panics_on_arbitrary_bytes(bytes in vec(any::<u8>(), 0..400)) {
        // Truncated, oversize or hostile: a typed error or a parsed
        // struct, never a panic.
        let _hello = MeshHello::decode(&bytes);
    }

    #[test]
    fn signed_hellos_round_trip_with_arbitrary_opaque_fields(
        card_hash in any::<[u8; 8]>(),
        store_digest in any::<[u8; 4]>(),
    ) {
        let identity = Identity::from_seed([0x42; 32]);
        let hello = MeshHello::sign(&identity, card_hash, store_digest).unwrap();
        prop_assert_eq!(MeshHello::decode(&hello.encode()).unwrap(), hello);
        prop_assert_eq!(hello::verified_node_id(&hello.encode()), Ok(identity.node_id()));
    }
}
