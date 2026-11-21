#![no_main]

//! MSH-28 engine input-stream target: a verified neighbour plus arbitrary
//! Data, Tick, StoreSummary, SyncItems, KnownCards, ObserveNode,
//! SubmitTelemetry and link events must stay bounded and never panic. The RNG
//! and clock are injected, so a crash is reproducible.

use std::hint::black_box;

use ao_idents::{Identity, NodeId};
use ao_mesh::{
    CAPS, MeshEngine, MeshHello, MeshInput, MessageId, NodeObservation, SyncOffer, TelemetryKind,
};
use ao_network::{AppHello, Channel, DisconnectReason, Hello, LinkId, LocalTag};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand::rngs::StdRng;

const CHUNK: usize = 4 * 1024;

fn remote_hello(peer: &Identity) -> Option<Hello> {
    let signed = MeshHello::sign(peer, [0; 8], [0; 4]).ok()?;
    let app_hello = AppHello::new(signed.encode().to_vec()).ok()?;
    Some(Hello {
        proto_min: 1,
        proto_max: 1,
        caps: CAPS,
        max_frame: 16 * 1024,
        tag: LocalTag::new([2; 16]),
        app_hello,
    })
}

fn channel(byte: u8) -> Channel {
    match byte & 3 {
        0 => Channel::Control,
        1 => Channel::Message,
        2 => Channel::Telemetry,
        _ => Channel::Bulk,
    }
}

fn ids_from(chunk: &[u8]) -> Vec<MessageId> {
    chunk
        .chunks_exact(16)
        .map(|bytes| {
            let mut id = [0u8; 16];
            id.copy_from_slice(bytes);
            MessageId::from_bytes(id)
        })
        .collect()
}

fn hashes_from(chunk: &[u8]) -> Vec<[u8; 8]> {
    chunk
        .chunks_exact(8)
        .map(|bytes| {
            let mut hash = [0u8; 8];
            hash.copy_from_slice(bytes);
            hash
        })
        .collect()
}

fn offers_from(chunk: &[u8]) -> Vec<SyncOffer<'_>> {
    chunk
        .chunks_exact(8)
        .map(|prefix| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(prefix);
            SyncOffer {
                prefix: bytes,
                wire: chunk,
                copies_left: 1,
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let local = Identity::from_seed([1; 32]);
    let peer = Identity::from_seed([2; 32]);
    let link = LinkId::new(1);
    let Some(hello) = remote_hello(&peer) else {
        return;
    };
    let mut engine = MeshEngine::new(StdRng::seed_from_u64(0x4d53_0028));
    if engine
        .handle(
            0,
            MeshInput::LinkUp {
                link,
                remote_hello: hello.clone(),
            },
        )
        .is_err()
    {
        return;
    }

    // One whole-buffer input first: libFuzzer grows this to the configured
    // 16 KiB maximum, which is larger than every engine decoder cap.
    let _ = black_box(engine.handle(
        1,
        MeshInput::Data {
            link,
            channel: Channel::Message,
            payload: data,
            identity: &local,
        },
    ));

    for (index, chunk) in data.chunks(CHUNK).enumerate() {
        let now = 1_000u64.saturating_add(index as u64 * 17);
        let selector = match chunk.first() {
            Some(byte) => *byte,
            None => 0,
        };
        match selector % 9 {
            0 | 1 => {
                let _ = black_box(engine.handle(
                    now,
                    MeshInput::Data {
                        link,
                        channel: channel(selector),
                        payload: chunk,
                        identity: &local,
                    },
                ));
            }
            2 => {
                let _ = black_box(engine.handle(
                    now,
                    MeshInput::Tick {
                        identity: &local,
                        card_hash: [selector; 8],
                    },
                ));
            }
            3 => {
                let ids = ids_from(chunk);
                let _ = black_box(engine.handle(now, MeshInput::StoreSummary { ids: &ids }));
            }
            4 => {
                let _ = black_box(engine.handle(
                    now,
                    MeshInput::LinkDown {
                        link,
                        reason: DisconnectReason::Closed,
                    },
                ));
                let _ = black_box(engine.handle(
                    now.saturating_add(1),
                    MeshInput::LinkUp {
                        link,
                        remote_hello: hello.clone(),
                    },
                ));
            }
            5 => {
                let offers = offers_from(chunk);
                let _ = black_box(engine.handle(
                    now,
                    MeshInput::SyncItems {
                        link,
                        items: &offers,
                    },
                ));
            }
            6 => {
                let hashes = hashes_from(chunk);
                let _ = black_box(engine.handle(now, MeshInput::KnownCards { hashes: &hashes }));
            }
            7 => {
                let observation = NodeObservation {
                    node: NodeId::from_bytes([selector; 16]),
                    card_hash: [selector; 8],
                    caps: u32::from(selector),
                    seq: u64::from(selector),
                    hops: selector % 8,
                    via: NodeId::from_bytes([2; 16]),
                    observed_at_ms: now,
                    location: chunk,
                };
                let _ = black_box(engine.handle(now, MeshInput::ObserveNode { observation }));
            }
            _ => {
                let _ = black_box(engine.handle(
                    now,
                    MeshInput::SubmitTelemetry {
                        identity: &local,
                        kind: TelemetryKind::new(selector),
                        seq: u64::from(selector),
                        payload: chunk,
                        via: Some(link),
                    },
                ));
            }
        }
    }
});
