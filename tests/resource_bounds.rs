//! Deterministic resource bounds for hostile input (MSH-28).
//!
//! A separate test binary: `#[global_allocator]` applies per binary, and the
//! file holds one test so no other test can pollute the counters. Every
//! fixture is built before the counters are reset; only engine/decoder work
//! is measured. The ceilings come from the configured bounds in `MeshConfig`,
//! `SeenConfig`, `StoreLimits` and the sync frame caps, with headroom for
//! allocator layout variation. A regression that allocates per input byte,
//! or grows a cache past its bound, fails here without a fuzz campaign.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering};

use ao_idents::{Identity, Signature};
use ao_mesh::packet::MAX_PAYLOAD;
use ao_mesh::store::{MemoryStore, MessageStore, StoreLimits, StoreMetadata, StoredMessage};
use ao_mesh::{
    CAPS, Header, MAX_FRAME_BODY_BYTES, MAX_SUMMARY_ENTRIES, MeshEngine, MeshHello, MeshInput,
    MessageId, Packet, PacketClass, StoreSummary, SYNC_MAGIC, SYNC_VERSION, SyncFrame, SyncFrameV2,
    derive_msg_id,
};
use ao_network::{AppHello, Channel, Hello, LinkId, LocalTag};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_core::RngCore;

struct Counting;

/// Net bytes held since the last reset.
static NET_BYTES: AtomicIsize = AtomicIsize::new(0);
/// Largest net value observed since the last reset.
static PEAK_BYTES: AtomicIsize = AtomicIsize::new(0);
/// Allocation calls since the last reset; a deterministic CPU proxy.
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every allocation is forwarded to the system allocator unchanged;
// the wrapper only counts. Three atomics per call are paid only in this test
// binary.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let net =
            NET_BYTES.fetch_add(layout.size() as isize, Ordering::SeqCst) + layout.size() as isize;
        PEAK_BYTES.fetch_max(net, Ordering::SeqCst);
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: forwarded verbatim; the caller's contract holds.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        NET_BYTES.fetch_sub(layout.size() as isize, Ordering::SeqCst);
        // SAFETY: ptr and layout come from this allocator's own alloc.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        NET_BYTES.fetch_add(new_size as isize, Ordering::SeqCst);
        NET_BYTES.fetch_sub(layout.size() as isize, Ordering::SeqCst);
        let net = NET_BYTES.load(Ordering::SeqCst);
        PEAK_BYTES.fetch_max(net, Ordering::SeqCst);
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: forwarded verbatim; the caller's contract holds.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn reset() {
    NET_BYTES.store(0, Ordering::SeqCst);
    PEAK_BYTES.store(0, Ordering::SeqCst);
    ALLOCS.store(0, Ordering::SeqCst);
}

fn peak() -> usize {
    PEAK_BYTES.load(Ordering::SeqCst).max(0) as usize
}

fn allocs() -> usize {
    ALLOCS.load(Ordering::SeqCst)
}

/// Counts RNG draws without changing the deterministic stream: a hostile
/// packet that is rejected before policy must not spend any engine entropy.
struct CountingRng {
    inner: StdRng,
    draws: Arc<AtomicU64>,
}

impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.draws.fetch_add(1, Ordering::SeqCst);
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.draws.fetch_add(1, Ordering::SeqCst);
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.draws.fetch_add(1, Ordering::SeqCst);
        self.inner.fill_bytes(dst);
    }
}

fn link_hello(identity: &Identity, tag: [u8; 16]) -> Hello {
    let signed = MeshHello::sign(identity, [0; 8], [0; 4]).expect("fixed key signs");
    Hello {
        proto_min: 1,
        proto_max: 1,
        caps: CAPS,
        max_frame: 16 * 1024,
        tag: LocalTag::new(tag),
        app_hello: AppHello::new(signed.encode().to_vec()).expect("fixed hello fits"),
    }
}

/// A structurally valid Broadcast packet: the content address matches the
/// bytes, so it reaches the suppression policy and spends RNG draws. The
/// signature is deliberately zero; the engine does not verify it here.
fn flood_packet(tag: u8) -> Vec<u8> {
    let payload = vec![tag; 64];
    let mut header = Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: [0; 16].into(),
        origin: [1; 16],
        created_ms: 1_000,
        lifetime_s: 60,
        payload_len: payload.len() as u64,
        ttl: 8,
        hops: 0,
    };
    header.msg_id = derive_msg_id(&header, &payload);
    Packet::new(header, Signature::from_bytes([0; 64]), &payload)
        .expect("fixture lengths agree")
        .encode()
}

#[test]
fn hostile_inputs_stay_inside_the_documented_bounds() {
    // ---- 1. Packet and header decode never allocate, whatever the size. ----
    let mut oversize = Header {
        class: PacketClass::Direct,
        dst: Some([2; 16]),
        msg_id: [1; 16].into(),
        origin: [3; 16],
        created_ms: u64::MAX,
        lifetime_s: u64::MAX,
        payload_len: MAX_PAYLOAD as u64 + 1,
        ttl: 8,
        hops: 0,
    }
    .encode();
    let valid = flood_packet(1);
    // A megabyte of continuation bytes: the varint reader must stop at ten.
    let runaway = vec![0x80u8; 1024 * 1024];

    reset();
    for _ in 0..1_000 {
        assert!(Header::decode(&oversize).is_err());
        assert!(Packet::decode(&oversize).is_err());
        assert!(Header::decode(&runaway).is_err());
        assert!(Packet::decode(&runaway).is_err());
        assert!(Packet::decode(&valid).is_ok());
    }
    assert_eq!(allocs(), 0, "packet decode allocated");
    assert_eq!(peak(), 0, "packet decode held bytes");

    // ---- 2. Sync frames reject hostile bodies before copying them. ----
    let mut big_item = vec![0x53, 1, 3];
    big_item.extend_from_slice(&((MAX_FRAME_BODY_BYTES + 1) as u16).to_be_bytes());
    big_item.resize(5 + MAX_FRAME_BODY_BYTES + 1, 0xAB);
    let mut big_v2 = vec![0x53, 2, 1];
    big_v2.extend_from_slice(&((MAX_FRAME_BODY_BYTES + 1) as u16).to_be_bytes());
    big_v2.resize(5 + MAX_FRAME_BODY_BYTES + 1, 0xCD);
    let mut trailing = SyncFrame::Summary {
        digest: [0; 4],
        short_ids: vec![[1; 8]],
    }
    .encode()
    .expect("fixture fits");
    trailing.extend_from_slice(&[7; 64]);
    oversize.truncate(5);
    oversize[0] = SYNC_MAGIC;
    oversize[1] = SYNC_VERSION;
    oversize[2] = 2; // summary tag
    oversize[3..5].copy_from_slice(&8u16.to_be_bytes());

    reset();
    for _ in 0..1_000 {
        assert!(SyncFrame::decode(&big_item).is_err());
        assert!(SyncFrameV2::decode(&big_v2).is_err());
        assert!(SyncFrame::decode(&trailing).is_err());
        assert!(SyncFrame::decode(&oversize).is_err());
    }
    assert!(
        allocs() <= 4_000,
        "one hostile sync frame must not allocate per input byte: {} allocations",
        allocs()
    );
    assert!(
        peak() <= 16 * 1024,
        "hostile sync frames held {} bytes",
        peak()
    );

    // ---- 3. A host summary slice cannot grow the engine's view. ----
    let ids: Vec<MessageId> = (0..100_000)
        .map(|i| MessageId::from_bytes((i as u128).to_le_bytes()))
        .collect();
    let identity = Identity::from_seed([3; 32]);
    let mut engine = MeshEngine::new(StdRng::seed_from_u64(0x4d53_0028));
    reset();
    let summary = StoreSummary::from_ids(&ids);
    assert_eq!(summary.len(), MAX_SUMMARY_ENTRIES);
    for round in 0..64 {
        assert!(
            engine
                .handle(round, MeshInput::StoreSummary { ids: &ids })
                .is_ok()
        );
    }
    assert!(
        peak() <= 256 * 1024,
        "summary inputs held {} bytes, cap is 1024 ids",
        peak()
    );

    // ---- 4. A stream of hostile Data inputs stays flat and spends no
    // entropy until a packet passes structural validation. ----
    let peer = Identity::from_seed([7; 32]);
    let link = LinkId::new(1);
    let draws = Arc::new(AtomicU64::new(0));
    let mut engine: MeshEngine<CountingRng> = MeshEngine::new(CountingRng {
        inner: StdRng::seed_from_u64(0x4d53_0029),
        draws: Arc::clone(&draws),
    });
    let _ = engine.handle(
        0,
        MeshInput::LinkUp {
            link,
            remote_hello: link_hello(&peer, [1; 16]),
        },
    );
    let mut hostile = vec![vec![1u8; 8 * 1024], vec![0x53, 1, 3, 0xFF, 0xFF]];
    hostile.push(vec![0x53, 2, 1, 0xFF, 0xFF]);
    hostile.push(vec![0x54, 1, 1, 1, 0xFF, 0xFF]);
    hostile.push(vec![0x55, 1, 1, 0, 0x10, 0x00, 0x10, 0x00]);
    hostile.push(flood_packet(9));
    let channels = [
        Channel::Message,
        Channel::Bulk,
        Channel::Telemetry,
        Channel::Bulk,
    ];

    reset();
    for round in 0..200u64 {
        let now = 1_000 + round * 17;
        for (index, payload) in hostile.iter().enumerate() {
            let before_allocs = allocs();
            let before_draws = draws.load(Ordering::SeqCst);
            let _ = engine.handle(
                now,
                MeshInput::Data {
                    link,
                    channel: channels[index % channels.len()],
                    payload,
                    identity: &identity,
                },
            );
            assert!(
                allocs() - before_allocs <= 128,
                "input {} spent {} allocations",
                index,
                allocs() - before_allocs
            );
            assert!(
                draws.load(Ordering::SeqCst) - before_draws <= 2,
                "input {} spent engine entropy",
                index
            );
        }
        let _ = engine.handle(
            now,
            MeshInput::Tick {
                identity: &identity,
                card_hash: [0; 8],
            },
        );
    }
    assert!(
        peak() <= 32 * 1024 * 1024,
        "engine held {} bytes after 1200 hostile inputs",
        peak()
    );

    // ---- 5. Store quotas hold under an oversized-wire flood. ----
    let limits = StoreLimits {
        entries: 4,
        total_bytes: 4 * 2_560,
        per_origin_bytes: 4 * 2_560,
        per_class_bytes: [4 * 2_560; 4],
    };
    let mut store = MemoryStore::new(limits);
    let oversized_wire = vec![0u8; ao_mesh::store::MAX_STORED_PACKET + 1];
    let metadata = StoreMetadata {
        copies_left: 1,
        first_seen: 0,
        received_at: 0,
        priority: 1,
        received_from: None,
        age_ms: 0,
    };
    let mut entries = Vec::new();
    for i in 0..32u128 {
        let mut header = Header {
            class: PacketClass::Direct,
            dst: Some([9; 16]),
            msg_id: MessageId::from_bytes(i.to_le_bytes()),
            origin: [1; 16],
            created_ms: 0,
            lifetime_s: 60,
            payload_len: 4,
            ttl: 8,
            hops: 0,
        };
        header.msg_id = derive_msg_id(&header, &[i as u8; 4]);
        let mut wire = header.encode();
        wire.extend_from_slice(&[i as u8; 4]);
        entries.push(StoredMessage::new(&wire, metadata).expect("fixture fits the store cap"));
    }
    reset();
    for _ in 0..1_000 {
        assert!(StoredMessage::new(&oversized_wire, metadata).is_err());
    }
    assert_eq!(allocs(), 0, "an oversized envelope allocated");
    for entry in entries {
        let _ = store.put(0, entry);
    }
    assert!(store.used_bytes() <= limits.total_bytes);
    assert!(store.summary(0).len() <= limits.entries);
}
