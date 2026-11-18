//! Memory bound for the seen-cache (MSH-05): a hostile flood must never
//! hold more than `capacity` recordings or the documented bytes. The full
//! flood of a million insertions runs in the Tests job; under Miri the
//! same test runs a reduced flood (see the loop below) so the Miri job
//! stays inside its time limit.
//!
//! A separate test binary: `#[global_allocator]` applies per binary, and
//! the file holds exactly one test so no other test can pollute the
//! counter.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use ao_mesh::packet::{MessageId, PacketClass};
use ao_mesh::seen::{Offer, SeenCache, SeenConfig};

struct Counting;

/// Net bytes currently held: allocations since the counter was reset,
/// less the bytes freed since.
static NET_BYTES: AtomicIsize = AtomicIsize::new(0);
/// The largest `NET_BYTES` observed, sampled after every insertion.
static PEAK_BYTES: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every allocation is forwarded to the system allocator unchanged;
// the wrapper only counts bytes. The single SeqCst update per call is the
// whole cost, paid only in this test binary.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let net =
            NET_BYTES.fetch_add(layout.size() as isize, Ordering::SeqCst) + layout.size() as isize;
        PEAK_BYTES.fetch_max(net, Ordering::SeqCst);
        // SAFETY: forwarded verbatim; the caller's contract holds.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        NET_BYTES.fetch_sub(layout.size() as isize, Ordering::SeqCst);
        // SAFETY: ptr and layout come from this allocator's own alloc.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

#[test]
fn a_million_insertions_stay_within_both_bounds() {
    // Reset after harness startup, before the cache reserves its bounds:
    // what follows is cache memory only.
    NET_BYTES.store(0, Ordering::SeqCst);
    PEAK_BYTES.store(0, Ordering::SeqCst);

    let config = SeenConfig::default();
    let capacity = config.capacity;
    let mut cache = SeenCache::new(config);
    let baseline = NET_BYTES.load(Ordering::SeqCst);

    // One instant: nothing expires by time, so every insertion exercises
    // the size bound alone, which is the hostile-flood case.
    let now = 1_700_000_000_000u64;
    // Miri interprets every insertion and instruments every counted
    // allocation, so a million of them cannot finish inside the Miri
    // job's time limit. Five times the capacity still fills the cache
    // and drives four capacities of evictions, and both structures
    // reserve their bounds at construction, so every assertion below
    // sees the state a full flood leaves; the Tests job runs this same
    // test with the full million on every platform.
    let insertions = if cfg!(miri) {
        capacity as u64 * 5
    } else {
        1_000_000
    };
    for i in 0..insertions {
        let msg_id = MessageId::from_bytes((i as u128).to_le_bytes());
        let class = match i % 4 {
            0 => PacketClass::Direct,
            1 => PacketClass::Broadcast,
            2 => PacketClass::Presence,
            _ => PacketClass::Telemetry,
        };
        // Every id in the flood is unique: nothing may read as seen.
        assert_eq!(cache.check_and_insert(now, class, msg_id), Offer::Fresh);
        if i % 997 == 0 {
            assert!(
                cache.len() <= capacity,
                "len {} over capacity {capacity} at insert {i}",
                cache.len()
            );
        }
    }

    assert_eq!(cache.len(), capacity, "a flood fills the cache exactly");
    let net = NET_BYTES.load(Ordering::SeqCst);
    let peak = PEAK_BYTES.load(Ordering::SeqCst);
    // The documented budget (seen.rs, ADR-0003): both structures are
    // functions of `capacity` — the order deque reserves up front, the
    // map holds at most `capacity` records — so held bytes stop growing
    // once filled and erase/insert churn cannot grow them. The peak is
    // sampled after every insertion, so the ceiling holds across the
    // whole run, not just at the end. Measured: reservation 65,536 B
    // (the deque), 262,904 B held after the fill, 263,560 B peak; the
    // 512 KiB budget is that measurement with headroom for std-layout
    // variation across platforms.
    const BUDGET_BYTES: isize = 512 * 1024;
    assert!(
        baseline > 0 && baseline <= BUDGET_BYTES,
        "reservation {baseline} bytes, budget {BUDGET_BYTES}"
    );
    assert!(
        net > 0 && net <= BUDGET_BYTES,
        "held {net} bytes (baseline {baseline}), budget {BUDGET_BYTES}"
    );
    assert!(
        peak <= BUDGET_BYTES,
        "peak {peak} bytes (held {net}, baseline {baseline}), budget {BUDGET_BYTES}"
    );
}
