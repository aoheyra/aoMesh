//! Allocation accounting for header-only parsing (MSH-03: a header-only
//! reject never allocates the payload).
//!
//! A separate test binary: `#[global_allocator]` applies per binary, and the
//! file holds exactly one test so no other test can pollute the counter.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use ao_mesh::packet::{Header, MAX_PAYLOAD, MSG_ID_LEN, NODE_ID_LEN, PacketClass, PacketError};

struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every allocation is forwarded to the system allocator unchanged;
// the wrapper only counts. The single relaxed-free (SeqCst) add per call is
// the whole cost, paid only in this test binary.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: forwarded verbatim; the caller's contract holds.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim; the caller's contract holds.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: forwarded verbatim; the caller's contract holds.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn header_with_payload_len(payload_len: u64) -> Header {
    Header {
        class: PacketClass::Broadcast,
        dst: None,
        msg_id: [1u8; MSG_ID_LEN],
        origin: [2u8; NODE_ID_LEN],
        created_ms: 1_700_000_000_000,
        lifetime_s: 3_600,
        payload_len,
        ttl: 6,
        hops: 0,
    }
}

#[test]
fn header_only_parse_and_reject_never_allocate() {
    // A header declaring a full-size payload with no payload bytes present
    // at all: parsing must succeed without ever looking for the payload.
    let declaring_full = header_with_payload_len(MAX_PAYLOAD as u64);
    let full_bytes = declaring_full.encode();

    // A header over the cap, which must be rejected at the header stage.
    let oversize = header_with_payload_len(MAX_PAYLOAD as u64 + 1);
    let oversize_bytes = oversize.encode();

    // Everything above allocated; the measurement starts here.
    ALLOCS.store(0, Ordering::SeqCst);

    let parsed = Header::decode(&full_bytes).expect("header parses with no payload present");
    let parse_allocs = ALLOCS.load(Ordering::SeqCst);

    let rejected = Header::decode(&oversize_bytes).expect_err("oversize is rejected");
    let reject_allocs = ALLOCS.load(Ordering::SeqCst);

    assert_eq!(parse_allocs, 0, "header-only parse allocated");
    assert_eq!(reject_allocs, 0, "header-only reject allocated");
    assert_eq!(parsed.payload_len, MAX_PAYLOAD as u64);
    assert!(matches!(rejected, PacketError::PayloadTooLarge { .. }));
}
