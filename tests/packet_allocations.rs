use ao_mesh::packet::{PacketView, parse_header};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record(size: usize) {
    // TLS can be gone during thread teardown, outside any measured closure.
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        COUNTS.with(|counts| {
            let (allocations, bytes) = counts.get();
            counts.set((allocations.saturating_add(1), bytes.saturating_add(size)));
        });
    }
}

// SAFETY: The wrapper preserves System's pointer/layout contracts and only adds
// allocation-free, non-panicking thread-local counters. It is test-only because
// measuring actual allocations requires implementing GlobalAlloc's unsafe API.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc's caller supplies the same valid layout to System.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller's valid layout is forwarded unchanged.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(layout.size());
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: All three arguments retain the caller's realloc contract.
        let new_pointer = unsafe { System.realloc(pointer, layout, size) };
        if !new_pointer.is_null() {
            record(size);
        }
        new_pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: No pointer or layout is changed or freed elsewhere by this wrapper.
        unsafe { System.dealloc(pointer, layout) };
    }
}

fn measure(run: impl FnOnce()) -> (usize, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TRACKING.with(|tracking| tracking.set(false));
        }
    }
    TRACKING.with(|tracking| assert!(!tracking.get()));
    COUNTS.with(|counts| counts.set((0, 0)));
    TRACKING.with(|tracking| tracking.set(true));
    let reset = Reset;
    run();
    drop(reset);
    COUNTS.with(Cell::get)
}

#[test]
fn header_rejection_and_borrowed_payload_parsing_allocate_nothing() {
    let control = measure(|| {
        let mut grown = Vec::with_capacity(1);
        grown.extend_from_slice(&[7u8; 64]);
        drop(black_box(grown));
        drop(black_box(vec![0u8; 64]));
    });
    assert!(
        control.0 >= 2 && control.1 >= 128,
        "counter must detect real allocations"
    );

    let mut valid = vec![1, 0, 0];
    valid.extend_from_slice(&[0x11; 16]);
    valid.extend_from_slice(&[0x22; 16]);
    valid.extend_from_slice(&[0, 0, 0, 3, 8, 0, 1, 2, 3]);
    let mut rejects: Vec<Vec<u8>> = (0..41).map(|end| valid[..end].to_vec()).collect();
    for (offset, value) in [(0, 2), (1, 4), (2, 1), (35, 2)] {
        let mut bytes = valid.clone();
        bytes[offset] = value;
        rejects.push(bytes);
    }
    for bad in [&[0x80, 0][..], &[0xff; 10][..]] {
        let mut bytes = valid[..36].to_vec();
        bytes.extend_from_slice(bad);
        rejects.push(bytes);
    }
    let mut oversized = valid[..38].to_vec();
    oversized.extend_from_slice(&[0x81, 0x80, 0x40]);
    rejects.push(oversized);

    // Inputs and test bookkeeping are allocated outside the measured region.
    let allocations = measure(|| {
        for bytes in &rejects {
            assert!(black_box(parse_header(black_box(bytes))).is_err());
            assert!(black_box(PacketView::parse(black_box(bytes))).is_err());
        }
        assert!(black_box(parse_header(black_box(&valid))).is_ok());
        let view = PacketView::parse(black_box(&valid)).unwrap();
        assert_eq!(view.payload().as_ptr(), valid[41..].as_ptr());
    });
    assert_eq!(allocations, (0, 0));
}
