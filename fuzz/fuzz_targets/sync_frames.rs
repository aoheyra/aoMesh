#![no_main]

//! MSH-28 sync target: v1 and v2 frames must reject hostile bodies before
//! copying, and every accepted frame must re-encode without panicking.

use std::hint::black_box;

use ao_mesh::{SyncFrame, SyncFrameV2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(frame)) = SyncFrame::decode(data) {
        let _ = black_box(&frame);
        if let Some(wire) = frame.encode() {
            let _ = black_box(SyncFrame::decode(&wire));
        }
    }

    if let Ok(Some(frame)) = SyncFrameV2::decode(data) {
        let _ = black_box(&frame);
        if let Some(wire) = frame.encode() {
            let _ = black_box(SyncFrameV2::decode(&wire));
        }
    }
});
