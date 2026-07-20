#![no_main]
//! The HFS+/HFSX volume header is fully attacker-controlled — parse must never
//! panic and returns `None` on any short/malformed buffer.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hfsplus_forensic::parse(data);
});
