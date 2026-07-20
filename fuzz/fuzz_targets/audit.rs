#![no_main]
//! The full anomaly auditor over an arbitrary volume buffer — drives the
//! inspect/audit pipeline end to end. Must never panic; returns findings only.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hfsplus_forensic::findings::audit(data);
});
