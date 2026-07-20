#![no_main]
//! Per-CNID metadata extraction (kind, fork size, HFS+ MAC timestamps). The
//! leading 4 bytes select the CNID; the rest is the volume.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((cnid_bytes, volume)) = data.split_first_chunk::<4>() else {
        return;
    };
    let cnid = u32::from_be_bytes(*cnid_bytes);
    let _ = hfsplus_forensic::stat(volume, cnid);
});
