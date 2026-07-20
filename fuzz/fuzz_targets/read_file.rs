#![no_main]
//! File-content extraction by CNID. Reaches fork resolution, allocation-block
//! reads, and — when a decmpfs xattr is present — the transparent-compression
//! decode path. The leading 4 bytes select the CNID; the rest is the volume.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((cnid_bytes, volume)) = data.split_first_chunk::<4>() else {
        return;
    };
    let cnid = u32::from_be_bytes(*cnid_bytes);
    let _ = hfsplus_forensic::read_file(volume, cnid);
});
