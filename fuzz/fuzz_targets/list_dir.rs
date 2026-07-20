#![no_main]
//! Directory listing by parent CNID. The leading 4 bytes select the parent
//! CNID so the fuzzer can probe arbitrary catalog keys; the rest is the volume.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((cnid_bytes, volume)) = data.split_first_chunk::<4>() else {
        return;
    };
    let cnid = u32::from_be_bytes(*cnid_bytes);
    let _ = hfsplus_forensic::list_dir(volume, cnid);
});
