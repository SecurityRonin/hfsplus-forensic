//! End-to-end decmpfs: `read_file` must transparently decompress an
//! HFS+-compressed file, validated against a REAL `ditto --hfsCompression`
//! volume (a layout-NONE HFS+ image minted on macOS).
//!
//! `comp.bin` is a type-8 (LZVN) resource-fork file; `plain.bin` is the same
//! bytes stored uncompressed (the control). The payload is a deterministic LCG
//! block repeated 32× — regenerated here byte-for-byte, so no expected-output
//! fixture is committed.

use hfsplus_forensic as hfs;

fn volume() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/decmpfs/hfs_decmpfs_volume.bin"
    ))
    .unwrap()
}

/// The exact bytes written to the volume: an 8192-byte LCG block repeated 32×.
fn expected_payload() -> Vec<u8> {
    let mut state: u32 = 2_654_435_761;
    let mut block = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        block.push((state >> 16) as u8);
    }
    block.iter().cycle().take(8192 * 32).copied().collect()
}

fn cnid_of(vol: &[u8], name: &str) -> u32 {
    hfs::list_root(vol)
        .expect("list root")
        .into_iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("{name} not found on volume"))
        .cnid
}

#[test]
fn read_file_transparently_decompresses_decmpfs_lzvn() {
    let vol = volume();
    let cnid = cnid_of(&vol, "comp.bin");
    let got = hfs::read_file(&vol, cnid).expect("read comp.bin");
    assert_eq!(
        got,
        expected_payload(),
        "a decmpfs-compressed file must read back as its original {} bytes, \
         not its (empty) data fork",
        expected_payload().len()
    );
}

#[test]
fn uncompressed_control_file_reads_unchanged() {
    let vol = volume();
    let cnid = cnid_of(&vol, "plain.bin");
    assert_eq!(
        hfs::read_file(&vol, cnid).expect("read plain.bin"),
        expected_payload(),
        "the uncompressed control file must still read correctly"
    );
}
