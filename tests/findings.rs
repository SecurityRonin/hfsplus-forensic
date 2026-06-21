//! HFS+ forensic anomaly analyzer tests.
//!
//! True-negative: the real `hdiutil`-created volumes (validated against The
//! Sleuth Kit `fsstat`/`fls`/`istat`) carry no anomalies. Positive: bytes
//! crafted from those same real volumes — a flipped B-tree node link, a
//! backdated timestamp, a decmpfs flag stripped of its payload — each surface
//! the matching graded `HFS-*` finding.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hfsplus_forensic::findings::{audit, AnomalyKind, Severity};

const VOLUME_HEADER_OFFSET: usize = 1024;
const CATALOG_FORK_OFFSET: usize = 272;
const ATTRIBUTES_FORK_OFFSET: usize = 352;

fn volume() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hfs_plus_volume.bin"
    ))
    .unwrap()
}

fn nested() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hfs_plus_nested.bin"
    ))
    .unwrap()
}

fn decmpfs_volume() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/decmpfs/hfs_decmpfs_volume.bin"
    ))
    .unwrap()
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Locate `(cat_base, node_size, first_leaf)` for the B-tree whose fork sits at
/// `fork_off` bytes into the volume header — mirrors the reader's `locate_btree`.
fn locate(vol: &[u8], fork_off: usize) -> (usize, usize, u32) {
    let h = VOLUME_HEADER_OFFSET;
    let bs = be32(vol, h + 40) as usize;
    let fork = h + fork_off;
    let start = be32(vol, fork + 16) as usize;
    let cat_base = start * bs;
    let hdr = cat_base + 14;
    let first_leaf = be32(vol, hdr + 10);
    let node_size = be16(vol, hdr + 18) as usize;
    (cat_base, node_size, first_leaf)
}

// ---- True-negative: clean real volumes are silent -------------------------

#[test]
fn clean_real_volume_has_no_anomalies() {
    let anomalies = audit(&volume());
    assert!(
        anomalies.is_empty(),
        "clean real HFS+ volume should be silent, got: {anomalies:?}"
    );
}

#[test]
fn clean_real_nested_volume_has_no_anomalies() {
    let anomalies = audit(&nested());
    assert!(
        anomalies.is_empty(),
        "clean real nested HFS+ volume should be silent, got: {anomalies:?}"
    );
}

#[test]
fn clean_real_decmpfs_volume_has_no_anomalies() {
    // A volume holding a real LZVN-compressed file whose resource fork IS
    // present must not trip HFS-DECMPFS-MISSING-RESOURCE.
    let anomalies = audit(&decmpfs_volume());
    assert!(
        anomalies.is_empty(),
        "clean real decmpfs HFS+ volume should be silent, got: {anomalies:?}"
    );
}

#[test]
fn non_hfs_buffer_has_no_anomalies() {
    assert!(audit(&[0u8; 4096]).is_empty());
    assert!(audit(&[0u8; 10]).is_empty());
}

// ---- Positive: crafted corruption of the real volumes ---------------------

/// Flip the catalog leaf node's forward link to a non-existent node so the
/// node-descriptor consistency check fires.
#[test]
fn corrupt_btree_node_link_is_flagged() {
    let mut vol = volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
    let leaf_off = first_leaf as usize * node_size + cat_base;
    // fLink at offset 0 of the node descriptor — point it back at itself, an
    // impossible self-link for a leaf chain.
    vol[leaf_off..leaf_off + 4].copy_from_slice(&first_leaf.to_be_bytes());

    let anomalies = audit(&vol);
    assert!(
        anomalies.iter().any(|a| a.code == "HFS-BTREE-NODE-INVALID"),
        "expected HFS-BTREE-NODE-INVALID, got: {anomalies:?}"
    );
}

/// Corrupt a leaf node's `kind` byte to an invalid value.
#[test]
fn corrupt_btree_node_kind_is_flagged() {
    let mut vol = volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
    let leaf_off = first_leaf as usize * node_size + cat_base;
    // kind at offset 8 (i8): leaf=-1, index=0, header=1, map=2. 0x42 is invalid.
    vol[leaf_off + 8] = 0x42;

    let anomalies = audit(&vol);
    assert!(
        anomalies.iter().any(|a| a.code == "HFS-BTREE-NODE-INVALID"),
        "expected HFS-BTREE-NODE-INVALID, got: {anomalies:?}"
    );
}

/// Backdate a file's create date to before the HFS+ epoch (1904) so it reads
/// as zero/implausible, and make create > modify.
#[test]
fn create_after_modify_is_flagged() {
    let mut vol = volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
    let leaf_off = first_leaf as usize * node_size + cat_base;
    let nd = &vol[leaf_off..leaf_off + node_size];
    // Find HELLO.TXT's file record and bump its createDate far past its
    // contentModDate.
    let num = be16(nd, 10) as usize;
    let mut patched = false;
    for i in 0..num {
        let slot = node_size - 2 * (i + 1);
        let rec = be16(nd, slot) as usize;
        let r = &nd[rec..];
        let key_len = be16(r, 0) as usize;
        let data = 2 + key_len;
        if i16::from_be_bytes([r[data], r[data + 1]]) == 2 {
            // file record: createDate@+16, contentModDate@+20
            let modt = be32(r, data + 20);
            let abs = leaf_off + rec + data + 16;
            vol[abs..abs + 4].copy_from_slice(&(modt + 1_000_000).to_be_bytes());
            patched = true;
            break;
        }
    }
    assert!(patched, "no file record found to patch");

    let anomalies = audit(&vol);
    assert!(
        anomalies.iter().any(|a| a.code == "HFS-TIME-ANOMALY"),
        "expected HFS-TIME-ANOMALY, got: {anomalies:?}"
    );
}

/// Strip a decmpfs-compressed file's resource-fork bytes (zero its extents in
/// the catalog file record) while leaving the `com.apple.decmpfs` xattr that
/// declares resource-fork storage — the payload is now missing.
#[test]
fn decmpfs_missing_resource_is_flagged() {
    // The decmpfs volume's comp.bin is type-8 LZVN in the resource fork.
    let mut vol = decmpfs_volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
    // Walk leaf chain to find the file record carrying a resource fork, zero it.
    let mut node = first_leaf;
    let mut patched = false;
    while node != 0 && !patched {
        let node_off = node as usize * node_size + cat_base;
        if node_off + node_size > vol.len() {
            break;
        }
        let nd = &vol[node_off..node_off + node_size];
        let f_link = be32(nd, 0);
        let num = be16(nd, 10) as usize;
        for i in 0..num {
            let slot = node_size - 2 * (i + 1);
            let rec = be16(nd, slot) as usize;
            let r = &nd[rec..];
            if r.len() < 8 {
                continue;
            }
            let key_len = be16(r, 0) as usize;
            let data = 2 + key_len;
            if data + 248 > r.len() {
                continue;
            }
            if i16::from_be_bytes([r[data], r[data + 1]]) == 2 {
                // resource fork HFSPlusForkData at data+168: logicalSize(8),
                // clumpSize(4), totalBlocks(4), then 8*(start,count). Zero the
                // total blocks and all extents so the fork is empty.
                let rsrc_logical =
                    u64::from_be_bytes(r[data + 168..data + 176].try_into().unwrap());
                if rsrc_logical > 0 {
                    let base = node_off + rec + data + 168;
                    for b in vol[base + 12..base + 16 + 64].iter_mut() {
                        *b = 0;
                    }
                    patched = true;
                    break;
                }
            }
        }
        node = f_link;
    }
    assert!(patched, "no compressed file with a resource fork found");

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-DECMPFS-MISSING-RESOURCE"),
        "expected HFS-DECMPFS-MISSING-RESOURCE, got: {anomalies:?}"
    );
}

#[test]
fn anomalies_are_graded_and_consistent_with() {
    let mut vol = volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
    let leaf_off = first_leaf as usize * node_size + cat_base;
    vol[leaf_off + 8] = 0x42;
    let anomalies = audit(&vol);
    let a = anomalies
        .iter()
        .find(|a| a.code == "HFS-BTREE-NODE-INVALID")
        .unwrap();
    assert!(matches!(a.severity, Severity::High | Severity::Critical));
    // Observations are "consistent with", never verdicts.
    assert!(!a.note.to_lowercase().contains("proves"));
    assert!(!a.note.to_lowercase().contains("confirms"));
    let _ = ATTRIBUTES_FORK_OFFSET; // referenced for documentation parity
    let _ = AnomalyKind::BtreeNodeInvalid {
        tree: String::new(),
        node: 0,
        detail: String::new(),
    };
}
