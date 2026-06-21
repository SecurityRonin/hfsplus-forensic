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
    let _ = AnomalyKind::BtreeNodeInvalid {
        tree: String::new(),
        node: 0,
        detail: String::new(),
    };
}

/// Locate the absolute byte offset of the first file record (recordType==2) in
/// the catalog's first leaf node, returning `(record_offset, data_offset)` where
/// `data_offset` points at the record body (past the variable key).
fn first_file_record(vol: &[u8]) -> (usize, usize) {
    let (cat_base, node_size, first_leaf) = locate(vol, CATALOG_FORK_OFFSET);
    let node_off = first_leaf as usize * node_size + cat_base;
    let nd = &vol[node_off..node_off + node_size];
    let num = be16(nd, 10) as usize;
    for i in 0..num {
        let slot = node_size - 2 * (i + 1);
        let rec = be16(nd, slot) as usize;
        let key_len = be16(nd, rec) as usize;
        let data = rec + 2 + key_len;
        if i16::from_be_bytes([nd[data], nd[data + 1]]) == 2 {
            return (node_off + rec, node_off + data);
        }
    }
    panic!("no file record in first leaf");
}

/// A file whose data-fork extents cover fewer blocks than its logical size needs
/// (with no overflow record) trips the catalog/extents mismatch.
#[test]
fn catalog_extents_mismatch_is_flagged() {
    let mut vol = volume();
    let (_rec, data) = first_file_record(&vol);
    // Data fork @ data+88: logicalSize(8) @+0, totalBlocks @+12, extents @+16.
    // Inflate the logical size to 10 blocks' worth while the single extent
    // covers one block → allocated < needed.
    let logical_off = data + 88;
    vol[logical_off..logical_off + 8].copy_from_slice(&(10u64 * 4096).to_be_bytes());

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-CATALOG-EXTENTS-MISMATCH"),
        "expected HFS-CATALOG-EXTENTS-MISMATCH, got: {anomalies:?}"
    );
}

/// A file record whose recordType is corrupted to a thread type leaves the
/// file's own thread record pointing at a now-absent CNID.
#[test]
fn deleted_but_referenced_is_flagged() {
    let mut vol = volume();
    let (rec, data) = first_file_record(&vol);
    let _ = rec;
    // Flip the file record's recordType (2) to an unrecognized value so the
    // entry vanishes from the catalog while its thread (which lives in a
    // separate record) still references the CNID.
    vol[data] = 0x00;
    vol[data + 1] = 0x7F;

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-DELETED-BUT-REFERENCED"),
        "expected HFS-DELETED-BUT-REFERENCED, got: {anomalies:?}"
    );
}

/// A leaf node whose descriptor height is corrupted to 0 (a leaf must sit at
/// height >= 1) is flagged.
#[test]
fn leaf_height_anomaly_is_flagged() {
    let mut vol = volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
    let leaf_off = first_leaf as usize * node_size + cat_base;
    // height at offset 9; the real value is 1, zero it.
    assert_eq!(vol[leaf_off + 9], 1, "fixture leaf height should be 1");
    vol[leaf_off + 9] = 0;

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-BTREE-NODE-INVALID" && a.note.contains("must sit at height")),
        "expected leaf-height HFS-BTREE-NODE-INVALID, got: {anomalies:?}"
    );
}

/// decmpfs xattr whose compression_type is undocumented is flagged (the reader
/// would refuse to materialize the file).
#[test]
fn decmpfs_unknown_type_is_flagged() {
    let mut vol = decmpfs_volume();
    // comp.bin's decmpfs compression_type field (LE u32) lives in the
    // attributes B-tree; locate it the same way audit's decmpfs_xattr does.
    let (cat_base, node_size, first_leaf) = locate(&vol, ATTRIBUTES_FORK_OFFSET);
    let off = patch_decmpfs_type(&mut vol, cat_base, node_size, first_leaf, 99);
    assert!(off, "no com.apple.decmpfs attribute found to patch");

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-DECMPFS-MISSING-RESOURCE"
                && a.note.contains("not a documented decmpfs type")),
        "expected unknown-type HFS-DECMPFS-MISSING-RESOURCE, got: {anomalies:?}"
    );
}

/// decmpfs xattr re-typed to an inline storage type while holding only the
/// 16-byte header (no inline payload) is flagged.
#[test]
fn decmpfs_inline_without_payload_is_flagged() {
    let mut vol = decmpfs_volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, ATTRIBUTES_FORK_OFFSET);
    // Type 3 = zlib inline; comp.bin's xattr is exactly the 16-byte header, so
    // an inline type with no trailing payload is unrecoverable.
    let ok = patch_decmpfs_type(&mut vol, cat_base, node_size, first_leaf, 3);
    assert!(ok, "no com.apple.decmpfs attribute found to patch");

    let anomalies = audit(&vol);
    assert!(
        anomalies.iter().any(|a| a.code == "HFS-DECMPFS-MISSING-RESOURCE"
            && a.note.contains("only the header")),
        "expected inline-no-payload HFS-DECMPFS-MISSING-RESOURCE, got: {anomalies:?}"
    );
}

/// A file timestamp before the HFS+ epoch (a non-zero value below the
/// epoch-to-Unix boundary) is impossible and flagged.
#[test]
fn timestamp_before_epoch_is_flagged() {
    let mut vol = volume();
    let (_rec, data) = first_file_record(&vol);
    // createDate@+16, contentModDate@+20: set create to a small non-zero value
    // (well below the epoch boundary) and keep it <= modify so the create>modify
    // arm does not pre-empt the pre-epoch check.
    let create_off = data + 16;
    let mod_off = data + 20;
    vol[create_off..create_off + 4].copy_from_slice(&100u32.to_be_bytes());
    vol[mod_off..mod_off + 4].copy_from_slice(&200u32.to_be_bytes());

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-TIME-ANOMALY" && a.note.contains("predates the HFS+ epoch")),
        "expected pre-epoch HFS-TIME-ANOMALY, got: {anomalies:?}"
    );
}

/// A file timestamp after the volume's own last-written date is impossible
/// (nothing inside a volume can postdate its header) and flagged.
#[test]
fn timestamp_after_volume_is_flagged() {
    let mut vol = volume();
    // Volume modifyDate @ header+20. Set a file's create/mod far past it.
    let (_rec, data) = first_file_record(&vol);
    let vol_mod = be32(&vol, VOLUME_HEADER_OFFSET + 20);
    let future = vol_mod.saturating_add(10_000_000);
    let create_off = data + 16;
    let mod_off = data + 20;
    vol[create_off..create_off + 4].copy_from_slice(&future.to_be_bytes());
    vol[mod_off..mod_off + 4].copy_from_slice(&future.to_be_bytes());

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-TIME-ANOMALY"
                && a.note.contains("after the volume's last-written")),
        "expected after-volume HFS-TIME-ANOMALY, got: {anomalies:?}"
    );
}

/// A header-kind node descriptor on a node other than node 0 is flagged.
#[test]
fn header_kind_on_nonzero_node_is_flagged() {
    let mut vol = volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
    let leaf_off = first_leaf as usize * node_size + cat_base;
    // Stamp the leaf node's descriptor kind to header (1) — illegal off node 0.
    vol[leaf_off + 8] = 1;

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-BTREE-NODE-INVALID"
                && a.note.contains("header node must be node 0")),
        "expected header-on-nonzero HFS-BTREE-NODE-INVALID, got: {anomalies:?}"
    );
}

/// A decmpfs xattr truncated below the 16-byte decmpfs header is flagged. We
/// shrink comp.bin's attribute `attrSize` to 8 so the returned xattr is short.
#[test]
fn decmpfs_truncated_header_is_flagged() {
    let mut vol = decmpfs_volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, ATTRIBUTES_FORK_OFFSET);
    let ok = shrink_decmpfs_attr_size(&mut vol, cat_base, node_size, first_leaf, 8);
    assert!(ok, "no com.apple.decmpfs attribute found to shrink");

    let anomalies = audit(&vol);
    assert!(
        anomalies
            .iter()
            .any(|a| a.code == "HFS-DECMPFS-MISSING-RESOURCE"
                && a.note.contains("shorter than the 16-byte decmpfs header")),
        "expected truncated-header HFS-DECMPFS-MISSING-RESOURCE, got: {anomalies:?}"
    );
}

/// A resource-fork decmpfs file whose resource fork is entirely zeroed (logical
/// size AND extents) trips the "resource fork is empty" arm.
#[test]
fn decmpfs_empty_resource_logical_is_flagged() {
    let mut vol = decmpfs_volume();
    let (cat_base, node_size, first_leaf) = locate(&vol, CATALOG_FORK_OFFSET);
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
                let rsrc_logical =
                    u64::from_be_bytes(r[data + 168..data + 176].try_into().unwrap());
                if rsrc_logical > 0 {
                    // Zero the resource fork's entire HFSPlusForkData (80 bytes):
                    // logicalSize + clump + totalBlocks + all 8 extents.
                    let base = node_off + rec + data + 168;
                    for b in vol[base..base + 80].iter_mut() {
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
            .any(|a| a.code == "HFS-DECMPFS-MISSING-RESOURCE"
                && a.note.contains("resource fork is empty")),
        "expected empty-resource HFS-DECMPFS-MISSING-RESOURCE, got: {anomalies:?}"
    );
}

/// Set the `attrSize` (BE u32 @ body+12) of the first `com.apple.decmpfs`
/// inline-data attribute, truncating the value the reader returns.
fn shrink_decmpfs_attr_size(
    vol: &mut [u8],
    cat_base: usize,
    node_size: usize,
    first_leaf: u32,
    new_size: u32,
) -> bool {
    let mut node = first_leaf;
    while node != 0 {
        let node_off = node as usize * node_size + cat_base;
        if node_off + node_size > vol.len() {
            break;
        }
        let f_link = be32(&vol[node_off..], 0);
        let num = be16(&vol[node_off..], 10) as usize;
        for i in 0..num {
            let nd = &vol[node_off..node_off + node_size];
            let slot = node_size - 2 * (i + 1);
            let rec = be16(nd, slot) as usize;
            let r = &nd[rec..];
            if r.len() < 14 {
                continue;
            }
            let key_len = be16(r, 0) as usize;
            let name_len = be16(r, 12) as usize;
            let name_end = 14 + name_len * 2;
            if name_end > r.len() {
                continue;
            }
            let name: String = r[14..name_end]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect::<Vec<u16>>()
                .iter()
                .map(|&u| char::from_u32(u32::from(u)).unwrap_or('?'))
                .collect();
            if name != "com.apple.decmpfs" {
                continue;
            }
            let body = 2 + key_len;
            let size_off = node_off + rec + body + 12;
            vol[size_off..size_off + 4].copy_from_slice(&new_size.to_be_bytes());
            return true;
        }
        node = f_link;
    }
    false
}

/// Set the `compression_type` (LE u32) of the first `com.apple.decmpfs`
/// inline-data attribute record found in the attributes B-tree leaf chain.
fn patch_decmpfs_type(
    vol: &mut [u8],
    cat_base: usize,
    node_size: usize,
    first_leaf: u32,
    new_type: u32,
) -> bool {
    let mut node = first_leaf;
    while node != 0 {
        let node_off = node as usize * node_size + cat_base;
        if node_off + node_size > vol.len() {
            break;
        }
        let f_link;
        let num;
        {
            let nd = &vol[node_off..node_off + node_size];
            f_link = be32(nd, 0);
            num = be16(nd, 10) as usize;
        }
        for i in 0..num {
            let nd = &vol[node_off..node_off + node_size];
            let slot = node_size - 2 * (i + 1);
            let rec = be16(nd, slot) as usize;
            let r = &nd[rec..];
            if r.len() < 14 {
                continue;
            }
            let key_len = be16(r, 0) as usize;
            let name_len = be16(r, 12) as usize;
            let name_end = 14 + name_len * 2;
            if name_end > r.len() {
                continue;
            }
            let name: String = r[14..name_end]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect::<Vec<u16>>()
                .iter()
                .map(|&u| char::from_u32(u32::from(u)).unwrap_or('?'))
                .collect();
            if name != "com.apple.decmpfs" {
                continue;
            }
            let body = 2 + key_len;
            // recordType@body (u32) must be inline-data (0x10); decmpfs header
            // follows at body+16, compression_type (LE u32) at body+16+4.
            let ct_off = node_off + rec + body + 16 + 4;
            vol[ct_off..ct_off + 4].copy_from_slice(&new_type.to_le_bytes());
            return true;
        }
        node = f_link;
    }
    false
}
