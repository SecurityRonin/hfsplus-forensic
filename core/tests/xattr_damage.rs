//! A damaged attributes B-tree must surface as an error, never as "this file
//! has fewer attributes" (ADR-0020).
//!
//! Each test takes the macOS-written volume from `vfs_xattr_streams.rs`, damages
//! exactly one structure, and asks for `file.txt`'s streams. The intact volume
//! lists three attributes on that file (pinned there), so a listing that comes
//! back `Ok` with fewer has turned damage into absence: the examiner reads "no
//! such attribute" where the image says "unreadable".

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_vfs::{FileSystem, StreamKind, VfsError};
use std::io::Read;

fn volume() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/xattr/hfs_xattr_volume.bin.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("fixture must decompress");
    out
}

fn be16(b: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([b[0], b[1]]))
}

fn be32(b: &[u8]) -> usize {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
}

/// Byte offset of the attributes B-tree's header record (node 0, past its
/// 14-byte node descriptor), read from the volume header: the attributes
/// file's `HFSPlusForkData` is at 1024 + 352, its first extent's startBlock 16
/// bytes into that, and the allocation block size at 1024 + 40.
fn attributes_header(v: &[u8]) -> usize {
    let block_size = be32(&v[1024 + 40..]);
    let start_block = be32(&v[1024 + 352 + 16..]);
    start_block * block_size + 14
}

/// Offset of the record BODY (its 4-byte recordType) of the attribute named
/// `name`. The name is located by its UTF-16BE bytes, which must occur exactly
/// once in the volume, so the damage lands on the record the test means.
fn record_body(v: &[u8], name: &str) -> usize {
    let needle: Vec<u8> = name.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let hits: Vec<usize> = v
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{name} must occur once in the volume: {hits:?}"
    );
    // HFSPlusAttrKey: keyLength(2) pad(2) fileID(4) startBlock(4) nameLen(2) name.
    let key = hits[0] - 14;
    key + 2 + be16(&v[key..])
}

/// Open the damaged volume and list `file.txt`'s streams.
fn streams_of_file(v: Vec<u8>) -> Result<Vec<forensic_vfs::StreamInfo>, VfsError> {
    let fs = hfsplus_core::vfs::HfsFs::new(v).expect("the volume header is intact");
    let file = fs
        .lookup(fs.root(), b"file.txt")
        .expect("the catalog is intact")
        .expect("file.txt exists");
    fs.data_streams(file)
}

fn xattr_count(streams: &[forensic_vfs::StreamInfo]) -> usize {
    streams
        .iter()
        .filter(|s| s.kind == StreamKind::Xattr)
        .count()
}

/// Control: the helpers find the real structures. Without it, a test below
/// could pass because the damage landed somewhere harmless.
#[test]
fn the_intact_volume_lists_three_attributes_and_the_offsets_are_real() {
    let v = volume();
    assert_eq!(xattr_count(&streams_of_file(v.clone()).unwrap()), 3);
    let body = record_body(&v, "com.example.small");
    assert_eq!(
        be32(&v[body..]),
        0x10,
        "an inline-data record (kHFSPlusAttrInlineData)"
    );
    let hdr = attributes_header(&v);
    assert!(be16(&v[hdr + 18..]) >= 512, "a plausible B-tree node size");
}

/// A record type this reader does not know is not "no attribute". The error
/// must name the attribute and show the value it could not interpret.
#[test]
fn an_unknown_record_type_is_an_error_naming_the_value() {
    let mut v = volume();
    let body = record_body(&v, "com.example.small");
    v[body..body + 4].copy_from_slice(&0x0000_0099u32.to_be_bytes());
    let err = streams_of_file(v).expect_err("an uninterpretable record must not be dropped");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("com.example.small"),
        "names the attribute: {msg}"
    );
    assert!(msg.contains("0x00000099"), "shows the record type: {msg}");
}

/// An inline record whose declared size runs past its own record is damaged,
/// not absent.
#[test]
fn an_inline_value_overrunning_its_record_is_an_error() {
    let mut v = volume();
    let body = record_body(&v, "com.example.small");
    // HFSPlusAttrData: recordType@0 reserved[2]@4 attrSize@12 attrData@16.
    v[body + 12..body + 16].copy_from_slice(&0xFFFFu32.to_be_bytes());
    let err = streams_of_file(v).expect_err("an overrunning value must not be dropped");
    assert!(format!("{err:?}").contains("com.example.small"), "{err:?}");
}

/// The volume header declares an attributes file, but its B-tree header is
/// unusable. That is not the same as a volume with no attributes file.
#[test]
fn an_unreadable_attributes_btree_header_is_an_error() {
    let mut v = volume();
    let hdr = attributes_header(&v);
    v[hdr + 18..hdr + 20].copy_from_slice(&0u16.to_be_bytes()); // nodeSize = 0
    streams_of_file(v)
        .expect_err("a declared but unreadable attributes B-tree must not read as empty");
}

/// A leaf-chain link pointing outside the volume ends the walk early. The
/// attributes it would have reached are unknown, not absent.
#[test]
fn a_leaf_link_past_the_volume_end_is_an_error() {
    let mut v = volume();
    let hdr = attributes_header(&v);
    // BTHeaderRec: treeDepth(2) rootNode(4) leafRecords(4) firstLeafNode@10.
    v[hdr + 10..hdr + 14].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
    streams_of_file(v).expect_err("an out-of-volume leaf node must not read as no attributes");
}

/// A fork-stored value whose extents cover less than its declared length must
/// not be served short as if complete. HFS+ continues a long extent list in
/// `kHFSPlusAttrExtents` records; bytes this reader did not assemble are
/// unread, not absent.
#[test]
fn a_fork_value_its_extents_do_not_cover_is_an_error_not_a_short_read() {
    let mut v = volume();
    let body = record_body(&v, "com.example.big");
    // HFSPlusAttrForkData: recordType(4) reserved(4) theFork: logicalSize(8)@8.
    assert_eq!(
        be32(&v[body..]),
        0x20,
        "a fork-data record (kHFSPlusAttrForkData)"
    );
    v[body + 8..body + 16].copy_from_slice(&600_000u64.to_be_bytes());
    let fs = hfsplus_core::vfs::HfsFs::new(v).unwrap();
    let file = fs.lookup(fs.root(), b"file.txt").unwrap().unwrap();
    let s = fs
        .data_streams(file)
        .unwrap()
        .into_iter()
        .find(|s| s.name.as_deref() == Some(&b"com.example.big"[..]))
        .unwrap();
    assert_eq!(
        s.size, 600_000,
        "the declared length is what the record says"
    );
    let mut buf = vec![0u8; 600_000];
    let got = fs.read_at(file, s.id, 0, &mut buf);
    assert!(
        got.is_err(),
        "extents cover far less than 600000 bytes; got {got:?}"
    );
}

/// Byte offset of the attributes B-tree's first leaf node, and its node size.
fn first_leaf(v: &[u8]) -> (usize, usize, usize) {
    let hdr = attributes_header(v);
    let base = hdr - 14;
    let leaf = be32(&v[hdr + 10..]);
    let node_size = be16(&v[hdr + 18..]);
    (base + leaf * node_size, node_size, leaf)
}

/// A node claiming more records than it has room for offsets has a corrupt
/// descriptor; what it holds cannot be enumerated with confidence.
#[test]
fn a_leaf_declaring_more_records_than_fit_is_an_error() {
    let mut v = volume();
    let (leaf, _, _) = first_leaf(&v);
    // BTNodeDescriptor: fLink(4) bLink(4) kind(1) height(1) numRecords@10.
    assert!(be16(&v[leaf + 10..]) > 0, "the first leaf holds records");
    v[leaf + 10..leaf + 12].copy_from_slice(&0xFFFFu16.to_be_bytes());
    streams_of_file(v).expect_err("an impossible record count must not be walked quietly");
}

/// A record offset pointing past its node skips a record that exists.
#[test]
fn a_record_offset_past_its_node_is_an_error() {
    let mut v = volume();
    let (leaf, node_size, _) = first_leaf(&v);
    // Record offsets are stored backwards from the node end; slot 0 is last.
    let slot0 = leaf + node_size - 2;
    v[slot0..slot0 + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    streams_of_file(v).expect_err("a record the walk had to skip must not read as absent");
}

/// A leaf whose forward link points to itself would list its records again
/// and again. The walk stops at its cap; that must be reported, not returned
/// as a listing.
#[test]
fn a_looping_leaf_chain_is_an_error() {
    let mut v = volume();
    let (leaf, _, leaf_no) = first_leaf(&v);
    v[leaf..leaf + 4].copy_from_slice(&u32::try_from(leaf_no).unwrap().to_be_bytes());
    streams_of_file(v).expect_err("a looping chain must not yield a listing");
}
