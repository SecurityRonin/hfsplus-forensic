//! The extended-attribute library API, below the VFS adapter: what it returns
//! for absence, and what it returns for damage the VFS path reaches only
//! through `list_xattrs` first.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use hfsplus_core::{list_xattrs, read_xattr, HfsXattrError};
use std::io::Read;

fn volume() -> Vec<u8> {
    let gz = include_bytes!("../../tests/data/xattr/hfs_xattr_volume.bin.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn be16(b: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([b[0], b[1]]))
}

fn be32(b: &[u8]) -> usize {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
}

/// file.txt's CNID, read from the intact catalog by name.
fn file_cnid(v: &[u8]) -> u32 {
    hfsplus_core::list_root(v)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "file.txt")
        .unwrap()
        .cnid
}

/// Offset of the key of the attribute named `name` (its UTF-16BE name occurs
/// once in the volume; the key header is the 14 bytes before it).
fn key_of(v: &[u8], name: &str) -> usize {
    let needle: Vec<u8> = name.encode_utf16().flat_map(u16::to_be_bytes).collect();
    let hits: Vec<usize> = v
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "{name}: {hits:?}");
    hits[0] - 14
}

/// The attributes B-tree's first leaf node offset and node size.
fn first_leaf(v: &[u8]) -> (usize, usize) {
    let bs = be32(&v[1024 + 40..]);
    let hdr = be32(&v[1024 + 352 + 16..]) * bs + 14;
    let node_size = be16(&v[hdr + 18..]);
    (hdr - 14 + be32(&v[hdr + 10..]) * node_size, node_size)
}

#[test]
fn reading_values_through_the_library_matches_what_macos_wrote() {
    let v = volume();
    let cnid = file_cnid(&v);
    assert_eq!(list_xattrs(&v, cnid).unwrap().len(), 3);
    assert_eq!(
        read_xattr(&v, cnid, "com.example.small")
            .unwrap()
            .as_deref(),
        Some(&b"tiny-value"[..])
    );
    assert_eq!(
        read_xattr(&v, cnid, "com.example.big").unwrap(),
        Some(vec![b'B'; 6000])
    );
    assert_eq!(read_xattr(&v, cnid, "com.example.absent").unwrap(), None);
}

/// A volume whose header declares no attributes file has no attributes. That
/// is absence, and the only absence this API reports as `Ok` empty.
#[test]
fn no_attributes_file_is_an_empty_answer_not_an_error() {
    let mut v = volume();
    let cnid = file_cnid(&v);
    v[1024 + 352 + 12..1024 + 352 + 16].fill(0); // attributesFile.totalBlocks
    assert_eq!(list_xattrs(&v, cnid).unwrap(), vec![]);
    assert_eq!(read_xattr(&v, cnid, "com.example.small").unwrap(), None);
}

#[test]
fn a_buffer_ending_before_the_attributes_fork_is_an_error() {
    let err = list_xattrs(&[0u8; 100], 2).unwrap_err();
    assert!(
        matches!(err, HfsXattrError::AttributesBtree { .. }),
        "{err:?}"
    );
    assert!(err.to_string().contains("100-byte volume ends"), "{err}");
}

#[test]
fn read_xattr_reports_an_unknown_record_type_too() {
    let mut v = volume();
    let cnid = file_cnid(&v);
    let key = key_of(&v, "com.example.small");
    let body = key + 2 + be16(&v[key..]);
    v[body..body + 4].copy_from_slice(&0x0000_0077u32.to_be_bytes());
    let err = read_xattr(&v, cnid, "com.example.small").unwrap_err();
    assert!(err.to_string().contains("0x00000077"), "{err}");
}

#[test]
fn a_name_running_past_its_record_is_an_error() {
    let mut v = volume();
    let cnid = file_cnid(&v);
    let key = key_of(&v, "com.example.small");
    v[key + 12..key + 14].copy_from_slice(&0xFFFFu16.to_be_bytes()); // attrNameLen
    let err = list_xattrs(&v, cnid).unwrap_err();
    assert!(err.to_string().contains("65535-character name"), "{err}");
}

#[test]
fn a_key_length_putting_the_body_past_the_record_is_an_error() {
    let mut v = volume();
    let cnid = file_cnid(&v);
    let key = key_of(&v, "com.example.small");
    v[key..key + 2].copy_from_slice(&0xFFF0u16.to_be_bytes()); // keyLength
    let err = list_xattrs(&v, cnid).unwrap_err();
    assert!(
        matches!(&err, HfsXattrError::Record { name: Some(n), .. } if n == "com.example.small"),
        "{err:?}"
    );
}

/// A record offset 10 bytes from the node end leaves a 10-byte record: too
/// short to say whose it is, so it cannot be skipped as another file's.
#[test]
fn a_record_too_short_for_its_key_is_an_error_without_a_name() {
    let mut v = volume();
    let cnid = file_cnid(&v);
    let (leaf, node_size) = first_leaf(&v);
    let slot0 = leaf + node_size - 2;
    let off = u16::try_from(node_size - 10).unwrap();
    v[slot0..slot0 + 2].copy_from_slice(&off.to_be_bytes());
    let err = list_xattrs(&v, cnid).unwrap_err();
    assert!(
        matches!(&err, HfsXattrError::Record { name: None, .. }),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("attribute record: a 10-byte record"),
        "{err}"
    );
}

#[test]
fn the_vfs_refuses_an_attribute_index_it_never_listed_and_reads_nothing_past_the_end() {
    use forensic_vfs::{FileSystem, StreamId, VfsError};
    let fs = hfsplus_core::vfs::HfsFs::new(volume()).unwrap();
    let file = fs.lookup(fs.root(), b"file.txt").unwrap().unwrap();
    let mut buf = [0u8; 16];
    let err = fs
        .read_at(file, StreamId::Xattr(3), 0, &mut buf)
        .unwrap_err();
    assert!(
        matches!(&err, VfsError::Unsupported { scheme, .. } if scheme.starts_with("attribute 3 of 3 on CNID")),
        "{err:?}"
    );
    // com.example.small is 10 bytes; a read from offset 10 is the end, not an error.
    let small = fs
        .data_streams(file)
        .unwrap()
        .into_iter()
        .find(|s| s.name.as_deref() == Some(&b"com.example.small"[..]))
        .unwrap();
    assert_eq!(fs.read_at(file, small.id, 10, &mut buf).unwrap(), 0);
}
