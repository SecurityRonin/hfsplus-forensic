//! `impl FileSystem for HfsFs`, driven as `Arc<dyn FileSystem>` over the REAL
//! `hdiutil`-created `hfs_plus_volume.bin` (doer-checker).
//!
//! Every asserted value is what **The Sleuth Kit** reports independently of this
//! crate — the tool is the oracle, not our own reader:
//!
//! ```text
//! $ fls   -f hfs hfs_plus_volume.bin      # root (CNID 2) → HELLO.TXT=18, READ.ME=20, SUBDIR=19(dir)
//! $ istat -f hfs hfs_plus_volume.bin 18   # HELLO.TXT: data-fork size 9
//! $ icat  -f hfs hfs_plus_volume.bin 18   # "hello hfs"
//! $ istat -f hfs hfs_plus_volume.bin 19   # SUBDIR: directory
//! ```

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use forensic_vfs::{FileId, FileSystem, FsKind, NodeKind, StreamId, TimeZonePolicy};
use hfsplus_forensic::vfs::HfsFs;

/// The committed real HFS+ volume (header at offset 1024, HELLO.TXT/READ.ME/SUBDIR).
fn volume_bytes() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hfs_plus_volume.bin"
    ))
    .unwrap()
}

/// Open the real volume as an `Arc<dyn FileSystem>` — proving `HfsFs` composes
/// object-safely.
fn open_real_volume() -> Arc<dyn FileSystem> {
    Arc::new(HfsFs::new(volume_bytes()).expect("open HFS+ volume"))
}

#[test]
fn identity_and_root() {
    let fs = open_real_volume();
    assert_eq!(fs.kind(), FsKind::HfsPlus);
    assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
    // The HFS+ root folder is CNID 2, addressed as an opaque inode.
    assert_eq!(fs.root(), FileId::Opaque(2));
    // block_size of this volume is 4096 (from the volume header).
    assert_eq!(fs.sector_sizes().cluster_or_block, 4096);
}

#[test]
fn new_rejects_non_hfs_buffer() {
    // A bootstrap failure is loud, never a silent empty filesystem.
    assert!(HfsFs::new(vec![0u8; 4096]).is_err());
}

#[test]
fn read_dir_lists_real_root_entries() {
    let fs = open_real_volume();
    let entries: Vec<_> = fs
        .read_dir(fs.root())
        .unwrap()
        .map(Result::unwrap)
        .collect();

    // fls: HELLO.TXT is CNID 18, a regular file.
    let hello = entries
        .iter()
        .find(|e| e.name == b"HELLO.TXT")
        .expect("HELLO.TXT in root");
    assert_eq!(hello.id, FileId::Opaque(18));
    assert_eq!(hello.kind, NodeKind::File);

    // fls: SUBDIR is CNID 19, a directory.
    let subdir = entries
        .iter()
        .find(|e| e.name == b"SUBDIR")
        .expect("SUBDIR in root");
    assert_eq!(subdir.id, FileId::Opaque(19));
    assert_eq!(subdir.kind, NodeKind::Dir);
}

#[test]
fn lookup_finds_a_known_file() {
    let fs = open_real_volume();
    assert_eq!(
        fs.lookup(fs.root(), b"HELLO.TXT").unwrap(),
        Some(FileId::Opaque(18))
    );
    assert_eq!(fs.lookup(fs.root(), b"no-such-file").unwrap(), None);
}

#[test]
fn meta_matches_istat() {
    let fs = open_real_volume();
    let m = fs.meta(FileId::Opaque(18)).unwrap();
    assert_eq!(m.ino, 18);
    assert_eq!(m.kind, NodeKind::File);
    // istat: HELLO.TXT data-fork size 9.
    assert_eq!(m.size, 9);
    // The three HFS+ MAC times are present (born/modified/accessed).
    assert!(m.times.born.is_some());
    assert!(m.times.modified.is_some());
    assert!(m.times.accessed.is_some());

    // SUBDIR (CNID 19) is a directory with size 0.
    let d = fs.meta(FileId::Opaque(19)).unwrap();
    assert_eq!(d.kind, NodeKind::Dir);
    assert_eq!(d.size, 0);
}

#[test]
fn read_at_returns_file_bytes() {
    let fs = open_real_volume();
    let id = FileId::Opaque(18);

    // icat: HELLO.TXT is 9 bytes, "hello hfs".
    let mut buf = [0u8; 64];
    let n = fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
    assert_eq!(n, 9);
    assert_eq!(&buf[..9], b"hello hfs");

    // A non-zero offset returns the windowed suffix.
    let mut win = [0u8; 4];
    let n = fs.read_at(id, StreamId::Default, 6, &mut win).unwrap();
    assert_eq!(&win[..n], b"hfs");

    // Reading past the end yields zero bytes, not an error.
    assert_eq!(
        fs.read_at(id, StreamId::Default, 10_000, &mut buf).unwrap(),
        0
    );
}

#[test]
fn read_dir_of_empty_subdir_is_empty() {
    let fs = open_real_volume();
    let children: Vec<_> = fs
        .read_dir(FileId::Opaque(19))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(children.is_empty(), "SUBDIR is empty, got {children:?}");
}

#[test]
fn unsupported_file_id_variant_is_loud() {
    let fs = open_real_volume();
    // An NTFS-style id addresses a different filesystem — refused, never guessed.
    assert!(fs.meta(FileId::NtfsRef { entry: 5, seq: 5 }).is_err());
}

#[test]
fn cnid_beyond_u32_is_out_of_range() {
    let fs = open_real_volume();
    // An opaque id that cannot be a 32-bit CNID is rejected, never truncated.
    assert!(fs.meta(FileId::Opaque(u64::from(u32::MAX) + 1)).is_err());
}

#[test]
fn read_at_named_stream_is_unsupported() {
    let fs = open_real_volume();
    // HFS+ resource/named streams are not wired through read_at yet — loud.
    let mut buf = [0u8; 8];
    assert!(fs
        .read_at(FileId::Opaque(18), StreamId::Named(1), 0, &mut buf)
        .is_err());
}

#[test]
fn meta_of_unknown_cnid_is_loud() {
    let fs = open_real_volume();
    // No catalog record for this CNID — a Decode error, never a fabricated node.
    assert!(fs.meta(FileId::Opaque(999_999)).is_err());
}

#[test]
fn read_at_of_a_directory_is_loud() {
    let fs = open_real_volume();
    // SUBDIR (CNID 19) has no data fork; read_file returns None → Decode error.
    let mut buf = [0u8; 8];
    assert!(fs
        .read_at(FileId::Opaque(19), StreamId::Default, 0, &mut buf)
        .is_err());
}

#[test]
fn forensic_surface_defaults_are_empty() {
    let fs = open_real_volume();
    // extents/deleted/unallocated are follow-ups: empty streams, not errors.
    assert_eq!(
        fs.extents(FileId::Opaque(18), StreamId::Default)
            .unwrap()
            .count(),
        0
    );
    assert_eq!(fs.deleted().unwrap().count(), 0);
    assert_eq!(fs.unallocated().unwrap().count(), 0);
    // A node with no reparse target reads as an empty link.
    assert!(fs.read_link(FileId::Opaque(18), 4096).unwrap().is_empty());
}
