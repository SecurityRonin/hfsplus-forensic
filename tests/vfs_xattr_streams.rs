//! Extended attributes must reach the VFS layer as STREAMS.
//!
//! The reader has been able to read an attribute since decmpfs shipped — but
//! only ONE, by name, for its own internal use (`decmpfs_xattr`). Nothing could
//! ask "what attributes does this file carry?", so every consumer above
//! `forensic-vfs` saw a file with none. On macOS that silently drops quarantine
//! flags, Finder metadata and `com.apple.decmpfs` itself.
//!
//! ## The oracle is macOS, not this crate
//!
//! `tests/data/xattr/hfs_xattr_volume.bin.gz` was written by macOS's own HFS+
//! driver, which also read the attributes back before the volume was detached:
//!
//! ```text
//! hdiutil create -megabytes 6 -fs HFS+ -volname HFSXATTR -layout NONE x
//! xattr -w com.example.small 'tiny-value'          file.txt
//! xattr -w user.comment      'a second attribute'  file.txt
//! xattr -w com.example.big   <6000 x 'B'>          file.txt
//! xattr -w com.example.dir   'on-a-directory'      adir
//! ```
//!
//! So the names, values and lengths asserted here are an INDEPENDENT
//! implementation's, not a fixture this crate generated to match itself.
//!
//! ## What the sizes are chosen to prove
//!
//! HFS+ stores an attribute two ways, and which one it picked is evidential —
//! it says where the bytes physically live:
//!
//! | record type | | asserted as |
//! |---|---|---|
//! | `kHFSPlusAttrInlineData` (0x10) | value sits in the B-tree record | `Resident { inline_len }` |
//! | `kHFSPlusAttrForkData` (0x20) | value is out in allocation blocks | `NonResident` |
//!
//! 10 and 18 bytes land inline; 6000 exceeds the inline ceiling and forces fork
//! storage. A reader that reported both as the same residency would be
//! describing the artifact wrongly, so the test pins each.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_vfs::{FileSystem, ResidencyKind, StreamId, StreamKind};
use std::io::Read;

/// The minted volume, decompressed. Committed gzipped: 6 MB of mostly-zero
/// volume is 7 KB compressed, and `flate2` is already a dependency.
fn volume() -> Vec<u8> {
    let gz = include_bytes!("data/xattr/hfs_xattr_volume.bin.gz");
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(&gz[..])
        .read_to_end(&mut out)
        .expect("fixture must decompress");
    out
}

fn fs() -> hfsplus_forensic::vfs::HfsFs {
    hfsplus_forensic::vfs::HfsFs::new(volume()).expect("fixture must open as HFS+")
}

/// Resolve a path from the root, so the test never hardcodes a CNID. A CNID is
/// an allocation detail of the minting run; a NAME is what the oracle used.
fn find(fs: &hfsplus_forensic::vfs::HfsFs, name: &str) -> forensic_vfs::FileId {
    let root = fs.root();
    fs.lookup(root, name.as_bytes())
        .expect("lookup must not error")
        .unwrap_or_else(|| panic!("{name} must exist in the fixture"))
}

/// Every attribute macOS wrote must be listed, under its own name.
#[test]
fn data_streams_lists_every_extended_attribute() {
    let fs = fs();
    let file = find(&fs, "file.txt");

    let streams = fs.data_streams(file).expect("data_streams must not error");

    let xattrs: Vec<(String, u64, ResidencyKind)> = streams
        .iter()
        .filter(|s| s.kind == StreamKind::Xattr)
        .map(|s| {
            (
                String::from_utf8_lossy(s.name.as_deref().unwrap_or(b"")).into_owned(),
                s.size,
                s.residency,
            )
        })
        .collect();

    // A non-zero baseline: if this filter ever yields nothing the assertions
    // below would all pass vacuously, which is how "0 carrying xattrs" once
    // reported success.
    assert_eq!(
        xattrs.len(),
        3,
        "macOS wrote 3 attributes on file.txt; got {xattrs:?}"
    );

    let by_name = |n: &str| -> (u64, ResidencyKind) {
        xattrs.iter().find(|(name, _, _)| name == n).map_or_else(
            || panic!("attribute {n} missing; got {xattrs:?}"),
            |(_, sz, r)| (*sz, *r),
        )
    };

    assert_eq!(
        by_name("com.example.small"),
        (10, ResidencyKind::Resident { inline_len: 10 }),
        "a 10-byte value is stored INLINE in the attributes B-tree record"
    );
    assert_eq!(
        by_name("user.comment"),
        (18, ResidencyKind::Resident { inline_len: 18 }),
        "an 18-byte value is stored INLINE"
    );
    assert_eq!(
        by_name("com.example.big").0,
        6000,
        "the 6000-byte value's length must survive"
    );
    assert_eq!(
        by_name("com.example.big").1,
        ResidencyKind::NonResident,
        "6000 bytes exceeds the inline ceiling, so HFS+ stored it in a fork -- \
         reporting it Resident would misdescribe where the bytes are"
    );

    // The default data stream is still reported alongside the attributes.
    assert!(
        streams.iter().any(|s| s.id == StreamId::Default),
        "the file's own contents must remain listed: {streams:?}"
    );
}

/// Listing an attribute is not reading it. Values must come back byte-exact,
/// through both storage forms.
#[test]
fn read_at_returns_attribute_values_byte_exact() {
    let fs = fs();
    let file = find(&fs, "file.txt");
    let streams = fs.data_streams(file).unwrap();

    let read = |name: &str| -> Vec<u8> {
        let s = streams
            .iter()
            .find(|s| s.kind == StreamKind::Xattr && s.name.as_deref() == Some(name.as_bytes()))
            .unwrap_or_else(|| panic!("no attribute {name}"));
        let mut buf = vec![0u8; usize::try_from(s.size).unwrap()];
        let n = fs
            .read_at(file, s.id, 0, &mut buf)
            .unwrap_or_else(|e| panic!("read_at({name}) failed: {e:?}"));
        buf.truncate(n);
        buf
    };

    assert_eq!(read("com.example.small"), b"tiny-value");
    assert_eq!(read("user.comment"), b"a second attribute");
    // Byte-exact over the whole 6000, not a length check: a fork-stored value
    // is assembled from allocation blocks, so a wrong extent walk yields the
    // right LENGTH and the wrong bytes.
    assert_eq!(read("com.example.big"), vec![b'B'; 6000]);
}

/// Attributes live on directories too, and a reader that only walked file
/// records would miss them.
#[test]
fn directories_carry_attributes_as_well() {
    let fs = fs();
    let dir = find(&fs, "adir");
    let streams = fs.data_streams(dir).expect("data_streams on a dir");

    let x: Vec<_> = streams
        .iter()
        .filter(|s| s.kind == StreamKind::Xattr)
        .collect();
    assert_eq!(x.len(), 1, "adir carries exactly one attribute: {x:?}");
    assert_eq!(x[0].name.as_deref(), Some(&b"com.example.dir"[..]));

    let mut buf = vec![0u8; 64];
    let n = fs
        .read_at(dir, x[0].id, 0, &mut buf)
        .expect("read dir xattr");
    assert_eq!(&buf[..n], b"on-a-directory");
}
