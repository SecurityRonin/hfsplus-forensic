// HFS+ reader tests, validated against REAL `hdiutil`-created volumes:
//   tests/data/hfs_plus_header.bin  — first 2 KiB of an HFS+ volume (header)
//   tests/data/hfs_plus_volume.bin  — a small layout-NONE HFS+ volume with
//                                     HELLO.TXT, READ.ME, and a SUBDIR folder.

use hfsplus_forensic::{self as hfs, HfsKind};

fn header() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hfs_plus_header.bin"
    ))
    .unwrap()
}

fn volume() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hfs_plus_volume.bin"
    ))
    .unwrap()
}

#[test]
fn parses_real_volume_header() {
    let vol = hfs::parse(&header()).expect("parse real HFS+ header");
    assert_eq!(vol.kind, HfsKind::HfsPlus);
    assert_eq!(vol.version, 4);
    assert_eq!(vol.block_size, 4096);
    assert_eq!(vol.total_blocks, 512);
    assert_eq!(vol.volume_size(), 2 * 1024 * 1024);
}

#[test]
fn non_hfs_buffer_is_none() {
    assert!(hfs::parse(&[0u8; 2048]).is_none());
    assert!(hfs::parse(&[0u8; 100]).is_none());
}

#[test]
fn lists_real_root_directory() {
    let entries = hfs::list_root(&volume()).expect("list HFS+ root");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"HELLO.TXT"), "entries: {names:?}");
    assert!(names.contains(&"READ.ME"), "entries: {names:?}");
    assert!(names.contains(&"SUBDIR"), "entries: {names:?}");
    assert!(
        !entries
            .iter()
            .find(|e| e.name == "HELLO.TXT")
            .unwrap()
            .is_dir
    );
    assert!(entries.iter().find(|e| e.name == "SUBDIR").unwrap().is_dir);
}

#[test]
fn list_root_none_for_non_hfs() {
    assert!(hfs::list_root(&[0u8; 4096]).is_none());
}

#[test]
fn reads_real_file_contents() {
    let vol = volume();
    let hello = hfs::list_root(&vol)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "HELLO.TXT")
        .unwrap();
    assert_eq!(hfs::read_file(&vol, hello.cnid).unwrap(), b"hello hfs");
}

#[test]
fn list_dir_of_empty_subdir_is_empty() {
    let vol = volume();
    let sub = hfs::list_root(&vol)
        .unwrap()
        .into_iter()
        .find(|e| e.name == "SUBDIR")
        .unwrap();
    assert!(hfs::list_dir(&vol, sub.cnid).unwrap().is_empty());
}

#[test]
fn read_file_unknown_cnid_is_none() {
    assert!(hfs::read_file(&volume(), 999_999).is_none());
}

#[test]
fn stat_returns_size_kind_and_times() {
    let vol = volume();
    // HELLO.TXT (CNID 18) is a 9-byte file.
    let s = hfs::stat(&vol, 18).expect("stat HELLO.TXT");
    assert_eq!(s.cnid, 18);
    assert!(!s.is_dir);
    assert_eq!(s.size, 9);
    // A real hdiutil volume stamps non-zero MAC times.
    assert!(s.created != 0 && s.modified != 0);
    // SUBDIR (CNID 19) is a folder with no data fork.
    let d = hfs::stat(&vol, 19).expect("stat SUBDIR");
    assert!(d.is_dir);
    assert_eq!(d.size, 0);
    // An unknown CNID has no record.
    assert!(hfs::stat(&vol, 999_999).is_none());
}

fn nested() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/hfs_plus_nested.bin"
    ))
    .unwrap()
}

#[test]
fn walk_lists_nested_paths() {
    let vol = nested();
    let entries = hfs::walk(&vol).expect("walk HFS+ volume");
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"TOP.TXT"), "paths: {paths:?}");
    assert!(paths.contains(&"SUB"), "paths: {paths:?}");
    assert!(paths.contains(&"SUB/NESTED.TXT"), "paths: {paths:?}");
    let nested_file = entries.iter().find(|e| e.path == "SUB/NESTED.TXT").unwrap();
    assert!(!nested_file.is_dir);
    assert_eq!(
        hfs::read_file(&vol, nested_file.cnid).unwrap(),
        b"nested data"
    );
}
