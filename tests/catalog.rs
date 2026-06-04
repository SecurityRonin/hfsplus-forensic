// HFS+ reader tests, validated against REAL `hdiutil`-created volumes:
//   tests/data/hfs_plus_header.bin  — first 2 KiB of an HFS+ volume (header)
//   tests/data/hfs_plus_volume.bin  — a small layout-NONE HFS+ volume with
//                                     HELLO.TXT, READ.ME, and a SUBDIR folder.

use hfsplus_forensic::{self as hfs, HfsKind};

fn header() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfs_plus_header.bin")).unwrap()
}

fn volume() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/hfs_plus_volume.bin")).unwrap()
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
    assert!(!entries.iter().find(|e| e.name == "HELLO.TXT").unwrap().is_dir);
    assert!(entries.iter().find(|e| e.name == "SUBDIR").unwrap().is_dir);
}

#[test]
fn list_root_none_for_non_hfs() {
    assert!(hfs::list_root(&[0u8; 4096]).is_none());
}

#[test]
fn reads_real_file_contents() {
    let vol = volume();
    let hello = hfs::list_root(&vol).unwrap().into_iter().find(|e| e.name == "HELLO.TXT").unwrap();
    assert_eq!(hfs::read_file(&vol, hello.cnid).unwrap(), b"hello hfs");
}

#[test]
fn list_dir_of_empty_subdir_is_empty() {
    let vol = volume();
    let sub = hfs::list_root(&vol).unwrap().into_iter().find(|e| e.name == "SUBDIR").unwrap();
    assert!(hfs::list_dir(&vol, sub.cnid).unwrap().is_empty());
}

#[test]
fn read_file_unknown_cnid_is_none() {
    assert!(hfs::read_file(&volume(), 999_999).is_none());
}
