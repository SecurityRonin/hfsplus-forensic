#![no_main]
//! Recursive catalog B-tree traversal — the highest-level entry point. Reaches
//! header geometry, B-tree node walking (`for_each_record`), fork parsing, and
//! UTF-16 name decode over one arbitrary buffer. Must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hfsplus_forensic::walk(data);
    // list_root shares the catalog walk but a distinct top-level entry.
    let _ = hfsplus_forensic::list_root(data);
});
