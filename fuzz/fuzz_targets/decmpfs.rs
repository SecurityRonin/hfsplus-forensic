#![no_main]
//! decmpfs transparent-compression decode (zlib / LZVN / LZFSE, inline xattr or
//! resource fork). The leading byte selects where the xattr ends and the
//! optional resource fork begins, so the fuzzer can drive both storage paths.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    let split = (sel as usize).min(body.len());
    let (xattr, rest) = body.split_at(split);
    let resource = (!rest.is_empty()).then_some(rest);
    let _ = hfsplus_forensic::decmpfs::decompress(xattr, resource);
});
