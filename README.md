[![Crates.io](https://img.shields.io/crates/v/hfsplus-forensic.svg)](https://crates.io/crates/hfsplus-forensic)
[![docs.rs](https://img.shields.io/docsrs/hfsplus-forensic)](https://docs.rs/hfsplus-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/hfsplus-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/hfsplus-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure-Rust forensic Apple HFS+/HFSX reader — volume-header geometry, catalog B-tree directory listing, and data-fork file extraction from a byte buffer.**

Built for parsing the HFS/HFS+ side of Apple hybrid optical discs and HFS+ volumes, with no `unsafe` and no allocations beyond the data it returns.

## Install

```toml
[dependencies]
hfsplus-forensic = "0.1"
```

## Quick start

```rust
// `volume` is the whole HFS+ volume (its header is at offset 1024).
let volume: Vec<u8> = std::fs::read("hfsplus.img")?;

if let Some(v) = hfsplus_forensic::parse(&volume) {
    println!("{:?}  {} blocks x {} bytes", v.kind, v.total_blocks, v.block_size);

    for e in hfsplus_forensic::list_root(&volume).unwrap_or_default() {
        println!("  {}  {}", if e.is_dir { "dir " } else { "file" }, e.name);
        if !e.is_dir {
            let bytes = hfsplus_forensic::read_file(&volume, e.cnid);
            println!("    {} bytes", bytes.map(|b| b.len()).unwrap_or(0));
        }
    }
}
```

## What it parses

| Capability | Notes |
|---|---|
| Volume header | `H+` / `HX` signature, version, allocation block size, block counts |
| Root + directory listing | catalog B-tree leaf walk; `list_dir(parent_cnid)` for any folder |
| File extraction | data-fork extents, truncated to the logical size |

Geometry and listing only; on-disk journal replay and resource-fork specifics are out of scope.

## Validation

Every capability is checked against **real Apple-produced bytes**, not hand-built fixtures. The HFS+ reader (header geometry, catalog listing, data-fork extraction) runs against **real `hdiutil`-created volumes**. The `decmpfs` transparent-compression codecs are validated against **real `ditto --hfsCompression` / `afsctool` forks** — and on a clean **macOS 26.5 (Tahoe)** system, with Apple's own `compression_decode_buffer` as the answer key — so LZVN, zlib, and LZFSE are each decoded and matched against the original pre-compression file.

Full oracle-by-oracle, corpus-by-corpus evidence (and the honest gaps — the HFS+ reader is not yet cross-checked against The Sleuth Kit): [securityronin.github.io/hfsplus-forensic/validation](https://securityronin.github.io/hfsplus-forensic/validation/).

## Related

Part of the [Security Ronin](https://github.com/SecurityRonin) forensic toolkit. Sibling filesystem readers: [`ext4fs-forensic`](https://github.com/SecurityRonin/ext4fs-forensic), [`ntfs-forensic`](https://github.com/SecurityRonin/ntfs-forensic), [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic); partition maps: [`apm-forensic`](https://github.com/SecurityRonin/apm-forensic), [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic), [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic). Consumed by [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) for Apple hybrid discs.

---

[Privacy Policy](https://securityronin.github.io/hfsplus-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/hfsplus-forensic/terms/) · © 2026 Security Ronin Ltd
