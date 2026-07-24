# hfsplus-forensic — Purpose & Scope (DESIGN)

*A library design note, not a PRD: `hfsplus-forensic` ships no binary an examiner
runs — it is a Rust filesystem-reader crate consumed by other fleet tools. Every
current-state claim below is grounded in a same-session read of `src/`,
`Cargo.toml`, and the git history (2026-07-24). The load-bearing decisions live as
ADRs [0001](decisions/0001-single-crate-reader-and-analyzer.md)–[0008](decisions/0008-low-msrv-floor-vs-pinned-toolchain.md)
under [`docs/decisions/`](decisions/); the real-artifact evidence lives in
[`validation.md`](validation.md).*

## Purpose

Read Apple **HFS+ / HFSX** volumes from a byte buffer, forensically: recover volume
geometry, list the catalog tree, extract file contents (including transparently
`decmpfs`-compressed files), and grade structural anomalies — with no `unsafe`,
no panics on malformed input, and no dependency on any particular container or
disk-image format.

The crate exists because Apple optical discs are frequently **hybrids** — an ISO
9660 filesystem and an HFS/HFS+ volume sharing one disc — and because HFS+ volumes
appear inside seized disk images. It was extracted from `iso9660-forensic` (commit
`424d57a`) so the HFS+ parser lives as a standalone sibling to `ext4fs-forensic`
and `ntfs-forensic`.

## Where it sits in the fleet

FILESYSTEM layer (ronin-issen `CLAUDE.md`, "Multi-Repo Architecture"): it navigates
a byte source by path — name → catalog node → extents → file bytes. It depends
**down** only on the `forensicnomicon` KNOWLEDGE leaf (format constants + the
`report` vocabulary; ADR 0002) and pure-Rust codec crates (ADR 0003), plus the
`forensic-vfs` contract behind an optional feature (ADR 0007). It is linked, never
run directly:

- `iso9660-forensic` reads the HFS+ side of Apple hybrid discs through it.
- `disk-forensic` / `forensic-vfs` stacks mount it as a `FileSystem` (feature `vfs`).

## What it does (grounded in `src/`)

| Capability | Public API | Source |
|---|---|---|
| Volume-header geometry (`H+`/`HX`, version, block size/counts) | `parse` | `src/lib.rs` |
| Directory listing (catalog B-tree leaf walk) | `list_root`, `list_dir`, recursive `walk` | `src/lib.rs` |
| File extraction (data-fork extents, truncated to logical size) | `read_file` | `src/lib.rs` |
| Transparent `decmpfs` decompression (zlib / LZVN / LZFSE, inline + resource fork) | folded into `read_file` | `src/decmpfs.rs` (ADR 0004) |
| Per-node metadata | `stat` → `HfsStat` | `src/lib.rs` |
| Graded anomaly analysis (`HFS-*` findings) | `findings::audit` → `Anomaly: Observation` | `src/findings.rs` (ADR 0001) |
| Mountable filesystem (optional) | `impl FileSystem for HfsFs` | `src/vfs.rs`, feature `vfs` (ADR 0007) |

`decmpfs` codes covered: inline/verbatim (types 1/9), zlib (3/4), LZVN (7/8), LZFSE
(11/12). Anomaly codes include `HFS-BTREE-NODE-INVALID`,
`HFS-CATALOG-EXTENTS-MISMATCH`, `HFS-DELETED-BUT-REFERENCED`, `HFS-TIME-ANOMALY`,
`HFS-DECMPFS-MISSING-RESOURCE` (commit `730ae4f`).

## Scope

- Volume-header geometry, catalog B-tree navigation, data-fork extraction.
- Extents-overflow B-tree lookup for fragmented forks.
- Transparent `decmpfs` decompression as part of the default read path.
- Graded, observation-only (`consistent with …`, never verdict) anomaly findings.
- An optional read-only `forensic-vfs` `FileSystem` adapter.

## Non-goals

- **On-disk journal replay** — out of scope (`src/lib.rs` module doc; README).
- **Write / repair** — the reader is immutable and slice-based; evidence is never
  modified (ADR 0005).
- **Container/image decoding** — the crate takes an already-addressable volume
  `&[u8]`; opening E01/VMDK/raw is the abstraction layer's job (`disk-forensic` /
  `forensic-vfs`), never this reader's.
- **Classic HFS (non-plus) beyond hybrid-disc geometry** — the focus is HFS+/HFSX.
- **`LZBitmap` and the de-dup generation store (type 5)** — surfaced as a loud
  `DecmpfsError::Unsupported`, not silently mis-decoded (`src/decmpfs.rs`).

## Validation approach

Correctness is proven against **real Apple-produced bytes**, not self-authored
round-trips (the fleet Doer-Checker / Evidence-Based Rigor bar). The reader runs
against real `hdiutil`-created HFS+ volumes; the `decmpfs` codecs against real
`ditto --hfsCompression` / `afsctool` forks, and on macOS 26.5 (Tahoe) against
Apple's own `compression_decode_buffer` as the answer key (35/35 LZVN samples).
The analyzer's true-negative baseline is checked with The Sleuth Kit
(`fsstat`/`istat`/`fls`) as an independent oracle. Robustness is checked by a
`cargo-fuzz` target per parsed structure (ADR 0006). Full oracle-by-oracle,
corpus-by-corpus evidence — and the honest gaps (the HFS+ reader is not yet
cross-checked against TSK on every path) — are in
[`validation.md`](validation.md).
