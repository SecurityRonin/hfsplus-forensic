# Validation

`hfsplus-forensic` parses untrusted Apple HFS+/HFSX structures from potentially
compromised disk images. Correctness is therefore established the way forensic
tooling must be: against **independent oracles** (a different tool, or a different
code path, that already decodes the same bytes correctly) on **real third-party
or real macOS-produced corpora** with known ground truth — never against fixtures
we hand-encoded and then graded ourselves.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Per-file provenance (source, generator
command, hashes, license) lives in [`tests/data/README.md`](https://github.com/SecurityRonin/hfsplus-forensic/blob/main/tests/data/README.md);
the fleet-wide machine index is `issen/docs/corpus-catalog.md`. This page
cross-references both rather than duplicating them.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **Apple AppleFSCompression** (`ditto --hfsCompression`) | Yes — Apple's own compressor wrote the real LZVN forks | LZVN (type 8) resource-fork decode: our output must equal the **original pre-compression file** that Apple compressed | 1 |
| **Apple AppleFSCompression** (`afsctool -c -T ZLIB` / `-T LZFSE`) | Yes — drives Apple's real framework | zlib (types 3/4) and LZFSE (types 11/12) decode: output must equal the original pre-compression file | 1 |
| **Apple `compression_decode_buffer`** (`COMPRESSION_LZVN`) | Yes — the OS's own decoder | The macOS 26.5 (Tahoe) type-8 `.expected` answer key (equals the kernel's transparent read) for a real LZVN block with trailing bytes | 1 |
| **`lzvn` crate** (`lzvn-core`) | Yes — vetted third-party codec we reuse | The LZVN decode itself (length-tolerant, reads real decmpfs blocks with trailing bytes after end-of-stream) | 1 |
| **`flate2` / `lzfse_rust` crates** | Yes — vetted third-party codecs we reuse | The zlib / LZFSE decode itself | 1 |
| **macOS `hdiutil` (HFS+ filesystem builder)** | Yes — Apple's own filesystem writer | HFS+ volume-header geometry, catalog B-tree directory listing, and data-fork extraction: ground truth is the layout Apple's builder wrote (the files/contents we placed) | 2 |

## Independent test corpora

All fixtures are produced by Apple's own tools (`hdiutil`, `ditto`,
`afsctool`, the kernel's transparent-compression read path) on real macOS,
including two captured from a clean macOS 26.5 (Tahoe) system. They are small,
committed (the parser is byte-buffer-driven and the tests `include_bytes!` them),
and carry ground truth derivable from the documented construction or from an
independent Apple decoder. Hashes and full provenance are in
[`tests/data/README.md`](https://github.com/SecurityRonin/hfsplus-forensic/blob/main/tests/data/README.md).

| Corpus | Source | Used for | License / redistribution |
|---|---|---|---|
| **HFS+ volume + header + nested** (`hfs_plus_header.bin`, `hfs_plus_volume.bin`, `hfs_plus_nested.bin`) | macOS `hdiutil create -fs HFS+ -layout NONE` | Volume-header geometry, root + nested directory listing, data-fork extraction | `REAL-self`; committed |
| **LZVN resource fork** (`lzvn.rsrc` + `lzvn.expected`) | macOS `ditto --hfsCompression` (decmpfs type 8) | Type-8 LZVN resource-fork decode vs the original file | `REAL-self`; committed |
| **decmpfs end-to-end volume** (`hfs_decmpfs_volume.bin`) | `hdiutil` + `ditto --hfsCompression` (4 MiB HFS+ volume, `comp.bin` + `plain.bin` control) | End-to-end `read_file` transparent decompression | `REAL-self`; committed |
| **zlib / LZFSE resource forks + inline payloads** (`real_zlib_rsrc.rsrc`, `real_lzfse_rsrc.rsrc`, `real_zlib_inline.payload`, `real_lzfse_inline.payload`, `zlib.expected`, `real_zlib_inline.expected`) | `afsctool -c -T ZLIB` / `-T LZFSE` over `/usr/share/dict/words` | Type 3/4 zlib and type 11/12 LZFSE decode vs the original files | `REAL-self`; committed |
| **Tahoe type-8 + type-9** (`tahoe_type8.rsrc`/`.expected`, `tahoe_type9.decmpfs`/`.expected`) | Real files (`/usr/bin/loads.d`, `/usr/bin/pp`) on macOS 26.5 (build 25F71), read-only mount | Real LZVN with trailing bytes; real type-9 inline marker; `.expected` for type-8 from Apple `compression_decode_buffer` | `REAL-self`; committed |
| **type-3 `0xFF`-stored inline** (`zlib_type3_stored.payload` + `zlib_inline.expected`) | Hand-built (Apple's compressor never emits this marker) | The decmpfs "stored" remainder branch | `SYNTHETIC` (the sole synthetic fixture); committed |

## Per-capability validation

### decmpfs LZVN (type 8) decompression — Tier 1

`src/decmpfs.rs:350` (`decodes_real_macos_lzvn_resource_fork`) decodes a **real
`ditto --hfsCompression` resource fork** (`lzvn.rsrc`, 2 × 64 KiB chunks) and
asserts the output equals `lzvn.expected` — the **original 80 000-byte file Apple
compressed**. Apple wrote the compressed bytes; the answer key is the file before
compression. The end-to-end path is validated by `tests/decmpfs_integration.rs:40`
(`read_file_transparently_decompresses_decmpfs_lzvn`), which reads `comp.bin` from
a real 4 MiB HFS+ volume and requires it to read back as the original 262 144-byte
payload (regenerated byte-for-byte from the documented LCG, so no expected fixture
is committed), with `plain.bin` as the uncompressed control. The codec itself is
the vetted third-party `lzvn` crate.

### decmpfs zlib (types 3/4) decompression — Tier 1

`src/decmpfs.rs:360` (`decodes_real_macos_zlib_resource_fork`) decodes a **real
`afsctool -T ZLIB` type-4 resource fork** and matches `zlib.expected` (150 KB of
real text). `src/decmpfs.rs:370` (`decodes_real_macos_inline_zlib`) does the same
for a **real type-3 inline (xattr) payload**. Real data earned its keep here: it
exposed that zlib block offsets are relative to `headerSize+4`, a bug
self-consistent synthetic fixtures had passed. The codec is `flate2`.

### decmpfs LZFSE (types 11/12) decompression — Tier 1

`src/decmpfs.rs:416` (`decodes_real_macos_lzfse_resource_fork`) decodes a **real
`afsctool -T LZFSE` type-12 resource fork** against the same 150 KB original;
`src/decmpfs.rs:426` (`decodes_real_macos_inline_lzfse`) validates a **real
type-11 inline payload**. Real data exposed that LZFSE forks zero-pad their chunk
table. The codec is `lzfse_rust`.

### decmpfs on real macOS 26.5 (Tahoe) — Tier 1

`src/decmpfs.rs:467` (`decodes_real_tahoe_type8_lzvn_with_trailing_bytes`) decodes
a **real type-8 LZVN block from `/usr/bin/loads.d`** that carries trailing bytes
after the LZVN end-of-stream opcode — the case strict whole-stream decoders
reject. Its `.expected` answer key is produced by **Apple's own
`compression_decode_buffer` (`COMPRESSION_LZVN`)**, an independent OS decoder
equal to the kernel's transparent read. `src/decmpfs.rs:477`
(`decodes_real_tahoe_type9_inline_marker`) validates a **real type-9 inline xattr
from `/usr/bin/pp`** with its 1-byte storage marker. These two real samples
exposed two decoder bugs that synthetic `ditto` fixtures had masked (strict
trailing-byte reject, and an unstripped type-9 marker); the wider Tahoe capture
moved from 0/35 to 35/35 real samples decoding correctly.

### decmpfs uncompressed / fail-loud branches — Tier 3 (per-branch coverage)

The inline-uncompressed (`src/decmpfs.rs:390`), chunked-uncompressed
(`src/decmpfs.rs:436`), and type-9-shape (`src/decmpfs.rs:451`) cases, plus the
fail-loud arms — bad magic (`:497`), truncated header (`:507`), unknown type
(`:512`), unsupported LZBITMAP/dedup (`:518`, `:527`), missing resource fork
(`:536`), and length-mismatch (`:486`) — use hand-built inputs. They establish
that each branch behaves and that a malformed or under-length input **fails loud**
(`DecmpfsError`) rather than returning a short or wrong buffer; they are not a
correctness claim against real-world bytes. The sole synthetic *fixture*, the
type-3 `0xFF`-stored payload (`src/decmpfs.rs:380`), covers a remainder branch
Apple's real compressor never emits.

### HFS+ volume header, directory listing, file extraction — Tier 2

`tests/catalog.rs` parses **real `hdiutil`-created HFS+ output**. The header test
(`parses_real_volume_header`, `tests/catalog.rs:24`) asserts version 4, 4096-byte
allocation blocks, 512 total blocks, 2 MiB volume size. Listing and extraction are
checked on a populated volume: `lists_real_root_directory`
(`tests/catalog.rs:40`) requires `HELLO.TXT` / `READ.ME` / `SUBDIR` with correct
dir/file flags; `reads_real_file_contents` (`tests/catalog.rs:62`) requires
`HELLO.TXT` to read back as `b"hello hfs"`; `walk_lists_nested_paths`
(`tests/catalog.rs:97`) requires the nested path `SUB/NESTED.TXT` and its
`b"nested data"` contents. Ground truth is the layout Apple's `hdiutil` wrote and
the files we placed — derivable from the documented construction, hence Tier 2.
This is **not yet** cross-checked against an independent HFS+ decoder.

### Robustness — never panic, never over-read

Production code is `#![forbid(unsafe_code)]` (enforced via `[lints.rust]
unsafe_code = "forbid"`). Every length and offset is bounds-checked, and a decmpfs
file that cannot be decoded returns `None`/`Err` rather than the (empty) data
fork — decmpfs never degrades to silently-wrong output.

## Gaps and honest caveats

- **HFS+ reader oracle is Tier 2, not Tier 1.** The volume/header/listing tests
  validate against Apple's own `hdiutil`-written layout, but no *independent*
  HFS+ decoder cross-checks the geometry and catalog walk. The recommended
  oracle is **The Sleuth Kit** (`fsstat` for header geometry, `fls`/`icat` for
  the catalog walk and data-fork extraction) on the same images — adding it would
  lift this capability to Tier 1.
- **No coverage gate or fuzzing harness yet.** CI runs `cargo fmt --check`,
  `cargo clippy --all-targets -D warnings`, and `cargo test`; it does **not**
  currently enforce `cargo llvm-cov` line coverage, and there is no `fuzz/`
  cargo-fuzz workspace. Both are recommended fleet backstops to add (the
  Paranoid-Gatekeeper standard), and neither is claimed here as in place.

## Reproducing the validation

All fixtures are committed, so every test runs with a plain `cargo test` — no
environment variables, no large-image download, no `--ignored` gate:

```bash
# Everything (decmpfs codec unit tests + HFS+ reader integration tests)
cargo test

# Just the decmpfs codec unit tests (real LZVN / zlib / LZFSE + Tahoe + fail-loud)
cargo test --lib

# Just the HFS+ reader integration tests (real hdiutil volumes)
cargo test --test catalog

# Just the end-to-end decmpfs read_file decompression
cargo test --test decmpfs_integration
```
