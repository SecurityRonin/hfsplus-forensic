# hfsplus-forensic test corpus

Co-located human-facing provenance for the fixtures under `tests/data/`. The
single machine-index is the fleet catalog
[`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md) — this
file cross-references it, never duplicates it.

Straight ASCII in paths/commands. `tests/data/` is committed (small fixtures
are needed for `include_bytes!`/`std::fs::read` in tests).

## HFS+ volume / header fixtures (`REAL-self`)

#### hfs_plus_header.bin / hfs_plus_volume.bin / hfs_plus_nested.bin

- **Source / Identity:** real Apple HFS+ structures from macOS
  `hdiutil create -fs HFS+ -layout NONE` volumes (header geometry, catalog
  B-tree, data forks). See the catalog entry C4.
- **Generator:** macOS `hdiutil` (exact lines in the corpus catalog).

## decmpfs (transparent-compression) fixtures — `tests/data/decmpfs/`

**Every codec is validated against REAL macOS-produced decmpfs bytes**, the
oracle being the original pre-compression file. LZVN (types 7/8) come from
`ditto --hfsCompression`; zlib (3/4) and LZFSE (11/12) from `afsctool -c -T
ZLIB|LZFSE` (both drive Apple's real AppleFSCompression framework — macOS itself
ships only LZVN, so these are the only way to obtain real zlib/LZFSE artifacts).
The sole synthetic fixture is the type-3 `0xFF`-"stored" payload, which the real
compressor never emits. macOS hides `com.apple.decmpfs` from the normal xattr
API; its compression type was read via `getxattr(..., XATTR_SHOWCOMPRESSION)`.

Real data earned its keep here: it exposed two bugs that self-consistent
synthetic fixtures had passed — zlib block offsets are relative to
`headerSize+4` (not `headerSize`), and LZFSE forks zero-pad their chunk table.

#### lzvn.rsrc + lzvn.expected — `REAL-self`

- **Identity:** the resource fork of a real `ditto --hfsCompression` file
  (decmpfs **type 8, LZVN**, 2 × 64 KiB chunks), and its original 80000 bytes.
- **Generator:** `head -c 80000 /usr/share/dict/words > src; ditto --hfsCompression src comp; cp 'comp/..namedfork/rsrc' lzvn.rsrc; cp src lzvn.expected`
- **md5:** `lzvn.rsrc` `fdb1fe68b815956f2de8fe1720cad6a5`; `lzvn.expected`
  `8bdc1b02b1288a30d6d9ad1c5b0451e4`.

#### hfs_decmpfs_volume.bin — `REAL-self`

- **Identity:** a 4 MiB layout-NONE HFS+ volume holding `comp.bin` (decmpfs
  **type 8 LZVN** resource fork, 262144 B) and `plain.bin` (the same bytes,
  uncompressed control). Drives the end-to-end `read_file` decompression test.
- **Generator:** payload = an 8192-byte LCG block (`state = state*1103515245 +
  12345`, byte = `state>>16`, seed 2654435761) repeated 32× = 262144 B;
  `hdiutil create -megabytes 4 -fs HFS+ -volname DCFS -layout NONE dc`;
  attach; `ditto --hfsCompression payload comp.bin`; `cp payload plain.bin`;
  detach. The test regenerates the payload from the same LCG (no expected
  fixture committed).

#### real_zlib_rsrc.rsrc / real_lzfse_rsrc.rsrc + zlib.expected — `REAL-self`

- **Identity:** real resource forks of decmpfs **type 4 (zlib)** and **type 12
  (LZFSE)** files over 150000 bytes of `/usr/share/dict/words`. Both decode to
  `zlib.expected` (the shared 150 KB original).
- **Generator:** `head -c 150000 /usr/share/dict/words > f; afsctool -c -T ZLIB f`
  (resp. `-T LZFSE`); `cp 'f/..namedfork/rsrc' real_zlib_rsrc.rsrc`.

#### real_zlib_inline.payload / real_lzfse_inline.payload + real_zlib_inline.expected — `REAL-self`

- **Identity:** real **inline** (xattr) payloads of decmpfs **type 3 (zlib)** and
  **type 11 (LZFSE)** over 2000 bytes of dict words. The test prepends a 16-byte
  decmpfs header. (Apple frames small "LZFSE" inline data as an LZVN `bvxn`
  block.)
- **Generator:** `head -c 2000 ... > f; afsctool -c -T ZLIB f` (resp. `-T LZFSE`);
  the inline payload is `getxattr(f, "com.apple.decmpfs", XATTR_SHOWCOMPRESSION)[16:]`.

#### zlib_type3_stored.payload + zlib_inline.expected — `SYNTHETIC` (only synthetic fixture)

- **Identity:** decmpfs **type 3 inline** with the `0xFF` "stored" marker (the
  payload did not compress, so the remainder is verbatim) over 3000 bytes of dict
  words. Apple's real compressor never emits this, so it is built by hand.
- **Generator:** `b'\xff' + words[:3000]`.
