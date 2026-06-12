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

The marquee `lzvn.rsrc` and `hfs_decmpfs_volume.bin` are **REAL macOS LZVN**
output (`ditto --hfsCompression`); the oracle is the original pre-compression
bytes. The zlib fixtures are minted with Python's `zlib` (an independent DEFLATE
implementation, not the `flate2` we test) in the documented block-table layout.
macOS hides the `com.apple.decmpfs` xattr from the normal xattr API; its
compression type was read via `getxattr(..., XATTR_SHOWCOMPRESSION)`.

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

#### zlib_type4.rsrc + zlib.expected — `SYNTHETIC` (independent oracle)

- **Identity:** a decmpfs **type 4 (zlib resource fork)** block table — classic
  Resource-Manager header + 3 × 64 KiB zlib blocks — over 150000 bytes of real
  `/usr/share/dict/words`, built with Python `zlib`.
- **Generator:** `python3` builds `HFSPlusCmpfRsrcHead` (BE headerSize=0x100,
  totalSize, dataSize, flags) + block table (BE dataSize, LE numBlocks, LE
  (offset,size)[]) + `zlib.compress(chunk, 6)` per 64 KiB. See the corpus
  catalog for the verbatim builder.

#### zlib_type3_inline.payload / zlib_type3_stored.payload + zlib_inline.expected — `SYNTHETIC`

- **Identity:** decmpfs **type 3 inline** payloads over 3000 bytes of real dict
  words: one a `zlib.compress` stream, one a `0xFF`-prefixed verbatim ("stored")
  payload. The test prepends a 16-byte decmpfs header.
- **Generator:** `python3 -c "import zlib; zlib.compress(words[:3000], 6)"` and
  `b'\xff' + words[:3000]`.
