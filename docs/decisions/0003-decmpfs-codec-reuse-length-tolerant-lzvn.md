# 3. Reuse audited codecs for decmpfs; decode LZVN via our length-tolerant crate

Date: 2026-07-24
Status: Accepted

## Context

HFS+/APFS transparent compression (`com.apple.decmpfs`) uses four codecs across
its storage types: DEFLATE/zlib (types 3/4), LZVN (types 7/8), and LZFSE (types
11/12), plus verbatim/uncompressed inline (types 1/9). Decoding real macOS output
requires a correct implementation of each.

The fleet's Research-First and "prefer our own crates" disciplines say: find a
mature implementation before writing one, and prefer a SecurityRonin crate where
one exists. Two constraints surfaced from **real** Apple data (not synthetic
fixtures):

- Real macOS LZVN blocks (type 8, ~45,720 system files on macOS 26.5 "Tahoe")
  carry **80–300 trailing bytes after the LZVN end-of-stream opcode**. A strict
  LZFSE stream decoder rejects every one (commit `c05e5c5`): "the strict
  `lzfse_rust` stream path rejected every one." A length-tolerant LZVN decoder
  that stops at end-of-stream is required.
- zlib and LZFSE fork block tables have real-world quirks a self-round-tripped
  synthetic test hides — zlib offsets are relative to `headerSize + 4`, and LZFSE
  forks zero-pad an over-allocated end-offset table (commit `1ffd6ad`, "the LZNT1
  self-consistency trap again").

## Decision

Reuse three codec crates rather than reimplement any codec math:

- **zlib/DEFLATE → `flate2`** (types 3/4). Mature, pure-Rust.
- **LZFSE → `lzfse_rust`** (types 11/12), where the stream is already a complete
  LZFSE block.
- **LZVN → `lzvn` (package `lzvn-core`, our crate)** (types 7/8). Chosen over
  routing LZVN through `lzfse_rust` because our decoder is **length-tolerant** —
  it reads the real decmpfs blocks with trailing bytes that `lzfse_rust` rejects.
  This satisfies "prefer our own crates" *and* is the only correct decoder for the
  real data. Originally a `path = "../lzvn"` dependency, switched to the published
  `lzvn-core 0.1` on crates.io once available (commit `fc24610`), per the fleet
  "prefer the published crate over a path dep" rule.

All three are pure-Rust, keeping `unsafe_code = "forbid"` intact (see ADR 0005).
The `Cargo.toml` dependency comments record each of these rationales inline.

## Consequences

- Every codec is validated against **real Apple-produced bytes** — `afsctool`/
  `ditto --hfsCompression` forks and, on macOS 26.5, Apple's own
  `compression_decode_buffer` as the answer key (35/35 Tahoe LZVN samples,
  `docs/validation.md`) — not self-authored round-trips.
- The LZVN choice is a deliberate split from LZFSE handling; a future consumer must
  not "simplify" it back to a single strict LZFSE path, which would re-break type
  7/8 decoding on real data. The `Cargo.toml` comment guards against that.
- The crate carries three codec dependencies, accepted as the reuse-over-reinvent
  trade the constitution mandates; none introduces `unsafe` or C-FFI.
