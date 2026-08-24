# 9. Split the reader into `hfsplus-core`, keeping `hfsplus-forensic` compatible

Date: 2026-08-24

Status: Accepted

Supersedes [ADR-0001](0001-single-crate-reader-and-analyzer.md).

## Context

[ADR-0001](0001-single-crate-reader-and-analyzer.md) kept the reader and the
`findings` analyzer in one published crate, `hfsplus-forensic`, on the fleet
standard's binding principle that the `core`/`forensic` split is *a default, not
a requirement*. That held while no reader-only consumer existed.

It exists now. `forensic-vfs-engine` composes HFS+ behind `Vfs::open(path)`, and
an external archiver reads HFS+ volumes — including `decmpfs` transparently
compressed files — to extract them. Neither wants the `findings` analyzer or its
`forensicnomicon::report` usage. This mirrors the same decision taken for
`udf-forensic` (its ADR-0010) and `iso9660-forensic`.

## Decision

Split the workspace into two published members:

- **`hfsplus-core`** — the reader: volume header, catalog/extents B-trees,
  data-fork extraction, `decmpfs` transparent decompression, and the optional
  `vfs` adapter. It carries no `forensicnomicon::report` usage. It does depend on
  `forensicnomicon` for the `decmpfs` **format table** (`forensicnomicon::decmpfs`
  magic / type→algorithm map / chunk size) — format knowledge a reader
  legitimately needs — but never the report/findings model.
- **`hfsplus-forensic`** — the analyzer (`findings`), depending on `hfsplus-core`
  and `forensicnomicon::report`.

`hfsplus-forensic` **re-exports the entire `hfsplus-core` surface** (`pub use
hfsplus_core::*`) and forwards the `vfs` feature, so existing
`hfsplus_forensic::parse` / `hfsplus_forensic::vfs::HfsFs` /
`hfsplus_forensic::findings::*` code — with or without `vfs` — **compiles
unchanged**, verified by an external consumer crate. No consumer must migrate;
new reader-only consumers depend on `hfsplus-core` directly.

The reader internals the analyzer grades over (the big-endian readers, catalog
locators, the `CatalogLoc` geometry, `decmpfs_xattr`) become `pub` on
`hfsplus-core` — the seam the analyzer needs.

## Consequences

- A reader-only consumer links `hfsplus-core` **without the findings analyzer**.
  Its dependency footprint is the reader plus the `decmpfs` codecs (`flate2`,
  `lzfse_rust`, `lzvn`) and the `forensicnomicon` format table — not the report
  model, and not the analyzer's logic. This is a smaller lean-reader win than
  `udf-core` (which needs no `forensicnomicon` at all), because HFS+'s `decmpfs`
  format constants live in `forensicnomicon`; it is still a genuine separation of
  the analyzer from the reader.
- No consumer is forced to migrate; `hfsplus-forensic` stays a drop-in.
- Two crates publish independently, in dependency order (`hfsplus-core` first).
- The analyzer depends on the reader across a crate boundary, so the reader
  internals it needs are now part of `hfsplus-core`'s public API.
