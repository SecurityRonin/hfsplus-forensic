# 1. Single crate carries both the HFS+ reader and its forensic analyzer

Date: 2026-07-24
Status: Accepted

## Context

The fleet's default crate-structure standard (ronin-issen `CLAUDE.md`,
"Crate-structure standard — reader/analyzer split") is Pattern A: a single-format
repo publishes **two** crates — `<x>-core` (the reader) and `<x>-forensic` (the
anomaly analyzer). `ntfs-forensic`, `vmdk-forensic`, and `qcow2-forensic` follow
that shape.

`hfsplus-forensic` deviates: one crate holds the reader (`src/lib.rs`), the
`decmpfs` codecs (`src/decmpfs.rs`), the graded anomaly analyzer
(`src/findings.rs`), and the optional VFS adapter (`src/vfs.rs`). The repo began
as a reader extracted from `iso9660-forensic` (commit `424d57a`, "extract HFS+/HFSX
reader into a standalone crate"); the analyzer was added into the *same* crate
later (commit `730ae4f`, "graded HFS+ anomaly analyzer over parsed structures").

The deciding structural fact is that the analyzer sits directly on the reader's
**crate-private** navigation primitives. `findings.rs` imports
`be16, be32, decmpfs_xattr, decode_utf16, for_each_record, locate_catalog,
locate_extents, CatalogLoc` from the crate root — all `pub(crate)`. Commit
`730ae4f` records the seam it needed: "Reader seam: `locate_extents()` +
`pub(crate)` on existing navigation helpers." A two-crate split would force those
B-tree walkers to become part of the reader's *public* API purely to let a sibling
analyzer reach them, widening the published surface for no consumer benefit.

## Decision

Ship reader and analyzer as **one crate, `hfsplus-forensic`**, rather than the
Pattern A `hfsplus-core` + `hfsplus-forensic` split.

- The reader (`parse`, `list_root`/`list_dir`/`walk`, `read_file`, `stat`) is the
  public API; the B-tree/extent navigation helpers stay `pub(crate)`.
- The analyzer (`findings::audit`) consumes those private helpers in-crate and
  emits graded `HFS-*` findings via `forensicnomicon::report::Observation`
  (see ADR 0002).
- The constitution permits this: its reader/analyzer split is stated as "the
  default, not a requirement," and `-forensic` may parse the raw structure
  directly when a happy-path reader API would hide the anomaly. Here the auditor
  reuses the reader's own low-level walkers instead, so a split would only export
  internals.

## Consequences

- One published crate, one version line, one changelog — simpler for a reader this
  compact than three-way workspace bookkeeping.
- The analyzer always tracks the reader's exact parse behavior because it calls the
  same `pub(crate)` functions; there is no risk of a `-core`/`-forensic` version
  skew.
- Consumers who want only geometry still link the analyzer code, but it is small,
  `std`-only, and pulls no extra dependency (`forensicnomicon` is needed by the
  reader anyway for `decmpfs` constants — ADR 0002).
- If HFS+ analysis ever grows to warrant an independent release cadence, the split
  can be reintroduced by promoting the `pub(crate)` walkers to a `-core` public API
  — a non-breaking direction for downstream users of the current public functions.
