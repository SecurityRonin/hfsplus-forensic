# 5. forbid(unsafe) — a slice-based, allocation-lean reader

Date: 2026-07-24
Status: Accepted

## Context

This crate parses **untrusted, attacker-controllable** HFS+/HFSX volume bytes
(Apple hybrid optical discs, seized disk images). The fleet's `unsafe` law makes
`forbid(unsafe)` the default *and* the goal — a provable "zero places a crafted
input can corrupt memory" — and downgrades to `deny` + a bounded per-site allow
only when a concrete benefit (typically an `mmap` scanner, as in `ewf` and
`memory-forensic`) justifies surrendering that guarantee.

The reader is designed around a single owned `&[u8]` volume buffer: `parse`,
`list_dir`, `read_file`, and `stat` all take the whole volume slice and read
through it with `&self`, allocating nothing beyond the data they return (README:
"no `unsafe` and no allocations beyond the data it returns"). There is no `mmap`,
no FFI, and no zero-copy transmute — so no benefit would be bought by any `unsafe`
block.

## Decision

Set `unsafe_code = "forbid"` in `[lints.rust]` (`Cargo.toml`) and keep it.

- All field reads go through safe big-endian helpers (`be16`/`be32`) over
  bounds-checked slices; no raw pointer arithmetic.
- The codec dependencies are all pure-Rust (ADR 0003), and `forensic-vfs` (ADR
  0007) is safe Rust, so the whole dependency-facing surface preserves `forbid`.
- Because the reader is slice-based and immutable, one buffer backs N concurrent
  readers with no locking — a property the VFS adapter relies on (ADR 0007).

## Consequences

- The crate earns the `unsafe forbidden` posture as a compiler-*proved* guarantee,
  not a claim — `rg unsafe` is empty, so the audit surface is nil.
- No mmap fast-path is available; for a filesystem reader operating over an
  already-extracted or already-mapped volume buffer this is the intended trade —
  memory safety over a micro-optimization the fleet does not need here.
- Adopting any future dependency that requires `unsafe`/C-FFI would force a
  deliberate `forbid → deny` downgrade with a justified per-site allow; that is a
  reviewable event, not a silent drift.
