# 7. The forensic-vfs adapter lives behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet's universal container/filesystem abstraction (`forensic-vfs`) lets a
whole stack — `E01 → GPT → BitLocker → NTFS` — read as one shared
`Arc<dyn ImageSource>`, so a consumer need not know one filesystem from another.
An HFS+ reader that wants to participate in a mounted stack must implement the
`forensic_vfs::FileSystem` contract.

Two tensions shape how to expose it:

- **Batteries-Included** bans `default-features = false` as a way to slim a *fleet*
  dependency, but explicitly permits an optional feature for **outside consumers**
  as long as fleet binaries turn it on: "The slim path is for outside consumers,
  never for our own tools."
- This is a **library** used two ways: directly as a bare byte-buffer reader
  (e.g. `iso9660-forensic` reading the HFS+ side of a hybrid disc), and as a
  mountable filesystem inside a `forensic-vfs` stack. Only the second use needs to
  pull `forensic-vfs`.

## Decision

Gate `impl FileSystem for HfsFs` behind a non-default `vfs` Cargo feature:

- `Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, with `forensic-vfs` marked
  `optional = true`; `src/vfs.rs` is `#[cfg(feature = "vfs")]`.
- A bare reader dependent (the common hybrid-disc case) does not pull
  `forensic-vfs`; a mount/stack consumer enables `vfs`.
- The adapter maps the slice-based reader onto the contract: HFS+ has no dedicated
  `FileId` variant, so every node is addressed by `FileId::Opaque` carrying its
  catalog node ID (CNID), root = CNID 2. Every fallible reader call is translated
  to a typed `VfsError` — never an `unwrap`/panic (`src/vfs.rs`).
- `forensic-vfs` is safe Rust, so enabling the feature preserves
  `unsafe_code = "forbid"` (ADR 0005).

## Consequences

- The default build stays lean for third-party and sibling-reader consumers;
  fleet mount tooling (4n6mount / `forensic-vfs-engine`) enables `vfs` to get the
  adapter — exactly the sanctioned "lean default, capable binary" pattern.
- The adapter tracks `forensic-vfs`'s evolving contract; the dependency is pinned
  at `0.7` and has been bumped in lockstep across releases (commits `df03646`
  0.1→…, `22a1533` `FsKind` newtype, `49a0133`, `f71f5ba` →0.7), each a mechanical
  contract-follow, not a semantic change to the reader.
- Because the reader is immutable and slice-based, one mounted `HfsFs` backs N
  workers with no locking — the concurrency property the mount layer needs comes
  for free from ADR 0005.
