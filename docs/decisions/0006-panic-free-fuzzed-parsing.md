# 6. Panic-free by lint, fuzzed per parsed structure, allocation-capped

Date: 2026-07-24
Status: Accepted

## Context

The fleet's Paranoid Gatekeeper standard is mandatory for every `*-forensic`
crate that parses attacker-controllable images: never panic, never read out of
bounds, never trust a length field, and cap allocations against alloc bombs. The
static half is the panic-free lint recipe; the runtime half is a fuzz target per
parsed structure.

Real evidence that this matters here: the `decmpfs` xattr header's
`uncompressed_size` is a fully attacker-controlled `u64`. A 17-byte malformed
xattr claiming a petabyte-scale size aborted the process with an
allocation-too-big fault — found by the `decmpfs` fuzz target (commit `45091f3`).

## Decision

Adopt the panic-free posture and fuzz the parsers:

- `[lints.clippy]` in `Cargo.toml` sets `unwrap_used = "deny"` and
  `expect_used = "deny"` (commit `f707d7c`); `correctness` and `suspicious` are
  `deny`. Tests opt out via `#![cfg_attr(test, allow(...))]` in `src/lib.rs` and a
  per-file allow in the integration tests.
- A `cargo-fuzz` harness covers **each parsed structure** (commit `7eb2db5`):
  `fuzz/fuzz_targets/{volume, list_dir, read_file, decmpfs, stat, walk, audit}.rs`
  — the reader entry points, the transparent-decompression path, and the analyzer.
- Attacker-controlled sizes are **capped**, behavior-preservingly (commit
  `45091f3`): inline LZVN output is capped to `CHUNK_SIZE`; both resource-fork
  `Vec::with_capacity` hints are capped against the actual input length. The
  `Vec` still grows as real data decodes and the `out.len() == uncompressed_size`
  check still fails loud on a mismatch — the cap changes only the *pre-allocation
  hint*, not the correctness guard.

## Consequences

- A malformed volume or xattr yields a typed `None`/`DecmpfsError`, never a panic
  or an OOM abort. The `decmpfs` fuzz target ran clean over 7.1M executions after
  the cap (commit `45091f3`).
- "Panic-free" is stated as the qualified *static* posture (panic-free by lint,
  bounds-checked readers) beside the *measured* fuzz evidence — never as a bare
  unprovable absolute, per the fleet robustness-wording rule.
- Defensive guard arms that are provably unreachable under a dominating invariant
  are annotated `// cov:unreachable` rather than deleted, keeping the coverage gate
  honest without trading away robustness (see `findings.rs`; commit `730ae4f`).
