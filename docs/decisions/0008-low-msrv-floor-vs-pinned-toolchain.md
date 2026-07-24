# 8. A low, CI-verified MSRV floor, separate from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet Rust MSRV policy separates two distinct promises:

- **Dev toolchain** (`rust-toolchain.toml`) — pinned to the current fleet stable so
  every contributor and CI builds/fmt/clippy identically. Here that pin is `1.96.0`
  (commit `88b6472`), with `clippy` + `rustfmt` components declared in the toml.
- **Declared MSRV** (`rust-version` in `Cargo.toml`) — a downstream-facing
  compatibility promise. For **published libraries** the policy is a low,
  CI-verified floor kept deliberately below the pinned toolchain, because a low
  MSRV is a real compatibility feature for third-party reuse. This crate is a
  published library (crates.io: `hfsplus-forensic`), consumed by
  `iso9660-forensic` and the `disk-forensic` stack.

Commit `88b6472` states the split directly: "One stable toolchain for
build/fmt/clippy … Declared MSRV (`rust-version`) is separate and unchanged —
published libraries keep their low, CI-verified MSRV."

## Decision

Declare `rust-version = "1.85"` in `Cargo.toml` and verify it in CI, independent of
the `1.96.0` dev-toolchain pin.

- `Cargo.toml`: `rust-version = "1.85"` (set at initial extraction, commit
  `424d57a`), edition 2021.
- `.github/workflows/ci.yml` runs a dedicated **MSRV (1.85)** job pinning
  `dtolnay/rust-toolchain@… # 1.85`, so the floor is a checked guarantee, not an
  aspiration.
- Raising the floor is treated as a near-breaking change, taken only when a
  dependency or language feature genuinely requires it — never merely to match the
  `1.96.0` toolchain.

## Consequences

- Downstream crates on an older stable can still depend on `hfsplus-forensic`; the
  CI job makes the promise honest.
- The pinned dev toolchain can advance fleet-wide (a routine bump) without silently
  raising this library's floor.
- **Unrecovered rationale:** the git history does not record *why the floor is
  exactly 1.85* rather than the more common `1.75`/`1.80` — the number was set in
  the first commit with no stated reason (likely the effective floor of a codec or
  `forensic-vfs`/`forensicnomicon` dependency at extraction time). The *decision*
  (a low, CI-verified floor separate from the pin) is grounded; the specific value
  is documented as-is, not reconstructed. Rationale reconstructed from structure;
  original intent not recovered in available history.
