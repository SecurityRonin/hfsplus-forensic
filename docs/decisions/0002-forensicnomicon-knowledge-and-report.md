# 2. Format knowledge and the finding vocabulary come from forensicnomicon

Date: 2026-07-24
Status: Accepted

## Context

Two kinds of shared fact live outside this crate:

1. **`decmpfs` format constants** — the `cmpf` magic, the
   `compression_type → algorithm/storage` map, the 16-byte header length, and the
   64 KiB chunk size. These are properties of Apple's on-disk format, not of any
   one decoder.
2. **The finding vocabulary** — `Severity`, the `Observation` trait, and the
   `Report` aggregate that an orchestrator (`disk-forensic`, Issen) renders
   uniformly across every fleet analyzer.

The fleet constitution designates `forensicnomicon` as the zero-dependency
KNOWLEDGE leaf that owns both roles: "Format specs are one role of the KNOWLEDGE
leaf; the normalized reporting vocabulary is the other. Every analyzer in the
fleet emits its findings as this single model." Re-deriving either here would
duplicate a fleet-owned constant table and produce an `XxxAnalysis` type that no
shared renderer understands.

## Decision

Depend on `forensicnomicon` (`forensicnomicon = "1"` in `Cargo.toml`) for both
roles:

- `src/decmpfs.rs` imports `Algorithm, Storage, CHUNK_SIZE, HEADER_LEN, MAGIC`
  from `forensicnomicon::decmpfs` — the decoder carries **no** private copy of the
  format map.
- `src/findings.rs` implements `forensicnomicon::report::Observation` for
  `Anomaly` and re-exports `forensicnomicon::report::Severity`, so `audit()`
  output aggregates into the shared `Report` alongside every sibling analyzer.

## Consequences

- HFS+ findings render identically to `iso9660-forensic`/`gpt-forensic` findings
  in any fleet orchestrator, with stable `HFS-*` codes as a published contract.
- A format-constant fix (e.g. a corrected `decmpfs` type mapping) lands once in
  `forensicnomicon` and reaches this crate on the next minor bump, rather than
  needing a matching edit here.
- The crate inherits `forensicnomicon`'s dependency posture (zero-dep leaf), so the
  coupling adds no transitive supply-chain weight beyond the facade itself.
- Findings are worded as observations ("consistent with …"), never verdicts —
  the constitution's epistemic rule for `report::Observation`, honored in the
  `findings.rs` module doc.
