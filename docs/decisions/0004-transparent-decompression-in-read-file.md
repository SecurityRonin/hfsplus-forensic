# 4. read_file transparently decompresses; it never returns a hollow data fork

Date: 2026-07-24
Status: Accepted

## Context

An HFS+/APFS file compressed with `decmpfs` stores **nothing** in its data fork.
The real bytes live either inline in the `com.apple.decmpfs` extended attribute or
in the file's resource fork. A reader that returns only the data fork therefore
hands the caller an *empty file* for exactly the files most worth reading (system
binaries, application resources), with no error to signal the emptiness.

The fleet's Batteries-Included discipline is explicit: "Decode/enrichment
capability is NEVER opt-in — the analysis layer is capable by default. An examiner
staring at an opaque BLOB must get the decoded value from the zero-config path, not
a rebuild." Fail-loud further forbids returning plausible-but-wrong output.

## Decision

Wire the `decmpfs` decoder directly into `read_file` (commit `71a8b4a`):

- `read_file(volume, cnid)` walks the attributes B-tree for the
  `com.apple.decmpfs` xattr, reads the resource fork (`HFSPlusForkData` at +168)
  when the payload is fork-stored, and returns the **decompressed** bytes.
- A compressed file returns its real content, not its empty data fork.
- A `decmpfs` file that cannot be decoded returns `None` — never a partial or
  silent-wrong buffer. Every `DecmpfsError` arm fails loud, including a
  `LengthMismatch { expected, got }` guard that rejects any decode whose output
  length does not equal the header's `uncompressed_size`.
- Transparent decompression is **not** behind a Cargo feature; it is part of the
  default read path, so a zero-config caller gets correct bytes.

## Consequences

- The common path (`read_file` on any file) is correct for both plain and
  compressed files with no caller knowledge of `decmpfs`.
- Because decode is capable-by-default, the codec dependencies of ADR 0003 are
  mandatory, not optional — consistent with "the slim path is for outside
  consumers, never for our own analysis."
- The `LengthMismatch` and `OutOfBounds` guards keep the transparent path honest:
  a malformed compressed file surfaces as `None`, never as truncated content that
  a downstream hash or carve would silently trust.
- The alloc-bomb hardening of ADR 0006 exists precisely because this read path
  feeds an attacker-controlled `uncompressed_size` into allocation.
