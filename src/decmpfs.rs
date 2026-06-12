//! HFS+/APFS transparent-compression (`decmpfs`) decoder.
//!
//! A compressed file carries a `com.apple.decmpfs` extended attribute whose
//! 16-byte header selects an algorithm and a storage location (see
//! [`forensicnomicon::decmpfs`]). This module turns that header — plus the
//! file's resource fork when the payload lives there — back into the original
//! file bytes.
//!
//! # Layouts (reverse-engineered; see [`forensicnomicon::decmpfs`] for sources)
//!
//! - **Inline** (odd types): the payload follows the 16-byte header in the
//!   xattr. Zlib type 3 has a quirk — a leading `0xFF` byte means the remainder
//!   is stored verbatim, not DEFLATE-compressed.
//! - **Zlib resource fork** (type 4): a classic Resource-Manager header
//!   (`HFSPlusCmpfRsrcHead`, big-endian `headerSize, totalSize, dataSize,
//!   flags`) followed at `headerSize` by a block table (big-endian `dataSize`,
//!   little-endian `numBlocks`, then `numBlocks × (offset, size)` little-endian,
//!   offsets relative to `headerSize`). Each block is an independent zlib stream
//!   that inflates to at most [`CHUNK_SIZE`] bytes.
//! - **LZVN/LZFSE resource fork** (types 8/12): a `HFSPlusCmpfLZVNRsrcHead` —
//!   little-endian `headerSize` then `headerSize/4 − 1` chunk **end-offsets**.
//!   The first chunk starts at `headerSize`; chunk *i* spans
//!   `[prev_end, end_offsets[i])`. Each chunk decodes to [`CHUNK_SIZE`] bytes
//!   (the last is shorter). LZVN chunks are raw (no block header) and are framed
//!   as a single-block LZFSE stream before decoding; LZFSE chunks are already
//!   complete streams.

use std::io::Read;

use forensicnomicon::decmpfs::{self, Algorithm, Storage, CHUNK_SIZE, HEADER_LEN, MAGIC};

/// A decmpfs decode failure. Every arm fails loud — decmpfs never degrades to
/// silent wrong output (a half-decoded file is worse than a named error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecmpfsError {
    /// The xattr is shorter than the 16-byte header.
    Truncated,
    /// The header magic was not `cmpf`.
    BadMagic(u32),
    /// `compression_type` is not a documented value.
    UnknownType(u32),
    /// A documented but unsupported type (LZBitmap — no public spec; or the
    /// de-dup generation store, type 5, which has no payload here).
    Unsupported(&'static str),
    /// An even (resource-fork) type was seen but no resource fork was supplied.
    MissingResourceFork,
    /// A length/offset field pointed outside the available bytes.
    OutOfBounds,
    /// The underlying codec rejected the stream.
    Codec(&'static str),
    /// The decoded output length did not match the header's `uncompressed_size`.
    LengthMismatch {
        /// `uncompressed_size` from the header.
        expected: usize,
        /// Bytes actually produced.
        got: usize,
    },
}

impl std::fmt::Display for DecmpfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "decmpfs xattr shorter than 16-byte header"),
            Self::BadMagic(m) => write!(f, "decmpfs bad magic {m:#010x} (expected 'cmpf')"),
            Self::UnknownType(t) => write!(f, "decmpfs unknown compression_type {t}"),
            Self::Unsupported(s) => write!(f, "decmpfs unsupported: {s}"),
            Self::MissingResourceFork => {
                write!(f, "decmpfs resource-fork type but no resource fork supplied")
            }
            Self::OutOfBounds => write!(f, "decmpfs length/offset field out of bounds"),
            Self::Codec(s) => write!(f, "decmpfs codec error: {s}"),
            Self::LengthMismatch { expected, got } => {
                write!(f, "decmpfs length mismatch: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for DecmpfsError {}

type Result<T> = std::result::Result<T, DecmpfsError>;

/// Decode a decmpfs-compressed file to its original bytes.
///
/// `xattr` is the raw `com.apple.decmpfs` attribute (16-byte header, optionally
/// followed by an inline payload). `resource_fork` is the file's resource fork,
/// required only for even (resource-fork) compression types — pass `None` when
/// the file has no resource fork.
///
/// # Errors
///
/// Returns a [`DecmpfsError`] on any malformed header, unsupported algorithm,
/// missing resource fork, codec failure, or output-length mismatch. It never
/// returns a partially-decoded buffer as success.
pub fn decompress(xattr: &[u8], resource_fork: Option<&[u8]>) -> Result<Vec<u8>> {
    // RED stub — replaced by the real decoder in the GREEN commit.
    let _ = (xattr, resource_fork, MAGIC, HEADER_LEN, CHUNK_SIZE);
    Err(DecmpfsError::Codec("unimplemented"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Build a 16-byte decmpfs header for a given type + uncompressed size.
    fn header(compression_type: u32, uncompressed_size: u64) -> Vec<u8> {
        let mut h = Vec::with_capacity(16);
        h.extend_from_slice(&MAGIC.to_le_bytes());
        h.extend_from_slice(&compression_type.to_le_bytes());
        h.extend_from_slice(&uncompressed_size.to_le_bytes());
        h
    }

    fn xattr(compression_type: u32, uncompressed_size: u64, payload: &[u8]) -> Vec<u8> {
        let mut x = header(compression_type, uncompressed_size);
        x.extend_from_slice(payload);
        x
    }

    // ── REAL macOS data: type-8 LZVN resource fork (ditto --hfsCompression) ──
    #[test]
    fn decodes_real_macos_lzvn_resource_fork() {
        let fork = include_bytes!("../tests/data/decmpfs/lzvn.rsrc");
        let expected = include_bytes!("../tests/data/decmpfs/lzvn.expected");
        let hdr = header(8, expected.len() as u64);
        let out = decompress(&hdr, Some(fork)).expect("real LZVN must decode");
        assert_eq!(out, expected, "decoded bytes must match the original file");
    }

    // ── zlib resource fork (type 4), independent python-zlib block table ──
    #[test]
    fn decodes_zlib_resource_fork_multi_block() {
        let fork = include_bytes!("../tests/data/decmpfs/zlib_type4.rsrc");
        let expected = include_bytes!("../tests/data/decmpfs/zlib.expected");
        let hdr = header(4, expected.len() as u64);
        let out = decompress(&hdr, Some(fork)).expect("type-4 zlib must decode");
        assert_eq!(out, expected);
    }

    // ── inline zlib (type 3) ──
    #[test]
    fn decodes_inline_zlib() {
        let payload = include_bytes!("../tests/data/decmpfs/zlib_type3_inline.payload");
        let expected = include_bytes!("../tests/data/decmpfs/zlib_inline.expected");
        let x = xattr(3, expected.len() as u64, payload);
        let out = decompress(&x, None).expect("type-3 inline zlib must decode");
        assert_eq!(out, expected);
    }

    // ── inline zlib type 3 with the 0xFF "stored" marker ──
    #[test]
    fn decodes_inline_zlib_stored_marker() {
        let payload = include_bytes!("../tests/data/decmpfs/zlib_type3_stored.payload");
        let expected = include_bytes!("../tests/data/decmpfs/zlib_inline.expected");
        let x = xattr(3, expected.len() as u64, payload);
        let out = decompress(&x, None).expect("0xFF-stored type-3 must decode");
        assert_eq!(out, expected);
    }

    // ── inline uncompressed (type 1) ──
    #[test]
    fn decodes_inline_uncompressed() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let x = xattr(1, data.len() as u64, data);
        let out = decompress(&x, None).expect("type-1 uncompressed must decode");
        assert_eq!(out, data);
    }

    // ── fail-loud arms ──
    #[test]
    fn rejects_bad_magic() {
        let mut x = xattr(1, 0, &[]);
        x[0] ^= 0xFF;
        assert!(matches!(decompress(&x, None), Err(DecmpfsError::BadMagic(_))));
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(decompress(&[0u8; 8], None), Err(DecmpfsError::Truncated));
    }

    #[test]
    fn rejects_unknown_type() {
        let x = xattr(99, 0, &[]);
        assert_eq!(decompress(&x, None), Err(DecmpfsError::UnknownType(99)));
    }

    #[test]
    fn rejects_lzbitmap_unsupported() {
        let x = xattr(14, 0, &[]);
        assert!(matches!(decompress(&x, None), Err(DecmpfsError::Unsupported(_))));
    }

    #[test]
    fn rejects_dedup_type5_unsupported() {
        let x = xattr(5, 0, &[]);
        assert!(matches!(decompress(&x, None), Err(DecmpfsError::Unsupported(_))));
    }

    #[test]
    fn resource_fork_type_without_fork_errors() {
        let hdr = header(8, 100);
        assert_eq!(decompress(&hdr, None), Err(DecmpfsError::MissingResourceFork));
    }
}
