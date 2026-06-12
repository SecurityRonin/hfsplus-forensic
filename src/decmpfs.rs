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
    if xattr.len() < HEADER_LEN {
        return Err(DecmpfsError::Truncated);
    }
    let magic = le_u32(xattr, 0)?;
    if magic != MAGIC {
        return Err(DecmpfsError::BadMagic(magic));
    }
    let compression_type = le_u32(xattr, decmpfs::COMPRESSION_TYPE_OFFSET)?;
    let uncompressed_size = le_u64(xattr, decmpfs::UNCOMPRESSED_SIZE_OFFSET)? as usize;

    let Some(kind) = decmpfs::classify(compression_type) else {
        return Err(match compression_type {
            5 => DecmpfsError::Unsupported("decmpfs type 5 (de-dup generation store)"),
            other => DecmpfsError::UnknownType(other),
        });
    };
    if kind.algorithm == Algorithm::LzBitmap {
        return Err(DecmpfsError::Unsupported("decmpfs LZBitmap (no public spec)"));
    }

    let out = match kind.storage {
        Storage::Inline => {
            let payload = xattr.get(HEADER_LEN..).ok_or(DecmpfsError::Truncated)?;
            decode_inline(kind.algorithm, payload, uncompressed_size)?
        }
        Storage::ResourceFork => {
            let fork = resource_fork.ok_or(DecmpfsError::MissingResourceFork)?;
            decode_resource_fork(kind.algorithm, fork, uncompressed_size)?
        }
    };

    if out.len() != uncompressed_size {
        return Err(DecmpfsError::LengthMismatch {
            expected: uncompressed_size,
            got: out.len(),
        });
    }
    Ok(out)
}

/// Decode an inline (odd-type) payload that follows the 16-byte header.
fn decode_inline(algorithm: Algorithm, payload: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Uncompressed => Ok(payload.to_vec()),
        Algorithm::Zlib => {
            // A leading 0xFF means the remainder is stored verbatim (the file
            // did not compress); otherwise the payload is a zlib stream.
            match payload.first() {
                Some(0xFF) => Ok(payload[1..].to_vec()),
                _ => inflate(payload),
            }
        }
        Algorithm::Lzvn => lzvn_decode(payload, uncompressed_size),
        Algorithm::Lzfse => lzfse_decode(payload),
        // LzBitmap is rejected before dispatch; the arm keeps the match total
        // against future `#[non_exhaustive]` Algorithm variants.
        _ => Err(DecmpfsError::Unsupported("decmpfs unsupported algorithm")),
    }
}

/// Decode an even-type payload stored across the resource fork.
fn decode_resource_fork(
    algorithm: Algorithm,
    fork: &[u8],
    uncompressed_size: usize,
) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Zlib => decode_zlib_resource_fork(fork, uncompressed_size),
        Algorithm::Lzvn | Algorithm::Lzfse | Algorithm::Uncompressed => {
            decode_chunked_resource_fork(algorithm, fork, uncompressed_size)
        }
        // LzBitmap is rejected before dispatch; arm keeps the match total.
        _ => Err(DecmpfsError::Unsupported("decmpfs unsupported algorithm")),
    }
}

/// Zlib resource fork (type 4): classic Resource-Manager header + block table.
fn decode_zlib_resource_fork(fork: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    // HFSPlusCmpfRsrcHead: big-endian headerSize, totalSize, dataSize, flags.
    let header_size = be_u32(fork, 0)? as usize;
    // Block table at `header_size`: big-endian dataSize, little-endian numBlocks,
    // then numBlocks × (offset, size) little-endian. Offsets are relative to
    // `header_size` (the start of the resource data).
    let num_blocks = le_u32(fork, header_size.checked_add(4).ok_or(DecmpfsError::OutOfBounds)?)?
        as usize;
    let mut out = Vec::with_capacity(uncompressed_size);
    for i in 0..num_blocks {
        let entry = header_size
            .checked_add(8)
            .and_then(|b| b.checked_add(i.checked_mul(8)?))
            .ok_or(DecmpfsError::OutOfBounds)?;
        let offset = le_u32(fork, entry)? as usize;
        let size = le_u32(fork, entry + 4)? as usize;
        let start = header_size.checked_add(offset).ok_or(DecmpfsError::OutOfBounds)?;
        let end = start.checked_add(size).ok_or(DecmpfsError::OutOfBounds)?;
        let block = fork.get(start..end).ok_or(DecmpfsError::OutOfBounds)?;
        out.extend_from_slice(&inflate(block)?);
    }
    Ok(out)
}

/// LZVN/LZFSE/uncompressed resource fork (types 8/12/10):
/// `HFSPlusCmpfLZVNRsrcHead` — little-endian headerSize then chunk end-offsets.
fn decode_chunked_resource_fork(
    algorithm: Algorithm,
    fork: &[u8],
    uncompressed_size: usize,
) -> Result<Vec<u8>> {
    let header_size = le_u32(fork, 0)? as usize;
    // The header holds headerSize/4 − 1 chunk end-offsets (the first u32 is the
    // headerSize itself). Chunk data begins at `header_size`.
    let n_chunks = (header_size / 4).checked_sub(1).ok_or(DecmpfsError::OutOfBounds)?;
    let mut out = Vec::with_capacity(uncompressed_size);
    let mut src = header_size;
    for i in 0..n_chunks {
        let end = le_u32(fork, 4 + i * 4)? as usize;
        if end < src {
            return Err(DecmpfsError::OutOfBounds);
        }
        let chunk = fork.get(src..end).ok_or(DecmpfsError::OutOfBounds)?;
        // Each chunk decodes to CHUNK_SIZE bytes, except the last (the remainder).
        let chunk_uncompressed = uncompressed_size
            .checked_sub(out.len())
            .ok_or(DecmpfsError::OutOfBounds)?
            .min(CHUNK_SIZE);
        let decoded = match algorithm {
            Algorithm::Lzvn => lzvn_decode(chunk, chunk_uncompressed)?,
            Algorithm::Lzfse => lzfse_decode(chunk)?,
            Algorithm::Uncompressed => chunk.to_vec(),
            // Zlib forks take the classic-header path; LzBitmap is rejected
            // before dispatch. Either here means a routing bug, not bad input.
            _ => return Err(DecmpfsError::Codec("unexpected algorithm for chunked fork")),
        };
        out.extend_from_slice(&decoded);
        src = end;
    }
    Ok(out)
}

/// Inflate a zlib stream (DEFLATE with a zlib wrapper).
fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|_| DecmpfsError::Codec("zlib"))?;
    Ok(out)
}

/// Decode a raw LZVN chunk by framing it as a single-block LZFSE stream
/// (`bvxn` header + payload + `bvx$` end-of-stream), then decoding with the
/// LZFSE codec — which natively handles LZVN (`bvxn`) blocks.
fn lzvn_decode(chunk: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    let n_raw = u32::try_from(uncompressed_len).map_err(|_| DecmpfsError::Codec("lzvn length"))?;
    let n_payload = u32::try_from(chunk.len()).map_err(|_| DecmpfsError::Codec("lzvn length"))?;
    let mut stream = Vec::with_capacity(chunk.len() + 16);
    stream.extend_from_slice(b"bvxn"); // lzvn_compressed_block_header magic
    stream.extend_from_slice(&n_raw.to_le_bytes());
    stream.extend_from_slice(&n_payload.to_le_bytes());
    stream.extend_from_slice(chunk);
    stream.extend_from_slice(b"bvx$"); // LZFSE end-of-stream block magic
    lzfse_decode(&stream)
}

/// Decode a complete LZFSE stream.
fn lzfse_decode(stream: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    lzfse_rust::decode_bytes(stream, &mut out).map_err(|_| DecmpfsError::Codec("lzfse/lzvn"))?;
    Ok(out)
}

// ── bounds-checked little/big-endian readers (panic-free) ──

fn le_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(DecmpfsError::OutOfBounds)?;
    let bytes = data.get(offset..end).ok_or(DecmpfsError::OutOfBounds)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(DecmpfsError::OutOfBounds)?;
    let bytes = data.get(offset..end).ok_or(DecmpfsError::OutOfBounds)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or(DecmpfsError::OutOfBounds)?;
    let bytes = data.get(offset..end).ok_or(DecmpfsError::OutOfBounds)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(a))
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

    /// Build an even-type chunked resource fork (`HFSPlusCmpfLZVNRsrcHead`):
    /// little-endian `headerSize` then one end-offset per chunk.
    fn chunked_fork(chunks: &[Vec<u8>]) -> Vec<u8> {
        let header_size = 4 * (chunks.len() + 1);
        let mut fork = Vec::new();
        fork.extend_from_slice(&(header_size as u32).to_le_bytes());
        let mut end = header_size;
        for c in chunks {
            end += c.len();
            fork.extend_from_slice(&(end as u32).to_le_bytes());
        }
        for c in chunks {
            fork.extend_from_slice(c);
        }
        fork
    }

    fn lzfse_stream(data: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        lzfse_rust::encode_bytes(data, &mut s).expect("encode");
        s
    }

    // ── LZFSE resource fork (type 12), round-tripped through the real codec ──
    #[test]
    fn decodes_lzfse_resource_fork_multi_chunk() {
        let words = include_bytes!("../tests/data/decmpfs/zlib.expected"); // ~150KB real text
        let data = &words[..80_000]; // 64KiB + 16000 → two chunks
        let c0 = lzfse_stream(&data[..CHUNK_SIZE]);
        let c1 = lzfse_stream(&data[CHUNK_SIZE..]);
        let fork = chunked_fork(&[c0, c1]);
        let hdr = header(12, data.len() as u64);
        let out = decompress(&hdr, Some(&fork)).expect("type-12 LZFSE must decode");
        assert_eq!(out, data);
    }

    // ── inline LZFSE (type 11) ──
    #[test]
    fn decodes_inline_lzfse() {
        let data = b"LZFSE inline payload: the quick brown fox jumps over the lazy dog.";
        let x = xattr(11, data.len() as u64, &lzfse_stream(data));
        let out = decompress(&x, None).expect("type-11 inline LZFSE must decode");
        assert_eq!(out, data);
    }

    // ── uncompressed resource fork (type 10): verbatim chunks ──
    #[test]
    fn decodes_uncompressed_resource_fork() {
        let mut data = Vec::new();
        for i in 0..(CHUNK_SIZE + 5000) {
            data.push((i % 251) as u8);
        }
        let c0 = data[..CHUNK_SIZE].to_vec();
        let c1 = data[CHUNK_SIZE..].to_vec();
        let fork = chunked_fork(&[c0, c1]);
        let hdr = header(10, data.len() as u64);
        let out = decompress(&hdr, Some(&fork)).expect("type-10 uncompressed fork must decode");
        assert_eq!(out, data);
    }

    // ── inline uncompressed variant (type 9) ──
    #[test]
    fn decodes_inline_uncompressed_type9() {
        let data = b"type 9 is uncompressed-inline, a variant of type 1";
        let x = xattr(9, data.len() as u64, data);
        assert_eq!(decompress(&x, None).expect("type-9 must decode"), data);
    }

    // ── a wrong uncompressed_size must fail loud, not return a short buffer ──
    #[test]
    fn length_mismatch_is_loud() {
        let data = b"the quick brown fox";
        let x = xattr(1, 999, data); // claim 999, payload is 19
        assert!(matches!(
            decompress(&x, None),
            Err(DecmpfsError::LengthMismatch { expected: 999, .. })
        ));
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
