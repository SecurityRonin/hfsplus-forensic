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
    /// A documented but unsupported type (`LZBitmap` — no public spec; or the
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
                write!(
                    f,
                    "decmpfs resource-fork type but no resource fork supplied"
                )
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
        return Err(DecmpfsError::Unsupported(
            "decmpfs LZBitmap (no public spec)",
        ));
    }

    let out = match kind.storage {
        Storage::Inline => {
            let payload = xattr.get(HEADER_LEN..).ok_or(DecmpfsError::Truncated)?;
            decode_inline(kind.algorithm, payload, uncompressed_size, compression_type)?
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
///
/// `compression_type` is threaded in because two inline-uncompressed types
/// share one [`Algorithm::Uncompressed`] but differ in framing: type 1 stores
/// its bytes verbatim, while type 9 is a *marker-prefixed* variant (one leading
/// byte before the raw data). That is a documented discontinuity in the decmpfs
/// format — verified against go-apfs `decmpfs.go` (strips `AttrBytes[1:]` for
/// `CMP_ATTR_UNCOMPRESSED`/type 9) and forensicnomicon's type table — not a
/// special case. Confirmed on real macOS 26.5 type-9 files (the marker byte,
/// 0xCC in those samples, precedes the verbatim content).
fn decode_inline(
    algorithm: Algorithm,
    payload: &[u8],
    uncompressed_size: usize,
    compression_type: u32,
) -> Result<Vec<u8>> {
    match algorithm {
        // Type 1: verbatim. Type 9: strip the one-byte storage marker.
        Algorithm::Uncompressed => match compression_type {
            9 => Ok(payload.get(1..).unwrap_or(&[]).to_vec()),
            _ => Ok(payload.to_vec()),
        },
        Algorithm::Zlib => {
            // A leading 0xFF means the remainder is stored verbatim (the file
            // did not compress); otherwise the payload is a zlib stream.
            match payload.first() {
                Some(0xFF) => Ok(payload[1..].to_vec()),
                _ => inflate(payload),
            }
        }
        // A leading 0x06 (the LZVN end-of-stream opcode) marks an inline payload
        // stored uncompressed after that marker (go-apfs `CMP_ATTR_LZVN`).
        Algorithm::Lzvn => match payload.first() {
            Some(0x06) => Ok(payload.get(1..).unwrap_or(&[]).to_vec()),
            // Inline storage inflates to at most CHUNK_SIZE (module invariant);
            // cap the attacker-controlled length so a malformed header cannot
            // drive an unbounded allocation inside the codec. A larger claimed
            // size then fails loud via the caller's length check, never panics.
            // Mirrors the `.min(CHUNK_SIZE)` cap on the resource-fork path.
            _ => lzvn_decode(payload, uncompressed_size.min(CHUNK_SIZE)),
        },
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
    // At `header_size`: a big-endian total-size prefix (4 bytes), then the block
    // table proper — little-endian numBlocks, then numBlocks × (offset, size)
    // little-endian. Block offsets are relative to `header_size + 4` (the start
    // of the block table, i.e. the numBlocks field), NOT to `header_size`.
    // (Verified against real afsctool/macOS forks — a synthetic round-trip can
    // pass with the wrong base because it is self-consistent.)
    let table = header_size
        .checked_add(4)
        .ok_or(DecmpfsError::OutOfBounds)?;
    let num_blocks = le_u32(fork, table)? as usize;
    // `uncompressed_size` is an attacker-controlled u64 from the xattr header;
    // cap the pre-allocation hint against the real input so a malformed value
    // cannot request an unbounded allocation. The Vec still grows as blocks
    // decode, and the caller verifies the final length.
    let mut out = Vec::with_capacity(uncompressed_size.min(fork.len()));
    for i in 0..num_blocks {
        let entry = table
            .checked_add(4)
            .and_then(|b| b.checked_add(i.checked_mul(8)?))
            .ok_or(DecmpfsError::OutOfBounds)?;
        let offset = le_u32(fork, entry)? as usize;
        let size = le_u32(fork, entry + 4)? as usize;
        let start = table.checked_add(offset).ok_or(DecmpfsError::OutOfBounds)?;
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
    // headerSize/4 − 1 is an *upper bound* on the chunk count: the compressor may
    // over-allocate the end-offset table and zero-pad the unused slots (observed
    // in afsctool LZFSE forks). The true count is ceil(uncompressed_size /
    // CHUNK_SIZE); the loop stops once it has produced that many bytes, never
    // reading a zero-padding slot.
    let n_slots = (header_size / 4)
        .checked_sub(1)
        .ok_or(DecmpfsError::OutOfBounds)?;
    // Cap the pre-allocation hint against the real input (see note in
    // `decode_zlib_resource_fork`): `uncompressed_size` is attacker-controlled.
    let mut out = Vec::with_capacity(uncompressed_size.min(fork.len()));
    let mut src = header_size;
    for i in 0..n_slots {
        if out.len() >= uncompressed_size {
            break;
        }
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
    decoder
        .read_to_end(&mut out)
        .map_err(|_| DecmpfsError::Codec("zlib"))?;
    Ok(out)
}

/// Decode a raw LZVN chunk with the length-tolerant `lzvn` codec.
///
/// A real macOS `decmpfs` resource-fork block ends with the LZVN end-of-stream
/// opcode and is then followed by 80–300 trailing bytes that the kernel ignores.
/// The previous bvxn+LZFSE-stream framing declared those trailing bytes as
/// payload, so a strict whole-stream decoder (`lzfse_rust`) rejected every real
/// Tahoe type-8 file. [`lzvn::decode`] stops at the end-of-stream opcode, so it
/// reads the genuine blocks. (Validated 25/25 on macOS 26.5 vs 0/25 before.)
fn lzvn_decode(chunk: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    lzvn::decode(chunk, uncompressed_len).map_err(|_| DecmpfsError::Codec("lzvn"))
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

    // ── REAL macOS zlib resource fork (type 4), minted by afsctool -T ZLIB ──
    #[test]
    fn decodes_real_macos_zlib_resource_fork() {
        let fork = include_bytes!("../tests/data/decmpfs/real_zlib_rsrc.rsrc");
        let expected = include_bytes!("../tests/data/decmpfs/zlib.expected");
        let hdr = header(4, expected.len() as u64);
        let out = decompress(&hdr, Some(fork)).expect("real type-4 zlib must decode");
        assert_eq!(out, expected);
    }

    // ── REAL macOS inline zlib (type 3), afsctool -T ZLIB on a small file ──
    #[test]
    fn decodes_real_macos_inline_zlib() {
        let payload = include_bytes!("../tests/data/decmpfs/real_zlib_inline.payload");
        let expected = include_bytes!("../tests/data/decmpfs/real_zlib_inline.expected");
        let x = xattr(3, expected.len() as u64, payload);
        let out = decompress(&x, None).expect("real type-3 inline zlib must decode");
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

    // ── REAL macOS LZFSE resource fork (type 12), minted by afsctool -T LZFSE ──
    #[test]
    fn decodes_real_macos_lzfse_resource_fork() {
        let fork = include_bytes!("../tests/data/decmpfs/real_lzfse_rsrc.rsrc");
        let expected = include_bytes!("../tests/data/decmpfs/zlib.expected"); // 150K real text
        let hdr = header(12, expected.len() as u64);
        let out = decompress(&hdr, Some(fork)).expect("real type-12 LZFSE must decode");
        assert_eq!(out, expected);
    }

    // ── REAL macOS inline LZFSE (type 11), afsctool -T LZFSE on a small file ──
    #[test]
    fn decodes_real_macos_inline_lzfse() {
        let payload = include_bytes!("../tests/data/decmpfs/real_lzfse_inline.payload");
        let expected = include_bytes!("../tests/data/decmpfs/real_zlib_inline.expected");
        let x = xattr(11, expected.len() as u64, payload);
        let out = decompress(&x, None).expect("real type-11 inline LZFSE must decode");
        assert_eq!(out, expected);
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
        // Type 9 is a *marker-prefixed* variant of type 1: one storage-marker
        // byte precedes the verbatim content, and uncompressed_size counts the
        // content only. (Confirmed on real macOS 26.5 files; see the
        // `tahoe_type9` fixture below. The earlier verbatim-only form was a
        // synthetic-fixture bug that real data exposed.)
        let content = b"type 9 is uncompressed-inline, a variant of type 1";
        let mut payload = vec![0xCC];
        payload.extend_from_slice(content);
        let x = xattr(9, content.len() as u64, &payload);
        assert_eq!(decompress(&x, None).expect("type-9 must decode"), content);
    }

    // ── REAL macOS 26.5 (Tahoe) type-8 LZVN resource fork WITH trailing bytes
    //    after the end-of-stream opcode — the case strict decoders reject. ──
    #[test]
    fn decodes_real_tahoe_type8_lzvn_with_trailing_bytes() {
        let fork = include_bytes!("../tests/data/decmpfs/tahoe_type8.rsrc");
        let expected = include_bytes!("../tests/data/decmpfs/tahoe_type8.expected");
        let hdr = header(8, expected.len() as u64);
        let out = decompress(&hdr, Some(fork)).expect("Tahoe LZVN must decode");
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    // ── REAL macOS 26.5 (Tahoe) type-9 inline xattr with its 1-byte marker. ──
    #[test]
    fn decodes_real_tahoe_type9_inline_marker() {
        let xattr_bytes = include_bytes!("../tests/data/decmpfs/tahoe_type9.decmpfs");
        let expected = include_bytes!("../tests/data/decmpfs/tahoe_type9.expected");
        let out = decompress(xattr_bytes, None).expect("Tahoe type-9 must decode");
        assert_eq!(out.as_slice(), expected.as_slice());
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
        assert!(matches!(
            decompress(&x, None),
            Err(DecmpfsError::BadMagic(_))
        ));
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
        assert!(matches!(
            decompress(&x, None),
            Err(DecmpfsError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_dedup_type5_unsupported() {
        let x = xattr(5, 0, &[]);
        assert!(matches!(
            decompress(&x, None),
            Err(DecmpfsError::Unsupported(_))
        ));
    }

    #[test]
    fn resource_fork_type_without_fork_errors() {
        let hdr = header(8, 100);
        assert_eq!(
            decompress(&hdr, None),
            Err(DecmpfsError::MissingResourceFork)
        );
    }

    // ── every DecmpfsError variant renders a distinct, self-describing message
    //    (the Display arm is what a caller logs when a decmpfs file is rejected) ──
    #[test]
    fn error_display_is_self_describing_per_variant() {
        assert_eq!(
            DecmpfsError::Truncated.to_string(),
            "decmpfs xattr shorter than 16-byte header"
        );
        assert_eq!(
            DecmpfsError::BadMagic(0xdead_beef).to_string(),
            "decmpfs bad magic 0xdeadbeef (expected 'cmpf')"
        );
        assert_eq!(
            DecmpfsError::UnknownType(99).to_string(),
            "decmpfs unknown compression_type 99"
        );
        assert_eq!(
            DecmpfsError::Unsupported("LZBitmap (no public spec)").to_string(),
            "decmpfs unsupported: LZBitmap (no public spec)"
        );
        assert_eq!(
            DecmpfsError::MissingResourceFork.to_string(),
            "decmpfs resource-fork type but no resource fork supplied"
        );
        assert_eq!(
            DecmpfsError::OutOfBounds.to_string(),
            "decmpfs length/offset field out of bounds"
        );
        assert_eq!(
            DecmpfsError::Codec("zlib").to_string(),
            "decmpfs codec error: zlib"
        );
        assert_eq!(
            DecmpfsError::LengthMismatch {
                expected: 999,
                got: 19
            }
            .to_string(),
            "decmpfs length mismatch: expected 999, got 19"
        );
    }
}
