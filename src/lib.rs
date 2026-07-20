//! HFS+ / HFSX volume-header detection (Apple TN1150).
//!
//! Apple optical discs are frequently *hybrids*: an ISO 9660 filesystem and an
//! HFS/HFS+ volume sharing the same disc, so a Mac and a PC each see their own
//! filesystem.  The HFS+ volume header sits at a fixed 1024-byte offset from the
//! volume start (TN1150 §"Volume Header"), with a big-endian `H+` (HFS+) or `HX`
//! (HFSX) signature.
//!
//! This crate reads the volume header (geometry), walks the catalog B-tree to
//! list directories ([`list_root`], [`list_dir`], recursive [`walk`]), and
//! extracts file contents ([`read_file`]) — including HFS+/APFS transparently
//! *compressed* files, which it decodes via the [`decmpfs`] module (zlib / LZVN
//! / LZFSE, inline xattr or resource fork). Journal replay is out of scope.
//! Validated against real `hdiutil`/`ditto`-created HFS+ volumes.

// Tests legitimately unwrap/expect; production code must not (enforced by the
// `unwrap_used`/`expect_used = deny` lints in Cargo.toml).
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod decmpfs;
pub mod findings;
#[cfg(feature = "vfs")]
pub mod vfs;

/// Byte offset of the HFS+ volume header from the start of the volume.
pub(crate) const VOLUME_HEADER_OFFSET: usize = 1024;
/// HFS+ signature `H+` (TN1150).
pub(crate) const SIG_HFS_PLUS: u16 = 0x482B;
/// HFSX signature `HX` (case-sensitive variant).
pub(crate) const SIG_HFSX: u16 = 0x4858;

/// Which Apple volume signature was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfsKind {
    /// `H+` — standard HFS Plus.
    HfsPlus,
    /// `HX` — case-sensitive HFSX.
    Hfsx,
}

/// Parsed HFS+ volume header fields (geometry only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HfsVolume {
    pub kind: HfsKind,
    /// Volume format version (4 for HFS+, 5 for HFSX).
    pub version: u16,
    /// Number of files in the volume's catalog.
    pub file_count: u32,
    /// Number of folders in the volume's catalog.
    pub folder_count: u32,
    /// Allocation block size in bytes.
    pub block_size: u32,
    /// Total allocation blocks in the volume.
    pub total_blocks: u32,
    /// Free allocation blocks.
    pub free_blocks: u32,
}

impl HfsVolume {
    /// Total volume size in bytes (`block_size * total_blocks`).
    #[must_use]
    pub fn volume_size(&self) -> u64 {
        u64::from(self.block_size) * u64::from(self.total_blocks)
    }
}

/// Parse the HFS+/HFSX volume header from a buffer that begins at the volume
/// start (the header is read at offset 1024).  Returns `None` if the buffer is
/// too short or carries no HFS+ signature.
#[must_use]
pub fn parse(volume: &[u8]) -> Option<HfsVolume> {
    let h = VOLUME_HEADER_OFFSET;
    if volume.len() < h + 52 {
        return None;
    }
    let hdr = &volume[h..];
    let kind = match be16(&hdr[0..2]) {
        SIG_HFS_PLUS => HfsKind::HfsPlus,
        SIG_HFSX => HfsKind::Hfsx,
        _ => return None,
    };
    Some(HfsVolume {
        kind,
        version: be16(&hdr[2..4]),
        file_count: be32(&hdr[32..36]),
        folder_count: be32(&hdr[36..40]),
        block_size: be32(&hdr[40..44]),
        total_blocks: be32(&hdr[44..48]),
        free_blocks: be32(&hdr[48..52]),
    })
}

/// Catalog node ID of the root folder (TN1150).
const ROOT_FOLDER_CNID: u32 = 2;
/// Catalog record types (TN1150): folder / file leaf records.
const RECORD_FOLDER: i16 = 1;
const RECORD_FILE: i16 = 2;
/// Bound on catalog leaf nodes walked, guarding against a corrupt `fLink` chain.
pub(crate) const MAX_LEAF_NODES: u32 = 65536;

/// An entry in an HFS+ directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsEntry {
    /// File or folder name (decoded from UTF-16).
    pub name: String,
    /// True for a folder, false for a file.
    pub is_dir: bool,
    /// Catalog node ID (CNID) of this entry.
    pub cnid: u32,
}

/// Located catalog B-tree geometry within an HFS+ volume.
pub(crate) struct CatalogLoc {
    pub(crate) cat_base: usize,
    pub(crate) node_size: usize,
    pub(crate) first_leaf: u32,
    pub(crate) block_size: usize,
}

/// Volume-header byte offset of the extentsFile `HFSPlusForkData` (TN1150) —
/// the extents-overflow B-tree, holding extent records for files whose fork
/// outgrows its 8 inline extents.
pub(crate) const EXTENTS_FORK_OFFSET: usize = 192;
/// Volume-header byte offset of the catalogFile `HFSPlusForkData` (TN1150).
pub(crate) const CATALOG_FORK_OFFSET: usize = 272;
/// Volume-header byte offset of the attributesFile `HFSPlusForkData` (the
/// catalogFile's successor, 80 bytes later) — home of extended attributes,
/// including `com.apple.decmpfs`.
pub(crate) const ATTRIBUTES_FORK_OFFSET: usize = 352;

/// Locate the catalog B-tree from the volume header (its first extent).
pub(crate) fn locate_catalog(volume: &[u8]) -> Option<CatalogLoc> {
    locate_btree(volume, CATALOG_FORK_OFFSET)
}

/// Locate the attributes B-tree, or `None` when the volume has no attributes
/// file (its fork holds zero blocks — i.e. no extended attributes anywhere).
pub(crate) fn locate_attributes(volume: &[u8]) -> Option<CatalogLoc> {
    locate_btree(volume, ATTRIBUTES_FORK_OFFSET)
}

/// Locate the extents-overflow B-tree, or `None` when the volume has none.
pub(crate) fn locate_extents(volume: &[u8]) -> Option<CatalogLoc> {
    locate_btree(volume, EXTENTS_FORK_OFFSET)
}

/// Locate a B-tree whose first-extent `HFSPlusForkData` sits at
/// `fork_offset_in_header` bytes into the volume header. The catalog and
/// attributes files share the identical fork-data + B-tree-header layout.
pub(crate) fn locate_btree(volume: &[u8], fork_offset_in_header: usize) -> Option<CatalogLoc> {
    let h = VOLUME_HEADER_OFFSET;
    let fork = h.checked_add(fork_offset_in_header)?;
    if volume.len() < fork + 20 {
        return None;
    }
    match be16(&volume[h..h + 2]) {
        SIG_HFS_PLUS | SIG_HFSX => {}
        _ => return None,
    }
    let block_size = be32(&volume[h + 40..h + 44]) as usize;
    if block_size == 0 {
        return None;
    }
    // HFSPlusForkData: logicalSize(8) clumpSize(4) totalBlocks(4) extents(...).
    // A zero totalBlocks means the file does not exist (no attributes B-tree).
    if be32(&volume[fork + 12..fork + 16]) == 0 {
        return None;
    }
    // First extent's startBlock is at fork+16.
    let start_block = be32(&volume[fork + 16..fork + 20]) as usize;
    let cat_base = start_block.checked_mul(block_size)?;
    // B-tree header record follows the 14-byte node descriptor of node 0.
    let hdr = cat_base.checked_add(14)?;
    if volume.len() < hdr + 20 {
        return None;
    }
    let first_leaf = be32(&volume[hdr + 10..hdr + 14]);
    let node_size = be16(&volume[hdr + 18..hdr + 20]) as usize;
    if node_size < 14 {
        return None;
    }
    Some(CatalogLoc {
        cat_base,
        node_size,
        first_leaf,
        block_size,
    })
}

/// Walk the catalog leaf-node chain, invoking `f` with each record slice.
pub(crate) fn for_each_record(volume: &[u8], loc: &CatalogLoc, mut f: impl FnMut(&[u8])) {
    let mut node = loc.first_leaf;
    let mut walked = 0u32;
    while node != 0 && walked < MAX_LEAF_NODES {
        walked += 1;
        let Some(node_off) = (node as usize)
            .checked_mul(loc.node_size)
            .and_then(|x| x.checked_add(loc.cat_base))
        else {
            break;
        };
        if volume.len() < node_off + loc.node_size {
            break;
        }
        let nd = &volume[node_off..node_off + loc.node_size];
        let f_link = be32(&nd[0..4]);
        let num_records = be16(&nd[10..12]) as usize;
        for i in 0..num_records {
            // Record offsets are stored backwards from the node end.
            let Some(slot) = loc.node_size.checked_sub(2 * (i + 1)) else {
                break;
            };
            let rec = be16(&nd[slot..slot + 2]) as usize;
            if rec + 8 <= loc.node_size {
                f(&nd[rec..]);
            }
        }
        node = f_link;
    }
}

/// List the root directory of an HFS+ volume.  See [`list_dir`].
#[must_use]
pub fn list_root(volume: &[u8]) -> Option<Vec<HfsEntry>> {
    list_dir(volume, ROOT_FOLDER_CNID)
}

/// List the immediate children of the folder `parent_cnid` by walking the HFS+
/// catalog B-tree.
///
/// `volume` must contain the whole HFS+ volume from its first byte (header at
/// offset 1024).  Entries include HFS+ private metadata directories (real, not
/// hidden); thread records are skipped.  Returns `None` if this is not an HFS+
/// volume or the catalog cannot be located.  Assumes the catalog fits in its
/// first extent (true for typical optical/hybrid volumes).
#[must_use]
pub fn list_dir(volume: &[u8], parent_cnid: u32) -> Option<Vec<HfsEntry>> {
    let loc = locate_catalog(volume)?;
    let mut entries = Vec::new();
    for_each_record(volume, &loc, |rec| {
        if let Some((parent, entry)) = record_entry(rec) {
            if parent == parent_cnid {
                entries.push(entry);
            }
        }
    });
    Some(entries)
}

/// Read a file's data-fork contents by catalog node ID.
///
/// Returns the file's bytes (concatenated from its data-fork extents, truncated
/// to the logical size), or `None` if `cnid` is not a file in this volume.
/// Read a file's contents by catalog node ID.
///
/// For a normal file this returns the data fork (concatenated extents, truncated
/// to the logical size). For an HFS+/APFS **transparently-compressed** file —
/// one carrying a `com.apple.decmpfs` extended attribute — the data fork is
/// empty and the real bytes are decoded from the xattr (inline) or the resource
/// fork ([`decmpfs`]). Returns `None` if `cnid` is not a file, or if a
/// recognised compressed file cannot be decoded (it never returns a misleading
/// empty or raw data fork in that case).
#[must_use]
pub fn read_file(volume: &[u8], cnid: u32) -> Option<Vec<u8>> {
    let loc = locate_catalog(volume)?;
    let mut forks: Option<(Fork, Fork)> = None;
    for_each_record(volume, &loc, |rec| {
        if forks.is_none() {
            forks = file_forks(rec, cnid);
        }
    });
    let (data_fork, resource_fork) = forks?;

    if let Some(xattr) = decmpfs_xattr(volume, cnid) {
        let resource = if resource_fork.logical > 0 {
            fork_bytes(volume, loc.block_size, &resource_fork)
        } else {
            None
        };
        // Fail loud: a decmpfs file we cannot decode returns None, never the
        // empty data fork — silent data loss is the bug this whole path fixes.
        return decmpfs::decompress(&xattr, resource.as_deref()).ok();
    }

    fork_bytes(volume, loc.block_size, &data_fork)
}

/// Per-CNID metadata for one catalog entry: kind, data-fork size, and the three
/// HFS+ MAC timestamps. Timestamps are raw HFS+ values (`u32` seconds since the
/// HFS+ epoch, 1904-01-01 UTC) — a consumer converts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HfsStat {
    /// Catalog node ID this stat describes.
    pub cnid: u32,
    /// True for a folder, false for a file.
    pub is_dir: bool,
    /// Data-fork logical size in bytes (0 for a folder).
    pub size: u64,
    /// Creation time (HFS+ epoch seconds).
    pub created: u32,
    /// Content-modification time (HFS+ epoch seconds).
    pub modified: u32,
    /// Access time (HFS+ epoch seconds).
    pub accessed: u32,
}

/// Look up the [`HfsStat`] of a catalog entry by CNID, walking the catalog B-tree
/// to its file/folder record. Returns the entry's kind, data-fork logical size
/// (0 for a folder), and its three HFS+ MAC timestamps (raw, unconverted).
///
/// `volume` must contain the whole HFS+ volume from its first byte (header at
/// offset 1024). Returns `None` if this is not an HFS+ volume or no file/folder
/// record with `cnid` exists (thread records carry no times and are skipped).
#[must_use]
pub fn stat(volume: &[u8], cnid: u32) -> Option<HfsStat> {
    let loc = locate_catalog(volume)?;
    let mut found = None;
    for_each_record(volume, &loc, |rec| {
        if found.is_none() {
            found = record_stat(rec, cnid);
        }
    });
    found
}

/// If `rec` is the file or folder record for `cnid`, return its [`HfsStat`].
/// Both `HFSPlusCatalogFile` and `HFSPlusCatalogFolder` share createDate@+16,
/// contentModDate@+20, and accessDate@+28 (relative to the record body); the
/// file additionally carries its data-fork `HFSPlusForkData` at +88, whose
/// logicalSize is the first 8 bytes (TN1150).
fn record_stat(rec: &[u8], cnid: u32) -> Option<HfsStat> {
    if rec.len() < 8 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    let data = 2 + key_len;
    // Need through accessDate@+32 at minimum for either record kind.
    if data + 32 > rec.len() {
        return None;
    }
    let is_dir = match i16::from_be_bytes([rec[data], rec[data + 1]]) {
        RECORD_FOLDER => true,
        RECORD_FILE => false,
        _ => return None, // thread records and anything else carry no times
    };
    if be32(&rec[data + 8..data + 12]) != cnid {
        return None;
    }
    let created = be32(&rec[data + 16..data + 20]);
    let modified = be32(&rec[data + 20..data + 24]);
    let accessed = be32(&rec[data + 28..data + 32]);
    // A file record carries its data-fork logicalSize at +88 (8 bytes BE); a
    // folder has no fork, so its size is 0.
    let size = if is_dir {
        0
    } else if data + 96 <= rec.len() {
        u64::from_be_bytes(rec[data + 88..data + 96].try_into().ok()?)
    } else {
        0
    };
    Some(HfsStat {
        cnid,
        is_dir,
        size,
        created,
        modified,
        accessed,
    })
}

/// Parse a catalog record into `(parentID, entry)` for file/folder records.
fn record_entry(rec: &[u8]) -> Option<(u32, HfsEntry)> {
    if rec.len() < 8 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    let parent_id = be32(&rec[2..6]);
    let name_len = be16(&rec[6..8]) as usize;
    let name_end = 8 + name_len * 2;
    if name_end > rec.len() {
        return None;
    }
    let name = decode_utf16(&rec[8..name_end]);
    let data = 2 + key_len;
    if data + 12 > rec.len() {
        return None;
    }
    let is_dir = match i16::from_be_bytes([rec[data], rec[data + 1]]) {
        RECORD_FOLDER => true,
        RECORD_FILE => false,
        _ => return None, // thread records and anything else
    };
    // folderID / fileID at offset 8 of the folder/file record.
    let cnid = be32(&rec[data + 8..data + 12]);
    Some((parent_id, HfsEntry { name, is_dir, cnid }))
}

/// A file fork: logical size plus its (`start_block`, `block_count`) extents.
struct Fork {
    logical: u64,
    extents: Vec<(u32, u32)>,
}

/// `com.apple.decmpfs` extended-attribute name.
const DECMPFS_XATTR_NAME: &str = "com.apple.decmpfs";
/// `kHFSPlusAttrInlineData` — the attribute record type whose value is stored
/// inline (the only form the small decmpfs header ever uses).
const ATTR_INLINE_DATA: u32 = 0x10;

/// If `rec` is the file record for `cnid`, return its `(data_fork,
/// resource_fork)`. The file record holds the data fork's `HFSPlusForkData` at
/// +88 and the resource fork's at +168 (TN1150).
fn file_forks(rec: &[u8], cnid: u32) -> Option<(Fork, Fork)> {
    if rec.len() < 8 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    let data = 2 + key_len;
    if data + 168 > rec.len() {
        return None;
    }
    if i16::from_be_bytes([rec[data], rec[data + 1]]) != RECORD_FILE {
        return None;
    }
    if be32(&rec[data + 8..data + 12]) != cnid {
        return None;
    }
    let data_fork = parse_fork(&rec[data + 88..])?;
    // The resource fork follows the 80-byte data fork. A record truncated before
    // it means no resource fork (an empty one is harmless for non-compressed files).
    let resource_fork = if data + 248 <= rec.len() {
        parse_fork(&rec[data + 168..])?
    } else {
        Fork {
            logical: 0,
            extents: Vec::new(),
        }
    };
    Some((data_fork, resource_fork))
}

/// Parse an 80-byte `HFSPlusForkData`: logical size + up to 8 extents.
fn parse_fork(fork: &[u8]) -> Option<Fork> {
    if fork.len() < 80 {
        return None;
    }
    let logical = u64::from_be_bytes(fork[0..8].try_into().ok()?);
    let mut extents = Vec::new();
    for i in 0..8 {
        let e = 16 + i * 8;
        let start = be32(&fork[e..e + 4]);
        let count = be32(&fork[e + 4..e + 8]);
        if count != 0 {
            extents.push((start, count));
        }
    }
    Some(Fork { logical, extents })
}

/// Materialize a fork's bytes from `volume`, truncated to its logical size.
fn fork_bytes(volume: &[u8], block_size: usize, fork: &Fork) -> Option<Vec<u8>> {
    let logical = fork.logical as usize;
    let mut data = Vec::with_capacity(logical.min(1 << 20));
    for &(start, count) in &fork.extents {
        if data.len() >= logical {
            break;
        }
        let begin = (start as usize).checked_mul(block_size)?;
        let len = (count as usize).checked_mul(block_size)?;
        let end = begin.checked_add(len)?.min(volume.len());
        if begin >= volume.len() {
            break;
        }
        data.extend_from_slice(&volume[begin..end]);
    }
    data.truncate(logical);
    Some(data)
}

/// Look up the `com.apple.decmpfs` extended attribute for `cnid` by walking the
/// attributes B-tree. Returns `None` if the volume has no attributes file or the
/// file carries no such attribute (i.e. it is not transparently compressed).
pub(crate) fn decmpfs_xattr(volume: &[u8], cnid: u32) -> Option<Vec<u8>> {
    let loc = locate_attributes(volume)?;
    let mut found = None;
    for_each_record(volume, &loc, |rec| {
        if found.is_none() {
            found = attr_inline_value(rec, cnid, DECMPFS_XATTR_NAME);
        }
    });
    found
}

/// If `rec` is the inline-data attribute record for `(cnid, want_name)`, return
/// its value. `HFSPlusAttrKey`: keyLength(2) pad(2) fileID@4 startBlock@8
/// attrNameLen@12 attrName@14 (UTF-16 BE). `HFSPlusAttrData`: `recordType@key_end`
/// reserved[2] attrSize@+12 attrData@+16.
fn attr_inline_value(rec: &[u8], cnid: u32, want_name: &str) -> Option<Vec<u8>> {
    if rec.len() < 14 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    if be32(&rec[4..8]) != cnid {
        return None;
    }
    let name_len = be16(&rec[12..14]) as usize;
    let name_end = 14usize.checked_add(name_len.checked_mul(2)?)?;
    if name_end > rec.len() {
        return None;
    }
    if decode_utf16(&rec[14..name_end]) != want_name {
        return None;
    }
    let body = 2 + key_len;
    if body + 16 > rec.len() {
        return None;
    }
    if be32(&rec[body..body + 4]) != ATTR_INLINE_DATA {
        return None;
    }
    let attr_size = be32(&rec[body + 12..body + 16]) as usize;
    let end = body.checked_add(16)?.checked_add(attr_size)?;
    if end > rec.len() {
        return None;
    }
    Some(rec[body + 16..end].to_vec())
}

/// Decode a big-endian UTF-16 byte slice to a `String` (lossy).
pub(crate) fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

pub(crate) fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
pub(crate) fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// A path-qualified entry produced by [`walk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsPathEntry {
    /// `/`-joined path from the volume root (e.g. `"SUB/NESTED.TXT"`).
    pub path: String,
    /// True for a folder.
    pub is_dir: bool,
    /// Catalog node ID (CNID).
    pub cnid: u32,
}

/// Recursively list every file and folder in an HFS+ volume, depth-first from
/// the root, returning `/`-joined paths.
///
/// Returns `None` if this is not an HFS+ volume.  A visited-CNID set guards
/// against cycles in a corrupt catalog.
#[must_use]
pub fn walk(volume: &[u8]) -> Option<Vec<HfsPathEntry>> {
    // Confirm this is an HFS+ volume up front so a non-HFS buffer yields None.
    list_dir(volume, ROOT_FOLDER_CNID)?;
    let mut out = Vec::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(ROOT_FOLDER_CNID);
    let mut stack = vec![(ROOT_FOLDER_CNID, String::new())];
    while let Some((parent, prefix)) = stack.pop() {
        let Some(entries) = list_dir(volume, parent) else {
            continue;
        };
        for e in entries {
            let path = if prefix.is_empty() {
                e.name.clone()
            } else {
                format!("{prefix}/{}", e.name)
            };
            if e.is_dir && visited.insert(e.cnid) {
                stack.push((e.cnid, path.clone()));
            }
            out.push(HfsPathEntry {
                path,
                is_dir: e.is_dir,
                cnid: e.cnid,
            });
        }
    }
    Some(out)
}
