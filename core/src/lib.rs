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
#[cfg(feature = "vfs")]
pub mod vfs;

/// Byte offset of the HFS+ volume header from the start of the volume.
pub const VOLUME_HEADER_OFFSET: usize = 1024;
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
pub const MAX_LEAF_NODES: u32 = 65536;

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
pub struct CatalogLoc {
    pub cat_base: usize,
    pub node_size: usize,
    pub first_leaf: u32,
    pub block_size: usize,
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
pub fn locate_catalog(volume: &[u8]) -> Option<CatalogLoc> {
    locate_btree(volume, CATALOG_FORK_OFFSET)
}

/// Locate the attributes B-tree, or `None` when the volume has no attributes
/// file (its fork holds zero blocks — i.e. no extended attributes anywhere).
pub(crate) fn locate_attributes(volume: &[u8]) -> Option<CatalogLoc> {
    locate_btree(volume, ATTRIBUTES_FORK_OFFSET)
}

/// Locate the extents-overflow B-tree, or `None` when the volume has none.
pub fn locate_extents(volume: &[u8]) -> Option<CatalogLoc> {
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
///
/// Lenient: a node outside the volume or a chain past [`MAX_LEAF_NODES`] ends
/// the walk, and a record slot outside its node is skipped, all quietly. The
/// extended-attribute readers use the checked walk instead, which reports each.
pub fn for_each_record(volume: &[u8], loc: &CatalogLoc, mut f: impl FnMut(&[u8])) {
    let _ = walk_leaves(volume, loc, false, |rec| {
        f(rec);
        Ok(())
    });
}

/// The leaf-chain walk behind [`for_each_record`].
///
/// A node outside the volume and a chain past [`MAX_LEAF_NODES`] are errors in
/// both modes (the lenient caller discards them, which is the old quiet stop).
/// With `strict`, a node declaring more record offsets than it can hold, or a
/// record offset past its node, is an error too; leniently those are skipped.
/// `f` stops the walk by returning an error.
fn walk_leaves(
    volume: &[u8],
    loc: &CatalogLoc,
    strict: bool,
    mut f: impl FnMut(&[u8]) -> Result<(), HfsXattrError>,
) -> Result<(), HfsXattrError> {
    let mut node = loc.first_leaf;
    let mut walked = 0u32;
    while node != 0 {
        if walked >= MAX_LEAF_NODES {
            return Err(HfsXattrError::LeafChain {
                node,
                detail: format!(
                    "the fLink chain runs past {MAX_LEAF_NODES} leaf nodes, so it loops or is corrupt"
                ),
            });
        }
        walked += 1;
        let Some(nd) = (node as usize)
            .checked_mul(loc.node_size)
            .and_then(|x| x.checked_add(loc.cat_base))
            .and_then(|off| volume.get(off..off.checked_add(loc.node_size)?))
        else {
            return Err(HfsXattrError::LeafChain {
                node,
                detail: format!(
                    "node {node} ({}-byte nodes from byte {}) lies outside the {}-byte volume",
                    loc.node_size,
                    loc.cat_base,
                    volume.len()
                ),
            });
        };
        let f_link = be32(&nd[0..4]);
        let num_records = be16(&nd[10..12]) as usize;
        for i in 0..num_records {
            // Record offsets are stored backwards from the node end.
            let Some(slot) = loc.node_size.checked_sub(2 * (i + 1)) else {
                if strict {
                    return Err(HfsXattrError::LeafChain {
                        node,
                        detail: format!(
                            "node {node} declares {num_records} records, more offsets than a {}-byte node holds",
                            loc.node_size
                        ),
                    });
                }
                break;
            };
            let rec = be16(&nd[slot..slot + 2]) as usize;
            if rec + 8 <= loc.node_size {
                f(&nd[rec..])?;
            } else if strict {
                return Err(HfsXattrError::LeafChain {
                    node,
                    detail: format!(
                        "record {i} of node {node} starts at byte {rec}, past the {}-byte node",
                        loc.node_size
                    ),
                });
            }
        }
        node = f_link;
    }
    Ok(())
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
pub fn decmpfs_xattr(volume: &[u8], cnid: u32) -> Option<Vec<u8>> {
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

/// `kHFSPlusAttrForkData` — the attribute's value lives out in allocation
/// blocks rather than in the B-tree record, because it exceeded the inline
/// ceiling. `kHFSPlusAttrExtents` (0x30) continues such a fork's extent list.
const ATTR_FORK_DATA: u32 = 0x20;

/// How HFS+ chose to store an extended attribute's value.
///
/// This distinction is evidential, not an implementation detail: it says where
/// the bytes physically are. Collapsing the two would describe the artifact
/// wrongly, so the reader reports what the volume actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HfsXattrValue {
    /// `kHFSPlusAttrInlineData` — the value is in the attributes B-tree record.
    Inline(Vec<u8>),
    /// `kHFSPlusAttrForkData` — the value occupies allocation blocks, with the
    /// given logical length.
    Fork {
        /// Logical size in bytes, from the record's `HFSPlusForkData`.
        logical: u64,
    },
}

impl HfsXattrValue {
    /// The value's length in bytes, whichever way it is stored.
    #[must_use]
    pub fn len(&self) -> u64 {
        match self {
            Self::Inline(b) => b.len() as u64,
            Self::Fork { logical } => *logical,
        }
    }

    /// True when the attribute carries no bytes. (An attribute may legitimately
    /// exist with an empty value — its PRESENCE is the evidence.)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One extended attribute: its name and how the volume stored it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsXattr {
    /// Attribute name, decoded from the key's big-endian UTF-16.
    pub name: String,
    /// The stored value, or its length when it lives in a fork.
    pub value: HfsXattrValue,
}

/// Why an extended-attribute question could not be answered.
///
/// Each variant is damage or an unread structure, never absence: "no such
/// attribute" is an `Ok` empty list or `Ok(None)`, and an error here means the
/// volume could not say.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HfsXattrError {
    /// The volume header declares an attributes file (non-zero `totalBlocks`),
    /// but its B-tree header cannot be used.
    AttributesBtree {
        /// What is wrong with it.
        detail: String,
    },
    /// The attributes B-tree's leaf chain could not be walked to its end.
    LeafChain {
        /// The node where the walk stopped.
        node: u32,
        /// What is wrong with it.
        detail: String,
    },
    /// A record of this file's attributes could not be decoded.
    Record {
        /// The attribute's name, when the key was readable enough to give one.
        name: Option<String>,
        /// What is wrong with it.
        detail: String,
        /// The record's first bytes, as found.
        bytes: Vec<u8>,
    },
}

impl std::fmt::Display for HfsXattrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AttributesBtree { detail } => write!(f, "attributes B-tree unreadable: {detail}"),
            Self::LeafChain { node, detail } => {
                write!(
                    f,
                    "attributes B-tree leaf chain broken at node {node}: {detail}"
                )
            }
            Self::Record {
                name,
                detail,
                bytes,
            } => {
                let hex = bytes.iter().fold(String::new(), |mut s, b| {
                    let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
                    s
                });
                match name {
                    Some(n) => write!(f, "attribute {n}: {detail} (record starts {hex})"),
                    None => write!(f, "attribute record: {detail} (record starts {hex})"),
                }
            }
        }
    }
}

impl std::error::Error for HfsXattrError {}

/// The first bytes of a record, for an error that has to show what it found.
fn record_prefix(rec: &[u8]) -> Vec<u8> {
    rec[..rec.len().min(32)].to_vec()
}

/// The attributes B-tree, `Ok(None)` when the volume header says there is no
/// attributes file, and an error when it says there is one that cannot be used.
fn attributes_btree(volume: &[u8]) -> Result<Option<CatalogLoc>, HfsXattrError> {
    let fork = VOLUME_HEADER_OFFSET + ATTRIBUTES_FORK_OFFSET;
    let Some(total_blocks) = volume.get(fork + 12..fork + 16) else {
        return Err(HfsXattrError::AttributesBtree {
            detail: format!(
                "the {}-byte volume ends before the attributes fork record at byte {fork}",
                volume.len()
            ),
        });
    };
    if be32(total_blocks) == 0 {
        return Ok(None);
    }
    locate_attributes(volume)
        .map(Some)
        .ok_or_else(|| HfsXattrError::AttributesBtree {
            detail: format!(
                "the volume header declares {} attributes-file blocks, but the B-tree header is unusable (bad signature, block size, location or node size)",
                be32(total_blocks)
            ),
        })
}

/// List every extended attribute attached to `cnid`, in B-tree (name) order.
///
/// Returns an empty vector for a file with no attributes and for a volume whose
/// header declares no attributes file; neither is an error.
///
/// `kHFSPlusAttrExtents` (0x30) continuation records are skipped: they carry
/// further extents for a fork record already listed, so treating one as its own
/// attribute would report a duplicate under the same name.
///
/// # Errors
///
/// [`HfsXattrError`] when the attributes B-tree is declared but unusable, its
/// leaf chain cannot be walked to the end, or a record of this file cannot be
/// decoded (including a record type this reader does not know). The list would
/// otherwise be silently incomplete.
pub fn list_xattrs(volume: &[u8], cnid: u32) -> Result<Vec<HfsXattr>, HfsXattrError> {
    let Some(loc) = attributes_btree(volume)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    walk_leaves(volume, &loc, true, |rec| {
        if let Some(x) = parse_attr_record(rec, cnid)? {
            out.push(x);
        }
        Ok(())
    })?;
    Ok(out)
}

/// Read one extended attribute's bytes, materializing a fork-stored value from
/// its allocation blocks.
///
/// Returns `Ok(None)` when no attribute of that name is attached to `cnid`.
///
/// # Errors
///
/// As [`list_xattrs`], and when a fork-stored value's extents cannot be read
/// or cover less than its logical length. A short value is never returned as
/// if it were whole.
pub fn read_xattr(volume: &[u8], cnid: u32, name: &str) -> Result<Option<Vec<u8>>, HfsXattrError> {
    let Some(loc) = attributes_btree(volume)? else {
        return Ok(None);
    };
    // The attributes B-tree's own CatalogLoc already carries the volume's
    // allocation block size; re-deriving it from the header would be a second
    // source of truth for the same number.
    let block_size = loc.block_size;
    let mut found = None;
    walk_leaves(volume, &loc, true, |rec| {
        if found.is_some() {
            return Ok(());
        }
        // Re-parse rather than reuse list_xattrs: a fork-stored value needs the
        // record's extents, which the public type deliberately does not carry.
        let Some(key) = attr_key(rec, cnid)? else {
            return Ok(());
        };
        if key.name != name || key.start_block != 0 {
            return Ok(());
        }
        let body = key.body;
        found = Some(match be32(&rec[body..body + 4]) {
            ATTR_INLINE_DATA => inline_value(rec, &key)?,
            ATTR_FORK_DATA => {
                let fork = fork_record(rec, &key)?;
                let bytes = fork_bytes(volume, block_size, &fork).unwrap_or_default();
                if (bytes.len() as u64) < fork.logical {
                    return Err(HfsXattrError::Record {
                        name: Some(key.name),
                        detail: format!(
                            "its extents yield {} of its {} bytes; the rest is in kHFSPlusAttrExtents records or past the volume end, and this reader does not assemble it",
                            bytes.len(),
                            fork.logical
                        ),
                        bytes: record_prefix(rec),
                    });
                }
                bytes
            }
            other => return Err(unknown_record_type(rec, key, other)),
        });
        Ok(())
    })?;
    Ok(found)
}

/// The parsed key of an attribute record, when it belongs to `cnid`.
struct AttrKey {
    name: String,
    /// Offset of the record BODY (`recordType`), i.e. just past the key.
    body: usize,
    /// First allocation block this record describes. Non-zero only on
    /// `kHFSPlusAttrExtents` continuation records.
    start_block: u32,
}

/// Parse `HFSPlusAttrKey`: keyLength(2) pad(2) fileID@4 startBlock@8
/// attrNameLen@12 attrName@14 (UTF-16 BE).
///
/// `Ok(None)` for a record of another file. A key too short to name its file is
/// an error: it might be this file's, so skipping it could hide an attribute.
fn attr_key(rec: &[u8], cnid: u32) -> Result<Option<AttrKey>, HfsXattrError> {
    let damaged = |name: Option<String>, detail: String| HfsXattrError::Record {
        name,
        detail,
        bytes: record_prefix(rec),
    };
    if rec.len() < 14 {
        return Err(damaged(
            None,
            format!(
                "a {}-byte record is too short for its 14-byte key header",
                rec.len()
            ),
        ));
    }
    let key_len = be16(&rec[0..2]) as usize;
    if be32(&rec[4..8]) != cnid {
        return Ok(None);
    }
    let start_block = be32(&rec[8..12]);
    let name_len = be16(&rec[12..14]) as usize;
    let name_end = 14 + name_len * 2;
    let Some(name_bytes) = rec.get(14..name_end) else {
        return Err(damaged(
            None,
            format!(
                "its {name_len}-character name runs past the {}-byte record",
                rec.len()
            ),
        ));
    };
    let name = decode_utf16(name_bytes);
    let body = 2 + key_len;
    // Every record body starts with a 4-byte recordType.
    if body + 4 > rec.len() {
        return Err(damaged(
            Some(name),
            format!(
                "keyLength {key_len} puts the record body past the {}-byte record",
                rec.len()
            ),
        ));
    }
    Ok(Some(AttrKey {
        name,
        body,
        start_block,
    }))
}

/// `HFSPlusAttrData`: recordType@0 reserved[2]@4 attrSize@12 attrData@16.
fn inline_value(rec: &[u8], key: &AttrKey) -> Result<Vec<u8>, HfsXattrError> {
    let body = key.body;
    let size = rec.get(body + 12..body + 16).map(|b| be32(b) as usize);
    match size.and_then(|n| rec.get(body + 16..body + 16 + n)) {
        Some(v) => Ok(v.to_vec()),
        None => Err(HfsXattrError::Record {
            name: Some(key.name.clone()),
            detail: match size {
                Some(n) => format!(
                    "its inline attrSize {n} runs past the {}-byte record",
                    rec.len()
                ),
                None => format!(
                    "the {}-byte record ends inside its inline-data header",
                    rec.len()
                ),
            },
            bytes: record_prefix(rec),
        }),
    }
}

/// `HFSPlusAttrForkData`: recordType(4) reserved(4) theFork(80)@8.
fn fork_record(rec: &[u8], key: &AttrKey) -> Result<Fork, HfsXattrError> {
    rec.get(key.body + 8..)
        .and_then(parse_fork)
        .ok_or_else(|| HfsXattrError::Record {
            name: Some(key.name.clone()),
            detail: format!(
                "the {}-byte record ends inside its 80-byte fork data",
                rec.len()
            ),
            bytes: record_prefix(rec),
        })
}

/// A record type this reader does not decode. Reported with the value found
/// rather than skipped: skipping would present the attribute as absent.
fn unknown_record_type(rec: &[u8], key: AttrKey, record_type: u32) -> HfsXattrError {
    HfsXattrError::Record {
        name: Some(key.name),
        detail: format!("record type 0x{record_type:08x} is not one this reader decodes"),
        bytes: record_prefix(rec),
    }
}

/// Turn one attributes-B-tree record into an [`HfsXattr`], if it is a listable
/// attribute belonging to `cnid`.
fn parse_attr_record(rec: &[u8], cnid: u32) -> Result<Option<HfsXattr>, HfsXattrError> {
    let Some(key) = attr_key(rec, cnid)? else {
        return Ok(None);
    };
    // A continuation record describes more extents for a fork already listed.
    if key.start_block != 0 {
        return Ok(None);
    }
    let body = key.body;
    let value = match be32(&rec[body..body + 4]) {
        ATTR_INLINE_DATA => HfsXattrValue::Inline(inline_value(rec, &key)?),
        ATTR_FORK_DATA => HfsXattrValue::Fork {
            logical: fork_record(rec, &key)?.logical,
        },
        other => return Err(unknown_record_type(rec, key, other)),
    };
    Ok(Some(HfsXattr {
        name: key.name,
        value,
    }))
}

/// Decode a big-endian UTF-16 byte slice to a `String` (lossy).
pub fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
pub fn be32(b: &[u8]) -> u32 {
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
