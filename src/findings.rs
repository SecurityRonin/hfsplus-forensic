//! HFS+ forensic findings: graded anomaly classification over the structures the
//! [reader](crate) already parses (volume header, catalog B-tree, extents-overflow
//! B-tree, file forks, `com.apple.decmpfs` attributes).
//!
//! Mirrors the sibling filesystem/partition crates (`iso9660-forensic`,
//! `gpt-forensic`): every anomaly's severity, stable machine-readable `HFS-*`
//! code, and human-readable note are *derived* from its [`AnomalyKind`], so they
//! cannot drift. Each finding is an **observation** ("consistent with …"), never
//! a verdict — the analyst draws the conclusion. The whole analyzer is
//! panic-free and bounds-checked, like the reader it sits over.
//!
//! A disk-forensic orchestrator aggregates these uniformly via
//! [`forensicnomicon::report::Observation`], which `Anomaly` implements.

use core::fmt;

use crate::{
    be16, be32, decmpfs_xattr, decode_utf16, for_each_record, locate_catalog, locate_extents,
    CatalogLoc, VOLUME_HEADER_OFFSET,
};

/// The canonical 5-level severity scale, shared across every SecurityRonin
/// analyzer via [`forensicnomicon::report`].
pub use forensicnomicon::report::Severity;

/// Seconds between the HFS+ epoch (1904-01-01) and the Unix epoch (1970-01-01).
/// A non-zero HFS+ timestamp below this is impossible (it predates the epoch).
const HFS_EPOCH_TO_UNIX: u32 = 2_082_844_800;

/// Catalog record types (TN1150).
const RECORD_FOLDER: i16 = 1;
const RECORD_FILE: i16 = 2;
const RECORD_FOLDER_THREAD: i16 = 3;
const RECORD_FILE_THREAD: i16 = 4;

/// B-tree node descriptor `kind` values (TN1150): leaf is stored as `-1`
/// (`0xFF`), index `0`, header `1`, map `2`.
const NODE_LEAF: i8 = -1;
const NODE_INDEX: i8 = 0;
const NODE_HEADER: i8 = 1;
const NODE_MAP: i8 = 2;

impl forensicnomicon::report::Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
}

/// Classification of an HFS+ forensic anomaly. Each variant carries the evidence
/// needed to reproduce the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A catalog or extents-overflow B-tree node's descriptor is internally
    /// inconsistent — an undocumented `kind`, a leaf node claiming a non-leaf
    /// height (or vice versa), or a forward/back link pointing at itself or
    /// outside the tree. The reader walks the leaf chain by these links, so a
    /// bad descriptor is consistent with structural corruption or with an edit
    /// that rewired the tree to hide or strand records.
    BtreeNodeInvalid {
        /// Which B-tree: `catalog` or `extents`.
        tree: String,
        /// 0-based node number within the B-tree.
        node: u32,
        /// What is inconsistent (the offending value + expectation).
        detail: String,
    },

    /// A file's catalog data-fork size disagrees with the blocks its extents
    /// actually allocate, and no extents-overflow record makes up the
    /// difference. The catalog and the extents B-tree are HFS+'s two records of
    /// a file's allocation and must agree; a divergence is consistent with a
    /// truncated/edited extent list or a forged size.
    CatalogExtentsMismatch {
        /// Catalog node ID of the file.
        cnid: u32,
        /// File name from the catalog key.
        name: String,
        /// Logical data-fork size in bytes (from the catalog file record).
        logical: u64,
        /// Allocation blocks the catalog + overflow extents actually cover.
        allocated_blocks: u32,
        /// Allocation blocks the logical size requires.
        needed_blocks: u32,
    },

    /// A CNID is referenced by a thread record (HFS+ stores a thread per
    /// file/folder so a CNID resolves back to its parent + name) but no
    /// file/folder catalog record with that CNID exists. The thread is a
    /// dangling reference — consistent with the record having been deleted while
    /// its thread leaked, leaving a recoverable name/parent for vanished content.
    DeletedButReferenced {
        /// The dangling CNID referenced by the orphan thread.
        cnid: u32,
        /// Parent CNID the thread points to.
        parent: u32,
        /// Name the thread records for the missing entry.
        name: String,
    },

    /// A file/folder timestamp is impossible: its creation time is later than
    /// its content-modification time, or a non-zero timestamp falls before the
    /// HFS+ epoch (1904) or after the volume's own last-written date. Consistent
    /// with a backdated/forged timestamp or with timestamp corruption.
    TimeAnomaly {
        /// Catalog node ID of the entry.
        cnid: u32,
        /// Entry name from the catalog key.
        name: String,
        /// Which relation failed (the two times involved).
        detail: String,
    },

    /// A file is flagged transparently compressed (it carries a
    /// `com.apple.decmpfs` extended attribute) but the payload the attribute
    /// points to is absent or truncated — a resource-fork type whose resource
    /// fork is empty/too small, or an inline type whose xattr is truncated.
    /// `read_file` would fail to materialize the file; consistent with the
    /// payload having been removed (data destruction) or partial corruption.
    DecmpfsMissingResource {
        /// Catalog node ID of the compressed file.
        cnid: u32,
        /// File name from the catalog key.
        name: String,
        /// decmpfs `compression_type` from the xattr header.
        compression_type: u32,
        /// Why the payload is unusable (storage kind + what is missing).
        detail: String,
    },
}

impl AnomalyKind {
    /// Severity assigned to this kind — the single source of truth.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            // A rewired/invalid B-tree node can strand or hide whole subtrees.
            AnomalyKind::BtreeNodeInvalid { .. } => Severity::High,
            // The two allocation records disagreeing points at edited metadata.
            AnomalyKind::CatalogExtentsMismatch { .. } => Severity::High,
            // A leaked thread is recoverable-deletion evidence, not destruction.
            AnomalyKind::DeletedButReferenced { .. } => Severity::Medium,
            AnomalyKind::TimeAnomaly { .. } => Severity::Medium,
            // The compressed payload is gone — the file cannot be read back.
            AnomalyKind::DecmpfsMissingResource { .. } => Severity::High,
        }
    }

    /// Stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::BtreeNodeInvalid { .. } => "HFS-BTREE-NODE-INVALID",
            AnomalyKind::CatalogExtentsMismatch { .. } => "HFS-CATALOG-EXTENTS-MISMATCH",
            AnomalyKind::DeletedButReferenced { .. } => "HFS-DELETED-BUT-REFERENCED",
            AnomalyKind::TimeAnomaly { .. } => "HFS-TIME-ANOMALY",
            AnomalyKind::DecmpfsMissingResource { .. } => "HFS-DECMPFS-MISSING-RESOURCE",
        }
    }

    /// Human-readable description (observation, not a conclusion).
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::BtreeNodeInvalid { tree, node, detail } => format!(
                "{tree} B-tree node {node}: {detail} — the reader walks the leaf chain by these \
                 node links/descriptors, so an inconsistent descriptor is consistent with \
                 structural corruption or an edit that rewired the tree to hide or strand records"
            ),
            AnomalyKind::CatalogExtentsMismatch {
                cnid,
                name,
                logical,
                allocated_blocks,
                needed_blocks,
            } => format!(
                "file `{name}` (CNID {cnid}) declares a {logical}-byte data fork needing \
                 {needed_blocks} allocation block(s) but its catalog + extents-overflow extents \
                 cover only {allocated_blocks} — the catalog and extents B-tree are HFS+'s two \
                 records of a file's allocation and must agree; a divergence is consistent with a \
                 truncated/edited extent list or a forged size"
            ),
            AnomalyKind::DeletedButReferenced { cnid, parent, name } => format!(
                "CNID {cnid} (`{name}`, parent {parent}) has a thread record but no file/folder \
                 catalog record — the thread is a dangling reference, consistent with the record \
                 having been deleted while its thread leaked, leaving a recoverable name/parent \
                 for vanished content"
            ),
            AnomalyKind::TimeAnomaly { cnid, name, detail } => format!(
                "entry `{name}` (CNID {cnid}): {detail} — consistent with a backdated/forged \
                 timestamp or with timestamp corruption"
            ),
            AnomalyKind::DecmpfsMissingResource {
                cnid,
                name,
                compression_type,
                detail,
            } => format!(
                "file `{name}` (CNID {cnid}) carries a com.apple.decmpfs attribute \
                 (compression_type {compression_type}) but {detail} — `read_file` cannot \
                 materialize it; consistent with the compressed payload having been removed (data \
                 destruction) or partial corruption"
            ),
        }
    }
}

/// A single HFS+ anomaly with derived severity/code/note.
#[derive(Debug, Clone)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind` so they
    /// cannot drift from the classification.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl fmt::Display for Anomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.code, self.note)
    }
}

/// A file's data fork as seen in its catalog record.
#[cfg_attr(test, derive(Debug))]
struct CatalogFile {
    cnid: u32,
    name: String,
    logical: u64,
    /// Allocation blocks covered by the up-to-8 inline catalog extents.
    inline_blocks: u32,
    /// True when the catalog record uses all 8 extent slots — the file *may*
    /// continue in the extents-overflow B-tree (TN1150).
    extents_full: bool,
    create: u32,
    content_mod: u32,
    has_resource_fork: bool,
    resource_logical: u64,
    resource_blocks: u32,
}

/// Audit an HFS+/HFSX volume, returning every observed anomaly. `volume` must
/// contain the whole volume from its first byte (header at offset 1024). A
/// non-HFS or unparseable buffer yields no anomalies (the reader's `parse`
/// returns `None`); this never panics on malformed input.
#[must_use]
pub fn audit(volume: &[u8]) -> Vec<Anomaly> {
    let Some(cat) = locate_catalog(volume) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // 1. B-tree structural integrity (catalog + extents-overflow).
    audit_btree_nodes(volume, &cat, "catalog", &mut out);
    if let Some(ext) = locate_extents(volume) {
        audit_btree_nodes(volume, &ext, "extents", &mut out);
    }

    // 2. Collect catalog records: file/folder CNIDs, files, thread targets.
    let mut record_cnids: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut files: Vec<CatalogFile> = Vec::new();
    let mut threads: Vec<(u32, u32, String)> = Vec::new(); // (cnid, parent, name)

    for_each_record(volume, &cat, |rec| match classify_record(rec) {
        Some(CatalogRecord::Entry { cnid, file }) => {
            record_cnids.insert(cnid);
            if let Some(f) = file {
                files.push(f);
            }
        }
        Some(CatalogRecord::Thread { cnid, parent, name }) => {
            threads.push((cnid, parent, name));
        }
        None => {}
    });

    // 3. Dangling thread references (deleted-but-referenced).
    for (cnid, parent, name) in &threads {
        if !record_cnids.contains(cnid) {
            out.push(Anomaly::new(AnomalyKind::DeletedButReferenced {
                cnid: *cnid,
                parent: *parent,
                name: name.clone(),
            }));
        }
    }

    // 4. Per-file timestamp, extents, and decmpfs integrity checks.
    let volume_modify = be32(&volume[VOLUME_HEADER_OFFSET + 20..VOLUME_HEADER_OFFSET + 24]);
    let block_size = cat.block_size.max(1) as u64;
    let ext_loc = locate_extents(volume);
    for f in &files {
        audit_time(f, volume_modify, &mut out);
        audit_extents(volume, f, block_size, ext_loc.as_ref(), &mut out);
        audit_decmpfs(volume, f, &mut out);
    }

    out
}

/// Walk a B-tree's whole node array (node 0 .. last by file size in the first
/// extent isn't known here, so bound by what the leaf chain plus the index
/// reach), checking each node descriptor for internal consistency. We check the
/// nodes actually reachable from the leaf chain — the same nodes the reader
/// trusts — plus node 0 (the header node).
fn audit_btree_nodes(volume: &[u8], loc: &CatalogLoc, tree: &str, out: &mut Vec<Anomaly>) {
    // Node 0 is the header node; its descriptor kind must be NODE_HEADER.
    check_node(volume, loc, 0, tree, out);

    // Follow the leaf chain (the reader's navigation path) and validate each.
    let mut node = loc.first_leaf;
    let mut walked = 0u32;
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    while node != 0 && walked < crate::MAX_LEAF_NODES {
        walked += 1;
        if !seen.insert(node) {
            // A node revisited means the forward-link chain loops.
            out.push(Anomaly::new(AnomalyKind::BtreeNodeInvalid {
                tree: tree.to_string(),
                node,
                detail: format!("forward-link chain loops back to already-visited node {node}"),
            }));
            break;
        }
        let Some(nd) = node_slice(volume, loc, node) else {
            break; // cov:unreachable: the reader bounds-checks identical node math
        };
        check_node(volume, loc, node, tree, out);
        node = be32(&nd[0..4]);
    }
}

/// Validate a single node's descriptor; push a finding for each inconsistency.
fn check_node(volume: &[u8], loc: &CatalogLoc, node: u32, tree: &str, out: &mut Vec<Anomaly>) {
    let Some(nd) = node_slice(volume, loc, node) else {
        return; // cov:unreachable: callers pass in-bounds nodes
    };
    let f_link = be32(&nd[0..4]);
    let b_link = be32(&nd[4..8]);
    let kind = nd[8] as i8;
    let height = nd[9];

    let kind_ok = matches!(kind, NODE_LEAF | NODE_INDEX | NODE_HEADER | NODE_MAP);
    if !kind_ok {
        out.push(Anomaly::new(AnomalyKind::BtreeNodeInvalid {
            tree: tree.to_string(),
            node,
            detail: format!(
                "undocumented node kind {kind} (expected leaf -1, index 0, header 1, or map 2)"
            ),
        }));
    }

    // A leaf node lives at height 1; an index node at height > 1; the header
    // node at height 0. A leaf claiming height 0, or a self-referential link,
    // is structurally impossible (TN1150).
    if kind == NODE_LEAF && height == 0 {
        out.push(Anomaly::new(AnomalyKind::BtreeNodeInvalid {
            tree: tree.to_string(),
            node,
            detail: format!("leaf node at height {height} (a leaf must sit at height >= 1)"),
        }));
    }
    if kind == NODE_HEADER && node != 0 {
        out.push(Anomaly::new(AnomalyKind::BtreeNodeInvalid {
            tree: tree.to_string(),
            node,
            detail: format!(
                "header-kind descriptor on node {node} (the header node must be node 0)"
            ),
        }));
    }
    // A link value of 0 is the "no neighbour" sentinel (valid). A *non-zero*
    // link equal to this node's own number is an impossible self-reference.
    if (f_link != 0 && f_link == node) || (b_link != 0 && b_link == node) {
        out.push(Anomaly::new(AnomalyKind::BtreeNodeInvalid {
            tree: tree.to_string(),
            node,
            detail: format!(
                "node links point at itself (fLink {f_link}, bLink {b_link}) — a node cannot be \
                 its own neighbour"
            ),
        }));
    }
}

/// Slice the `node_size` bytes of node `n`, or `None` if out of bounds.
fn node_slice<'a>(volume: &'a [u8], loc: &CatalogLoc, n: u32) -> Option<&'a [u8]> {
    let off = (n as usize)
        .checked_mul(loc.node_size)?
        .checked_add(loc.cat_base)?;
    let end = off.checked_add(loc.node_size)?;
    if end > volume.len() || loc.node_size < 14 {
        return None; // cov:unreachable: callers pass nodes the reader already bounds-checked; node_size >= 14 holds from locate_btree
    }
    Some(&volume[off..end])
}

/// A classified catalog record.
#[cfg_attr(test, derive(Debug))]
enum CatalogRecord {
    Entry {
        cnid: u32,
        file: Option<CatalogFile>,
    },
    Thread {
        cnid: u32,
        parent: u32,
        name: String,
    },
}

/// Parse a catalog leaf record into a classified form.
fn classify_record(rec: &[u8]) -> Option<CatalogRecord> {
    if rec.len() < 8 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    let name_len = be16(&rec[6..8]) as usize;
    let name_end = 8usize.checked_add(name_len.checked_mul(2)?)?;
    if name_end > rec.len() {
        return None;
    }
    let key_name = decode_utf16(&rec[8..name_end]);
    let data = 2usize.checked_add(key_len)?;
    if data.checked_add(2)? > rec.len() {
        return None;
    }
    let rtype = i16::from_be_bytes([rec[data], rec[data + 1]]);
    match rtype {
        RECORD_FOLDER => {
            if data.checked_add(12)? > rec.len() {
                return None;
            }
            let cnid = be32(&rec[data + 8..data + 12]);
            Some(CatalogRecord::Entry { cnid, file: None })
        }
        RECORD_FILE => {
            if data.checked_add(248)? > rec.len() {
                // A file record is 248 bytes; a shorter slice is malformed but
                // we still know its CNID if the header fits.
                if data.checked_add(12)? <= rec.len() {
                    let cnid = be32(&rec[data + 8..data + 12]);
                    return Some(CatalogRecord::Entry { cnid, file: None });
                }
                return None;
            }
            let cnid = be32(&rec[data + 8..data + 12]);
            let create = be32(&rec[data + 16..data + 20]);
            let content_mod = be32(&rec[data + 20..data + 24]);
            // Data fork HFSPlusForkData @ data+88, resource fork @ data+168.
            let logical = u64::from_be_bytes(rec[data + 88..data + 96].try_into().ok()?);
            let inline_blocks = fork_inline_blocks(&rec[data + 88..]);
            let extents_full = fork_all_slots_used(&rec[data + 88..]);
            let resource_logical = u64::from_be_bytes(rec[data + 168..data + 176].try_into().ok()?);
            let resource_blocks = fork_inline_blocks(&rec[data + 168..]);
            Some(CatalogRecord::Entry {
                cnid,
                file: Some(CatalogFile {
                    cnid,
                    name: key_name,
                    logical,
                    inline_blocks,
                    extents_full,
                    create,
                    content_mod,
                    has_resource_fork: resource_logical > 0,
                    resource_logical,
                    resource_blocks,
                }),
            })
        }
        RECORD_FOLDER_THREAD | RECORD_FILE_THREAD => {
            // Thread: recordType(2) reserved(2) parentID(4) nodeName(len+UTF16).
            if data.checked_add(10)? > rec.len() {
                return None;
            }
            // The thread's *key* parent is the CNID it represents.
            let cnid = be32(&rec[2..6]);
            let parent = be32(&rec[data + 4..data + 8]);
            let tnl = be16(&rec[data + 8..data + 10]) as usize;
            let tn_end = (data + 10).checked_add(tnl.checked_mul(2)?)?;
            let name = if tn_end <= rec.len() {
                decode_utf16(&rec[data + 10..tn_end])
            } else {
                String::new()
            };
            Some(CatalogRecord::Thread { cnid, parent, name })
        }
        _ => None,
    }
}

/// Sum the allocation blocks of the up-to-8 inline extents of an
/// `HFSPlusForkData` (logicalSize(8) clumpSize(4) totalBlocks(4) extents(64)).
fn fork_inline_blocks(fork: &[u8]) -> u32 {
    if fork.len() < 80 {
        return 0;
    }
    let mut total: u32 = 0;
    for i in 0..8 {
        let e = 16 + i * 8;
        let count = be32(&fork[e + 4..e + 8]);
        total = total.saturating_add(count);
    }
    total
}

/// True when all 8 inline extent slots carry a non-zero block count — the file
/// may continue in the extents-overflow B-tree.
fn fork_all_slots_used(fork: &[u8]) -> bool {
    if fork.len() < 80 {
        return false;
    }
    (0..8).all(|i| {
        let e = 16 + i * 8;
        be32(&fork[e + 4..e + 8]) != 0
    })
}

/// Sum the extents-overflow allocation blocks recorded for `(cnid, fork_type)`.
/// `fork_type` is 0 for the data fork, 0xFF for the resource fork (TN1150).
fn overflow_blocks(volume: &[u8], loc: &CatalogLoc, cnid: u32, fork_type: u8) -> u32 {
    let mut total: u32 = 0;
    for_each_record(volume, loc, |rec| {
        // HFSPlusExtentKey: keyLength(2) forkType(1) pad(1) fileID(4) startBlock(4),
        // then the HFSPlusExtentRecord: 8 * (startBlock(4), blockCount(4)).
        if rec.len() < 12 {
            return; // cov:unreachable: a well-formed extents-overflow key is >= 12 bytes (keyLength..startBlock)
        }
        if rec[2] != fork_type {
            return;
        }
        if be32(&rec[4..8]) != cnid {
            return;
        }
        let key_len = be16(&rec[0..2]) as usize;
        let data = 2 + key_len;
        for i in 0..8 {
            let e = data + i * 8;
            if e + 8 > rec.len() {
                break; // cov:unreachable: a full HFSPlusExtentRecord holds all 8 (start,count) pairs within the record
            }
            total = total.saturating_add(be32(&rec[e + 4..e + 8]));
        }
    });
    total
}

/// Number of allocation blocks a `logical`-byte fork needs at `block_size`.
fn needed_blocks(logical: u64, block_size: u64) -> u32 {
    logical.div_ceil(block_size).min(u64::from(u32::MAX)) as u32
}

fn audit_time(f: &CatalogFile, volume_modify: u32, out: &mut Vec<Anomaly>) {
    // create > contentMod: a file modified before it was created is impossible.
    if f.create > f.content_mod && f.content_mod != 0 {
        out.push(Anomaly::new(AnomalyKind::TimeAnomaly {
            cnid: f.cnid,
            name: f.name.clone(),
            detail: format!(
                "creation time {} is later than content-modification time {} (a file cannot be \
                 modified before it is created)",
                f.create, f.content_mod
            ),
        }));
        return;
    }
    // A non-zero timestamp below the epoch boundary predates 1904 — impossible.
    for (label, t) in [
        ("creation", f.create),
        ("content-modification", f.content_mod),
    ] {
        if t != 0 && t < HFS_EPOCH_TO_UNIX {
            out.push(Anomaly::new(AnomalyKind::TimeAnomaly {
                cnid: f.cnid,
                name: f.name.clone(),
                detail: format!(
                    "{label} time {t} predates the HFS+ epoch boundary (before 1904 — impossible)"
                ),
            }));
            return;
        }
    }
    // A timestamp after the volume's own last-written date is impossible: the
    // volume header is rewritten on every change, so nothing inside can be newer.
    // A zero volume_modify means "unknown" and disables this check.
    for (label, t) in [
        ("creation", f.create),
        ("content-modification", f.content_mod),
    ] {
        if volume_modify != 0 && t > volume_modify {
            out.push(Anomaly::new(AnomalyKind::TimeAnomaly {
                cnid: f.cnid,
                name: f.name.clone(),
                detail: format!(
                    "{label} time {t} is after the volume's last-written date {volume_modify} \
                     (nothing inside a volume can postdate the volume header)"
                ),
            }));
            return;
        }
    }
}

fn audit_extents(
    volume: &[u8],
    f: &CatalogFile,
    block_size: u64,
    ext_loc: Option<&CatalogLoc>,
    out: &mut Vec<Anomaly>,
) {
    let needed = needed_blocks(f.logical, block_size);
    let mut allocated = f.inline_blocks;
    // Only consult the extents-overflow B-tree when the inline slots are full —
    // a file with spare inline slots never spills over (TN1150), so an overflow
    // lookup there would be meaningless.
    if f.extents_full {
        if let Some(ext) = ext_loc {
            allocated = allocated.saturating_add(overflow_blocks(volume, ext, f.cnid, 0));
        }
    }
    if allocated < needed {
        out.push(Anomaly::new(AnomalyKind::CatalogExtentsMismatch {
            cnid: f.cnid,
            name: f.name.clone(),
            logical: f.logical,
            allocated_blocks: allocated,
            needed_blocks: needed,
        }));
    }
}

fn audit_decmpfs(volume: &[u8], f: &CatalogFile, out: &mut Vec<Anomaly>) {
    let Some(xattr) = decmpfs_xattr(volume, f.cnid) else {
        return;
    };
    // Parse the 16-byte decmpfs header (magic 'cmpf' LE, type LE, size LE).
    if xattr.len() < forensicnomicon::decmpfs::HEADER_LEN {
        out.push(Anomaly::new(AnomalyKind::DecmpfsMissingResource {
            cnid: f.cnid,
            name: f.name.clone(),
            compression_type: 0,
            detail: format!(
                "its com.apple.decmpfs xattr is {} bytes, shorter than the 16-byte decmpfs header",
                xattr.len()
            ),
        }));
        return;
    }
    let off = forensicnomicon::decmpfs::COMPRESSION_TYPE_OFFSET;
    let compression_type =
        u32::from_le_bytes([xattr[off], xattr[off + 1], xattr[off + 2], xattr[off + 3]]);
    let Some(compression) = forensicnomicon::decmpfs::classify(compression_type) else {
        // Unknown/undocumented type — the reader fails loud on read; report the
        // raw type so an analyst can identify it.
        out.push(Anomaly::new(AnomalyKind::DecmpfsMissingResource {
            cnid: f.cnid,
            name: f.name.clone(),
            compression_type,
            detail: "its compression_type is not a documented decmpfs type (read_file refuses it)"
                .to_string(),
        }));
        return;
    };

    match compression.storage {
        forensicnomicon::decmpfs::Storage::ResourceFork => {
            if !f.has_resource_fork || f.resource_logical == 0 {
                out.push(Anomaly::new(AnomalyKind::DecmpfsMissingResource {
                    cnid: f.cnid,
                    name: f.name.clone(),
                    compression_type,
                    detail: "it declares resource-fork storage but its resource fork is empty"
                        .to_string(),
                }));
            } else if f.resource_blocks == 0 {
                out.push(Anomaly::new(AnomalyKind::DecmpfsMissingResource {
                    cnid: f.cnid,
                    name: f.name.clone(),
                    compression_type,
                    detail: format!(
                        "it declares a {}-byte resource fork but the fork allocates zero blocks \
                         (the payload is unrecoverable)",
                        f.resource_logical
                    ),
                }));
            }
        }
        forensicnomicon::decmpfs::Storage::Inline => {
            // Inline payload follows the 16-byte header in the xattr. An xattr
            // that is exactly the header (no payload) cannot decode to anything.
            if xattr.len() == forensicnomicon::decmpfs::HEADER_LEN {
                out.push(Anomaly::new(AnomalyKind::DecmpfsMissingResource {
                    cnid: f.cnid,
                    name: f.name.clone(),
                    compression_type,
                    detail: "it declares inline storage but the xattr holds only the header, with \
                             no payload following it"
                        .to_string(),
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::report::Observation;

    /// Every `AnomalyKind` derives a stable code, a grade, and a note that reads
    /// as an observation — never a verdict.
    fn all_kinds() -> Vec<AnomalyKind> {
        vec![
            AnomalyKind::BtreeNodeInvalid {
                tree: "catalog".into(),
                node: 7,
                detail: "undocumented node kind 66".into(),
            },
            AnomalyKind::CatalogExtentsMismatch {
                cnid: 18,
                name: "A.TXT".into(),
                logical: 9000,
                allocated_blocks: 1,
                needed_blocks: 3,
            },
            AnomalyKind::DeletedButReferenced {
                cnid: 42,
                parent: 2,
                name: "GONE".into(),
            },
            AnomalyKind::TimeAnomaly {
                cnid: 18,
                name: "A.TXT".into(),
                detail: "creation later than modification".into(),
            },
            AnomalyKind::DecmpfsMissingResource {
                cnid: 20,
                name: "comp.bin".into(),
                compression_type: 8,
                detail: "resource fork is empty".into(),
            },
        ]
    }

    #[test]
    fn every_kind_has_a_stable_code_and_grade() {
        let mut codes = std::collections::HashSet::new();
        for kind in all_kinds() {
            let a = Anomaly::new(kind.clone());
            assert_eq!(a.code, kind.code());
            assert_eq!(a.severity, kind.severity());
            assert_eq!(a.note, kind.note());
            assert!(
                a.code.starts_with("HFS-"),
                "code not HFS-prefixed: {}",
                a.code
            );
            assert!(codes.insert(a.code), "duplicate code {}", a.code);
        }
    }

    #[test]
    fn notes_are_observations_not_verdicts() {
        for kind in all_kinds() {
            let note = kind.note().to_lowercase();
            assert!(note.contains("consistent with"), "note lacks hedge: {note}");
            for verdict in ["proves", "confirms", "guilty", "malicious actor"] {
                assert!(
                    !note.contains(verdict),
                    "verdict word `{verdict}` in: {note}"
                );
            }
        }
    }

    #[test]
    fn display_renders_severity_code_note() {
        let a = Anomaly::new(AnomalyKind::DeletedButReferenced {
            cnid: 42,
            parent: 2,
            name: "GONE".into(),
        });
        let s = format!("{a}");
        assert!(
            s.contains("HFS-DELETED-BUT-REFERENCED:") && s.starts_with('['),
            "{s}"
        );
    }

    #[test]
    fn observation_to_finding_carries_code_and_grade() {
        let a = Anomaly::new(AnomalyKind::BtreeNodeInvalid {
            tree: "extents".into(),
            node: 3,
            detail: "bad".into(),
        });
        assert_eq!(Observation::severity(&a), Some(Severity::High));
        assert_eq!(Observation::code(&a), "HFS-BTREE-NODE-INVALID");
        assert_eq!(Observation::note(&a), a.note);
    }

    #[test]
    fn audit_of_non_hfs_buffer_is_empty() {
        assert!(audit(&[0u8; 64]).is_empty());
        assert!(audit(&[]).is_empty());
    }

    #[test]
    fn classify_rejects_malformed_records() {
        // Too short for the 8-byte key prefix.
        assert!(classify_record(&[0u8; 4]).is_none());
        // key_len claims a name that runs off the end.
        let mut rec = vec![0u8; 8];
        rec[6] = 0xFF; // name_len huge
        rec[7] = 0xFF;
        assert!(classify_record(&rec).is_none());
    }

    #[test]
    fn fork_helpers_reject_short_forks() {
        assert_eq!(fork_inline_blocks(&[0u8; 10]), 0);
        assert!(!fork_all_slots_used(&[0u8; 10]));
    }

    #[test]
    fn needed_blocks_rounds_up() {
        assert_eq!(needed_blocks(0, 4096), 0);
        assert_eq!(needed_blocks(1, 4096), 1);
        assert_eq!(needed_blocks(4096, 4096), 1);
        assert_eq!(needed_blocks(4097, 4096), 2);
    }

    #[test]
    fn classify_folder_and_thread_records() {
        // A minimal folder record: keyLength(2)=6 parentID(4) nameLen(2)=0,
        // body recordType(2)=1 flags(2) valence(4) folderID(4)=17.
        let mut rec = vec![0u8; 32];
        rec[0..2].copy_from_slice(&6u16.to_be_bytes()); // key_len
        rec[6..8].copy_from_slice(&0u16.to_be_bytes()); // name_len
        let data = 2 + 6;
        rec[data..data + 2].copy_from_slice(&1i16.to_be_bytes()); // RECORD_FOLDER
        rec[data + 8..data + 12].copy_from_slice(&17u32.to_be_bytes()); // folderID
        match classify_record(&rec) {
            Some(CatalogRecord::Entry { cnid, file }) => {
                assert_eq!(cnid, 17);
                assert!(file.is_none());
            }
            other => panic!("expected folder Entry, got {other:?}"),
        }

        // A folder-thread record: body recordType(2)=3 reserved(2) parentID(4)=2
        // nameLen(2)=1 name(UTF-16 'A'). The thread's *key* parent (rec[2..6]) is
        // the CNID it represents.
        let mut t = vec![0u8; 40];
        t[0..2].copy_from_slice(&6u16.to_be_bytes());
        t[2..6].copy_from_slice(&99u32.to_be_bytes()); // key parent = CNID
        t[6..8].copy_from_slice(&0u16.to_be_bytes());
        let d = 2 + 6;
        t[d..d + 2].copy_from_slice(&3i16.to_be_bytes()); // RECORD_FOLDER_THREAD
        t[d + 4..d + 8].copy_from_slice(&2u32.to_be_bytes()); // real parent
        t[d + 8..d + 10].copy_from_slice(&1u16.to_be_bytes()); // name_len
        t[d + 10..d + 12].copy_from_slice(&u16::from(b'A').to_be_bytes());
        match classify_record(&t) {
            Some(CatalogRecord::Thread { cnid, parent, name }) => {
                assert_eq!(cnid, 99);
                assert_eq!(parent, 2);
                assert_eq!(name, "A");
            }
            other => panic!("expected Thread, got {other:?}"),
        }
    }

    #[test]
    fn classify_unknown_record_type_is_none() {
        let mut rec = vec![0u8; 16];
        rec[0..2].copy_from_slice(&6u16.to_be_bytes());
        let data = 2 + 6;
        rec[data..data + 2].copy_from_slice(&99i16.to_be_bytes()); // not a known type
        assert!(classify_record(&rec).is_none());
    }

    #[test]
    fn classify_truncated_folder_yields_none() {
        // recordType says folder but the record ends before folderID@+12.
        let mut rec = vec![0u8; 10];
        rec[0..2].copy_from_slice(&6u16.to_be_bytes());
        let data = 2 + 6;
        rec[data..data + 2].copy_from_slice(&1i16.to_be_bytes());
        assert!(classify_record(&rec).is_none());
    }

    #[test]
    fn classify_short_file_record_still_yields_cnid() {
        // A file record shorter than the full 248 bytes but long enough for its
        // CNID: we keep the entry (so its thread isn't falsely flagged orphan)
        // but carry no file detail.
        let mut rec = vec![0u8; 24];
        rec[0..2].copy_from_slice(&6u16.to_be_bytes());
        let data = 2 + 6;
        rec[data..data + 2].copy_from_slice(&2i16.to_be_bytes()); // RECORD_FILE
        rec[data + 8..data + 12].copy_from_slice(&18u32.to_be_bytes());
        match classify_record(&rec) {
            Some(CatalogRecord::Entry { cnid, file }) => {
                assert_eq!(cnid, 18);
                assert!(file.is_none());
            }
            other => panic!("expected short-file Entry, got {other:?}"),
        }
    }

    #[test]
    fn classify_record_with_bad_key_len_is_none() {
        // key_len runs the body type field off the end.
        let mut rec = vec![0u8; 9];
        rec[0..2].copy_from_slice(&100u16.to_be_bytes());
        assert!(classify_record(&rec).is_none());
    }

    #[test]
    fn classify_record_name_runs_off_end_is_none() {
        // key_len small (so the body checks pass) but nameLen claims a name
        // that overruns the record — the name-bounds guard rejects it.
        let mut rec = vec![0u8; 12];
        rec[0..2].copy_from_slice(&4u16.to_be_bytes()); // small key_len
        rec[6..8].copy_from_slice(&50u16.to_be_bytes()); // name_len overruns
        assert!(classify_record(&rec).is_none());
    }

    #[test]
    fn classify_file_record_too_short_for_cnid_is_none() {
        // recordType file but the record ends before even the CNID@+12.
        let mut rec = vec![0u8; 12];
        rec[0..2].copy_from_slice(&2u16.to_be_bytes()); // key_len=2 → data=4
        let data = 2 + 2;
        rec[data..data + 2].copy_from_slice(&2i16.to_be_bytes()); // RECORD_FILE
                                                                  // rec.len()=12, data+12=16 > 12, and data+12 (cnid) = 16 > 12 → None.
        assert!(classify_record(&rec).is_none());
    }

    #[test]
    fn classify_truncated_thread_is_none() {
        // recordType thread but the record ends before parentID/name fields.
        let mut rec = vec![0u8; 11];
        rec[0..2].copy_from_slice(&2u16.to_be_bytes());
        let data = 2 + 2;
        rec[data..data + 2].copy_from_slice(&3i16.to_be_bytes()); // FOLDER_THREAD
        assert!(classify_record(&rec).is_none());
    }

    #[test]
    fn classify_thread_with_name_overrun_uses_empty_name() {
        // A thread whose declared name length overruns the record degrades to an
        // empty name rather than panicking (the thread CNID/parent still parse).
        let mut rec = vec![0u8; 20];
        rec[0..2].copy_from_slice(&6u16.to_be_bytes());
        rec[2..6].copy_from_slice(&77u32.to_be_bytes()); // key parent = CNID
        let d = 2 + 6;
        rec[d..d + 2].copy_from_slice(&4i16.to_be_bytes()); // FILE_THREAD
        rec[d + 4..d + 8].copy_from_slice(&2u32.to_be_bytes()); // parent
        rec[d + 8..d + 10].copy_from_slice(&100u16.to_be_bytes()); // name_len overrun
        match classify_record(&rec) {
            Some(CatalogRecord::Thread { cnid, parent, name }) => {
                assert_eq!(cnid, 77);
                assert_eq!(parent, 2);
                assert!(name.is_empty());
            }
            other => panic!("expected Thread, got {other:?}"),
        }
    }

    #[test]
    fn audit_extents_consults_overflow_when_slots_full() {
        // A file that fills all 8 inline slots (8 blocks) but needs 10 — without
        // an overflow record it is a mismatch; with a 2-block overflow record it
        // is clean. This exercises the extents-overflow consult path.
        let f = CatalogFile {
            cnid: 18,
            name: "BIG.BIN".into(),
            logical: 10 * 4096,
            inline_blocks: 8,
            extents_full: true,
            create: HFS_EPOCH_TO_UNIX,
            content_mod: HFS_EPOCH_TO_UNIX,
            has_resource_fork: false,
            resource_logical: 0,
            resource_blocks: 0,
        };

        // Build a one-record extents-overflow leaf covering 2 blocks for cnid 18.
        let node_size = 512usize;
        let mut vol = vec![0u8; node_size * 2];
        let no = node_size; // leaf = node 1
        vol[no + 8] = 0xFF;
        vol[no + 9] = 1;
        vol[no + 10..no + 12].copy_from_slice(&1u16.to_be_bytes());
        let rec = 14usize;
        let r = no + rec;
        vol[r..r + 2].copy_from_slice(&10u16.to_be_bytes());
        vol[r + 4..r + 8].copy_from_slice(&18u32.to_be_bytes());
        let data = rec + 2 + 10;
        vol[no + data + 4..no + data + 8].copy_from_slice(&2u32.to_be_bytes());
        let slot = node_size - 2;
        vol[no + slot..no + slot + 2].copy_from_slice(&(rec as u16).to_be_bytes());
        let loc = CatalogLoc {
            cat_base: 0,
            node_size,
            first_leaf: 1,
            block_size: 4096,
        };

        // With the 2-block overflow record, allocated (8+2) >= needed (10): clean.
        let mut out = Vec::new();
        audit_extents(&vol, &f, 4096, Some(&loc), &mut out);
        assert!(
            out.is_empty(),
            "overflow should satisfy the size, got {out:?}"
        );

        // Without any overflow B-tree, allocated (8) < needed (10): mismatch.
        let mut out2 = Vec::new();
        audit_extents(&vol, &f, 4096, None, &mut out2);
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].code, "HFS-CATALOG-EXTENTS-MISMATCH");
    }

    /// Build one extents-overflow leaf node holding a record for `(cnid, fork=0)`
    /// covering `blocks` allocation blocks, and confirm `overflow_blocks` sums it.
    #[test]
    fn overflow_blocks_sums_extent_record() {
        let node_size = 512usize;
        let cat_base = 0usize;
        // Header node (node 0): descriptor(14) + B-tree header record at +14:
        // we only need firstLeafNode@+10 and nodeSize@+18 for locate-style math,
        // but overflow_blocks takes a CatalogLoc directly.
        let mut vol = vec![0u8; node_size * 2];
        // Leaf node = node 1.
        let leaf = 1usize;
        let no = leaf * node_size + cat_base;
        // descriptor: fLink=0, bLink=0, kind=-1(leaf), height=1, numRecords=1.
        vol[no + 8] = 0xFF; // leaf kind
        vol[no + 9] = 1;
        vol[no + 10..no + 12].copy_from_slice(&1u16.to_be_bytes());
        // record 0 at offset 14.
        let rec = 14usize;
        // HFSPlusExtentKey: keyLength(2)=10 forkType(1)=0 pad(1) fileID(4)=18
        // startBlock(4)=0; then 8*(start,count) — first extent count = 5.
        let r = no + rec;
        vol[r..r + 2].copy_from_slice(&10u16.to_be_bytes()); // key_len
        vol[r + 2] = 0; // forkType data
        vol[r + 4..r + 8].copy_from_slice(&18u32.to_be_bytes()); // fileID
        let data = rec + 2 + 10;
        // first extent: startBlock@+0, blockCount@+4 = 5
        vol[no + data + 4..no + data + 8].copy_from_slice(&5u32.to_be_bytes());
        // record-offset slot at node end (stored backwards): slot for record 0.
        let slot = node_size - 2;
        vol[no + slot..no + slot + 2].copy_from_slice(&(rec as u16).to_be_bytes());

        let loc = CatalogLoc {
            cat_base,
            node_size,
            first_leaf: leaf as u32,
            block_size: 4096,
        };
        assert_eq!(overflow_blocks(&vol, &loc, 18, 0), 5);
        // A different fork type or cnid sums nothing.
        assert_eq!(overflow_blocks(&vol, &loc, 18, 0xFF), 0);
        assert_eq!(overflow_blocks(&vol, &loc, 999, 0), 0);
    }
}
