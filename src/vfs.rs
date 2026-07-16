//! `impl FileSystem for HfsFs` — the forensic-vfs adapter (behind the `vfs`
//! feature).
//!
//! This crate's reader is slice-based and immutable: every operation takes the
//! whole volume `&[u8]` and reads through it with `&self`, so one mounted
//! [`HfsFs`] backs N workers with no locking. This module maps that reader onto
//! the [`forensic_vfs::FileSystem`] contract. HFS+ has no dedicated [`FileId`]
//! variant, so every node is addressed by [`FileId::Opaque`] carrying its
//! catalog node ID (CNID); the root folder is CNID 2. Every fallible reader call
//! is translated to a typed [`VfsError`] — never an `unwrap`/panic
//! (Paranoid Gatekeeper).

use forensic_vfs::{
    Allocation, DirEntry, DirStream, ExtentStream, FileId, FileSystem, FsKind, FsMeta, MacbTimes,
    NodeKind, NodeStream, ResidencyKind, SectorSizes, SmallHex, StreamId, TimeResolution,
    TimeSource, TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};

use crate::{HfsStat, HfsVolume, ROOT_FOLDER_CNID};

/// Seconds between the HFS+ epoch (1904-01-01 UTC) and the Unix epoch
/// (1970-01-01 UTC). HFS+ timestamps are `u32` seconds since 1904; this rebases
/// them onto Unix time.
const HFS_EPOCH_TO_UNIX: i128 = 2_082_844_800;

/// The catalog node ID carried by a [`FileId`]. Only opaque inode ids address
/// this filesystem; any other identity domain (an NTFS reference, an ext inode,
/// …) is a caller error, surfaced loud rather than silently mis-read.
fn cnid_of(id: FileId) -> VfsResult<u32> {
    match id {
        FileId::Opaque(n) => u32::try_from(n).map_err(|_| VfsError::OutOfRange {
            what: "hfs+ cnid",
            offset: n,
            len: 0,
            bound: u64::from(u32::MAX),
        }),
        other => Err(VfsError::Unsupported {
            layer: "hfs+ file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Convert one raw HFS+ timestamp (`u32` seconds since 1904) into a VFS
/// [`TimeStamp`] anchored on Unix nanoseconds.
fn hfs_time(secs: u32) -> TimeStamp {
    TimeStamp {
        unix_nanos: (i128::from(secs) - HFS_EPOCH_TO_UNIX) * 1_000_000_000,
        source: TimeSource::InodeTable,
        resolution: TimeResolution::Seconds,
    }
}

/// A mounted, read-only HFS+/HFSX volume behind the [`FileSystem`] contract.
///
/// Holds the whole volume in memory (the reader is slice-based), so all reads are
/// `&self` and the handle is trivially `Send + Sync`.
pub struct HfsFs {
    volume: Vec<u8>,
}

impl HfsFs {
    /// Mount a whole HFS+/HFSX volume (its first byte is the volume start; the
    /// header sits at offset 1024). Fails loud if the buffer carries no HFS+
    /// signature — never a silent empty filesystem.
    pub fn new(volume: Vec<u8>) -> VfsResult<Self> {
        let _: HfsVolume = crate::parse(&volume).ok_or_else(|| VfsError::Bootstrap {
            stage: "hfs+ volume header",
            detail: "no HFS+/HFSX signature at offset 1024".to_string(),
        })?;
        Ok(Self { volume })
    }
}

impl FileSystem for HfsFs {
    fn kind(&self) -> FsKind {
        FsKind::HfsPlus
    }

    fn root(&self) -> FileId {
        FileId::Opaque(u64::from(ROOT_FOLDER_CNID))
    }

    fn sector_sizes(&self) -> SectorSizes {
        // HFS+ has no separate sector concept exposed by the reader; the
        // allocation block is the meaningful unit. Report the block size as the
        // cluster/block, and fall back to 512 for the logical/physical sector
        // (the conventional HFS+ device sector) when the header is unreadable —
        // which cannot happen after `new` validated it.
        let block = crate::parse(&self.volume).map_or(512, |v| v.block_size);
        SectorSizes {
            logical: 512,
            physical: 512,
            cluster_or_block: block,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let cnid = cnid_of(ino)?;
        // `new` validated the volume header signature, but the catalog B-tree can
        // still be unlocatable (a fork with zero totalBlocks / unreadable
        // geometry) — surface that as a loud Decode error, never a silent empty
        // directory.
        let entries = crate::list_dir(&self.volume, cnid).ok_or_else(|| VfsError::Decode {
            layer: "hfs+ catalog",
            offset: 0,
            detail: format!("cannot list directory CNID {cnid}"),
            bytes: SmallHex::new(&[]),
        })?;
        let out: Vec<VfsResult<DirEntry>> = entries
            .into_iter()
            .map(|e| {
                Ok(DirEntry {
                    name: e.name.into_bytes(),
                    id: FileId::Opaque(u64::from(e.cnid)),
                    kind: if e.is_dir {
                        NodeKind::Dir
                    } else {
                        NodeKind::File
                    },
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
        // The reader materializes whole forks; per-run extent byte-run exposure
        // is a follow-up (it would re-parse the fork's HFSPlusForkData extents
        // here). Return an empty stream rather than fabricate runs.
        Ok(ExtentStream::empty())
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let cnid = cnid_of(parent)?;
        // As in `read_dir`: a validated header does not guarantee a locatable
        // catalog, so an unlistable directory is a loud Decode error.
        let entries = crate::list_dir(&self.volume, cnid).ok_or_else(|| VfsError::Decode {
            layer: "hfs+ catalog",
            offset: 0,
            detail: format!("cannot list directory CNID {cnid}"),
            bytes: SmallHex::new(&[]),
        })?;
        for e in entries {
            if e.name.as_bytes() == name {
                return Ok(Some(FileId::Opaque(u64::from(e.cnid))));
            }
        }
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let cnid = cnid_of(ino)?;
        let s: HfsStat = crate::stat(&self.volume, cnid).ok_or_else(|| VfsError::Decode {
            layer: "hfs+ catalog",
            offset: 0,
            detail: format!("no catalog record for CNID {cnid}"),
            bytes: SmallHex::new(&[]),
        })?;
        Ok(FsMeta {
            ino: u64::from(cnid),
            kind: if s.is_dir {
                NodeKind::Dir
            } else {
                NodeKind::File
            },
            allocated: Allocation::Allocated,
            size: s.size,
            nlink: 1,
            uid: None,
            gid: None,
            mode: None,
            times: MacbTimes {
                born: Some(hfs_time(s.created)),
                modified: Some(hfs_time(s.modified)),
                changed: None,
                accessed: Some(hfs_time(s.accessed)),
            },
            streams: Vec::new(),
            residency: ResidencyKind::NonResident,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let cnid = cnid_of(ino)?;
        if stream != StreamId::Default {
            return Err(VfsError::Unsupported {
                layer: "hfs+ stream",
                scheme: format!("{stream:?}"),
            });
        }
        let data = crate::read_file(&self.volume, cnid).ok_or_else(|| VfsError::Decode {
            layer: "hfs+ file",
            offset: off,
            detail: format!("cannot read file CNID {cnid}"),
            bytes: SmallHex::new(&[]),
        })?;
        let start = usize::try_from(off).unwrap_or(usize::MAX);
        if start >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        // HFS+ symlink targets are not resolved by this adapter; a node with none
        // reads as an empty target.
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Catalog carving of deleted records is a follow-up; the default surface
        // is an empty stream, not a bootstrap failure.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}
