//! HFS+ / HFSX forensic analyzer, and the reader it grades over.
//!
//! This crate is the anomaly auditor: [`findings`] emits
//! [`forensicnomicon::report`] observations over the parsed volume produced by
//! the [`hfsplus_core`] reader.
//!
//! # Reader access is re-exported unchanged
//!
//! The reader (volume header, catalog/extents B-trees, `decmpfs` transparent
//! decompression, the optional `vfs` adapter) now lives in the standalone
//! [`hfsplus_core`], which carries no `forensicnomicon::report` usage so a
//! consumer that only reads an HFS+ volume (a mount adapter, an archiver) can
//! depend on it without the findings layer. For source compatibility this crate
//! **re-exports the entire reader surface**, so existing `hfsplus_forensic::…`
//! paths keep resolving and the `vfs` feature keeps working — no consumer change
//! is needed. New reader-only consumers should prefer `hfsplus-core` directly.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod findings;

/// The complete `hfsplus-core` reader surface, re-exported so this crate stays a
/// drop-in for consumers that depended on the reader when it lived here.
pub use hfsplus_core::*;
