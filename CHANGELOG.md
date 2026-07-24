# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6](https://github.com/SecurityRonin/hfsplus-forensic/compare/hfsplus-forensic-v0.2.5...hfsplus-forensic-v0.2.6) - 2026-07-24

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)

### Fixed

- *(decmpfs)* cap attacker-controlled uncompressed_size to stop alloc bomb

## [0.2.4](https://github.com/SecurityRonin/hfsplus-forensic/compare/v0.2.3...v0.2.4) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5

## [0.2.2]

### Changed

- Migrate to `forensic-vfs` 0.3 (`FsKind` newtype). The `vfs` adapter's
  `kind()` now returns the `FsKind::HFS_PLUS` const; the former
  `FsKind::HfsPlus` enum variant is gone (`FsKind` is a string-backed newtype
  re-exported from `forensicnomicon-core`).
