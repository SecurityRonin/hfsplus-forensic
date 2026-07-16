# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2]

### Changed

- Migrate to `forensic-vfs` 0.3 (`FsKind` newtype). The `vfs` adapter's
  `kind()` now returns the `FsKind::HFS_PLUS` const; the former
  `FsKind::HfsPlus` enum variant is gone (`FsKind` is a string-backed newtype
  re-exported from `forensicnomicon-core`).
