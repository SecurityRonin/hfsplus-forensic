# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/SecurityRonin/hfsplus-forensic/compare/hfsplus-core-v0.1.0...hfsplus-core-v0.2.0) - 2026-11-12

### Added

- *(vfs)* GREEN - enumerate HFS+ extended attributes as streams

### Fixed

- *(vfs)* [**breaking**] implement forensic-vfs 0.10, the trait the engine links against
- *(tests)* re-home the xattr test after origin split the crate into core/

## [0.1.0](https://github.com/SecurityRonin/hfsplus-forensic/releases/tag/hfsplus-core-v0.1.0) - 2026-08-24

### Documentation

- *(hfsplus-forensic)* add validation.md — independent oracles + corpora

### Other

- split the reader into hfsplus-core, keeping hfsplus-forensic compatible ([#14](https://github.com/SecurityRonin/hfsplus-forensic/pull/14))
