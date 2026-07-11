# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). 

## [Unreleased]

### Changed
- Updated to `zewif 1.0.0-rc.2`, which flattens the tagged-union wire encoding
  to `[variant-id, body?]`. Exported documents use the revised encoding;
  documents produced against `zewif 1.0.0-rc.1` do not decode with this
  version.

## [0.1.0-rc.1] 2026-07-11

Initial release candidate. This provides decoding from the historic zcashd
wallet.dat file format into the Zcash Wallet Interchange Format. The
serialization format used by this crate should not be considered stable until
the final zewif-1.0 release has been published.


