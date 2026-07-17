# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). 

## [Unreleased]

## [0.1.0-rc.3] 2026-07-17

### Changed
- Updated to `zewif 1.0.0-rc.3` that removes the leading magic bytes in favor
  of self-describing CBOR, with an identifying tag registered via the RFC 8949
  §9.2 process.

## [0.1.0-rc.2] 2026-07-11

### Added
- Support for decrypting the key material of passphrase-encrypted `zcashd`
  wallets on export. `ZcashdParser::parse_dump_with_policy` takes an
  `EncryptedKeyPolicy` to either decrypt the encrypted key records with a
  supplied passphrase, reject an encrypted wallet, or skip its encrypted
  records and migrate only the plaintext data.

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


