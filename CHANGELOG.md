# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). 

## [Unreleased]

### Fixed
- Watch-only P2PK entries (zcashd `importpubkey`) and transparent keypairs are
  now surfaced at the P2PKH address of the public key's serialization as
  stored, matching the key id zcashd computes for it. An uncompressed key was
  previously keyed under its compressed form's address — one the source wallet
  never watched — and a wallet holding both serializations of one key
  collapsed to a single entry, discarding the other.

### Added
- `KeyId::from_pubkey`, the key id of a public key's serialization as stored
  (RIPEMD-160 of SHA-256, zcashd's `CPubKey::GetID()`).
- `MigrateError` variants `InvalidMnemonic`, `UnsupportedMnemonicLanguage`,
  `MnemonicFingerprintMismatch` and `LegacyAccountDerivation`.

### Changed
- Migrated to the librustzcash NU7 pre-release cohort: `zcash_address`
  0.14.0-pre.0, `zcash_keys` 0.17.0-pre.0, `zcash_primitives` 0.31.0-pre.0,
  `zcash_protocol` 0.11.0-pre.0 and `zcash_transparent` 0.11.0-pre.0, together
  with `orchard` 0.16, `sapling-crypto` 0.9, `incrementalmerkletree` 0.9,
  `zcash_encoding` 0.5, `zip32` 0.3, `secp256k1` 0.33 and `bridgetree` 0.8.
- `regtest_params_from_local` now always includes the NU7 activation height. It
  was previously included only when built with `--cfg zcash_unstable="nu7"`,
  which `zcash_protocol` 0.11 no longer requires.
- `migrate_to_zewif` now exports each legacy Sapling spending key as its own
  account, keyed by the key's extended full viewing key, with provenance
  `zcashd_legacy` and (where the key's metadata records one) its seed
  derivation. Keys that duplicate the Sapling component of a stored UFVK
  (unified account receiver keys, which zcashd also stores in the Sapling
  keystore) are identified by their diversifiable full viewing keys and
  skipped. Previously legacy Sapling keys traveled only in the secret store,
  so a viewing-only importer had no account under which to represent them.
- `migrate_to_zewif` attaches each Sapling address and received note to the
  account whose Sapling viewing key views it: a legacy Sapling key's account,
  or the unified account whose Sapling receiver it is, with the matching key
  scope. Sapling addresses of view-only keys remain on the synthesized legacy
  account, now with scope `Foreign`. Previously all Sapling addresses and
  notes were attached to the synthesized legacy account.
- The synthesized legacy account now carries the unified full viewing key
  derived from the post-v4.7.0 mnemonic seed at ZIP 32 account `0x7FFFFFFF`
  (the identifier zcashd reserves for legacy transparent addresses derived
  from system randomness), where the mnemonic — or, for a pre-mnemonic
  wallet, the mnemonic zcashd's upgrade would derive from its legacy HD
  seed — is recoverable. The account therefore imports from that location
  like any other seed-derived account, including into viewing-only wallets.
  A wallet with no seed material at all still exports it as a bare
  transparent address set.
- The exported mnemonic seed's fingerprint is now derived from the wallet's
  recorded mnemonic phrase, which is validated against the wordlist of its
  recorded language. `migrate_to_zewif` fails when the phrase does not parse,
  when its language has no BIP-39 wordlist, or when the wallet's mnemonic HD
  chain record stores a different fingerprint. Previously the fingerprint was
  read from the mnemonic HD chain record without a check.
- Transparent addresses now carry their public keys whenever the wallet
  holds them, not only for watch-only imports. The public key is the
  transparent key's viewing half; a viewing-only import (which strips the
  secret store) needs it to register the address for watching.

### Fixed
- The legacy HD seed of an unencrypted wallet is now parsed. The `hdseed`
  record is keyed by the seed's fingerprint, but it was looked up as a
  keyname-only singleton, which never matches; every unencrypted wallet
  therefore reported its legacy HD seed as absent, and exports omitted the
  seed from the secret store. Encrypted wallets (`chdseed`) were unaffected.

## [0.1.0-rc.5] - 2026-08-17

### Fixed
- `regtest_params_from_local` now includes NU6.3 (Ironwood) in the regtest
  activation schedule. Previously it mapped only through NU6.2, causing
  transactions mined under NU6.3 to fail with "Consensus branch ID not known"
  during wallet import.

## [0.1.0-rc.4] - 2026-08-13

### Added
- Support for parsing pre-Sapling (HD-seedless) wallets, e.g. those created by
  zcashd 1.x. Records that such wallets lack — the address book (`name` /
  `purpose`), keypool (`pool`), `witnesscachesize`, transparent key records
  (`key` / `keymeta`, for watch-only wallets), and the NU5-era
  `orchard_note_commitment_tree` — now parse as empty rather than failing.
  The leniency is bounded by the wallet's own `version` record: a wallet
  last written by zcashd 5.0.0 or later must carry `networkinfo`,
  `orchard_note_commitment_tree`, and transparent key records, and parsing
  fails with the new `Error::MissingExpectedRecords` when such a record set
  is absent, since that proves the file was stripped or corrupted. Below
  that version a dump cannot distinguish a record that never existed from
  one that was stripped, so callers expecting particular contents must
  verify them on the parsed wallet. See the
  `ZcashdParser::parse_dump_with_options` documentation.
- `ZcashdParser::parse_dump_with_options` and `ParseOptions`, whose
  `fallback_network` supplies the wallet's network when it predates the
  `networkinfo` record (zcashd < 5.0.0). Without a `networkinfo` record or a
  fallback network, parsing fails with the new `Error::MissingNetworkInfo`
  instead of guessing the chain; for a 5.0.0+ wallet the missing record is
  reported as `Error::MissingExpectedRecords` and the fallback is never
  substituted.
- `ZcashdDump::records_for_keyname_or_empty`, implementing the parser's
  missing-records policy at the record-lookup layer.

### Changed
- Bumped dependency stack to the `zcash_protocol 0.10` cohort:
  `zcash_protocol` 0.9 → 0.10, `zcash_address` 0.12 → 0.13,
  `zcash_keys` 0.14 → 0.16.1, `zcash_primitives` 0.28 → 0.30,
  `zcash_transparent` 0.8 → 0.10, `orchard` 0.14 → 0.15. The wallet.dat
  binary format is unaffected; these bumps align the crate with the current
  librustzcash release cohort and eliminate the need for downstream
  consumers to maintain a versioned `zcash_protocol` alias.
- `ZcashdWallet::witnesscachesize` now returns `Option<i64>`, as the record is
  absent from wallets never touched by a witness-caching zcashd version.
- A truncated `orchard_note_commitment_tree` record is now reported as a parse
  error instead of causing a panic.
- A key record set whose metadata record set is missing or of a different
  size — `key` without `keymeta` or vice versa, and likewise the Sapling and
  Sprout pairs — now fails with `Error::MismatchedKeyMetadata` instead of a
  generic "keyname not found" error, as the asymmetry is evidence of a
  stripped or hand-modified wallet.

### Fixed
- A regtest wallet's unified full viewing keys and unified addresses are now
  encoded with regtest HRPs (`uviewregtest…`, `uregtest…`) when the caller
  supplies `RegtestActivations` to `migrate_to_zewif`, instead of the testnet
  HRPs that importers decoding against regtest parameters reject. Without
  supplied activations they are still encoded as for the test network, matching
  the wallet's transparent addresses.

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


