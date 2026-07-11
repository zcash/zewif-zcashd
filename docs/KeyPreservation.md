# Key Preservation Strategy

This document describes what cryptographic material `zewif-zcashd` preserves
when migrating a `zcashd` `wallet.dat` into the ZeWIF format, and why some
derivable material is deliberately left out. The guiding principle is
**preserve what the source wallet actually holds** — enough to reconstruct
spending and viewing capability — rather than re-deriving or recomputing data
that a ZeWIF-aware importer can recover on its own.

The relevant code lives in `src/migrate/secrets.rs` (spending material),
`src/migrate/accounts.rs` and `src/migrate/addresses.rs` (viewing material and
addresses), and `src/migrate/received_outputs.rs` (note commitment positions).

> **Encrypted wallets.** When a `zcashd` wallet is passphrase-encrypted, its
> spending keys and mnemonic live in encrypted records (`ckey`, `csapzkey`,
> `cmnemonicphrase`, `chdseed`) guarded by a master key (`mkey`). Given the
> passphrase, this crate recovers the master key and decrypts those records
> back into the same material described below, so the preservation strategy is
> identical; see the "Encrypted wallets" section of the README and
> `src/zcashd_wallet/crypto.rs`. Encrypted **Sprout** spending keys (`czkey`)
> are the one exception — they are not yet decrypted.

## Spending material: the secret store

All spending authority the wallet exposes is collected into the ZeWIF document's
secret store (`build_secret_store`). If the wallet holds no spending material at
all, no secret store is emitted and the export is **viewing-only**.

The secret store carries:

- **Seeds.** A v4.7.0+ wallet records its BIP-39 mnemonic directly; it is stored
  keyed by its ZIP-32 seed fingerprint. A pre-mnemonic (pre-v4.7.0) wallet that
  carries a legacy HD seed has a mnemonic **re-derived** from that seed exactly
  as `zcashd`'s own wallet upgrade would (`zcash_keys::keys::zcashd::derive_mnemonic`),
  so its legacy account imports as a seed-derived account rather than a bag of
  loose keys. The raw legacy seed is additionally retained, because legacy
  Sapling keys were derived from it under the pre-v4.7.0 scheme.
- **Transparent private keys**, keyed by public key, drawn from both the legacy
  `key`/`keys` records and the encrypted-comment `wkey` records. Each is emitted
  in canonical WIF Base58Check encoding (compressed form when the public key is
  compressed).
- **Sapling extended spending keys**, keyed by their extended full viewing key
  encoding (169-byte ZIP-32 form).
- **Sprout spending keys**, keyed by their `zc`-prefixed payment address and
  emitted in canonical Base58Check (`SK…`/`ST…`) encoding.

Spending keys are preserved as-is; they are never regenerated, so spending
capability is carried over exactly.

## Viewing material

Viewing capability is preserved at the level of accounts and addresses rather
than as a separate per-address key registry:

- **Unified accounts** each carry their **unified full viewing key (UFVK)** as
  the account's viewing key (`AccountViewingKey::Ufvk`). This is the full
  viewing capability for the account's Orchard, Sapling, and transparent
  receivers.
- The **synthesized legacy account** (see
  [TransactionAssignment.md](TransactionAssignment.md)) is keyed as a
  transparent address set and carries every legacy transparent, Sapling, and
  Sprout address the wallet knows. Each Sapling and Sprout address carries its
  protocol address; the corresponding spending key (from which the incoming and
  full viewing keys are derivable) lives in the secret store.
- **View-only imported Sapling keys** (extended FVKs imported with
  `addDefaultAddress=false`, which have no companion `sapzaddr` record) are
  recovered by computing their canonical default address, so the address is not
  lost even when no spending key is present.

## What is deliberately not stored

Some data is omitted because a ZeWIF importer can recover it from what is
preserved plus chain access:

- **Full viewing keys as separate records.** For unified accounts the UFVK is
  already the full viewing key; for shielded addresses the FVK is derivable from
  the spending key held in the secret store. Storing FVKs separately would
  duplicate derivable data.
- **Full incremental witnesses.** Only the **note commitment tree position** of
  each received note is recorded (`CommitmentTreeData::Position`), not a
  reconstructed witness. `zcashd`'s parsed witness snapshot exposes only raw
  tree nodes with no path or root derivation, so rebuilding a spec-conformant
  witness would mean reimplementing the Sapling/Orchard Merkle hashing. A
  position plus the account birthday is enough for an importer with chain access
  to rebuild the witness by scanning forward.
- **Note values, memos, and (for Orchard) nullifiers.** These are recoverable by
  trial-decrypting the raw transaction — which the export carries — with the
  viewing key, so they are not extracted during migration.

## Viewing-only wallets

A wallet that holds only viewing keys and watch-only material — no seeds and no
spending keys — migrates to a ZeWIF document with **no secret store**. Its
accounts, addresses, and viewing keys are preserved so the wallet can still
track its funds, but no spending authority is (or could be) carried over.
