# Account Model and Transaction Assignment

This document describes how `zewif-zcashd` groups a `zcashd` wallet's addresses,
notes, and transactions into ZeWIF accounts. The relevant code lives in
`src/migrate/`: `accounts.rs`, `addresses.rs`, `received_outputs.rs`,
`sent_outputs.rs`, `transactions.rs`, and `address_book.rs`.

## The account model

`zcashd` does not expose a general account abstraction the way newer wallets do.
It has explicit **unified accounts** (each identified by a ZIP-32 account index
and a unified full viewing key), plus a single reserved **legacy pool** at
account index `0x7FFFFFFF` that holds everything else — imported and
`getnewaddress`-derived transparent keys, `z_getnewaddress` Sapling addresses,
and Sprout keys. The migration mirrors that structure (`build_accounts`):

- **One account per unified account.** Keyed by the account's UFVK
  (`AccountViewingKey::Ufvk`), named `Account #<n>`, and emitted in ascending
  ZIP-32 account-index order. Its key source is the mnemonic seed fingerprint
  and account index, and its purpose is `Spending` (a `zcashd` mnemonic account
  holds spend authority).
- **One synthesized "Legacy" account.** Keyed as a transparent address set
  (`AccountViewingKey::TransparentAddressSet`), mirroring `zcashd` account
  `0x7FFFFFFF`. It collects all legacy transparent, Sapling, and Sprout
  material. Its key source is a seed-derived source when the wallet has a
  mnemonic (or a legacy HD seed from which the mnemonic can be re-derived; see
  [KeyPreservation.md](KeyPreservation.md)), and `Imported` otherwise (a bare
  set of imported keys with no derivation root).

Account ordering and every within-account collection are emitted in a
deterministic order (by index, then address- or key-sorted), so a given
`wallet.dat` migrates to the same document on every run.

## Address routing

`attach_addresses` assigns every address the wallet can produce to an account:

- **Unified addresses** go to the unified account whose UFVK fingerprint matches
  the address metadata's key ID, falling back to the legacy account if no such
  account is present.
- **Transparent addresses** — reconstructed from the key database (each
  keypair's P2PKH address), watch-only `importaddress`/`importpubkey` scripts,
  and `cscript` redeem scripts (P2SH) — all go to the legacy account.
  HD-derived keys carry their derivation and key scope; independently generated
  or imported keys are marked `Imported`/`Foreign`.
- **Legacy Sapling addresses** (both `sapzaddr` records and view-only extended
  FVKs recovered to their default address) go to the legacy account.
- **Sprout addresses** go to the legacy account.

## Transaction assignment

A transaction becomes *relevant* to an account when one of its outputs is
attributed to that account. There are two contributing paths.

### Received outputs

`attach_received_outputs` walks each wallet transaction and attributes its
shielded notes:

- **Sapling notes** → the legacy account (standalone Sapling addresses belong to
  `zcashd`'s legacy pool). Each records its note commitment tree position and
  nullifier.
- **Orchard actions** → routed to the unified account whose Orchard incoming
  viewing key (external or internal scope) matches the action's receiving key,
  falling back to the legacy account when none matches. Each records its note
  commitment tree position.
- **Sprout notes** → the legacy account, recording the nullifier.

The attributed outputs are attached to the account as a *relevant transaction*
(`add_relevant_transaction`), with outputs ordered deterministically by pool and
then output index.

### Sent outputs

`attach_sent_outputs` reconstructs sent-output metadata from `zcashd`'s
`recipientmapping` records. Only **transparent recipients** are reconstructed:
their output index and value are read directly from the transaction's
transparent outputs. These are attributed to the legacy account, because the
sending account is not recoverable from `recipientmapping` alone and the legacy
account holds the transparent keys in this migration.

Sapling and Orchard sent outputs are **not** reconstructed — recovering their
value and index would require trial-decrypting the outputs with the wallet's
outgoing viewing keys. The raw transaction (carried in the export) remains
authoritative, and destination unified addresses are preserved in the address
book (`build_address_book`, tagged `send`).

## The global transaction table

Independently of account assignment, every wallet transaction is added to the
document's global transaction table (`convert_transactions`) as its canonical
re-serialized bytes plus metadata: block position (hash and in-block index) when
mined, expiry height, and time received. A **mined height** is recorded only for
transactions that appended notes to the Orchard note commitment tree, since that
is the only place `zcashd` retains a per-transaction height.

## Account birthdays

Each account's birthday (`set_account_birthdays`) is estimated as the earliest
mined height among its relevant transactions. Because heights are only
recoverable for transactions that touched the Orchard commitment tree, an
account with no such transactions is left without a birthday, and an importer
must rescan from an earlier point.

## Inherent limitations

These are consequences of what `zcashd`'s `wallet.dat` records, not gaps to be
filled in later:

- The **sending account** of an outgoing transaction is not recorded, so sent
  outputs are attributed to the legacy account rather than a specific source
  account.
- **Mined heights** (and therefore account birthdays) are only available for
  transactions that contributed to the Orchard commitment tree.
- **Shielded sent-output values and indices** are not reconstructed; they remain
  recoverable from the raw transaction plus the wallet's viewing keys.
