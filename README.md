# zewif-zcashd

A Rust crate that reads a `zcashd` `wallet.dat` file and converts its contents
into the **Zcash Wallet Interchange Format (ZeWIF)**.

## Minimum Supported Rust Version (MSRV)

This crate requires **Rust 1.88**. New language features that raise the MSRV
must not be introduced without a corresponding bump here and in CI; the
`msrv` job in `.github/workflows/ci.yml` enforces this.

## What is ZeWIF?

ZeWIF is a wallet-agnostic representation of Zcash wallet data — seeds, keys,
addresses, accounts, and transaction history — designed so that users can move
between Zcash wallets without losing data. Each wallet implementation provides
an importer/exporter that translates its native format to and from ZeWIF; once
data is in ZeWIF, any other ZeWIF-aware wallet can consume it.

The format itself is defined by the [`zewif`](https://crates.io/crates/zewif)
crate, which this crate depends on. This crate is the `zcashd`-side translator:
it knows how to take a legacy `zcashd` Berkeley DB wallet and produce the
generic ZeWIF representation.

## What this crate does

This crate provides the ability to migrate wallet data from a `zcashd` wallet
backup, into the ZeWIF standard format. `zcashd` stores wallets as Berkeley DB
files containing a heterogeneous mix of serialized records (HD seeds,
transparent keys, sapling keys, unified accounts, transactions, witnesses,
metadata, etc.). Migrating that data
faithfully requires:

1. **Reading the BDB file.** Done by shelling out to `db_dump` to produce a
   key/value listing. A copy of Berkeley DB 6.2.23 (matching the version used
   by `zcashd`) is vendored in `vendor/`
   and built by `build.rs`, so the crate is self-contained and does not
   require a system-installed BDB. A user-supplied `db_dump` binary can also
   be passed explicitly via `BDBDump::from_file_with_path`.
2. **Parsing the records.** The raw bytes are decoded into typed `zcashd`
   wallet structures using the same serialization that `zcashd` itself uses.
   To stay byte-compatible with `zcashd 0.6.20`, the `zcash_*` and `sapling`
   dependency versions are pinned to match — they should not be bumped
   independently.
3. **Migrating to ZeWIF.** The parsed `ZcashdWallet` is walked and
   re-projected into the generic ZeWIF model: accounts, addresses (transparent,
   sapling, unified), transactions, witnesses, and seed material.

## Usage

See [`examples/read_wallet.rs`](examples/read_wallet.rs) for a runnable example
that reads a `wallet.dat`, prints a summary, migrates it to ZeWIF, and writes
the serialized ZeWIF document to disk. It is also handy as a smoke test that
real wallet files still parse after a patch:

```sh
cargo run --example read_wallet -- /path/to/wallet.dat [out.zewif]
```

With no arguments it reads `$HOME/.zcash/wallet.dat` and writes `wallet.zewif`
in the current directory.

### Encrypted wallets

A passphrase-encrypted `wallet.dat` stores its spending keys and seeds in
encrypted records. `ZcashdParser::parse_dump_with_policy` takes an
[`EncryptedKeyPolicy`] with three modes:

- **`Reject`** (the default, also `parse_dump`) — treat the wallet as
  unencrypted and fail if any encrypted key material is present.
- **`Decrypt(passphrase)`** — decrypt the encrypted keys with the given
  `SecretVec` passphrase, failing if decryption does not succeed. A wrong
  passphrase is reported as an error rather than producing incorrect keys.
- **`Skip`** — for a lost passphrase: skip the encrypted keys and migrate only
  the plaintext records (viewing keys, addresses, transactions, and any
  plaintext seeds).

The `read_wallet` example selects the mode from the environment — set
`ZCASHD_WALLET_PASSPHRASE` to decrypt, or `ZCASHD_WALLET_SKIP_ENCRYPTED` to
skip:

```sh
ZCASHD_WALLET_PASSPHRASE='…' cargo run --example read_wallet -- /path/to/wallet.dat
```

Encrypted Sprout spending keys are not decrypted; in `Decrypt` mode a wallet
containing them is rejected, and in `Skip` mode they are omitted.

## Layout

- `src/bdb_dump.rs` — invokes `db_dump` and collects its key/value output.
- `build.rs` + `vendor/db-6.2.23.tar.gz` — vendors and builds Berkeley DB so
  `db_dump` is available at compile time.
- `src/zcashd_dump.rs`, `src/zcashd_parser.rs`, `src/zcashd_wallet/`,
  `src/parser/` — decode the BDB records into typed `zcashd` wallet structs.
- `src/migrate/` — converts a parsed `ZcashdWallet` into a `Zewif` value.
- `docs/KeyPreservation.md` — what cryptographic material is preserved during
  migration and why.
- `docs/TransactionAssignment.md` — how transactions are assigned to accounts
  in the migrated wallet.

## Status

This is a one-way migration tool: `zcashd` → ZeWIF. It is intended for users
moving off `zcashd` (which is being deprecated) into ZeWIF-aware wallets.

## License

Licensed under either of MIT or Apache-2.0 at your option. See `LICENSE.md`.
