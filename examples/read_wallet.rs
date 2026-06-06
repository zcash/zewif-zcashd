//! Read a `zcashd` `wallet.dat` and print a summary.
//!
//! Useful as a smoke test that real wallet files still parse after a patch:
//! point it at an actual `wallet.dat` and confirm the read succeeds.
//!
//! Usage: cargo run --example read_wallet -- /path/to/wallet.dat
//!
//! With no argument, defaults to `$HOME/.zcash/wallet.dat`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use zewif::BlockHeight;
use zewif_zcashd::{BDBDump, ZcashdDump, ZcashdParser, migrate_to_zewif};

fn default_wallet_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".zcash").join("wallet.dat")
}

fn main() -> Result<()> {
    let path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_wallet_path);

    println!("Reading wallet: {}", path.display());

    let bdb = BDBDump::from_file(&path)
        .with_context(|| format!("failed to db_dump {}", path.display()))?;
    let dump = ZcashdDump::from_bdb_dump(&bdb, false)
        .context("failed to collect BDB key/value records")?;
    let (wallet, unparsed) =
        ZcashdParser::parse_dump(&dump, false).context("failed to parse zcashd wallet records")?;

    println!("\n=== Wallet summary ===");
    println!("network:            {:?}", wallet.network());
    println!("client version:     {}", wallet.client_version());
    println!("min version:        {}", wallet.min_version());
    println!("transactions:       {}", wallet.transactions().len());
    println!("transparent addrs:  {}", wallet.address_names().len());
    println!("sapling z-addrs:    {}", wallet.sapling_z_addresses().len());
    println!("key pool entries:   {}", wallet.key_pool().len());
    println!(
        "legacy HD seed:     {}",
        if wallet.legacy_hd_seed().is_some() {
            "present"
        } else {
            "absent"
        }
    );
    println!("unparsed records:   {}", unparsed.len());

    // migrate_to_zewif still hits an internal todo!() on some branches;
    // guard against it so wallet reading above is not lost.
    let export_height = BlockHeight::from_u32(2_400_000);
    println!("\n=== ZeWIF migration ===");
    let migrated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        migrate_to_zewif(&wallet, export_height)
    }));
    match migrated {
        Ok(Ok(zewif)) => {
            println!("wallets:      {}", zewif.wallets().len());
            println!("transactions: {}", zewif.transactions().len());
        }
        Ok(Err(e)) => println!("migration error: {e:#}"),
        Err(_) => println!("migration not yet implemented in this crate"),
    }

    Ok(())
}
