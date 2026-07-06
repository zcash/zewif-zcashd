//! Read a `zcashd` `wallet.dat`, migrate it to ZeWIF, and write the document.
//!
//! Usage: cargo run --example read_wallet -- /path/to/wallet.dat [out.zewif]
//!
//! With no arguments, reads `$HOME/.zcash/wallet.dat` and writes `wallet.zewif`
//! in the current directory.

use std::path::PathBuf;

use zewif::BlockHeight;
use zewif_zcashd::{BDBDump, ZcashdDump, ZcashdParser, migrate_to_zewif};

fn default_wallet_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".zcash").join("wallet.dat")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(default_wallet_path);
    let out_path: PathBuf = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("wallet.zewif"));

    println!("Reading wallet: {}", path.display());

    let bdb = BDBDump::from_file(&path)?;
    let dump = ZcashdDump::from_bdb_dump(&bdb, false)?;
    let (wallet, unparsed) = ZcashdParser::parse_dump(&dump, false)?;

    println!("\n=== Wallet summary ===");
    println!("network:            {:?}", wallet.network());
    println!("client version:     {}", wallet.client_version());
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

    // The caller supplies the export (chain-tip) height; zcashd's wallet.dat
    // records only a block-hash locator, not a numeric height.
    let export_height = BlockHeight::from_u32(2_400_000);

    println!("\n=== ZeWIF migration ===");
    let zewif = migrate_to_zewif(&wallet, export_height)?;
    for w in zewif.wallets() {
        println!("accounts:      {}", w.accounts().len());
        println!("address book:  {}", w.address_book().len());
    }
    println!("transactions:  {}", zewif.transactions().len());
    println!(
        "secret store:  {}",
        if zewif.secrets().is_some() {
            "present"
        } else {
            "absent (viewing-only)"
        }
    );

    let bytes = zewif.to_bytes()?;
    std::fs::write(&out_path, &bytes)?;
    println!("\nWrote {} bytes to {}", bytes.len(), out_path.display());

    Ok(())
}
