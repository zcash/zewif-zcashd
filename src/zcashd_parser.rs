use anyhow::{Context, Result, anyhow, bail};
use hex::ToHex as _;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zewif::{
    Bip39Mnemonic, Data, LegacySeed, SeedFingerprint, TxId, sapling::SaplingIncomingViewingKey,
};

use crate::{
    DBValue, ZcashdDump, ZcashdWallet, parse,
    parser::prelude::*,
    zcashd_dump::DBKey,
    zcashd_wallet::{
        Address, BlockLocator, ClientVersion, KeyMetadata, MnemonicHDChain, NetworkInfo,
        RecipientAddress, RecipientMapping, UfvkFingerprint, UnifiedAccountMetadata,
        UnifiedAccounts, UnifiedAddressMetadata,
        orchard::OrchardNoteCommitmentTree,
        sapling::{SaplingKey, SaplingKeys, SaplingZPaymentAddress},
        sprout::{SproutKeys, SproutPaymentAddress, SproutSpendingKey},
        transparent::{
            KeyPair, KeyPoolEntry, Keys, PrivKey, PubKey, ScriptId, WalletKey, WalletKeys,
            WatchScript,
        },
        u252,
    },
};
use zewif::Script;

#[derive(Debug)]
pub struct ZcashdParser<'a> {
    pub dump: &'a ZcashdDump,
    pub unparsed_keys: RefCell<HashSet<DBKey>>,
    pub strict: bool,
}

impl<'a> ZcashdParser<'a> {
    pub fn parse_dump(dump: &ZcashdDump, strict: bool) -> Result<(ZcashdWallet, HashSet<DBKey>)> {
        let parser = ZcashdParser::new(dump, strict);
        parser.parse()
    }

    fn new(dump: &'a ZcashdDump, strict: bool) -> Self {
        let unparsed_keys = RefCell::new(dump.records().keys().cloned().collect());
        Self {
            dump,
            unparsed_keys,
            strict,
        }
    }

    // Keep track of which keys have been parsed
    fn mark_key_parsed(&self, key: &DBKey) {
        self.unparsed_keys.borrow_mut().remove(key);
    }

    fn value_for_keyname(&self, keyname: &str) -> Result<&DBValue> {
        let key = self.dump.key_for_keyname(keyname);
        self.mark_key_parsed(&key);
        self.dump.value_for_keyname(keyname)
    }

    fn parse(&self) -> Result<(ZcashdWallet, HashSet<DBKey>)> {
        //
        // Since version 3
        //

        // ~~acc~~: Removed in 4.5.0
        // ~~acentry~~: Removed in 4.5.0

        // **bestblock**: Empty in 6.0.0
        let bestblock = self.parse_block_locator("bestblock")?;

        // ~~**chdseed**~~: Removed in 5.0.0

        // ckey

        // csapzkey

        // cscript
        let cscripts = self.parse_cscripts()?;

        // czkey

        // **defaultkey**
        let default_key = self.parse_default_key()?;

        // destdata

        // **hdchain**

        // hdseed
        let legacy_hd_seed = self.parse_hdseed()?;

        // key
        // keymeta
        let keys = self.parse_keys()?;

        // **minversion**
        let min_version = self.parse_client_version("minversion")?;

        // **mkey**

        // name
        let address_names = self.parse_address_names()?;

        // **orderposnext**
        let orderposnext = self.parse_opt_i64("orderposnext")?;

        // pool
        let key_pool = self.parse_key_pool()?;

        // purpose
        let address_purposes = self.parse_address_purposes()?;

        // sapzaddr
        let sapling_z_addresses = self.parse_sapling_z_addresses()?;

        // sapextfvk
        let sapling_extended_full_viewing_keys = self.parse_sapling_extended_full_viewing_keys()?;

        // sapzkey
        let sapling_keys = self.parse_sapling_keys()?;

        // tx
        let transactions = self.parse_transactions(self.strict)?;

        // **version**
        let client_version = self.parse_client_version("version")?;

        // vkey

        // watchs
        let watch_scripts = self.parse_watch_scripts()?;

        // **witnesscachesize**
        let witnesscachesize = self.parse_i64("witnesscachesize")?;

        // wkey
        let wallet_keys = self.parse_wallet_keys()?;

        // zkey
        // zkeymeta
        let sprout_keys = self.parse_sprout_keys()?;

        //
        // Since version 5
        //

        // **networkinfo**
        let network_info = self.parse_network_info()?;

        // **orchard_note_commitment_tree**
        let orchard_note_commitment_tree = self.parse_orchard_note_commitment_tree()?;

        // unifiedaccount

        // unifiedfvk

        // unifiedaddrmeta
        let unified_accounts = self.parse_unified_accounts()?;

        // **mnemonicphrase**
        let mnemonic_phrase = self.parse_mnemonic_phrase()?;

        // **cmnemonicphrase**

        // **mnemonichdchain**
        let mnemonic_hd_chain = self.parse_mnemonic_hd_chain()?;

        // recipientmapping
        let send_recipients = self.parse_send_recipients()?;

        //
        // Since version 6
        //

        // **bestblock_nomerkle**
        let bestblock_nomerkle = self.parse_opt_block_locator("bestblock_nomerkle")?;

        let wallet = ZcashdWallet::new(
            address_names,
            address_purposes,
            bestblock_nomerkle,
            bestblock,
            client_version,
            cscripts,
            default_key,
            key_pool,
            keys,
            min_version,
            legacy_hd_seed,
            mnemonic_hd_chain,
            mnemonic_phrase,
            network_info,
            orchard_note_commitment_tree,
            orderposnext,
            sapling_extended_full_viewing_keys,
            sapling_keys,
            sapling_z_addresses,
            send_recipients,
            sprout_keys,
            wallet_keys,
            transactions,
            unified_accounts,
            watch_scripts,
            witnesscachesize,
        );

        Ok((wallet, self.unparsed_keys.borrow().clone()))
    }

    fn parse_i64(&self, keyname: &str) -> Result<i64> {
        let value = self.value_for_keyname(keyname)?;
        parse!(buf = value, i64, format!("i64 for keyname: {}", keyname))
    }

    fn parse_opt_i64(&self, keyname: &str) -> Result<Option<i64>> {
        if self.dump.has_value_for_keyname(keyname) {
            self.parse_i64(keyname).map(Some)
        } else {
            Ok(None)
        }
    }

    fn parse_client_version(&self, keyname: &str) -> Result<ClientVersion> {
        let value = self.value_for_keyname(keyname)?;
        parse!(
            buf = value,
            ClientVersion,
            format!("client version for keyname: {}", keyname)
        )
    }

    fn parse_block_locator(&self, keyname: &str) -> Result<BlockLocator> {
        let value = self.value_for_keyname(keyname)?;
        parse!(
            buf = value,
            BlockLocator,
            format!("block locator for keyname: {}", keyname)
        )
    }

    fn parse_opt_block_locator(&self, keyname: &str) -> Result<Option<BlockLocator>> {
        if self.dump.has_value_for_keyname(keyname) {
            self.parse_block_locator(keyname).map(Some)
        } else {
            Ok(None)
        }
    }

    fn parse_keys(&self) -> Result<Keys> {
        let key_records = self
            .dump
            .records_for_keyname("key")
            .context("Getting 'key' records")?;
        let keymeta_records = self
            .dump
            .records_for_keyname("keymeta")
            .context("Getting 'keymeta' records")?;
        if key_records.len() != keymeta_records.len() {
            bail!("Mismatched key and keymeta records");
        }
        let mut keys_map = HashMap::new();
        for (key, value) in key_records {
            let pubkey = parse!(buf = &key.data, PubKey, "pubkey")?;
            let privkey = parse!(buf = value.as_data(), PrivKey, "privkey")?;
            let metakey = DBKey::new("keymeta", &key.data);
            let metadata_binary = self
                .dump
                .value_for_key(&metakey)
                .context("Getting metadata")?;
            let metadata = parse!(buf = metadata_binary, KeyMetadata, "metadata")?;
            let keypair = KeyPair::new(pubkey.clone(), privkey.clone(), metadata)
                .context("Creating keypair")?;
            keys_map.insert(pubkey, keypair);

            self.mark_key_parsed(&key);
            self.mark_key_parsed(&metakey);
        }
        Ok(Keys::new(keys_map))
    }

    fn parse_wallet_keys(&self) -> Result<Option<WalletKeys>> {
        if !self.dump.has_keys_for_keyname("wkey") {
            return Ok(None);
        }
        let key_records = self
            .dump
            .records_for_keyname("wkey")
            .context("Getting 'wkey' records")?;
        if key_records.is_empty() {
            return Ok(None);
        }
        let mut keys_map = HashMap::new();
        for (key, value) in key_records {
            let pubkey = parse!(buf = &key.data, PubKey, "pubkey")?;
            let mut parser = Parser::new(value.as_data());
            let privkey = parse!(&mut parser, PrivKey, "privkey")?;
            let time_created = parse!(&mut parser, SecondsSinceEpoch, "time_created")?;
            let time_expires = parse!(&mut parser, SecondsSinceEpoch, "time_expires")?;
            let comment = parse!(&mut parser, String, "comment")?;
            let wallet_key = WalletKey::new(
                pubkey.clone(),
                privkey.clone(),
                time_created,
                time_expires,
                comment,
            );
            keys_map.insert(pubkey, wallet_key);

            self.mark_key_parsed(&key);
        }
        Ok(Some(WalletKeys::new(keys_map)))
    }

    fn parse_sapling_keys(&self) -> Result<SaplingKeys> {
        let mut keys_map = HashMap::new();
        if !self.dump.has_keys_for_keyname("sapzkey") {
            return Ok(SaplingKeys::new(keys_map));
        }
        let key_records = self
            .dump
            .records_for_keyname("sapzkey")
            .context("Getting 'sapzkey' records")?;
        let keymeta_records = self
            .dump
            .records_for_keyname("sapzkeymeta")
            .context("Getting 'sapzkeymeta' records")?;
        if key_records.len() != keymeta_records.len() {
            bail!("Mismatched sapzkey and sapzkeymeta records");
        }
        for (key, value) in key_records {
            let ivk = parse!(buf = &key.data, SaplingIncomingViewingKey, "ivk")?;
            let spending_key = parse!(
                buf = value.as_data(),
                ::sapling::zip32::ExtendedSpendingKey,
                "spending_key"
            )?;
            let metakey = DBKey::new("sapzkeymeta", &key.data);
            let metadata_binary = self
                .dump
                .value_for_key(&metakey)
                .context("Getting sapzkeymeta metadata")?;
            let metadata = parse!(buf = metadata_binary, KeyMetadata, "sapzkeymeta metadata")?;
            let keypair =
                SaplingKey::new(ivk, spending_key.clone(), metadata).context("Creating keypair")?;
            keys_map.insert(ivk, keypair);

            self.mark_key_parsed(&key);
            self.mark_key_parsed(&metakey);
        }
        Ok(SaplingKeys::new(keys_map))
    }

    fn parse_sapling_extended_full_viewing_keys(
        &self,
    ) -> Result<HashMap<SaplingIncomingViewingKey, ::sapling::zip32::ExtendedFullViewingKey>> {
        let mut viewing_keys = HashMap::new();
        if !self.dump.has_keys_for_keyname("sapextfvk") {
            return Ok(viewing_keys);
        }
        let records = self
            .dump
            .records_for_keyname("sapextfvk")
            .context("Getting 'sapextfvk' records")?;
        for (key, value) in records {
            let extfvk = parse!(
                buf = &key.data,
                ::sapling::zip32::ExtendedFullViewingKey,
                "sapextfvk extended full viewing key"
            )?;
            // zcashd writes a single byte `'1'` (0x31) and treats any other
            // value as "do not load this key" (see zcashd
            // walletdb.cpp:486-499). Mirror that contract: anything else
            // means the record is not what it claims to be.
            let marker = parse!(buf = value.as_data(), u8, "sapextfvk marker byte")?;
            if marker != b'1' {
                bail!(
                    "Unexpected sapextfvk marker byte: 0x{:02x} (expected 0x31)",
                    marker
                );
            }
            let ivk = SaplingIncomingViewingKey::new(
                extfvk
                    .to_diversifiable_full_viewing_key()
                    .to_ivk(::zip32::Scope::External)
                    .to_repr(),
            );
            if viewing_keys.contains_key(&ivk) {
                bail!("Duplicate sapextfvk record for ivk {:?}", ivk);
            }
            viewing_keys.insert(ivk, extfvk);

            self.mark_key_parsed(&key);
        }
        Ok(viewing_keys)
    }

    fn parse_sprout_keys(&self) -> Result<Option<SproutKeys>> {
        if !self.dump.has_keys_for_keyname("zkey") {
            return Ok(None);
        }
        let zkey_records = self
            .dump
            .records_for_keyname("zkey")
            .context("Getting 'zkey' records")?;
        let zkeymeta_records = self
            .dump
            .records_for_keyname("zkeymeta")
            .context("Getting 'zkeymeta' records")?;
        if zkey_records.len() != zkeymeta_records.len() {
            bail!("Mismatched zkey and zkeymeta records");
        }
        let mut zkeys_map = HashMap::new();
        for (key, value) in zkey_records {
            let payment_address = parse!(buf = &key.data, SproutPaymentAddress, "payment_address")?;
            let spending_key = parse!(buf = value.as_data(), u252, "spending_key")?;
            let metakey = DBKey::new("zkeymeta", &key.data);
            let metadata_binary = self
                .dump
                .value_for_key(&metakey)
                .context("Getting metadata")?;
            let metadata = parse!(buf = metadata_binary, KeyMetadata, "metadata")?;
            let keypair = SproutSpendingKey::new(spending_key, metadata);
            zkeys_map.insert(payment_address, keypair);

            self.mark_key_parsed(&key);
            self.mark_key_parsed(&metakey);
        }
        Ok(Some(SproutKeys::new(zkeys_map)))
    }

    fn parse_default_key(&self) -> Result<PubKey> {
        let value = self.value_for_keyname("defaultkey")?;
        parse!(buf = value, PubKey, "defaultkey")
    }

    fn parse_mnemonic_hd_chain(&self) -> Result<MnemonicHDChain> {
        let value = self.value_for_keyname("mnemonichdchain")?;
        parse!(buf = value, MnemonicHDChain, "mnemonichdchain")
    }

    fn parse_send_recipients(&self) -> Result<HashMap<TxId, Vec<RecipientMapping>>> {
        let mut send_recipients: HashMap<TxId, Vec<RecipientMapping>> = HashMap::new();
        if !self.dump.has_keys_for_keyname("recipientmapping") {
            return Ok(send_recipients);
        }
        let records = self
            .dump
            .records_for_keyname("recipientmapping")
            .context("Getting 'recipientmapping' records")?;
        for (key, value) in records {
            let mut p = Parser::new(&key.data);
            let txid = parse!(&mut p, TxId, "txid")?;
            let recipient_address = parse!(&mut p, RecipientAddress, "recipient_address")?;
            p.check_finished()?;
            let unified_address = parse!(buf = &value, String, "unified_address")?;
            let recipient_mapping = RecipientMapping::new(recipient_address, unified_address);
            send_recipients
                .entry(txid)
                .or_default()
                .push(recipient_mapping);
            self.mark_key_parsed(&key);
        }

        Ok(send_recipients)
    }

    fn parse_unified_accounts(&self) -> Result<UnifiedAccounts> {
        if !self.dump.has_keys_for_keyname("unifiedaddrmeta") {
            return Ok(UnifiedAccounts::none());
        }
        let address_metadata_records = self.dump.records_for_keyname("unifiedaddrmeta")?;
        let mut address_metadata = vec![];
        for (key, value) in address_metadata_records {
            let metadata = parse!(
                buf = &key.data,
                UnifiedAddressMetadata,
                "UnifiedAddressMetadata key"
            )?;
            address_metadata.push(metadata);
            let v: u32 = parse!(buf = value.as_data(), u32, "UnifiedAddressMetadata value")?;
            if v != 0 {
                bail!("Unexpected value for UnifiedAddressMetadata: 0x{:08x}", v);
            }
            self.mark_key_parsed(&key);
        }

        let account_metadata_records = self.dump.records_for_keyname("unifiedaccount")?;
        let mut account_metadata = HashMap::new();
        for (key, value) in account_metadata_records {
            let metadata = parse!(
                buf = &key.data,
                UnifiedAccountMetadata,
                "UnifiedAccountMetadata key"
            )?;
            account_metadata.insert(*metadata.ufvk_fingerprint(), metadata);
            let v: u32 = parse!(buf = value.as_data(), u32, "UnifiedAccountMetadata value")?;
            if v != 0 {
                bail!("Unexpected value for UnifiedAccountMetadata: 0x{:08x}", v);
            }
            self.mark_key_parsed(&key);
        }

        let full_viewing_keys_records = self.dump.records_for_keyname("unifiedfvk")?;
        let mut full_viewing_keys = HashMap::new();
        for (key, value) in full_viewing_keys_records {
            let key_id = parse!(
                buf = &key.data,
                UfvkFingerprint,
                "UnifiedFullViewingKey key"
            )?;
            let fvk = parse!(
                buf = value.as_data(),
                UnifiedFullViewingKey,
                "UnifiedFullViewingKey value"
            )?;
            full_viewing_keys.insert(key_id, fvk);
            self.mark_key_parsed(&key);
        }

        Ok(UnifiedAccounts::new(
            address_metadata,
            full_viewing_keys,
            account_metadata,
        ))
    }

    fn parse_hdseed(&self) -> Result<Option<LegacySeed>> {
        Ok(if self.dump.has_value_for_keyname("hdseed") {
            let (key, value) = self
                .dump
                .record_for_keyname("hdseed")
                .context("Getting 'hdseed' record")?;
            // The `hdseed` record is keyed by the seed's ZIP 32 fingerprint;
            // it is recomputed from the seed bytes during migration, so the
            // key is not retained here.
            let _fingerprint = parse!(buf = &key.data, SeedFingerprint, "seed fingerprint")?;
            let seed_data = parse!(buf = &value, Data, "legacy seed data")?;
            self.mark_key_parsed(&key);
            let seed = LegacySeed::from_vec(seed_data.into())
                .map_err(|_| anyhow!("legacy HD seed must be exactly 32 bytes"))?;
            Some(seed)
        } else {
            None
        })
    }

    fn parse_mnemonic_phrase(&self) -> Result<Bip39Mnemonic> {
        let (key, value) = self
            .dump
            .record_for_keyname("mnemonicphrase")
            .context("Getting 'mnemonicphrase' record")?;
        // The `mnemonicphrase` record is keyed by the seed's ZIP 32
        // fingerprint; the same value is recorded in the mnemonic HD chain
        // (`seed_fp`), which is the source used during migration.
        let _fingerprint = parse!(buf = &key.data, SeedFingerprint, "seed fingerprint")?;
        let bip39_mnemonic = parse!(buf = &value, Bip39Mnemonic, "mnemonic phrase")?;
        self.mark_key_parsed(&key);
        Ok(bip39_mnemonic)
    }

    fn parse_address_names(&self) -> Result<HashMap<Address, String>> {
        let records = self
            .dump
            .records_for_keyname("name")
            .context("Getting 'name' records")?;
        let mut address_names = HashMap::new();
        for (key, value) in records {
            let address = parse!(buf = &key.data, Address, "address")?;
            let name = parse!(buf = value.as_data(), String, "name")?;
            if address_names.contains_key(&address) {
                bail!("Duplicate address found: {}", address);
            }
            address_names.insert(address, name);

            self.mark_key_parsed(&key);
        }
        Ok(address_names)
    }

    fn parse_address_purposes(&self) -> Result<HashMap<Address, String>> {
        let records = self
            .dump
            .records_for_keyname("purpose")
            .context("Getting 'purpose' records")?;
        let mut address_purposes = HashMap::new();
        for (key, value) in records {
            let address = parse!(buf = &key.data, Address, "address")?;
            let purpose = parse!(buf = value.as_data(), String, "purpose")?;
            if address_purposes.contains_key(&address) {
                bail!("Duplicate address found: {}", address);
            }
            address_purposes.insert(address, purpose);

            self.mark_key_parsed(&key);
        }
        Ok(address_purposes)
    }

    fn parse_sapling_z_addresses(
        &self,
    ) -> Result<HashMap<SaplingZPaymentAddress, SaplingIncomingViewingKey>> {
        let mut sapling_z_addresses = HashMap::new();
        if !self.dump.has_keys_for_keyname("sapzaddr") {
            return Ok(sapling_z_addresses);
        }
        let records = self
            .dump
            .records_for_keyname("sapzaddr")
            .context("Getting 'sapzaddr' records")?;
        for (key, value) in records {
            let payment_address =
                parse!(buf = &key.data, SaplingZPaymentAddress, "payment address")?;
            let viewing_key = parse!(
                buf = value.as_data(),
                SaplingIncomingViewingKey,
                "viewing key"
            )?;
            if sapling_z_addresses.contains_key(&payment_address) {
                bail!("Duplicate payment address found: {:?}", payment_address);
            }
            sapling_z_addresses.insert(payment_address, viewing_key);

            self.mark_key_parsed(&key);
        }
        Ok(sapling_z_addresses)
    }

    fn parse_network_info(&self) -> Result<NetworkInfo> {
        let value = self
            .value_for_keyname("networkinfo")
            .context("Getting 'networkinfo' record")?;
        let network_info = parse!(buf = value.as_data(), NetworkInfo, "network info")?;
        Ok(network_info)
    }

    fn parse_orchard_note_commitment_tree(&self) -> Result<OrchardNoteCommitmentTree> {
        let value = self
            .value_for_keyname("orchard_note_commitment_tree")
            .context("Getting 'orchard_note_commitment_tree' record")?;
        let orchard_note_commitment_tree = parse!(
            buf = &&value.as_data()[4..],
            OrchardNoteCommitmentTree,
            "orchard note commitment tree"
        )?;
        Ok(orchard_note_commitment_tree)
    }

    fn parse_key_pool(&self) -> Result<HashMap<i64, KeyPoolEntry>> {
        let records = self
            .dump
            .records_for_keyname("pool")
            .context("Getting 'pool' records")?;
        let mut key_pool = HashMap::new();
        for (key, value) in records {
            let index = parse!(buf = &key.data, i64, "key pool index")?;
            let entry = parse!(buf = value.as_data(), KeyPoolEntry, "key pool entry")?;
            key_pool.insert(index, entry);

            self.mark_key_parsed(&key);
        }
        Ok(key_pool)
    }

    fn parse_cscripts(&self) -> Result<HashMap<ScriptId, Script>> {
        let mut cscripts = HashMap::new();
        if !self.dump.has_keys_for_keyname("cscript") {
            return Ok(cscripts);
        }
        let records = self
            .dump
            .records_for_keyname("cscript")
            .context("Getting 'cscript' records")?;
        for (key, value) in records {
            let script_id = parse!(buf = &key.data, ScriptId, "cscript ScriptID")?;
            let script = parse!(buf = value.as_data(), Script, "cscript redeem script")?;
            if cscripts.contains_key(&script_id) {
                bail!("Duplicate cscript ScriptID found: {:?}", script_id);
            }
            cscripts.insert(script_id, script);

            self.mark_key_parsed(&key);
        }
        Ok(cscripts)
    }

    fn parse_watch_scripts(&self) -> Result<Vec<WatchScript>> {
        if !self.dump.has_keys_for_keyname("watchs") {
            return Ok(Vec::new());
        }
        let records = self
            .dump
            .records_for_keyname("watchs")
            .context("Getting 'watchs' records")?;
        // Sort by BDB key bytes so the resulting `Vec` is deterministic
        // across runs. BDB primary-key uniqueness already guarantees no
        // duplicates, so an explicit dedupe set is unnecessary.
        let mut sorted: Vec<_> = records.into_iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.data.cmp(&b.data));
        let mut watch_scripts = Vec::with_capacity(sorted.len());
        for (key, _value) in sorted {
            let watch_script = parse!(buf = &key.data, WatchScript, "watch-only script")?;
            watch_scripts.push(watch_script);
            self.mark_key_parsed(&key);
        }
        Ok(watch_scripts)
    }

    fn parse_transactions(&self, strict: bool) -> Result<HashMap<TxId, WalletTx>> {
        let mut transactions = HashMap::new();
        // Some wallet files don't have any transactions
        if self.dump.has_keys_for_keyname("tx") {
            let records = self
                .dump
                .records_for_keyname("tx")
                .context("Getting 'tx' records")?;
            let mut sorted_records: Vec<_> = records.into_iter().collect();
            sorted_records.sort_by(|(key1, _), (key2, _)| key1.data.cmp(&key2.data));
            for (key, value) in sorted_records {
                let txid = parse!(buf = &key.data, TxId, "transaction ID")?;
                let trace = false;
                match parse!(buf = value.as_data(), WalletTx, "transaction", trace) {
                    Ok(transaction) => {
                        if transactions.contains_key(&txid) {
                            bail!("Duplicate transaction found: {:?}", txid);
                        }
                        transactions.insert(txid, transaction);
                    }
                    Err(e) if !strict => {
                        eprintln!(
                            "Unable to parse transaction data {}: {}",
                            value.as_data().encode_hex::<String>(),
                            e
                        );
                    }
                    err => {
                        err?;
                    }
                }

                self.mark_key_parsed(&key);
            }
        }
        Ok(transactions)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ::sapling::zip32::ExtendedSpendingKey;
    use zewif::{Data, Network, sapling::SaplingIncomingViewingKey};

    use super::*;
    use crate::{
        BDBDump, ZcashdDump, parse,
        zcashd_wallet::{transparent::WatchScriptKind, u160},
    };

    /// Round-trip a `sapextfvk` payload through the byte format that
    /// `parse_sapling_extended_full_viewing_keys` consumes, and confirm the
    /// IVK derived from the parsed EFVK matches the one computed directly
    /// from the originating spending key.
    #[test]
    fn extfvk_round_trip_yields_expected_ivk() {
        let xsk = ExtendedSpendingKey::master(b"sapextfvk-test-seed");
        #[allow(deprecated)]
        let original_efvk = xsk.to_extended_full_viewing_key();

        let mut bytes = Vec::new();
        original_efvk.write(&mut bytes).unwrap();

        let parsed_efvk = parse!(
            buf = &bytes,
            ::sapling::zip32::ExtendedFullViewingKey,
            "round-trip extfvk"
        )
        .unwrap();

        let parsed_ivk = SaplingIncomingViewingKey::new(
            parsed_efvk
                .to_diversifiable_full_viewing_key()
                .to_ivk(::zip32::Scope::External)
                .to_repr(),
        );
        let expected_ivk = SaplingIncomingViewingKey::new(
            xsk.to_diversifiable_full_viewing_key()
                .to_ivk(::zip32::Scope::External)
                .to_repr(),
        );

        assert_eq!(parsed_ivk, expected_ivk);
    }

    /// Serializes a BDB key as a length-prefixed keyname followed by raw key
    /// bytes — the exact wire format `ZcashdDump::from_bdb_dump` consumes.
    /// Only the keynames used by these tests are short enough that
    /// `CompactSize` reduces to a single byte.
    fn make_bdb_key(keyname: &str, key_data: &[u8]) -> Data {
        assert!(keyname.len() < 253, "test helper only supports short keynames");
        let mut bytes = Vec::with_capacity(1 + keyname.len() + key_data.len());
        bytes.push(keyname.len() as u8);
        bytes.extend_from_slice(keyname.as_bytes());
        bytes.extend_from_slice(key_data);
        Data::from_slice(&bytes)
    }

    /// Serializes a `Script` payload — CompactSize length followed by the
    /// script bytes — using the same restriction on short lengths.
    fn make_script_value(script: &[u8]) -> Data {
        assert!(script.len() < 253, "test helper only supports short scripts");
        let mut bytes = Vec::with_capacity(1 + script.len());
        bytes.push(script.len() as u8);
        bytes.extend_from_slice(script);
        Data::from_slice(&bytes)
    }

    fn dump_with_records(records: Vec<(Data, Data)>) -> ZcashdDump {
        let bdb = BDBDump {
            header_records: HashMap::new(),
            data_records: records.into_iter().collect(),
        };
        ZcashdDump::from_bdb_dump(&bdb, true).expect("from_bdb_dump")
    }

    /// Verifies `parse_cscripts` plumbs BDB records all the way through to a
    /// `HashMap<ScriptId, Script>` keyed by the 20-byte script hash carried in
    /// the BDB key, with the value-side bytes preserved verbatim.
    #[test]
    fn parse_cscripts_returns_scriptid_to_script_map() {
        let script_id_bytes = [0x42u8; 20];
        let redeem_script = [0xa9, 0x14, 0xff, 0x11, 0x87];

        let bdb_key = make_bdb_key("cscript", &script_id_bytes);
        let bdb_value = make_script_value(&redeem_script);

        let dump = dump_with_records(vec![(bdb_key, bdb_value)]);
        let parser = ZcashdParser::new(&dump, true);

        let cscripts = parser.parse_cscripts().expect("parse_cscripts");
        assert_eq!(cscripts.len(), 1);

        // Recover the ScriptId from the same bytes used in the BDB key and
        // look it up.
        let script_id = ScriptId::from(u160::from_slice(&script_id_bytes).unwrap());
        let script = cscripts.get(&script_id).expect("script for id");
        assert_eq!(script.as_ref(), &redeem_script[..]);
    }

    /// Multiple `cscript` records with distinct `ScriptId`s all appear in
    /// the resulting map, keyed correctly.
    #[test]
    fn parse_cscripts_collects_multiple_records() {
        let id_a = [0x11u8; 20];
        let id_b = [0x22u8; 20];
        let script_a = [0xa9, 0x14, 0x01, 0x87];
        let script_b = [0x76, 0xa9, 0x14, 0x02];

        let dump = dump_with_records(vec![
            (make_bdb_key("cscript", &id_a), make_script_value(&script_a)),
            (make_bdb_key("cscript", &id_b), make_script_value(&script_b)),
        ]);
        let parser = ZcashdParser::new(&dump, true);

        let cscripts = parser.parse_cscripts().expect("parse_cscripts");
        assert_eq!(cscripts.len(), 2);

        let sid_a = ScriptId::from(u160::from_slice(&id_a).unwrap());
        let sid_b = ScriptId::from(u160::from_slice(&id_b).unwrap());
        assert_eq!(cscripts.get(&sid_a).unwrap().as_ref(), &script_a[..]);
        assert_eq!(cscripts.get(&sid_b).unwrap().as_ref(), &script_b[..]);
    }

    /// Verifies `parse_watch_scripts` plumbs BDB records through to
    /// `WatchScript`s whose classification matches the encoded address (here,
    /// a P2PKH script).
    #[test]
    fn parse_watch_scripts_classifies_p2pkh() {
        // OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76u8, 0xa9, 0x14];
        script.extend_from_slice(&[0x77; 20]);
        script.extend_from_slice(&[0x88, 0xac]);

        // The `watchs` BDB key embeds the script as a length-prefixed
        // payload, mirroring the `Script::parse` contract.
        let mut key_data = Vec::with_capacity(1 + script.len());
        key_data.push(script.len() as u8);
        key_data.extend_from_slice(&script);

        let bdb_key = make_bdb_key("watchs", &key_data);
        let bdb_value = Data::from_slice(&[]);

        let dump = dump_with_records(vec![(bdb_key, bdb_value)]);
        let parser = ZcashdParser::new(&dump, true);

        let watch_scripts = parser.parse_watch_scripts().expect("parse_watch_scripts");
        assert_eq!(watch_scripts.len(), 1);

        let entry = &watch_scripts[0];
        assert_eq!(entry.script().as_ref(), script.as_slice());
        assert!(matches!(entry.kind(), WatchScriptKind::P2PKH(_)));
        assert!(entry.to_address_string(&Network::Mainnet).is_some());
    }

    /// A `watchs` record whose payload is non-standard must round-trip
    /// verbatim into `WatchScriptKind::Other(...)`.
    #[test]
    fn parse_watch_scripts_preserves_other_bytes() {
        let script = [0xde, 0xad, 0xbe, 0xef];

        let mut key_data = Vec::with_capacity(1 + script.len());
        key_data.push(script.len() as u8);
        key_data.extend_from_slice(&script);

        let bdb_key = make_bdb_key("watchs", &key_data);
        let bdb_value = Data::from_slice(&[]);

        let dump = dump_with_records(vec![(bdb_key, bdb_value)]);
        let parser = ZcashdParser::new(&dump, true);

        let watch_scripts = parser.parse_watch_scripts().expect("parse_watch_scripts");
        assert_eq!(watch_scripts.len(), 1);

        let entry = &watch_scripts[0];
        match entry.kind() {
            WatchScriptKind::Other(bytes) => {
                let raw: &[u8] = bytes.as_ref();
                assert_eq!(raw, &script[..]);
            }
            other => panic!("expected Other, got {:?}", other),
        }
        assert!(entry.to_address_string(&Network::Mainnet).is_none());
    }

    /// When neither key is present in the dump, both parsers must return
    /// empty collections rather than erroring.
    #[test]
    fn parsers_return_empty_when_keys_absent() {
        let dump = dump_with_records(vec![]);
        let parser = ZcashdParser::new(&dump, true);

        assert!(parser.parse_cscripts().expect("parse_cscripts").is_empty());
        assert!(parser.parse_watch_scripts().expect("parse_watch_scripts").is_empty());
    }
}
