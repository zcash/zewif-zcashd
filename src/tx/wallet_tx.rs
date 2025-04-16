use std::collections::HashMap;

use anyhow::Result;

use zewif::{parse, parser::prelude::*};

use super::{OrchardTxMeta, SaplingBundleV5, ZIP225_TX_VERSION};

use zewif::{BranchId, CompactSize, Data, ExpiryHeight, u256};

use super::{
    JSOutPoint, JoinSplits, LockTime, OrchardBundle, SAPLING_TX_VERSION, SaplingBundle,
    SaplingBundleV4, SaplingNoteData, SaplingOutPoint, SproutNoteData, TxIn, TxOut, TxVersion,
};

#[derive(Debug, Clone, PartialEq)]
pub struct WalletTx {
    // CTransaction
    version: TxVersion,

    consensus_branch_id: Option<BranchId>,

    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    lock_time: Option<LockTime>,
    expiry_height: Option<ExpiryHeight>,
    sapling_bundle: SaplingBundle,

    orchard_bundle: OrchardBundle,

    join_splits: Option<JoinSplits>,

    // CMerkleTx
    hash_block: u256,
    merkle_branch: Vec<u256>,
    index: i32,

    // CWalletTx
    map_value: HashMap<String, String>,
    map_sprout_note_data: HashMap<JSOutPoint, SproutNoteData>,
    order_form: Vec<(String, String)>,
    time_received_is_tx_time: i32,
    time_received: i32,
    is_from_me: bool,
    is_spent: bool,
    sapling_note_data: Option<HashMap<SaplingOutPoint, SaplingNoteData>>,
    orchard_tx_meta: Option<OrchardTxMeta>,

    unparsed_data: Data,
}

impl WalletTx {
    pub fn version(&self) -> TxVersion {
        self.version
    }

    pub fn consensus_branch_id(&self) -> Option<BranchId> {
        self.consensus_branch_id
    }

    pub fn vin(&self) -> &[TxIn] {
        &self.vin
    }

    pub fn vout(&self) -> &[TxOut] {
        &self.vout
    }

    pub fn lock_time(&self) -> Option<LockTime> {
        self.lock_time
    }

    pub fn expiry_height(&self) -> Option<ExpiryHeight> {
        self.expiry_height
    }

    pub fn sapling_bundle(&self) -> &SaplingBundle {
        &self.sapling_bundle
    }

    pub fn orchard_bundle(&self) -> &OrchardBundle {
        &self.orchard_bundle
    }

    pub fn join_splits(&self) -> Option<&JoinSplits> {
        self.join_splits.as_ref()
    }

    pub fn hash_block(&self) -> u256 {
        self.hash_block
    }

    pub fn merkle_branch(&self) -> &[u256] {
        &self.merkle_branch
    }

    pub fn index(&self) -> i32 {
        self.index
    }

    pub fn map_value(&self) -> &HashMap<String, String> {
        &self.map_value
    }

    pub fn map_sprout_note_data(&self) -> &HashMap<JSOutPoint, SproutNoteData> {
        &self.map_sprout_note_data
    }

    pub fn order_form(&self) -> &[(String, String)] {
        &self.order_form
    }

    pub fn time_received_is_tx_time(&self) -> i32 {
        self.time_received_is_tx_time
    }

    pub fn time_received(&self) -> i32 {
        self.time_received
    }

    pub fn is_from_me(&self) -> bool {
        self.is_from_me
    }

    pub fn is_spent(&self) -> bool {
        self.is_spent
    }

    pub fn sapling_note_data(&self) -> Option<&HashMap<SaplingOutPoint, SaplingNoteData>> {
        self.sapling_note_data.as_ref()
    }

    pub fn orchard_tx_meta(&self) -> Option<&OrchardTxMeta> {
        self.orchard_tx_meta.as_ref()
    }

    pub fn unparsed_data(&self) -> &Data {
        &self.unparsed_data
    }
}

impl Parse for WalletTx {
    fn parse(p: &mut Parser) -> Result<Self> {
        // CTransaction

        let version: TxVersion = parse!(p, "version")?;

        let vin;
        let vout;
        let lock_time;
        let mut expiry_height = None;
        let sapling_bundle: SaplingBundle;
        let mut join_splits = None;
        let mut consensus_branch_id = None;
        let mut orchard_bundle = OrchardBundle::default();

        if version.is_zip225() {
            consensus_branch_id = Some(parse!(p, BranchId, "consensus_branch_id")?);
            lock_time = parse!(p, LockTime, "lock_time")?.as_option();
            expiry_height = parse!(p, ExpiryHeight, "expiry_height")?.as_option();
            vin = parse!(p, "vin")?;
            vout = parse!(p, "vout")?;
            let sapling_bundle_v5: SaplingBundleV5 = parse!(p, "sapling_bundle")?;
            sapling_bundle = SaplingBundle::V5(sapling_bundle_v5);

            orchard_bundle = parse!(p, "orchard_bundle")?;
        } else {
            vin = parse!(p, "vin")?;
            vout = parse!(p, "vout")?;
            lock_time = parse!(p, LockTime, "lock_time")?.as_option();
            if version.is_overwinter() || version.is_sapling() || version.is_future() {
                expiry_height = parse!(p, ExpiryHeight, "expiry_height")?.as_option();
            }

            let mut sapling_bundle_v4: SaplingBundleV4 = (version.is_sapling()
                || version.is_future())
            .then(|| parse!(p, "sapling_bundle"))
            .transpose()?
            .unwrap_or_default();

            if version.number() >= 2 {
                let use_groth = version.is_overwinter() && version.number() >= SAPLING_TX_VERSION;
                join_splits = Some(parse!(p, param = use_groth, "join_splits")?);
            }

            if (version.is_sapling() || version.is_future()) && sapling_bundle_v4.have_actions() {
                let binding_sig = parse!(p, "binding_sig")?;
                sapling_bundle_v4.set_binding_sig(binding_sig);
            }

            sapling_bundle = SaplingBundle::V4(sapling_bundle_v4);
        }

        // CMerkleTx
        let hash_block = parse!(p, "hash_block")?;
        let merkle_branch = parse!(p, "merkle_branch")?;
        let index = parse!(p, "index")?;

        // CWalletTx
        let unused_vt_prev = *parse!(p, CompactSize, "unused_vt_prev")?;
        assert!(
            unused_vt_prev == 0,
            "unused field in CWalletTx is not empty"
        );

        let map_value = parse!(p, "map_value")?;
        let map_sprout_note_data = parse!(p, "map_sprout_note_data")?;
        let order_form = parse!(p, "order_form")?;
        let time_received_is_tx_time = parse!(p, "time_received_is_tx_time")?;
        let time_received = parse!(p, "time_received")?;
        let from_me = parse!(p, "from_me")?;
        let is_spent = parse!(p, "is_spent")?;

        let mut sapling_note_data = None;
        if version.is_overwinter() && version.number() >= SAPLING_TX_VERSION {
            sapling_note_data = parse!(p, "sapling_note_data")?;
        }

        let mut orchard_tx_meta: Option<OrchardTxMeta> = None;
        if version.is_overwinter() && version.number() >= ZIP225_TX_VERSION {
            let meta = parse!(p, "orchard_tx_meta")?;
            orchard_tx_meta = Some(meta);
        }

        let unparsed_data = p.rest();
        if !unparsed_data.is_empty() {
            println!("💔 unparsed_data: {:?}", unparsed_data);
        }
        assert!(
            unparsed_data.is_empty(),
            "unparsed_data in CWalletTx is not empty"
        );

        Ok(Self {
            // CTransaction
            version,
            consensus_branch_id,
            vin,
            vout,
            lock_time,
            expiry_height,
            sapling_bundle,
            orchard_bundle,
            join_splits,

            // CMerkleTx
            hash_block,
            merkle_branch,
            index,

            // CWalletTx
            map_value,
            map_sprout_note_data,
            order_form,
            time_received_is_tx_time,
            time_received,
            is_from_me: from_me,
            is_spent,
            sapling_note_data,
            orchard_tx_meta,

            unparsed_data,
        })
    }
}
