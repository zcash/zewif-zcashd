use zcash_transparent::address::TransparentAddress;

use zewif::{Amount, Network, SentOutput, transparent::TransparentSentOutput};

use crate::migrate::MigrateError;
use crate::{
    ZcashdWallet,
    migrate::WalletAccounts,
    zcashd_wallet::{
        u160, RecipientAddress,
        transparent::{KeyId, ScriptId},
    },
};

/// Attach sent-output metadata recovered from zcashd's `recipientmapping`
/// records to the synthesized legacy account.
///
/// Only transparent recipients are reconstructed here: their output index and
/// value are read directly from the transaction's transparent outputs. Sapling
/// and Orchard sent outputs would require trial-decrypting the outputs with the
/// wallet's outgoing viewing keys to recover their value and index, which is
/// not attempted; the raw transaction (carried in the export) remains
/// authoritative, and the destination unified addresses are preserved in the
/// address book.
///
/// The sending account is not recoverable from `recipientmapping` alone, so
/// sent outputs are attributed to the legacy account, which holds the
/// transparent keys in this migration.
pub(crate) fn attach_sent_outputs(
    wallet: &ZcashdWallet,
    accounts: &mut WalletAccounts,
) -> Result<(), MigrateError> {
    let legacy_index = accounts.legacy_index;
    let network = wallet.network();

    for (txid, mappings) in wallet.send_recipients() {
        let Some(wtx) = wallet.transactions().get(txid) else {
            continue;
        };
        let Some(bundle) = wtx.transaction().transparent_bundle() else {
            continue;
        };

        let mut outputs = Vec::new();
        for mapping in mappings {
            let Some(target) = transparent_target(&mapping.recipient_address) else {
                continue;
            };

            for (idx, tx_out) in bundle.vout.iter().enumerate() {
                if tx_out.recipient_address() == Some(target) {
                    let value = Amount::from_u64(tx_out.value().into_u64())?;
                    let recipient = if mapping.unified_address.is_empty() {
                        transparent_recipient_string(&mapping.recipient_address, network)
                    } else {
                        mapping.unified_address.clone()
                    };
                    outputs.push(SentOutput::Transparent(TransparentSentOutput::from_parts(
                        idx as u32, recipient, value,
                    )));
                    break;
                }
            }
        }

        if !outputs.is_empty() {
            accounts.accounts[legacy_index].add_sent_outputs(*txid, outputs);
        }
    }

    Ok(())
}

/// The transparent address a recipient mapping targets, if the recipient is
/// transparent.
fn transparent_target(recipient: &RecipientAddress) -> Option<TransparentAddress> {
    match recipient {
        RecipientAddress::KeyId(key_id) => Some(TransparentAddress::PublicKeyHash(key_id_bytes(
            key_id,
        ))),
        RecipientAddress::ScriptId(script_id) => {
            Some(TransparentAddress::ScriptHash(script_id_bytes(script_id)))
        }
        RecipientAddress::Sapling(_) | RecipientAddress::Orchard(_) => None,
    }
}

fn key_id_bytes(key_id: &KeyId) -> [u8; 20] {
    *AsRef::<[u8; 20]>::as_ref(&u160::from(key_id.clone()))
}

fn script_id_bytes(script_id: &ScriptId) -> [u8; 20] {
    *AsRef::<[u8; 20]>::as_ref(&u160::from(script_id.clone()))
}

/// The canonical t-address string for a transparent recipient.
fn transparent_recipient_string(recipient: &RecipientAddress, network: &Network) -> String {
    match recipient {
        RecipientAddress::KeyId(key_id) => key_id.to_string(network),
        RecipientAddress::ScriptId(script_id) => script_id.to_string(network),
        // Not reached: callers only pass transparent recipients here.
        RecipientAddress::Sapling(addr) => addr.to_string(network),
        RecipientAddress::Orchard(addr) => addr.to_string(network),
    }
}
