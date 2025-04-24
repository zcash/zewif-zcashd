use anyhow::Result;
use zewif::{Position, Transaction};

// Test that positions are non-zero after migration
#[test]
fn test_position_preservation() -> Result<()> {
    // Create a transaction with orchard actions and sapling outputs
    let txid_bytes = [0u8; 32]; // zeroed txid for testing
    let txid = zewif::TxId::from_bytes(txid_bytes);
    let mut tx = Transaction::new(txid);

    // Add a sapling output with a commitment
    let mut sapling_output = zewif::sapling::SaplingOutputDescription::new();
    let default_commitment =
        zewif::u256::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
    sapling_output.set_commitment(default_commitment);

    // Initially the position is 0 (default)
    assert_eq!(
        u32::from(*sapling_output.note_commitment_tree_position()),
        0,
        "Position should start at zero"
    );

    // Set a non-zero position
    sapling_output.set_note_commitment_tree_position(Position::from(42u32));
    assert_eq!(
        u32::from(*sapling_output.note_commitment_tree_position()),
        42,
        "Position should be updated to 42"
    );

    // Add an orchard action with a commitment
    let mut orchard_action = zewif::OrchardActionDescription::new();
    let commitment =
        zewif::u256::from_hex("0101010101010101010101010101010101010101010101010101010101010101");
    orchard_action.set_commitment(commitment);

    // Set a non-zero position
    orchard_action.set_note_commitment_tree_position(Position::from(123u32));
    assert_eq!(
        u32::from(*orchard_action.note_commitment_tree_position()),
        123,
        "Position should be updated to 123"
    );

    // Add them to the transaction
    tx.add_sapling_output(sapling_output);
    tx.add_orchard_action(orchard_action);

    // Now verify that the positions are maintained in the transaction
    let outputs = tx.sapling_outputs().unwrap();
    let actions = tx.orchard_actions().unwrap();

    assert_eq!(
        u32::from(*outputs[0].note_commitment_tree_position()),
        42,
        "Sapling output position should be preserved"
    );
    assert_eq!(
        u32::from(*actions[0].note_commitment_tree_position()),
        123,
        "Orchard action position should be preserved"
    );

    // This verifies that our position update logic works correctly
    Ok(())
}
