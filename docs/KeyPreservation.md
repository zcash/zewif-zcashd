# ZCash Key Preservation Strategy

This document outlines how cryptographic keys are handled during wallet migration with the ZeWIF format.

## Key Types in ZCash

ZCash uses several different types of cryptographic keys for various purposes:

### Spending Keys

Spending keys enable the creation of shielded transactions and authorize spending from shielded addresses. These include:

- **Extended Spending Keys**: Full keys that grant complete spending authority
- **Raw Spending Keys**: The core cryptographic material needed for spending

During migration, spending keys are preserved exactly as they exist in the source wallet to maintain spending capability.

### Viewing Keys

ZCash has a hierarchy of viewing keys with different capabilities:

- **Full Viewing Keys (FVKs)**: Allow viewing all transaction details (incoming and outgoing)
- **Incoming Viewing Keys (IVKs)**: Allow detection of incoming transactions only
- **Diversified Payment Addresses**: Multiple addresses can be derived from a single IVK

## Migration Strategy

Our migration strategy focuses on **data preservation** rather than recreating wallet functionality:

### What We Preserve

1. **Spending Keys**: All spending keys are preserved exactly as they exist in the source wallet
2. **Incoming Viewing Keys (IVKs)**: All IVKs are preserved exactly as they exist in the source wallet
3. **Address-to-Key Relationships**: The connection between addresses and their keys is maintained

### What We Don't Store Separately

1. **Full Viewing Keys (FVKs)**: We don't separately store FVKs because:
   - They can be derived from spending keys when needed
   - Source wallets typically don't store FVKs separately when spending keys exist
   - In data migration, we focus on preserving what exists rather than deriving new data

## Implementation Details

### IVK Preservation

Incoming Viewing Keys are preserved through these steps:

1. During wallet parsing, we extract IVKs associated with each shielded address
2. Each IVK is stored as a property of its shielded address in the ZeWIF format
3. When migrating to a different wallet format, IVKs are transferred to maintain viewing capability

```rust
// Example of how IVKs are preserved during Sapling address migration
pub fn convert_sapling_addresses(wallet: &ZcashdWallet, /* other params */) -> Result<()> {
    for (sapling_address, viewing_key) in wallet.sapling_z_addresses() {
        let address_str = sapling_address.to_string(wallet.network());
        
        // Create a new ShieldedAddress and preserve the incoming viewing key
        let mut shielded_address = zewif::ShieldedAddress::new(address_str.clone());
        shielded_address.set_incoming_viewing_key(viewing_key.to_owned());
        
        // ... additional code to handle other properties and account assignment
    }
}
```

### Spending Key Preservation

Spending keys follow a similar pattern:

1. During wallet parsing, we extract spending keys where available
2. Each spending key is stored with its associated address
3. The original key format is preserved to maintain compatibility

## Benefits of This Approach

1. **Minimalism**: We store only what's necessary and actually present in source wallets
2. **Accuracy**: All preserved keys match exactly what was in the source wallet
3. **Completeness**: All necessary data for spending and viewing is maintained
4. **Simplicity**: The implementation avoids unnecessary complexity from key derivation

## Testing

We validate key preservation through comprehensive tests:

1. **IVK Preservation Tests**: Verify all IVKs are correctly preserved during migration
2. **Spending Key Tests**: Ensure spending capability is maintained
3. **Edge Case Tests**: Handle scenarios where keys may be missing

These tests ensure the migration process maintains all cryptographic capabilities of the original wallet.