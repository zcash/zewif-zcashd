# ZCash Transaction Assignment Logic

This document details how transactions are assigned to accounts in zcashd and how this should be implemented in our migration tool. The goal is to accurately reproduce the transaction assignment behavior of zcashd when migrating wallets.

## 1. How zcashd Determines Transaction Ownership

### 1.1 Transaction-to-Account Association

In zcashd, transactions are determined to belong to a wallet if any of the following conditions are met (via `AddToWalletIfInvolvingMe` function):

1. The transaction was created by the wallet (`IsFromMe(tx)`)
2. The transaction contains outputs that belong to the wallet (`IsMine(tx)`)
3. The transaction spends notes that belong to the wallet (via nullifier matching)
4. The transaction is already known by the wallet (mapping exists)

### 1.2 Key Data Structures

- **RecipientMapping**: Maps transaction IDs to specific recipient addresses and unified addresses
  ```cpp
  class RecipientMapping {
  public:
      std::optional<libzcash::UnifiedAddress> ua;
      libzcash::RecipientAddress address;
  };
  ```

- **ZcashdUnifiedAccountMetadata**: Contains metadata about unified accounts, including seed fingerprint, coin type, account ID, and UFVK ID
  ```cpp
  class ZcashdUnifiedAccountMetadata {
  private:
      libzcash::SeedFingerprint seedFp;
      uint32_t bip44CoinType;
      libzcash::AccountId accountId;
      libzcash::UFVKId ufvkId;
  };
  ```

- **ZcashdUnifiedAddressMetadata**: Contains metadata about unified addresses including key ID, diversifier index, and receiver types
  ```cpp
  class ZcashdUnifiedAddressMetadata {
  private:
      libzcash::UFVKId ufvkId;
      libzcash::diversifier_index_t diversifierIndex;
      std::set<libzcash::ReceiverType> receiverTypes;
  };
  ```

### 1.3 Transaction Processing Flow

1. When a transaction is detected, `AddToWalletIfInvolvingMe` checks if it relates to any of the wallet's keys
2. The wallet stores the `RecipientMapping` between transaction IDs and recipient addresses
3. For unified addresses, transactions are linked to specific receiver types within the unified address
4. Transactions are added to the global transaction map (`mapWallet`), and their relationships to accounts are determined through various mappings

### 1.4 Account Determination Logic

Account determination follows this hierarchical approach:

1. **Explicit Address-Account Mappings**:
   - Unified addresses are explicitly mapped to accounts via `ZcashdUnifiedAddressMetadata`
   - Each address type has a corresponding account registry

2. **Nullifier-Based Assignment**:
   - Spent notes are tracked through nullifiers
   - Nullifiers are mapped back to specific accounts using:
     - `mapSproutNullifiersToNotes` for Sprout notes
     - `mapSaplingNullifiersToNotes` for Sapling notes
     - `orchardWallet` for Orchard notes

3. **Receiver-Type Identification**:
   - Different address types (transparent, sapling, orchard) are handled separately
   - Unified addresses contain multiple receiver types mapped to a single account

4. **Change Address Handling**:
   - Change addresses are detected through `IsChange(txout)`
   - Internal key paths are identified with specific HD derivation paths

## 2. Current Implementation in zewif-zcashd

### 2.1 Current Transaction Assignment Logic

Our current implementation in `migrate.rs` has several key functions for transaction assignment:

1. **extract_transaction_addresses**: 
   - Extracts all addresses involved in a transaction (lines 273-526)
   - Handles different address types (transparent, sapling, orchard)
   - Extracts addresses from:
     - Recipient mappings via `wallet.send_recipients()`
     - Transparent inputs and outputs
     - Sapling spends and outputs
     - Orchard actions
   - Uses fallback logic if transaction is "from me" but no addresses found

2. **convert_unified_accounts**:
   - Creates accounts based on unified account metadata (lines 685-875)
   - Maps addresses to accounts using `AddressRegistry`
   - Assigns transactions to accounts based on address involvement
   - Currently has fallback logic that adds transactions to all accounts when no relevant accounts can be determined (lines 851-854)

3. **initialize_address_registry**:
   - Creates an `AddressRegistry` to track address-to-account mappings (lines 646-682)
   - Currently only maps unified account addresses to accounts (line 658)
   - Has TODOs for mapping transparent and sapling addresses (lines 666, 677)

### 2.2 Current Limitations

Our current implementation has several limitations:

1. **Incomplete Registry Initialization**:
   - Only unified addresses are mapped to accounts
   - Transparent and sapling addresses lack explicit mappings
   - Contains placeholder TODO entries (lines 666-669, 677-678)

2. **Fallback Assignment Logic**:
   - Falls back to adding transactions to all accounts (lines 851-854)
   - Error handling assigns transactions to all accounts (lines 864-870)

3. **Viewing Key Support**:
   - Incomplete implementation for viewing keys (lines 805-822)

4. **Address Extraction**:
   - Complex, but incomplete detection of addresses from transaction components

## 3. Implementation Approach for Improved Transaction Assignment

### 3.1 Core Improvements Needed

1. **Complete AddressRegistry Initialization**:
   - Implement explicit mappings for all address types
   - Add proper handling for transparent addresses
   - Add proper handling for sapling addresses
   - Add proper handling for orchard addresses

2. **Enhanced Transaction Analysis**:
   - Improve nullifier tracking and matching
   - Detect internal change addresses accurately
   - Identify multi-account transactions properly

3. **Hierarchical Assignment Logic**:
   - Implement tiered assignment logic with specific fallbacks
   - Prioritize explicit account associations over implicit ones
   - Handle transactions that legitimately involve multiple accounts

4. **Improved Error Handling**:
   - Replace generic fallback with deterministic behavior
   - Add diagnostics for transaction assignment failures
   - Avoid assigning transactions to all accounts indiscriminately

### 3.2 Implementation Plan

1. **Enhance AddressRegistry**:
   - Complete the TODOs in `initialize_address_registry`
   - Map transparent addresses to accounts based on key metadata
   - Map sapling addresses to accounts based on viewing key relationships
   - Map orchard addresses based on unified account information

2. **Refine Transaction Address Extraction**:
   - Update `extract_transaction_addresses` to extract more accurate information
   - Improve how we identify "from me" transactions
   - Add better nullifier tracking for shielded transactions

3. **Improve Account Assignment Logic**:
   - Update the transaction-to-account assignment in `convert_unified_accounts`
   - Implement smarter fallback logic when direct assignment isn't possible
   - Handle multi-account transactions appropriately

4. **Add Verification and Validation**:
   - Add consistency checks for transaction assignment
   - Create metrics to evaluate the quality of transaction assignment
   - Log detailed information for debugging and improvement

## 4. Specific Implementation Details

### 4.1 Address-to-Account Mapping Improvements

Replace the TODOs in `initialize_address_registry` with:

```rust
// For transparent addresses
for zcashd_address in wallet.address_names().keys() {
    // Create an AddressId for this transparent address
    let addr_id = AddressId::Transparent(zcashd_address.into());
    
    // Determine the account this address belongs to
    if let Some(key_id) = find_account_for_transparent_address(wallet, zcashd_address) {
        registry.register(addr_id, key_id);
    }
}

// For sapling addresses
for (sapling_address, viewing_key) in wallet.sapling_z_addresses() {
    let addr_str = sapling_address.to_string(wallet.network());
    let addr_id = AddressId::Sapling(addr_str);
    
    // Determine the account this address belongs to
    if let Some(key_id) = find_account_for_sapling_address(wallet, sapling_address, viewing_key) {
        registry.register(addr_id, key_id);
    }
}
```

### 4.2 Transaction Analysis Improvements

Update the transaction analysis to better extract relevant addresses:

```rust
// Add improved nullifier handling for Sapling
if let Some(sapling_note_data) = tx.sapling_note_data() {
    for (outpoint, note_data) in sapling_note_data {
        if let Some(nullifier) = note_data.nullifer() {
            // Map nullifier to address
            if let Some(account_id) = find_account_for_sapling_nullifier(wallet, nullifier) {
                relevant_accounts.insert(account_id);
            }
        }
    }
}

// Add improved change detection
for (vout_idx, tx_out) in tx.vout().iter().enumerate() {
    if is_likely_change_output(wallet, tx_out) {
        // Change outputs should be assigned to the source account
        if tx.is_from_me() {
            if let Some(account_id) = find_source_account_for_transaction(wallet, tx) {
                relevant_accounts.insert(account_id);
            }
        }
    }
}
```

### 4.3 Smart Fallback Logic

Replace the current fallback logic with smarter alternatives:

```rust
// If we couldn't determine relevant accounts
if relevant_accounts.is_empty() {
    // Try to find the source account if this is an outgoing transaction
    if tx.is_from_me() {
        if let Some(account_id) = find_source_account_for_transaction(wallet, tx) {
            relevant_accounts.insert(account_id);
        }
    }
    
    // If still no accounts, check for default account assignment logic
    if relevant_accounts.is_empty() {
        if let Some(default_account_id) = find_default_account_id(wallet) {
            // Only assign to default account if it meets certain criteria
            if tx_could_belong_to_default_account(wallet, tx) {
                relevant_accounts.insert(default_account_id);
            }
        }
    }
}
```

### 4.4 Validation Logic

Add validation to ensure correct transaction assignment:

```rust
// Validation logic to ensure transactions are properly assigned
fn validate_transaction_assignment(wallet: &ZcashdWallet, tx_id: &TxId, assigned_accounts: &HashSet<u256>) -> Result<()> {
    // Check if the transaction should be assigned to any accounts
    let expected_accounts = determine_expected_accounts(wallet, tx_id);
    
    // Compare assigned accounts with expected accounts
    let missing_accounts: Vec<_> = expected_accounts.difference(assigned_accounts).collect();
    let extra_accounts: Vec<_> = assigned_accounts.difference(&expected_accounts).collect();
    
    if \!missing_accounts.is_empty() || \!extra_accounts.is_empty() {
        // Log warning about potential assignment issues
        eprintln\!("Warning: Transaction {} may have incorrect account assignment", tx_id);
        eprintln\!("  Missing accounts: {:?}", missing_accounts);
        eprintln\!("  Extra accounts: {:?}", extra_accounts);
    }
    
    Ok(())
}
```

## 5. Edge Cases and Special Handling

### 5.1 Multi-Account Transactions

Transactions that legitimately involve multiple accounts should be handled properly:

- Transactions between accounts in the same wallet
- Transactions with multiple recipient accounts
- Transactions that spend from multiple accounts

### 5.2 Legacy vs. Unified Account Handling

Different logic is needed for:
- Legacy transparent addresses (non-HD)
- Legacy Sapling addresses (pre-unified accounts)
- Modern unified account addresses

### 5.3 Detecting Change Addresses

Change addresses have special treatment:
- May not be recorded in the address book
- Are generated from internal key paths
- Should be assigned to the source account of the transaction

### 5.4 Handling Missing Metadata

Some wallet dumps may have incomplete metadata:
- Missing nullifiers for encrypted wallets
- Missing key paths for legacy addresses
- Missing unified account data for older wallets

## 6. Testing Strategy

To verify the improved transaction assignment logic:

1. **Unit Tests**:
   - Test each component of the assignment logic separately
   - Verify address-to-account mapping for each address type
   - Test transaction analysis with various transaction types

2. **Integration Tests**:
   - Test with real wallet dumps from different zcashd versions
   - Compare assignment results with expected behavior
   - Validate multi-account transaction handling

3. **Edge Case Testing**:
   - Test with wallets that have unified and non-unified accounts
   - Test with transactions between accounts in the same wallet
   - Test with missing metadata scenarios

## 7. Relationship to Other Components

The transaction assignment logic interacts with:

1. **Note Commitment Trees**:
   - Positions in the tree need to be preserved
   - Note data provides critical information for assignment

2. **Viewing Key Migration**:
   - Viewing keys are essential for identifying which addresses belong to which accounts
   - Both incoming and full viewing keys need accurate mapping

3. **Unified Address Support**:
   - Unified addresses contain multiple receiver types
   - Assignment needs to respect the unified account structure
