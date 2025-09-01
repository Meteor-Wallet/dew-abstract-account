use crate::*;

impl SmartAccountContract {
    pub fn internal_verify_signature(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        message: String,
        signature: String,
    ) {
        // We believe that even if user signed 1000 signatures per day, 18,446,744,073,709,551,595 nonce
        // can be used for more than 5e13 years. So most likely user will never run out of nonce.
        assert!(
            self.internal_usable_nonce_left(blockchain_id.clone(), blockchain_address.clone()) > 20,
            "{}",
            ContractError::NonceNearlyExhausted.message()
        );

        match blockchain_id.to_lowercase().as_str() {
            "ethereum" | "bnb" | "bsc" | "polygon" | "arbitrum" | "optimism" | "base"
            | "avalanche" => {
                self.internal_verify_evm_signature(blockchain_address, signature, message)
            }
            "solana" => {
                self.internal_verify_solana_signature(blockchain_address, signature, message)
            }
            _ => panic!("{}", ContractError::UnsupportedBlockchain.message()),
        }
    }

    pub fn internal_verify_evm_signature(
        &self,
        blockchain_address: String,
        signature: String,
        message: String,
    ) {
        // Step 1: Get the hash of the constructed message, this hash is what was signed
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut to_hash = Vec::new();
        to_hash.extend(prefix.as_bytes());
        to_hash.extend(message.as_bytes());
        let hash = env::keccak256_array(&to_hash);

        // Step 2: Extract rsv components from the signature
        let sig_clean = signature.trim_start_matches("0x");
        let sig_bytes =
            hex::decode(sig_clean).expect(ContractError::InvalidSignatureFormat.message());

        assert!(
            sig_bytes.len() == 65,
            "{}",
            ContractError::InvalidSignatureFormat.message()
        );

        let mut rs = [0u8; 64];
        rs.copy_from_slice(&sig_bytes[0..64]);
        let mut v = sig_bytes[64];
        if v >= 27 {
            v -= 27;
        }

        // Step 3: Recover the public key from the signature using rsv components and the message hash
        let pubkey_bytes = env::ecrecover(&hash, &rs, v, false)
            .expect(ContractError::SignatureVerificationFailed.message());

        // Step 4: Derive Ethereum address from recovered public key
        let hash_pub = env::keccak256_array(&pubkey_bytes);
        let mut recovered_addr = hex::encode(&hash_pub[12..32]); // last 20 bytes of keccak256(pubkey)
        recovered_addr = format!("0x{}", recovered_addr);

        // Step 5: Verify that the recovered address matches the provided Ethereum address
        assert!(
            recovered_addr.to_lowercase() == blockchain_address.to_lowercase(),
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }

    pub fn internal_verify_solana_signature(
        &self,
        blockchain_address: String,
        signature: String,
        message: String,
    ) {
        let pubkey: [u8; 32] = bs58::decode(blockchain_address)
            .into_vec()
            .expect(ContractError::InvalidAddressFormat.message())
            .try_into()
            .expect(ContractError::InvalidKeyLen.message());

        // 2. Decode base58 signature (64 bytes)
        let sig: [u8; 64] = bs58::decode(signature)
            .into_vec()
            .expect(ContractError::InvalidSignatureFormat.message())
            .try_into()
            .expect(ContractError::InvalidSignatureFormat.message());

        // 3. Use raw message bytes (must match exactly what Solana signed)
        let msg = message.as_bytes();

        // 4. Verify signature
        assert!(
            env::ed25519_verify(&sig, msg, &pubkey),
            "{}",
            ContractError::SignatureVerificationFailed.message()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, AccountId};

    fn get_context(predecessor: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder.predecessor_account_id(predecessor);
        builder
    }

    #[test]
    fn test_internal_verify_evm_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "ethereum".to_string();
        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);

        let message = "Hello, NEAR!".to_string();
        let signature = "0xc26a320535280363c7caa54fb8ba9a923fa9111dc99310e775d7d9e30a27745f4e23306be095be18fa29193ff17b6e5fc3fbf8bf759ee8b0b8a670fe5ffce22a1c".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_evm_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "ethereum".to_string();
        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);

        let message = "Hello, Bob!".to_string();

        // This signature was generated for message "Hello, NEAR!"
        let signature = "0xc26a320535280363c7caa54fb8ba9a923fa9111dc99310e775d7d9e30a27745f4e23306be095be18fa29193ff17b6e5fc3fbf8bf759ee8b0b8a670fe5ffce22a1c".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_evm_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "ethereum".to_string();
        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);

        let message = "Hello, NEAR!".to_string();

        // This signature was generated with address 0x30fe32f6f345e1fe048e8b2452dc058693d5f736
        let signature =
            "0xccba0dbb0265fd5fb917599e6c45bf409f3b4cc7f3a0ac12b8b1596369b643593d5d985449e0f54621d932d867796fca2526fdb2c072da44d6d9f0419f689dd41c".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_evm_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "ethereum".to_string();
        let blockchain_address = "0x7286e6950fbdadf6c3f613b781eb6e007f5f1c0a".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_evm_signature(blockchain_address, signature, message);
    }

    #[test]
    fn test_internal_verify_solana_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "solana".to_string();
        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);

        let message = "Hello, NEAR!".to_string();
        let signature = "4rNekrB9jANZyy3wWXveCZJKAf2tQX3afNEp8odvXiDr3yBiCXZGkJjibTA9Lvgt9Vcor6b2zJ4sgSAsXHfQZz4d".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_solana_signature_wrong_message() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "solana".to_string();
        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);

        let message = "Hello, Bob!".to_string();
        // This signature was generated for message "Hello, NEAR!"
        let signature = "4rNekrB9jANZyy3wWXveCZJKAf2tQX3afNEp8odvXiDr3yBiCXZGkJjibTA9Lvgt9Vcor6b2zJ4sgSAsXHfQZz4d".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E004: signature verification failed")]
    fn test_internal_verify_solana_signature_wrong_address() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "solana".to_string();
        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);
        let message = "Hello, NEAR!".to_string();
        // This signature was generated with address 5rPKwR6HNWfFK4RqghMZjxLNBUFRPKUBSLTmmxjgHqcK
        let signature = "46y9R2juQbQmEAPXmD2GBbrV97vY29CQnjHAXsAg5ydXstZNSJAn34faUE1wjyfZe5KAqwoRx1XXMX3WQTnBAgVD".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }

    #[test]
    #[should_panic(expected = "E005: invalid signature format")]
    fn test_internal_verify_solana_signature_invalid_signature() {
        let context = get_context(accounts(0));
        testing_env!(context.build());

        let blockchain_id = "solana".to_string();
        let blockchain_address = "3pVqCdnjVfqSvb5XcKTh5XVdRc9ftVFEwSRMfD5DwTF5".to_string();
        let code_hash = CryptoHash::default();

        let contract =
            SmartAccountContract::init(blockchain_id, blockchain_address.clone(), code_hash);

        let message = "Hello, NEAR!".to_string();
        let signature = "abc123".to_string();

        contract.internal_verify_solana_signature(blockchain_address, signature, message);
    }
}
