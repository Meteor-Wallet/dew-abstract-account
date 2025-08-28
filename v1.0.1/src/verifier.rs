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
