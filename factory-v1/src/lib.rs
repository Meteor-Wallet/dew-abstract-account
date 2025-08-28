use borsh::{BorshDeserialize, BorshSerialize};
use contract_errors::*;
use near_sdk::serde_json::json;
use near_sdk::{env, near, store::LookupMap, AccountId, BorshStorageKey, CryptoHash};
use near_sdk::{Gas, NearToken, Promise};
use types::*;

mod contract_errors;
mod internal;
mod types;
mod verifier;

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
pub enum StorageKey {
    CodeHashUpgradeTarget,
}

#[near(contract_state)]
pub struct FactoryContract {
    pub owner_id: AccountId,
    pub latest_code_hash: CryptoHash,
    pub code_hash_upgrade_target: LookupMap<CryptoHash, CryptoHash>,
}

#[near]
impl FactoryContract {
    #[init]
    pub fn new(owner_id: AccountId, latest_code_hash: CryptoHash) -> Self {
        Self {
            owner_id,
            latest_code_hash,
            code_hash_upgrade_target: LookupMap::new(StorageKey::CodeHashUpgradeTarget),
        }
    }

    pub fn update_latest_code_hash(&mut self, new_code_hash: CryptoHash) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "{}",
            ContractError::MustBeOwner.message()
        );

        self.code_hash_upgrade_target
            .insert(self.latest_code_hash, new_code_hash);

        self.latest_code_hash = new_code_hash;
    }

    pub fn get_latest_code_hash(&self) -> CryptoHash {
        self.latest_code_hash
    }

    pub fn get_code_hash_upgrade_target(&self, code_hash: CryptoHash) -> Option<&CryptoHash> {
        self.code_hash_upgrade_target.get(&code_hash)
    }

    pub fn message_for_create_account(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> String {
        let deadline = env::block_timestamp() + 300_000_000_000; // 5 minutes from now

        self.internal_message_for_create_account(blockchain_id, blockchain_address, deadline)
    }

    pub fn create_account(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        deadline: u64,
        signature: String,
    ) -> Promise {
        assert!(
            env::block_timestamp() <= deadline,
            "{}",
            ContractError::SignatureExpired.message()
        );

        let deposit = env::attached_deposit();

        assert!(
            deposit.as_millinear() > 1,
            "{}",
            ContractError::InsufficientDeposit.message()
        );

        let message = self.internal_message_for_create_account(
            blockchain_id.clone(),
            blockchain_address.clone(),
            deadline,
        );

        self.internal_verify_signature(
            blockchain_id.clone(),
            blockchain_address.clone(),
            message,
            signature,
        );

        let account_id =
            self.internal_generate_account_id(blockchain_id.clone(), blockchain_address.clone());

        Promise::new(account_id)
            .create_account()
            .transfer(deposit)
            .use_global_contract(self.latest_code_hash.into())
            .function_call(
                "init".to_string(),
                json!({
                    "blockchain_id": blockchain_id,
                    "blockchain_address": blockchain_address,
                    "code_hash": self.latest_code_hash,
                })
                .to_string()
                .as_bytes()
                .to_vec(),
                NearToken::from_near(0),
                Gas::from_tgas(50),
            )
    }
}
