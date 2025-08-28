pub mod contract_errors;
pub mod internal;
pub mod transaction;
pub mod types;
pub mod verifier;

use crate::types::{BlockchainAddress, BlockchainId, CrossChainAccessKey, Nonce};
use borsh::{BorshDeserialize, BorshSerialize};
use contract_errors::ContractError;
use near_sdk::json_types::Base64VecU8;
use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};
use near_sdk::serde_json::{self, json, Value};
use near_sdk::{env, near, store::LookupMap, AccountId, Promise, PublicKey};
use near_sdk::{ext_contract, BorshStorageKey, Gas, NearToken};
use transaction::{Action, AddKeyPermission, Transaction};

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
pub enum StorageKey {
    CrossChainAccessKeys,
}

#[near(contract_state)]
pub struct SmartAccountContract {
    factory: AccountId,
    cross_chain_access_keys: LookupMap<(BlockchainId, BlockchainAddress), CrossChainAccessKey>,
}

impl Default for SmartAccountContract {
    fn default() -> Self {
        panic!("{}", ContractError::ContractUninitialized.message());
    }
}

#[near]
impl SmartAccountContract {
    #[init]
    #[private]
    pub fn init(blockchain_id: BlockchainId, blockchain_address: BlockchainAddress) -> Self {
        let mut contract = Self {
            factory: env::predecessor_account_id(),
            cross_chain_access_keys: LookupMap::new(StorageKey::CrossChainAccessKeys),
        };

        contract.cross_chain_access_keys.insert(
            (blockchain_id.clone(), blockchain_address.clone()),
            CrossChainAccessKey {
                blockchain: blockchain_id,
                address: blockchain_address,
                nonce: contract.internal_generate_nonce(),
            },
        );

        contract
    }
}

#[ext_contract(ext_self)]
pub trait ExtSelf {
    fn sign_transaction_execution(&mut self, transaction: Transaction) -> Promise;
}

#[near]
impl SmartAccountContract {
    pub fn message_for_sign_transaction(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        transaction: Transaction,
    ) -> String {
        let cross_chain_access_key = self
            .cross_chain_access_keys
            .get(&(blockchain_id.clone(), blockchain_address.clone()))
            .expect(ContractError::UnauthorizedCrossChainAccessKey.message());

        self.internal_validate_transaction(&transaction);

        serde_json::to_string(&json!({
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "transaction": transaction,
            "nonce": cross_chain_access_key.nonce + 1,
        }))
        .unwrap()
    }

    pub fn blind_message_for_sign_transaction(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        transaction: Transaction,
    ) -> String {
        let message = self.message_for_sign_transaction(
            blockchain_id.clone(),
            blockchain_address.clone(),
            transaction,
        );

        let sha256_hash = env::sha256(message.as_bytes());

        bs58::encode(sha256_hash).into_string()
    }

    pub fn sign_transaction(
        &mut self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        transaction: Transaction,
        signature: String,
        blind_message: Option<bool>,
    ) -> Promise {
        let blind_message = blind_message.unwrap_or(false);

        let message = if blind_message {
            self.blind_message_for_sign_transaction(
                blockchain_id.clone(),
                blockchain_address.clone(),
                transaction.clone(),
            )
        } else {
            self.message_for_sign_transaction(
                blockchain_id.clone(),
                blockchain_address.clone(),
                transaction.clone(),
            )
        };

        self.internal_verify_signature(
            blockchain_id.clone(),
            blockchain_address.clone(),
            message,
            signature,
        );

        self.internal_update_nonce(blockchain_id, blockchain_address);

        let remaining_gas = env::prepaid_gas()
            .checked_sub(Gas::from_tgas(10))
            .expect(ContractError::NotEnoughGasLeft.message());

        // We use a cross contract call to self for the promise generation of the transaction
        // So that the nonce is consumed and won't be reverted if the promise generation fails
        // As long as this receipt is executed successfully, the nonce is updated
        // Even if the promise generation fails in next receipt, the nonce is still consumed,
        //   so the signature can't be reused
        ext_self::ext(env::current_account_id())
            .with_static_gas(remaining_gas)
            .sign_transaction_execution(transaction)
    }

    // This function is private
    // User should not have full access key to the contract
    // User should not have function call access key to the contract
    // transaction already validated in sign_transaction -> message_for_sign_transaction -> internal_validate_transaction
    // so the transaction can be executed directly
    #[private]
    pub fn sign_transaction_execution(&mut self, transaction: Transaction) -> Promise {
        self.internal_generate_promise(transaction)
    }
}
