use std::str::FromStr;

use crate::*;

impl FactoryContract {
    pub fn internal_message_for_create_account(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
        deadline: u64,
    ) -> String {
        json!({
            "blockchain_id": blockchain_id,
            "blockchain_address": blockchain_address,
            "account_id": self.internal_generate_account_id(blockchain_id.clone(), blockchain_address.clone()),
            "deadline": deadline
        })
        .to_string()
    }

    pub fn internal_generate_account_id(
        &self,
        blockchain_id: BlockchainId,
        blockchain_address: BlockchainAddress,
    ) -> AccountId {
        let account_id = format!(
            "{}-{}.{}",
            blockchain_address,
            blockchain_id,
            env::current_account_id()
        )
        .to_lowercase();

        AccountId::from_str(&account_id).expect(ContractError::InvalidAccountId.message())
    }
}
