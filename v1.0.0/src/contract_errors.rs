#[derive(Debug)]
pub enum ContractError {
    UnsupportedBlockchain,           // E001
    InvalidAddressFormat,            // E002
    InvalidKeyLen,                   // E003
    SignatureVerificationFailed,     // E004
    InvalidSignatureFormat,          // E005
    UnauthorizedCrossChainAccessKey, // E008
    NotEnoughGasLeft,                // E011
    CannotGrantAccessKeyToSelf,      // E013
    ContractUninitialized,           // E014
    EmptyTransaction,                // E016
    ActionNotAllowed,                // E018
}

impl ContractError {
    pub fn message(&self) -> &'static str {
        match self {
            ContractError::UnsupportedBlockchain => "E001: unsupported blockchain",
            ContractError::InvalidAddressFormat => "E002: invalid address format",
            ContractError::InvalidKeyLen => "E003: invalid public key length",
            ContractError::SignatureVerificationFailed => "E004: signature verification failed",
            ContractError::InvalidSignatureFormat => "E005: invalid signature format",
            ContractError::UnauthorizedCrossChainAccessKey => {
                "E008: unauthorized cross-chain access key"
            }
            ContractError::NotEnoughGasLeft => "E011: not enough gas left",
            ContractError::CannotGrantAccessKeyToSelf => "E013: cannot grant access key to self",
            ContractError::ContractUninitialized => "E014: contract uninitialized",
            ContractError::EmptyTransaction => "E016: empty transaction",
            ContractError::ActionNotAllowed => "E018: action not allowed",
        }
    }
}
