#[derive(Debug)]
pub enum ContractError {
    UnsupportedBlockchain,       // E001
    InvalidAddressFormat,        // E002
    InvalidKeyLen,               // E003
    SignatureVerificationFailed, // E004
    InvalidSignatureFormat,      // E005
    MustBeOwner,                 // E019
    SignatureExpired,            // E020
    InvalidAccountId,            // E021
    InsufficientDeposit,         // E022
}

impl ContractError {
    pub fn message(&self) -> &'static str {
        match self {
            ContractError::UnsupportedBlockchain => "E001: unsupported blockchain",
            ContractError::InvalidAddressFormat => "E002: invalid address format",
            ContractError::InvalidKeyLen => "E003: invalid public key length",
            ContractError::SignatureVerificationFailed => "E004: signature verification failed",
            ContractError::InvalidSignatureFormat => "E005: invalid signature format",
            ContractError::MustBeOwner => "E019: caller must be the owner",
            ContractError::SignatureExpired => "E020: signature has expired",
            ContractError::InvalidAccountId => "E021: invalid account id",
            ContractError::InsufficientDeposit => "E022: insufficient deposit",
        }
    }
}
