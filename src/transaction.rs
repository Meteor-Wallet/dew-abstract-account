use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};
use near_sdk::serde_json::Value;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "near_sdk::serde")]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub signer_id: String,
    pub receiver_id: String,
    pub actions: Vec<Action>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "near_sdk::serde")]
#[serde(tag = "type", content = "params")]
pub enum Action {
    CreateAccount,

    #[serde(rename_all = "camelCase")]
    DeployContract {
        code: Vec<u8>,
    },

    #[serde(rename_all = "camelCase")]
    FunctionCall {
        method_name: String,
        args: Value,
        gas: String,
        deposit: String,
    },

    #[serde(rename_all = "camelCase")]
    Transfer {
        deposit: String,
    },

    #[serde(rename_all = "camelCase")]
    Stake {
        stake: String,
        public_key: String,
    },

    #[serde(rename_all = "camelCase")]
    AddKey {
        public_key: String,
        access_key: AccessKey,
    },

    #[serde(rename_all = "camelCase")]
    DeleteKey {
        public_key: String,
    },

    #[serde(rename_all = "camelCase")]
    DeleteAccount {
        beneficiary_id: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "near_sdk::serde")]
#[serde(rename_all = "camelCase")]
pub struct AccessKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    pub permission: AddKeyPermission,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AddKeyPermission {
    FullAccess,
    FunctionCall {
        receiver_id: String,
        allowance: Option<String>,
        method_names: Option<Vec<String>>,
    },
}

impl Serialize for AddKeyPermission {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AddKeyPermission::FullAccess => serializer.serialize_str("FullAccess"),
            AddKeyPermission::FunctionCall {
                receiver_id,
                allowance,
                method_names,
            } => {
                #[derive(Serialize)]
                #[serde(crate = "near_sdk::serde")]
                #[serde(rename_all = "camelCase")]
                struct Perm<'a> {
                    receiver_id: &'a String,
                    allowance: &'a Option<String>,
                    method_names: &'a Option<Vec<String>>,
                }
                let p = Perm {
                    receiver_id,
                    allowance,
                    method_names,
                };
                p.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for AddKeyPermission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(crate = "near_sdk::serde")]
        #[serde(untagged)]
        enum Repr {
            FullAccess(String),
            #[serde(rename_all = "camelCase")]
            FunctionCall {
                receiver_id: String,
                allowance: Option<String>,
                method_names: Option<Vec<String>>,
            },
        }

        match Repr::deserialize(deserializer)? {
            Repr::FullAccess(s) if s == "FullAccess" => Ok(AddKeyPermission::FullAccess),
            Repr::FunctionCall {
                receiver_id,
                allowance,
                method_names,
            } => Ok(AddKeyPermission::FunctionCall {
                receiver_id,
                allowance,
                method_names,
            }),
            _ => Err(near_sdk::serde::de::Error::custom(
                "invalid AddKeyPermission",
            )),
        }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use serde_json::json;

    fn roundtrip<T>(value: &T, expected: serde_json::Value)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        // serialize
        let serialized = serde_json::to_value(value).unwrap();
        assert_eq!(serialized, expected, "serialization mismatch");

        // deserialize
        let decoded: T = serde_json::from_value(expected.clone()).unwrap();
        assert_eq!(&decoded, value, "deserialization mismatch");
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction {
            signer_id: "alice.near".to_string(),
            receiver_id: "contract.near".to_string(),
            actions: vec![
                Action::CreateAccount,
                Action::Transfer {
                    deposit: "1000".to_string(),
                },
            ],
        };

        let expected = json!({
            "signerId": "alice.near",
            "receiverId": "contract.near",
            "actions": [
                { "type": "CreateAccount" },
                { "type": "Transfer", "params": { "deposit": "1000" } }
            ]
        });

        roundtrip(&tx, expected);
    }

    #[test]
    fn schema_create_account() {
        let action = Action::CreateAccount;
        let expected = json!({ "type": "CreateAccount" });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_deploy_contract() {
        let action = Action::DeployContract {
            code: vec![1, 2, 3],
        };
        let expected = json!({
            "type": "DeployContract",
            "params": { "code": [1, 2, 3] }
        });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_function_call() {
        let action = Action::FunctionCall {
            method_name: "foo".to_string(),
            args: json!({"x": 42}),
            gas: "1000".to_string(),
            deposit: "2000".to_string(),
        };
        let expected = json!({
            "type": "FunctionCall",
            "params": {
                "methodName": "foo",
                "args": { "x": 42 },
                "gas": "1000",
                "deposit": "2000"
            }
        });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_add_key_full_access() {
        let action = Action::AddKey {
            public_key: "ed25519:abcd".to_string(),
            access_key: AccessKey {
                nonce: Some(1),
                permission: AddKeyPermission::FullAccess,
            },
        };
        let expected = json!({
            "type": "AddKey",
            "params": {
                "publicKey": "ed25519:abcd",
                "accessKey": {
                    "nonce": 1,
                    "permission": "FullAccess"
                }
            }
        });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_add_key_function_call() {
        let action = Action::AddKey {
            public_key: "ed25519:xyz".to_string(),
            access_key: AccessKey {
                nonce: None,
                permission: AddKeyPermission::FunctionCall {
                    receiver_id: "contract.near".to_string(),
                    allowance: Some("500".to_string()),
                    method_names: Some(vec!["m1".to_string(), "m2".to_string()]),
                },
            },
        };
        let expected = json!({
            "type": "AddKey",
            "params": {
                "publicKey": "ed25519:xyz",
                "accessKey": {
                    "permission": {
                        "receiverId": "contract.near",
                        "allowance": "500",
                        "methodNames": ["m1", "m2"]
                    }
                }
            }
        });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_transfer() {
        let action = Action::Transfer {
            deposit: "123".to_string(),
        };
        let expected = json!({
            "type": "Transfer",
            "params": { "deposit": "123" }
        });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_stake() {
        let action = Action::Stake {
            stake: "1000".to_string(),
            public_key: "ed25519:xxx".to_string(),
        };
        let expected = json!({
            "type": "Stake",
            "params": { "stake": "1000", "publicKey": "ed25519:xxx" }
        });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_delete_key() {
        let action = Action::DeleteKey {
            public_key: "ed25519:zzz".to_string(),
        };
        let expected = json!({
            "type": "DeleteKey",
            "params": { "publicKey": "ed25519:zzz" }
        });
        roundtrip(&action, expected);
    }

    #[test]
    fn schema_delete_account() {
        let action = Action::DeleteAccount {
            beneficiary_id: "alice.near".to_string(),
        };
        let expected = json!({
            "type": "DeleteAccount",
            "params": { "beneficiaryId": "alice.near" }
        });
        roundtrip(&action, expected);
    }
}
