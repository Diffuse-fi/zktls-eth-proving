use crate::eth::{de, header::Header, primitives::*};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(flatten)]
    pub header: Header,
    pub transactions: Vec<B256>,
    #[serde(default)]
    pub withdrawals: Option<Vec<Withdrawal>>,
}

#[derive(Debug, Deserialize)]
pub struct Withdrawal {
    #[serde(deserialize_with = "de::hex_u64")]
    pub index: u64,
    #[serde(rename = "validatorIndex", deserialize_with = "de::hex_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(deserialize_with = "de::hex_u64")]
    pub amount: u64,
}
