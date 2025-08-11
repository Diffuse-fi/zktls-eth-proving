use serde::Deserialize;

use super::aliases::{Address, B256};

/// Storage-proof leaf (only parts needed by the verifier).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    pub key: B256,
    pub proof: Vec<String>,
}

/// Response type for `eth_getProof`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofResponse {
    pub address: Address,
    pub storage_hash: B256,
    pub account_proof: Vec<String>,
    pub storage_proof: Vec<StorageProof>,
}
