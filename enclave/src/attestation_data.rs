use serde::Serialize;

use crate::eth::aliases::{Address, B256};

/// Information about a single proven slot.
#[derive(Serialize, Debug, Clone)]
pub struct SlotProofData {
    pub address: Address,
    #[serde(rename = "slotKey")]
    pub slot_key: B256,
    #[serde(skip_serializing)]
    pub value_hash: B256,
    #[serde(skip_serializing)]
    pub value_unhashed: B256, // Store actual slot value for price validation (not serialized)
}

/// Data to be included in the SGX report_data field commitment.
/// This structure itself is not directly put into report_data, but hashed.
#[derive(Serialize, Debug, Clone)]
pub struct AttestationPayload {
    pub blocks: Vec<(u64, B256)>,
    #[serde(rename = "vaultPositions")]
    pub vault_positions: Vec<(Address, u64)>,
    #[serde(rename = "finalBlocksHash")]
    pub final_blocks_hash: B256,
    #[serde(rename = "finalPositionsHash")]
    pub final_positions_hash: B256,
}

/// The final JSON output.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProvingResultOutput {
    pub attestation_payload: AttestationPayload,
    pub sgx_quote_hex: String,
}

/// Clean JSON output without timing information for parsing.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CleanProvingResultOutput {
    pub attestation_payload: AttestationPayload,
    pub sgx_quote_hex: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct SlotsProofPayload {
    pub block_hash: B256,
    pub block_number: u64,
    pub proven_slots: Vec<SlotProofData>,
    pub block_timestamp: u64,
}
