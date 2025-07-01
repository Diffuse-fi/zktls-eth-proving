use serde::Serialize;

use crate::eth::primitives::B256;
use crate::timing::Timings;

/// Information about a single proven slot.
#[derive(Serialize, Debug, Clone)]
pub struct SlotProofData {
    pub slot_key: B256,
    pub value_hash: B256,
}

/// Data to be included in the SGX report_data field commitment.
/// This structure itself is not directly put into report_data, but hashed.
#[derive(Serialize, Debug, Clone)]
pub struct AttestationPayload {
    pub block_hash: B256,
    pub block_number: u64,
    pub proven_slots: Vec<SlotProofData>,
}

/// The final JSON output.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProvingResultOutput {
    pub attestation_payload: AttestationPayload,
    pub sgx_quote_hex: String,
    pub timings: Timings,
}
