use serde::Serialize;

use crate::eth::aliases::B256;

/// Information about a single proven slot.
#[derive(Serialize, Debug, Clone)]
pub struct SlotProofData {
    pub slot_key: B256,
    pub value_hash: B256,
    pub value_unhashed: B256,
}

/// Data to be included in the SGX report_data field commitment.
/// This structure itself is not directly put into report_data, but hashed.
#[derive(Serialize, Debug, Clone)]
pub struct SlotsProofPayload {
    pub block_hash: B256,
    pub block_number: u64,
    pub proven_slots: Vec<SlotProofData>,
}
