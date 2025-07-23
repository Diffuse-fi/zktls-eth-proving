
use anyhow::Result;
use ruint::aliases::U256 as RuintU256;
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

use crate::{attestation_data::AttestationPayload, eth::primitives::B256};

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut res);
    res
}



#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub(crate) struct RpcResponse<T> {
    jsonrpc: String,
    id: serde_json::Value,
    pub(crate) result: T,
}

pub(crate) fn construct_report_data(payload: &AttestationPayload) -> Result<[u8; 64]> {
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(payload.block_hash.as_ref());

    if !payload.proven_slots.is_empty() {
        let mut concatenated_value_hashes = Vec::new();
        for slot_data in &payload.proven_slots {
            concatenated_value_hashes.extend_from_slice(slot_data.value_hash.as_ref());
        }
        let slot_commitment_hash = keccak256(&concatenated_value_hashes);
        report_data[32..64].copy_from_slice(&slot_commitment_hash);
    }
    Ok(report_data)
}




pub(crate) fn parse_slots_to_prove(slots_str: &str) -> Result<Vec<B256>> {
    let slot_numbers: Result<Vec<RuintU256>, _> = slots_str
        .split(',')
        .map(|s| {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                RuintU256::from_str_radix(hex, 16)
            } else {
                RuintU256::from_str_radix(s, 10)
            }
        })
        .collect();

    let slot_numbers = slot_numbers
        .map_err(|e| anyhow::anyhow!("Invalid slot number format: {}", e))?;

    if slot_numbers.len() > 1000 {
        anyhow::bail!("Requested too many slots to prove (max 1000): {}", slot_numbers.len());
    }

    let mut slot_keys = Vec::with_capacity(slot_numbers.len());
    for slot_number in slot_numbers {
        let slot_key: B256 = slot_number.to_be_bytes().into();
        slot_keys.push(slot_key);
    }

    tracing::debug!(
        slots_count = slot_keys.len(),
        first_slot = ?slot_keys.first(),
        last_slot = ?slot_keys.last(),
        "Parsed storage slots to prove"
    );
    Ok(slot_keys)
}

pub(crate) fn get_semantic_u256_bytes(bytes_after_first_mpt_decode: &[u8]) -> Result<[u8; 32]> {
    let final_bytes: Vec<u8>;

    if bytes_after_first_mpt_decode.is_empty() {
        final_bytes = Vec::new();
    } else if bytes_after_first_mpt_decode.len() == 1 && bytes_after_first_mpt_decode[0] < 0x80 {
        final_bytes = bytes_after_first_mpt_decode.to_vec();
    } else {
        match rlp::decode::<Vec<u8>>(bytes_after_first_mpt_decode) {
            Ok(decoded_inner) => {
                final_bytes = decoded_inner;
            }
            Err(_) => {
                final_bytes = bytes_after_first_mpt_decode.to_vec();
            }
        }
    }

    let mut padded_value = [0u8; 32];
    let len = final_bytes.len();
    if len > 32 {
        return Err(anyhow::anyhow!(
            "Final semantic numeric value 0x{} is longer than 32 bytes (length: {})",
            hex::encode(final_bytes),
            len
        ));
    }
    let start_index = 32_usize.saturating_sub(len);
    padded_value[start_index..].copy_from_slice(&final_bytes);
    Ok(padded_value)
}
