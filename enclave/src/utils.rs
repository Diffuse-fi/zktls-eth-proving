use anyhow::Result;
use ruint::aliases::U256 as RuintU256;
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

use crate::{attestation_data::AttestationPayload, eth::primitives::{Address, B256}};

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

pub(crate) fn calculate_final_blocks_hash(blocks: &[(u64, B256)]) -> [u8; 32] {
    let mut data = Vec::new();
    for (block_number, block_hash) in blocks {
        // Convert block_number to 32 bytes for efficient calldata usage
        let mut block_number_32 = [0u8; 32];
        block_number_32[24..32].copy_from_slice(&block_number.to_be_bytes()); // Put u64 in last 8 bytes
        data.extend_from_slice(&block_number_32);     // 32 bytes
        data.extend_from_slice(block_hash.as_ref());  // 32 bytes
    }
    println!("hex data blocs hash: {}", hex::encode(&data));
    keccak256(&data)
}

pub(crate) fn calculate_final_positions_hash(vault_position_pairs: &[(Address, u64)]) -> [u8; 32] {
    let mut data = Vec::new();
    for (vault_address, position_id) in vault_position_pairs {
        data.extend_from_slice(vault_address.as_ref()); // 20 bytes
        data.extend_from_slice(&position_id.to_be_bytes()); // 8 bytes
    }
    println!("hex data positions hash: {}", hex::encode(&data));
    keccak256(&data)
}

pub(crate) fn construct_report_data(payload: &AttestationPayload) -> Result<[u8; 64]> {
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(payload.final_blocks_hash.as_ref());
    report_data[32..64].copy_from_slice(payload.final_positions_hash.as_ref());
    Ok(report_data)
}

pub(crate) fn convert_slots_to_b256(slot_numbers: &[u64]) -> Vec<B256> {
    let mut slot_keys = Vec::with_capacity(slot_numbers.len());
    for &slot_number in slot_numbers {
        let slot_u256 = RuintU256::from(slot_number);
        let slot_key: B256 = slot_u256.to_be_bytes().into();
        slot_keys.push(slot_key);
    }
    slot_keys
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
