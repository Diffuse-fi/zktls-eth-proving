use anyhow::Result;
use serde::Deserialize;
use std::{collections::HashMap, ffi::CString, os::raw::c_char};
use tiny_keccak::{Hasher, Keccak};

use crate::{
    attestation_data::{AttestationPayload, SlotProofData, SlotsProofPayload},
    eth::{
        aliases::{Address, B256, U256},
        block::Block,
        header::Header,
        proof::ProofResponse,
    },
    trie::verify_proof,
};

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut res);
    res
}

#[derive(Clone)]
pub struct StorageProvingConfig {
    pub(crate) rpc_url: String,
    pub(crate) address: Address,
    pub(crate) storage_slots: Vec<B256>,
    pub(crate) block_number: u64,
    pub(crate) input_tokens_amount: U256,
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
        data.extend_from_slice(&block_number_32); // 32 bytes
        data.extend_from_slice(block_hash.as_ref()); // 32 bytes
    }
    keccak256(&data)
}

pub(crate) fn calculate_final_positions_hash(vault_position_pairs: &[(Address, u64)]) -> [u8; 32] {
    let mut data = Vec::new();
    for (vault_address, position_id) in vault_position_pairs {
        data.extend_from_slice(vault_address.as_ref()); // 20 bytes
        data.extend_from_slice(&[0u8; 4]); // 4 bytes of padding
        data.extend_from_slice(&position_id.to_be_bytes()); // 8 bytes
    }
    keccak256(&data)
}

pub(crate) fn construct_report_data(payload: &AttestationPayload) -> Result<[u8; 64]> {
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(payload.final_blocks_hash.as_ref());
    report_data[32..64].copy_from_slice(payload.final_positions_hash.as_ref());
    Ok(report_data)
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

extern "C" {
    fn ocall_make_http_request(
        url: *const c_char,
        method: *const c_char,
        body: *const u8,
        body_len: usize,
        response: *mut c_char,
        max_response_len: usize,
        actual_response_len: *mut usize,
        http_status: *mut u16,
    );
}

pub(crate) fn make_http_request(url: &str, method: &str, body: &[u8]) -> anyhow::Result<String> {
    const MAX_RESPONSE_LEN: usize = 256 * 1024 * 4 * 4;
    let mut response_buffer = vec![0u8; MAX_RESPONSE_LEN];
    let mut actual_response_len: usize = 0;
    let mut http_status: u16 = 0;

    let url_cstring = CString::new(url)?;
    let method_cstring = CString::new(method)?;

    unsafe {
        ocall_make_http_request(
            url_cstring.as_ptr(),
            method_cstring.as_ptr(),
            body.as_ptr(),
            body.len(),
            response_buffer.as_mut_ptr() as *mut c_char,
            MAX_RESPONSE_LEN,
            &mut actual_response_len,
            &mut http_status,
        );
    }

    if http_status != 200 {
        return Err(anyhow::anyhow!(
            "HTTP request failed with status: {}",
            http_status
        ));
    }

    if actual_response_len == 0 {
        tracing::warn!("Empty response from HTTP request, but status was 200");
        return Ok(String::new());
    }

    let response_slice = &response_buffer[..actual_response_len];
    let response_str = String::from_utf8(response_slice.to_vec())?;
    Ok(response_str)
}

pub fn get_block_header_from_rpc(
    rpc_url: &str,
    block_tag: &str,
) -> anyhow::Result<Header> {
    tracing::info!(block_tag, "Fetching block header");

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [block_tag, false],
        "id": 1
    })
    .to_string();

    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("HTTP request for block header failed: {:?}", e))?;

    tracing::debug!(
        response_body_len = response_str.len(),
        "Received block header response body"
    );

    let rpc_block_response: RpcResponse<Block> =
        serde_json::from_str(&response_str).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse block header RPC response: {}, response_str: {}",
                e,
                response_str
            )
        })?;

    let header = rpc_block_response.result.header;
    let rpc_block_hash = header.block_hash_untrusted;
    let calculated_block_hash = header.hash();

    if calculated_block_hash != rpc_block_hash {
        anyhow::bail!(
            "Block hash mismatch. Calculated: {:?}, RPC provided: {:?}",
            calculated_block_hash,
            rpc_block_hash
        );
    }
    tracing::info!(block_hash = ?calculated_block_hash, block_number = header.number, "Block header verified");
    Ok(header)
}

fn get_proof_from_rpc(
    rpc_url: &str,
    contract_address: Address,
    slot_keys: &[B256],
    block_number: u64,
) -> anyhow::Result<ProofResponse> {
    let slot_keys_hex: Vec<String> = slot_keys
        .iter()
        .map(|key| format!("0x{}", hex::encode(key.as_ref())))
        .collect();

    tracing::info!(%contract_address, block_number, "Fetching proof");

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getProof",
        "params": [
            format!("0x{}", hex::encode(contract_address.as_ref())),
            slot_keys_hex,
            format!("0x{:x}", block_number)
        ],
        "id": 1
    })
    .to_string();

    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("HTTP request for proof failed: {:?}", e))?;

    tracing::debug!(
        response_body_len = response_str.len(),
        "Received proof response body"
    );

    let rpc_proof_response: RpcResponse<ProofResponse> = serde_json::from_str(&response_str)
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse proof RPC response: \"{}\", response_str: {}",
                e,
                response_str
            )
        })?;

    tracing::info!("Proof received successfully");
    Ok(rpc_proof_response.result)
}

pub(crate) fn extract_storage_slots_with_merkle_proving(
    cli: &StorageProvingConfig,
    block_header: Header,
) -> anyhow::Result<SlotsProofPayload> {
    let contract_address = cli.address;

    let target_slot_keys = &cli.storage_slots;

    let block_number_val = block_header.number;

    let proof_response = get_proof_from_rpc(
        &cli.rpc_url,
        contract_address,
        target_slot_keys,
        block_number_val,
    )?;
    let verified_slot_values =
        verify_proof(proof_response, block_header.state_root.as_ref())
            .map_err(|e| anyhow::anyhow!("MPT proof verification failed: {:?}", e))?;
    tracing::info!("MPT proof verification successful");

    let mut processed_semantic_values: HashMap<B256, [u8; 32]> = HashMap::new();
    let mut non_existent_slots: Vec<B256> = Vec::new();

    for (proved_key, opt_mpt_value) in verified_slot_values {
        if let Some(mpt_value_bytes) = opt_mpt_value {
            tracing::debug!(slot_key = ?proved_key, value_bytes_len = mpt_value_bytes.len(), value_hex = %hex::encode(&mpt_value_bytes), "Slot has value from MPT");
            match get_semantic_u256_bytes(&mpt_value_bytes) {
                Ok(semantic_bytes) => {
                    let is_zero = semantic_bytes == [0u8; 32];
                    tracing::debug!(slot_key = ?proved_key, semantic_hex = %hex::encode(semantic_bytes), is_zero = is_zero, "Processed semantic bytes");

                    // check if this is actually a zero value that should be considered non-existent
                    if is_zero && mpt_value_bytes.is_empty() {
                        tracing::info!(slot_key = ?proved_key, "Slot has empty MPT value, treating as non-existent. Excluding from attestation.");
                        non_existent_slots.push(proved_key);
                    } else {
                        processed_semantic_values.insert(proved_key, semantic_bytes);
                    }
                }
                Err(e) => {
                    tracing::warn!(slot_key = ?proved_key, error = %e, "Failed to get semantic uint256 bytes for slot. It will be excluded from attestation if it was a target slot.");
                }
            }
        } else {
            // non-existent storage slots are excluded from final attestation
            tracing::info!(slot_key = ?proved_key, "Slot proven but does not exist (None). Excluding from attestation.");
            non_existent_slots.push(proved_key);
        }
    }

    if !non_existent_slots.is_empty() {
        let non_existent_json = serde_json::json!({
            "non_existent_slots": non_existent_slots.iter().map(|slot| format!("0x{}", hex::encode(slot.as_ref()))).collect::<Vec<_>>(),
            "count": non_existent_slots.len(),
            "message": "These slots do not exist and are excluded from the final attestation"
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&non_existent_json)
                .unwrap_or_else(|_| "Failed to serialize non-existent slots".to_string())
        );
    }

    let mut attested_slots_data: Vec<SlotProofData> = Vec::with_capacity(target_slot_keys.len());

    // only include slots that actually exist
    for target_slot_key in target_slot_keys.iter() {
        if let Some(semantic_bytes) = processed_semantic_values.get(target_slot_key) {
            attested_slots_data.push(SlotProofData {
                address: contract_address,
                slot_key: *target_slot_key,
                value_hash: keccak256(semantic_bytes).into(),
                value_unhashed: (*semantic_bytes).into(),
            });
        }
    }

    tracing::info!(
        count = attested_slots_data.len(),
        "Slots prepared for attestation payload"
    );

    Ok(SlotsProofPayload {
        block_hash: block_header.hash(),
        block_number: block_number_val,
        proven_slots: attested_slots_data,
        block_timestamp: block_header.timestamp,
    })
}
