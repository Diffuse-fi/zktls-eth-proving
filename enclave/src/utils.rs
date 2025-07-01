use std::io::{BufRead, Read};

use anyhow::Result;
use automata_sgx_sdk::types::SgxStatus;
use serde::Deserialize;
use tiny_keccak::{Hasher, Keccak};

use crate::attestation_data::AttestationPayload;

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut res);
    res
}

pub(crate) fn extract_body(response: &str) -> Result<String> {
    let mut parts = response.splitn(2, "\r\n\r\n");
    let headers = parts.next().ok_or(SgxStatus::Unexpected)?;
    let body = parts.next().ok_or(SgxStatus::Unexpected)?;

    if headers.contains("Transfer-Encoding: chunked") {
        decode_chunked_body(body)
    } else {
        Ok(body.to_string())
    }
}

fn decode_chunked_body(body: &str) -> Result<String> {
    let mut reader = std::io::BufReader::new(body.as_bytes());
    let mut decoded = Vec::new();
    loop {
        let mut chunk_size_hex = String::new();
        reader.read_line(&mut chunk_size_hex)?;
        let chunk_size_hex = chunk_size_hex.trim();
        if chunk_size_hex.is_empty() {
            continue;
        }
        let chunk_size = usize::from_str_radix(chunk_size_hex, 16)?;
        if chunk_size == 0 {
            break;
        }
        let mut chunk_data = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk_data)?;
        decoded.extend_from_slice(&chunk_data);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
    String::from_utf8(decoded)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 sequence in chunked body: {}", e))
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
