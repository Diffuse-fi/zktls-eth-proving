use std::io::{BufRead, BufReader, Cursor, Read};

use anyhow::Result;
use automata_sgx_sdk::types::SgxStatus;
use tiny_keccak::{Hasher, Keccak};

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut res);
    res
}

pub(crate) fn extract_body(response: &str) -> Result<String> {
    let parts: Vec<&str> = response.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return Err(SgxStatus::Unexpected.into());
    }

    let headers = parts[0];
    let body = parts[1];

    if headers.contains("Transfer-Encoding: chunked") {
        decode_chunked(body.as_bytes()).map_err(|_| SgxStatus::Unexpected.into())
    } else {
        Ok(body.to_string())
    }
}

fn decode_chunked(chunked: &[u8]) -> Result<String> {
    let mut reader = BufReader::new(Cursor::new(chunked));
    let mut decoded = Vec::new();

    loop {
        let mut chunk_size_line = String::new();
        reader.read_line(&mut chunk_size_line)?;

        let chunk_size_line = chunk_size_line.trim();

        if chunk_size_line.is_empty() {
            continue;
        }

        let chunk_size = usize::from_str_radix(chunk_size_line, 16)?;

        if chunk_size == 0 {
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        reader.read_exact(&mut chunk)?;
        decoded.extend_from_slice(&chunk);

        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }

    Ok(String::from_utf8(decoded).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8 sequence")
    })?)
}

use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct RpcResponse<T> {
    jsonrpc: String,
    id: u32,
    pub(crate) result: T,
}

fn decode_storage_slot(input: &[u8]) -> [u8; 32] {
    if input.len() == 1 && input[0] <= 0x7f {
        let mut out = [0u8; 32];
        out[31] = input[0];
        return out;
    }
    if !input.is_empty() && input[0] >= 0x80 && input[0] <= 0xb7 {
        let content_len = (input[0] - 0x80) as usize;
        if input.len() < 1 + content_len {
            panic!("Invalid RLP encoding: insufficient length");
        }
        let content = &input[1..1 + content_len];
        let mut out = [0u8; 32];
        out[32 - content.len()..].copy_from_slice(content);
        return out;
    }
    let mut out = [0u8; 32];
    if input.len() <= 32 {
        out[32 - input.len()..].copy_from_slice(input);
    } else {
        panic!("Storage slot exceeds 32 bytes");
    }
    out
}

// v0.1 specific!
#[derive(Debug)]
pub(crate) struct MessageData {
    pub(crate) eth_amount: [u8; 32],
    pub(crate) other_full: [u8; 32],
    empty: u8, // always 0
    func: u8,
    nonce: [u8; 10],
    depositor: [u8; 20],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvingOutput {
    /// Hex‑encoded 32‑byte value for `eth_amount`
    pub eth_amount: String,
    /// Hex‑encoded 32‑byte value for `storage_slot2`
    pub storage_slot2: String,
    /// Hex‑encoded sgx_quote (variable length bytes)
    pub sgx_quote: String,
}

impl MessageData {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut data = [0u8; 64];

        data[0..32].copy_from_slice(&self.eth_amount);
        data[32] = self.empty;
        data[33] = self.func;
        data[34..44].copy_from_slice(&self.nonce);
        data[44..64].copy_from_slice(&self.depositor);
        data
    }
}

pub(crate) fn reassemble_message(eth_slot_raw: &[u8], other_slot_raw: &[u8]) -> MessageData {
    let eth_amount_full = decode_storage_slot(eth_slot_raw);
    let other_full = decode_storage_slot(other_slot_raw);
    let empty = other_full[0];
    let func = other_full[1];
    let mut nonce = [0u8; 10];
    nonce.copy_from_slice(&other_full[2..12]);
    let mut depositor = [0u8; 20];
    depositor.copy_from_slice(&other_full[12..32]);

    MessageData {
        eth_amount: eth_amount_full,
        other_full,
        empty,
        func,
        nonce,
        depositor,
    }
}
