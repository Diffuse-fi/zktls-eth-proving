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

use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct RpcResponse<T> {
    jsonrpc: String,
    id: u32,
    pub(crate) result: T,
}
