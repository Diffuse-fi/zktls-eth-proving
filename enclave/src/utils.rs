use automata_sgx_sdk::types::SgxStatus;
use tiny_keccak::{Hasher, Keccak};

use crate::error::ZkTlsStateHeaderResult;

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut res = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut res);
    res
}

pub(crate) fn extract_body(response: &str) -> ZkTlsStateHeaderResult<String> {
    let parts: Vec<&str> = response.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return Err(SgxStatus::Unexpected.into());
    }
    Ok(parts[1].to_string())
}

use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct RpcResponse<T> {
    jsonrpc: String,
    id: u32,
    pub(crate) result: T,
}
