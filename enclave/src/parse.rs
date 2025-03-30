use automata_sgx_sdk::types::SgxStatus;

use crate::error::ZkTlsStateHeaderResult;

pub(crate) fn extract_body(response: &str) -> ZkTlsStateHeaderResult<String> {
    let parts: Vec<&str> = response.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return Err(SgxStatus::Unexpected.into());
    }
    Ok(parts[1].to_string())
}
