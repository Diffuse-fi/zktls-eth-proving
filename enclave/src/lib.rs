mod error;
mod tls;
mod trie;
mod utils;

use alloy_rpc_types_eth::{Block, EIP1186AccountProofResponse};
use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;
use tls_enclave::tls_request;

use crate::{
    tls::{ZkTlsStateHeader, ZkTlsStateProof, RPC_DOMAIN},
    trie::verify_proof,
    utils::{extract_body, keccak256, RpcResponse},
};

#[derive(Parser)]
#[clap(author = "Diffuse", version = "v0", about)]
struct ZkTlsStateHeaderCli {
    /// Ethereum address to prove
    #[clap(
        long,
        default_value = "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        help = "Ethereum address"
    )]
    address: String,

    /// Storage slot key
    #[clap(
        long,
        default_value = "0x9c7fca54b386399991ce2d6f6fbfc3879e4204c469d179ec0bba12523ed3d44c",
        help = "Storage slot key"
    )]
    storage_slot: String,

    /// Block number for the proof
    #[clap(
        long,
        default_value = "latest",
        help = "Block number (use 'latest' or hex number like '0x1234AB')"
    )]
    block_number: String,
}

#[no_mangle]
pub unsafe extern "C" fn simple_proving() -> SgxStatus {
    let cli = ZkTlsStateHeaderCli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let zktls_state_get_proof = ZkTlsStateProof::new(
        RPC_DOMAIN.to_string(),
        cli.address,
        cli.storage_slot,
        cli.block_number.clone(),
    );
    let response_str = match tls_request(RPC_DOMAIN, zktls_state_get_proof) {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("Error encountered in TLS request: {e}");
            return SgxStatus::Unexpected;
        }
    };
    let body = match extract_body(&response_str) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to extract HTTP body: {:?}", e);
            return SgxStatus::Unexpected;
        }
    };
    let proof_response: RpcResponse<EIP1186AccountProofResponse> =
        serde_json::from_str(&body).expect("Failed to parse JSON into ethers Block");

    let zktls_state_get_header = ZkTlsStateHeader::new(RPC_DOMAIN.to_string(), cli.block_number);
    let response_str = match tls_request(RPC_DOMAIN, zktls_state_get_header) {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("Error encountered in TLS request: {e}");
            return SgxStatus::Unexpected;
        }
    };
    let body = match extract_body(&response_str) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to extract HTTP body: {:?}", e);
            return SgxStatus::Unexpected;
        }
    };
    let block: RpcResponse<Block> =
        serde_json::from_str(&body).expect("Failed to parse JSON into ethers Block");

    let expected_hash = if let Some(hash) = block.result.header.hash {
        hash
    } else {
        tracing::error!("Block hash not found in the response");
        return SgxStatus::Unexpected;
    };

    let header = alloy_consensus::Header::try_from(block.result.header)
        .expect("Failed to convert BlockResult to EvmBlockHeader");
    tracing::debug!("Block header: {:?}", header);
    let encoded_header = alloy_rlp::encode(&header);
    let hash = keccak256(&encoded_header);

    tracing::debug!("Hash of the block header: 0x{}", hex::encode(hash));
    tracing::debug!("Expected block hash: {}", expected_hash);
    assert_eq!(
        hash, expected_hash,
        "Hash of the block header does not match the expected hash"
    );

    let val = verify_proof(proof_response.result, encoded_header);

    if val.is_err() {
        tracing::error!("Failed to verify proof: {:?}", val);
        return SgxStatus::Unexpected;
    } else {
        tracing::info!("Proof verified successfully");
        tracing::info!("Value : {:?}", val);
    }

    let data = [0u8; 64];
    let attestation = automata_sgx_sdk::dcap::dcap_quote(data);
    match attestation {
        Ok(attestation) => {
            println!("DCAP attestation: 0x{}", hex::encode(attestation));
            SgxStatus::Success
        }
        Err(e) => {
            println!("Generating attestation failed: {:?}", e);
            SgxStatus::Unexpected
        }
    }
}
