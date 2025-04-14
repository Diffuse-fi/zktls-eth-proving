mod error;
mod tls;
mod trie;
mod utils;

use alloy_primitives::{BlockNumber, B256};
use alloy_rpc_types_eth::{Block, EIP1186AccountProofResponse};
use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;
use tls_enclave::tls_request;

use crate::{
    tls::{RpcInfo, ZkTlsStateHeader, ZkTlsStateProof},
    trie::verify_proof,
    utils::{extract_body, keccak256, RpcResponse},
};

#[derive(Parser, Debug)]
#[clap(
    author = "Diffuse",
    version = "v0",
    about = "ZK TLS Ethereum State Prover"
)]
struct ZkTlsProverCli {
    /// RPC node domain (e.g., eth-mainnet.g.alchemy.com)
    #[clap(long, short, env = "RPC_DOMAIN")]
    rpc_domain: String,

    /// RPC node path (e.g., /v2/your-private-key) - Provide this OR API key
    #[clap(long, short = 'P', env = "RPC_PATH")]
    rpc_path: Option<String>,

    /// Alchemy API key (used to construct path: /v2/<key>) - Provide this OR full path
    #[clap(long, env = "ALCHEMY_API_KEY")]
    alchemy_api_key: Option<String>,

    /// Ethereum address to prove state for
    #[clap(
        long,
        short,
        default_value = "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        help = "Ethereum address"
    )]
    address: String,

    /// Storage slot keys (provide one or more, space-separated)
    #[clap(
        long,
        short,
        min_values = 1,
        value_delimiter = ' ',
        default_value = "0x9c7fca54b386399991ce2d6f6fbfc3879e4204c469d179ec0bba12523ed3d44c",
        help = "Storage slot key(s) (hex format, space-separated)"
    )]
    storage_slots: Vec<String>,

    /// Block number for the proof
    #[clap(
        long,
        short,
        default_value = "latest",
        help = "Block number (use 'latest' or hex number like '0x1234AB')"
    )]
    block_number: String,
}

#[no_mangle]
pub unsafe extern "C" fn simple_proving() -> SgxStatus {
    match verify() {
        Ok(()) => {
            tracing::info!("Proving process completed successfully.");
            SgxStatus::Success
        }
        Err(e) => {
            tracing::error!("Proving process failed: {:?}", e);
            SgxStatus::Unexpected
        }
    }
}

fn verify() -> anyhow::Result<()> {
    let cli = ZkTlsProverCli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    if cli.rpc_path.is_none() && cli.alchemy_api_key.is_none() {
        tracing::error!("RPC target missing: Provide either --rpc-path (-P) or --alchemy-api-key");
        return Err(anyhow::anyhow!(
            "RPC target missing: Provide either --rpc-path (-P) or --alchemy-api-key".to_string()
        ));
    }

    tracing::info!("Starting ZK TLS Ethereum State Proving...");
    tracing::debug!("CLI arguments: {:?}", cli);

    let final_rpc_path = if let Some(path) = cli.rpc_path {
        if cli.alchemy_api_key.is_some() {
            tracing::warn!(
                "Both --rpc-path and --alchemy-api-key provided. Using --rpc-path ('{}').",
                path
            );
        }
        path
    } else if let Some(key) = cli.alchemy_api_key {
        format!("/v2/{}", key)
    } else {
        unreachable!("Manual validation should have caught missing RPC target.");
    };

    let rpc_info = RpcInfo {
        domain: cli.rpc_domain,
        path: final_rpc_path,
    };

    tracing::info!(
        "Using RPC Endpoint: Domain={}, Path={}",
        rpc_info.domain,
        rpc_info.path
    );
    tracing::info!("Address: {}", cli.address);
    tracing::info!("Storage Slot Keys: {:?}", cli.storage_slots);

    let (block_header, _block_hash_from_rpc, encoded_header) =
        get_block_header(&rpc_info, &cli.block_number)?;

    let block_number = block_header.number;

    let proof_response = get_proof(&rpc_info, cli.address, &cli.storage_slots, block_number)?;

    tracing::info!("Verifying proofs...");
    let verified_values = verify_proof(proof_response, encoded_header)?;

    tracing::info!("Proof verification successful!");
    for (slot, value_opt) in &verified_values {
        match value_opt {
            Some(value) => tracing::info!("  Slot {}: Value {}", slot, value),
            None => tracing::info!("  Slot {}: Value is zero/empty", slot),
        }
    }

    let data = [0u8; 64];
    let attestation = automata_sgx_sdk::dcap::dcap_quote(data);
    match attestation {
        Ok(attestation) => {
            tracing::info!("DCAP attestation: 0x{}", hex::encode(attestation));
            Ok(())
        }
        Err(e) => {
            tracing::error!("Generating attestation failed: {:?}", e);
            Err(anyhow::anyhow!("Failed to generate attestation"))
        }
    }
}

fn get_block_header(
    rpc_info: &RpcInfo,
    block_number_str: &str,
) -> anyhow::Result<(alloy_consensus::Header, B256, Vec<u8>)> {
    tracing::info!("Fetching block header for block '{}'...", block_number_str);
    let zktls_state_get_header =
        ZkTlsStateHeader::new(rpc_info.clone(), block_number_str.to_string());
    let response_str = tls_request(&rpc_info.domain, zktls_state_get_header)?;

    let body = extract_body(&response_str)?;
    let block_response: RpcResponse<Block> = serde_json::from_str(&body)?;

    let block = block_response.result;
    let block_hash_from_rpc = block
        .header
        .hash
        .ok_or(anyhow::anyhow!("Empty block hash"))?;
    tracing::debug!("Received block hash: {}", block_hash_from_rpc);

    let header = alloy_consensus::Header::try_from(block.header)?;
    tracing::debug!("Parsed block header: {:?}", header);

    let encoded_header = alloy_rlp::encode(&header);
    let calculated_hash = keccak256(&encoded_header);
    tracing::debug!("Calculated block hash: 0x{}", hex::encode(calculated_hash));

    assert_eq!(
        calculated_hash, block_hash_from_rpc,
        "Calculated block hash does not match the expected hash"
    );

    tracing::info!("Block header hash verified successfully.");

    Ok((header, block_hash_from_rpc, encoded_header))
}

fn get_proof(
    rpc_info: &RpcInfo,
    address: String,
    storage_slots: &[String],
    block_number: BlockNumber,
) -> anyhow::Result<EIP1186AccountProofResponse> {
    tracing::info!(
        "Fetching proof for address {} at block '{}'...",
        address,
        block_number
    );
    let zktls_state_get_proof = ZkTlsStateProof::new(
        rpc_info.clone(),
        address,
        storage_slots.to_vec(),
        format!("0x{:x}", block_number),
    );

    let response_str = tls_request(&rpc_info.domain, zktls_state_get_proof)?;
    let body = extract_body(&response_str)?;

    let proof_response: RpcResponse<EIP1186AccountProofResponse> = serde_json::from_str(&body)?;

    tracing::info!("Received proof successfully.");
    tracing::debug!("Proof response: {:?}", proof_response.result);

    Ok(proof_response.result)
}
