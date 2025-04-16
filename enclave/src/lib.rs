mod error;
mod tls;
mod trie;
mod utils;

use alloy_primitives::{BlockNumber, B256};
use alloy_rpc_types_eth::{Block, EIP1186AccountProofResponse};
use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;
// use sgx_ocalls::bindings::ocall_write_to_file;
use tls_enclave::tls_request;

use crate::{
    tls::{RpcInfo, ZkTlsStateHeader, ZkTlsStateProof},
    trie::verify_proof,
    utils::{extract_body, keccak256, reassemble_message, ProvingOutput, RpcResponse},
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
        min_values = 0,
        value_delimiter = ' ',
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
        Ok(_attestation) => {
            tracing::info!("Proving process completed successfully.");
            // TODO: decide on how we store the attestation
            // let filename_bytes = create_buffer_from_stirng("sgx_quote.bin".to_string());
            // ocall_write_to_file(
            //     attestation.as_ptr(),
            //     attestation.len(),
            //     filename_bytes.as_ptr(),
            //     filename_bytes.len(),
            // );
            SgxStatus::Success
        }
        Err(e) => {
            tracing::error!("Proving process failed: {:?}", e);
            SgxStatus::Unexpected
        }
    }
}

fn verify() -> anyhow::Result<Vec<u8>> {
    let cli = ZkTlsProverCli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
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

    // v0.1 specific!
    let slots: Vec<(B256, Vec<u8>)> = verified_values
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect();

    if slots.len() != 2 {
        return Err(anyhow::anyhow!(
            "Expected 2 storage slots, but got {}",
            slots.len()
        ));
    }

    let eth_amount_raw = &slots[0].1;
    let other_slot_raw = &slots[1].1;

    tracing::info!(
        "Raw data: eth_amount_raw = 0x{}, other_slot_raw = 0x{}",
        hex::encode(eth_amount_raw),
        hex::encode(other_slot_raw)
    );

    let msg = reassemble_message(eth_amount_raw, other_slot_raw);
    tracing::info!("Reassembled message: {:?}", msg);
    let data = msg.to_bytes();
    let attestation = automata_sgx_sdk::dcap::dcap_quote(data);
    match attestation {
        Ok(attestation) => {
            tracing::info!("DCAP attestation: 0x{}", hex::encode(&attestation));

            let result = ProvingOutput {
                eth_amount: hex::encode(&msg.eth_amount),
                storage_slot2: hex::encode(&msg.other_full),
                sgx_quote: hex::encode(&attestation),
            };

            println!("{}", serde_json::to_string(&result)?);
            Ok(attestation)
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
