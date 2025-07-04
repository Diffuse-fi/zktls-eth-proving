mod attestation_data;
mod error;
pub(crate) mod eth;
mod tls;
mod trie;
mod utils;

use std::{collections::HashMap, str::FromStr};

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;
use tls_enclave::tls_request;

use crate::{
    attestation_data::{AttestationPayload, ProvingResultOutput, SlotProofData},
    eth::{
        block::Block,
        header::Header,
        primitives::{Address, B256},
        proof::ProofResponse,
    },
    tls::{RpcInfo, ZkTlsStateHeader, ZkTlsStateProof},
    trie::verify_proof,
    utils::{construct_report_data, extract_body, get_semantic_u256_bytes, keccak256, RpcResponse},
};

#[derive(Parser, Debug)]
#[clap(
    author = "Diffuse",
    version = "v0.2",
    about = "ZK TLS Ethereum State Prover for specific contract message structure"
)]
struct ZkTlsProverCli {
    #[clap(long, short, env = "RPC_DOMAIN")]
    rpc_domain: String,
    #[clap(long, short = 'P', env = "RPC_PATH")]
    rpc_path: Option<String>,
    #[clap(long, env = "ALCHEMY_API_KEY")]
    alchemy_api_key: Option<String>,
    #[clap(
        long,
        short,
        env = "CONTRACT_ADDRESS",
        help = "Ethereum address of the target contract"
    )]
    address: String,
    #[clap(long, short = 's', help = "Storage slot keys in hex format (0x...)")]
    storage_keys: Vec<String>,
    #[clap(
        long,
        short = 'B',
        default_value = "latest",
        help = "Block number (e.g., 'latest', '0x1234AB')"
    )]
    block_number: String,
}

#[no_mangle]
pub unsafe extern "C" fn simple_proving() -> SgxStatus {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let cli = ZkTlsProverCli::parse();
    tracing::info!(config = ?cli, "Starting proving process with configuration");

    match verify_attestation(cli) {
        Ok(result) => {
            tracing::info!("Proving process completed successfully.");
            match serde_json::to_string_pretty(&result) {
                Ok(json_output) => println!("{}", json_output),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to serialize proving result to JSON");
                    return SgxStatus::Unexpected;
                }
            }
            SgxStatus::Success
        }
        Err(e) => {
            tracing::error!(error = %e, "Proving process failed");
            SgxStatus::Unexpected
        }
    }
}

fn verify_attestation(cli: ZkTlsProverCli) -> anyhow::Result<ProvingResultOutput> {
    if cli.rpc_path.is_none() && cli.alchemy_api_key.is_none() {
        anyhow::bail!("RPC target missing: Provide either --rpc-path (-P) or --alchemy-api-key");
    }

    let rpc_path = cli
        .rpc_path
        .or_else(|| cli.alchemy_api_key.map(|key| format!("/v2/{}", key)))
        .ok_or_else(|| anyhow::anyhow!("RPC target path could not be determined."))?;

    let rpc_info = RpcInfo {
        domain: cli.rpc_domain,
        path: rpc_path,
    };

    let contract_address = Address::from_str(&cli.address)
        .map_err(|e| anyhow::anyhow!("Invalid contract address format '{}': {}", cli.address, e))?;

    tracing::info!(rpc_domain = %rpc_info.domain, rpc_path = %rpc_info.path, %contract_address, storage_keys = ?cli.storage_keys, block_tag = %cli.block_number, "Proving parameters");

    let mut target_slot_keys: Vec<B256> = Vec::new();
    for key_str in &cli.storage_keys {
        let key_str = if key_str.starts_with("0x") {
            &key_str[2..]
        } else {
            key_str
        };
        let key_bytes = hex::decode(key_str).map_err(|e| {
            anyhow::anyhow!("Invalid hex format for storage key '{}': {}", key_str, e)
        })?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "Storage key '{}' must be exactly 32 bytes (64 hex chars), got {} bytes",
                key_str,
                key_bytes.len()
            );
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        target_slot_keys.push(B256::from(key_array));
    }

    if target_slot_keys.is_empty() {
        anyhow::bail!("At least one storage key must be provided via -s flag");
    }

    tracing::info!(storage_keys = ?target_slot_keys, "Parsed {} storage keys", target_slot_keys.len());

    let block_header = get_block_header_from_rpc(&rpc_info, &cli.block_number)?;
    let block_number_val = block_header.number;

    let slot_keys_for_rpc = target_slot_keys.clone();

    let proof_response = get_proof_from_rpc(
        &rpc_info,
        contract_address,
        &slot_keys_for_rpc,
        block_number_val,
    )?;
    let verified_slot_values = verify_proof(proof_response, block_header.state_root.as_ref())
        .map_err(|e| anyhow::anyhow!("MPT proof verification failed: {:?}", e))?;
    tracing::info!("MPT proof verification successful");

    let mut processed_semantic_values: HashMap<B256, [u8; 32]> = HashMap::new();
    for (proved_key, opt_mpt_value) in verified_slot_values {
        if let Some(mpt_value_bytes) = opt_mpt_value {
            match get_semantic_u256_bytes(&mpt_value_bytes) {
                Ok(semantic_bytes) => {
                    processed_semantic_values.insert(proved_key, semantic_bytes);
                }
                Err(e) => {
                    tracing::warn!(slot_key = ?proved_key, error = %e, "Failed to get semantic uint256 bytes for slot. It will be excluded from attestation if it was a target slot.");
                }
            }
        } else {
            tracing::warn!(slot_key = ?proved_key, "Slot proven but MPT proof yielded no value (None).");
        }
    }

    let mut attested_slots_data: Vec<SlotProofData> = Vec::with_capacity(target_slot_keys.len());

    for (i, target_slot_key) in target_slot_keys.iter().enumerate() {
        if let Some(semantic_bytes) = processed_semantic_values.get(target_slot_key) {
            attested_slots_data.push(SlotProofData {
                slot_key: *target_slot_key,
                value_hash: keccak256(semantic_bytes).into(),
            });
        } else {
            anyhow::bail!(
                "Proof value for target slot {} ({:?}) not found or failed to process.",
                i + 1,
                target_slot_key
            );
        }
    }

    if attested_slots_data.len() != target_slot_keys.len() {
        anyhow::bail!("Expected to attest to {} slots, but processed {}. This indicates a logic error or incomplete proof data for target slots.", target_slot_keys.len(), attested_slots_data.len());
    }
    tracing::info!(
        count = attested_slots_data.len(),
        "Slots prepared for attestation payload"
    );

    let attestation_payload = AttestationPayload {
        block_hash: block_header.hash(),
        block_number: block_number_val,
        proven_slots: attested_slots_data,
    };

    let report_data = construct_report_data(&attestation_payload)?;
    tracing::debug!(report_data_hex = %hex::encode(report_data), "Constructed report_data for DCAP quote");

    let quote_bytes = automata_sgx_sdk::dcap::dcap_quote(report_data)
        .map_err(|e| anyhow::anyhow!("DCAP quote generation failed: {:?}", e))?;
    tracing::info!(
        quote_len = quote_bytes.len(),
        "DCAP quote generated successfully"
    );

    Ok(ProvingResultOutput {
        attestation_payload,
        sgx_quote_hex: hex::encode(quote_bytes),
    })
}

fn get_block_header_from_rpc(rpc_info: &RpcInfo, block_tag: &str) -> anyhow::Result<Header> {
    tracing::info!(block_tag, "Fetching block header");
    let zktls_request_provider = ZkTlsStateHeader::new(rpc_info.clone(), block_tag.to_string());
    let response_str = tls_request(&rpc_info.domain, zktls_request_provider)
        .map_err(|e| anyhow::anyhow!("TLS request for block header failed: {:?}", e))?;

    let body = extract_body(&response_str)?;
    tracing::debug!(
        response_body_len = body.len(),
        "Received block header response body"
    );

    let rpc_block_response: RpcResponse<Block> = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse block header RPC response: {}", e))?;

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
    rpc_info: &RpcInfo,
    contract_address: Address,
    slot_keys: &[B256],
    block_number: u64,
) -> anyhow::Result<ProofResponse> {
    let slot_keys_hex: Vec<String> = slot_keys
        .iter()
        .map(|key| format!("0x{}", hex::encode(key.as_ref())))
        .collect();

    tracing::info!(%contract_address, ?slot_keys_hex, block_number, "Fetching proof");

    let zktls_request_provider = ZkTlsStateProof::new(
        rpc_info.clone(),
        format!("0x{}", hex::encode(contract_address.as_ref())),
        slot_keys_hex,
        format!("0x{:x}", block_number),
    );

    let response_str = tls_request(&rpc_info.domain, zktls_request_provider)
        .map_err(|e| anyhow::anyhow!("TLS request for proof failed: {:?}", e))?;
    let body = extract_body(&response_str)?;
    tracing::debug!(
        response_body_len = body.len(),
        "Received proof response body"
    );

    let rpc_proof_response: RpcResponse<ProofResponse> = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse proof RPC response: {}", e))?;

    tracing::info!("Proof received successfully");
    Ok(rpc_proof_response.result)
}
