mod attestation_data;
mod error;
pub(crate) mod eth;
mod timing;
mod tls;
mod trie;
mod utils;

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;
use std::{collections::HashMap, str::FromStr};
use tls_enclave::tls_request;

use crate::utils::calculate_fixed_array_storage_slots;
use crate::{
    attestation_data::{AttestationPayload, ProvingResultOutput, SlotProofData},
    eth::{
        block::Block,
        header::Header,
        primitives::{Address, B256},
        proof::ProofResponse,
    },
    timing::{Lap, Timings},
    tls::{RpcInfo, ZkTlsStateHeader, ZkTlsStateProof},
    trie::verify_proof,
    utils::{construct_report_data, extract_body, get_semantic_u256_bytes, keccak256, RpcResponse},
};

#[derive(serde::Serialize)]
struct TimingDebugOutput {
    error: String,
    timings: Timings,
}

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
    #[clap(long, short = 'n')]
    slots_to_prove: u32,
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
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let cli = ZkTlsProverCli::parse();
    tracing::info!(config = ?cli, "Starting proving process with configuration");

    let total_timer_start = std::time::Instant::now();
    let mut timings = Timings::default();
    
    match verify_attestation_with_timing(cli, &mut timings, total_timer_start) {
        Ok(result) => {
            tracing::info!("Proving process completed successfully.");
            
            // Always output timing data for debugging
            tracing::debug!("Timing breakdown: {:?}", result.timings);
            
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
            
            // Always output timing data, even on failure
            timings.total_ms = total_timer_start.elapsed().as_secs_f64() * 1000.0;
            let timing_output = TimingDebugOutput {
                error: format!("{:?}", e),
                timings,
            };
            
            let json_output = serde_json::to_string_pretty(&timing_output);
            println!("{}", json_output.unwrap_or_else(|e| format!("Failed to serialize timing output: {}", e)));
            
            SgxStatus::Unexpected
        }
    }
}

fn verify_attestation_with_timing(cli: ZkTlsProverCli, timings: &mut Timings, total_timer_start: std::time::Instant) -> anyhow::Result<ProvingResultOutput> {
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

    // tracing::info!(rpc_domain = %rpc_info.domain, rpc_path = %rpc_info.path, %contract_address, message_index = cli.message_index, block_tag = %cli.block_number, "Proving parameters");

    let target_slot_keys = calculate_fixed_array_storage_slots(0, cli.slots_to_prove)?;

    let lap1 = Lap::new("get_block_header");
    let block_header = get_block_header_from_rpc(&rpc_info, &cli.block_number, timings)?;
    lap1.stop(timings);
    let block_number_val = block_header.number;

    let lap2 = Lap::new("get_proof");
    let proof_response = get_proof_from_rpc(
        &rpc_info,
        contract_address,
        &target_slot_keys,
        block_number_val,
        timings,
    )?;
    lap2.stop(timings);
    let lap3 = Lap::new("verify_mpt_proof");
    let verified_slot_values = verify_proof(proof_response, block_header.state_root.as_ref(), timings)
        .map_err(|e| anyhow::anyhow!("MPT proof verification failed: {:?}", e))?;
    lap3.stop(timings);
    tracing::info!("MPT proof verification successful");

    let lap_processing = Lap::new("slot_processing");
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
    lap_processing.stop(timings);

    let mut attested_slots_data: Vec<SlotProofData> = Vec::with_capacity(2);

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

    tracing::info!(
        count = attested_slots_data.len(),
        "Slots prepared for attestation payload"
    );

    let attestation_payload = AttestationPayload {
        block_hash: block_header.hash(),
        block_number: block_number_val,
        proven_slots: attested_slots_data,
    };

    let lap_report = Lap::new("construct_report_data");
    let report_data = construct_report_data(&attestation_payload)?;
    lap_report.stop(timings);
    tracing::debug!(report_data_hex = %hex::encode(report_data), "Constructed report_data for DCAP quote");

    let lap4 = Lap::new("dcap_quote_generation");
    let quote_bytes = automata_sgx_sdk::dcap::dcap_quote(report_data)
        .map_err(|e| anyhow::anyhow!("DCAP quote generation failed: {:?}", e))?;
    lap4.stop(timings);
    tracing::info!(
        quote_len = quote_bytes.len(),
        "DCAP quote generated successfully"
    );

    timings.total_ms = total_timer_start.elapsed().as_secs_f64() * 1000.0;

    Ok(ProvingResultOutput {
        attestation_payload,
        sgx_quote_hex: hex::encode(quote_bytes),
        timings: timings.clone(),
    })
}

fn get_block_header_from_rpc(rpc_info: &RpcInfo, block_tag: &str, timings: &mut Timings) -> anyhow::Result<Header> {
    tracing::info!(block_tag, "Fetching block header");
    let zktls_request_provider = ZkTlsStateHeader::new(rpc_info.clone(), block_tag.to_string());
    
    let lap_tls = Lap::new("get_block_header::tls_request");
    let response_str = tls_request(&rpc_info.domain, zktls_request_provider)
        .map_err(|e| anyhow::anyhow!("TLS request for block header failed: {:?}", e))?;
    lap_tls.stop(timings);

    let body = extract_body(&response_str)?;
    tracing::debug!(
        response_body_len = body.len(),
        "Received block header response body"
    );

    let lap_parse = Lap::new("get_block_header::json_parsing");
    let rpc_block_response: RpcResponse<Block> = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse block header RPC response: {}", e))?;
    lap_parse.stop(timings);

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
    timings: &mut Timings,
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

    let lap_tls = Lap::new("get_proof::tls_request");
    let response_str = tls_request(&rpc_info.domain, zktls_request_provider)
        .map_err(|e| anyhow::anyhow!("TLS request for proof failed: {:?}", e))?;
    lap_tls.stop(timings);
    let body = extract_body(&response_str)?;
    tracing::debug!(
        response_body_len = body.len(),
        "Received proof response body"
    );

    let lap_parse = Lap::new("get_proof::json_parsing");
    let rpc_proof_response: RpcResponse<ProofResponse> = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("Failed to parse proof RPC response: {}", e))?;
    lap_parse.stop(timings);

    tracing::info!("Proof received successfully");
    Ok(rpc_proof_response.result)
}
