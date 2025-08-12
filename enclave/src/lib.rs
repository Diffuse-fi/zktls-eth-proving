mod attestation_data;
mod error;
pub(crate) mod eth;
mod mock_v0;
mod timing;
mod trie;
mod utils;

use std::{collections::HashMap, ffi::CString, os::raw::c_char, str::FromStr};

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;

use crate::{
    attestation_data::{AttestationPayload, CleanProvingResultOutput, ProvingResultOutput, SlotProofData},
    eth::{
        block::Block,
        header::Header,
        primitives::{Address, B256},
        proof::ProofResponse,
    },
    mock_v0::{validate_liquidation_price, parse_price_from_slot, PriceData, SLOT_TO_PROVE_MOCK},
    timing::{Lap, Timings},
    trie::verify_proof,
    utils::{
        calculate_final_blocks_hash, calculate_final_positions_hash, construct_report_data, convert_slots_to_b256,
        get_semantic_u256_bytes, keccak256, RpcResponse,
    },
};

extern "C" {
    fn ocall_make_http_request(
        url: *const c_char,
        method: *const c_char,
        body: *const u8,
        body_len: usize,
        response: *mut c_char,
        max_response_len: usize,
        actual_response_len: *mut usize,
        http_status: *mut u16,
    );
}

fn make_http_request(url: &str, method: &str, body: &[u8]) -> anyhow::Result<String> {
    const MAX_RESPONSE_LEN: usize = 256 * 1024 * 4 * 4;
    let mut response_buffer = vec![0u8; MAX_RESPONSE_LEN];
    let mut actual_response_len: usize = 0;
    let mut http_status: u16 = 0;

    let url_cstring = CString::new(url)?;
    let method_cstring = CString::new(method)?;

    unsafe {
        ocall_make_http_request(
            url_cstring.as_ptr(),
            method_cstring.as_ptr(),
            body.as_ptr(),
            body.len(),
            response_buffer.as_mut_ptr() as *mut c_char,
            MAX_RESPONSE_LEN,
            &mut actual_response_len,
            &mut http_status,
        );
    }

    if http_status != 200 {
        return Err(anyhow::anyhow!(
            "HTTP request failed with status: {}",
            http_status
        ));
    }

    if actual_response_len == 0 {
        tracing::warn!("Empty response from HTTP request, but status was 200");
        return Ok(String::new());
    }

    let response_slice = &response_buffer[..actual_response_len];
    let response_str = String::from_utf8(response_slice.to_vec())?;
    Ok(response_str)
}

#[derive(serde::Serialize)]
struct TimingDebugOutput {
    error: String,
    timings: Timings,
}

#[derive(serde::Deserialize, Debug)]
struct ProvingTask {
    address: String,
    slots: Vec<u64>,
    vault_address: String,
    position_id: u64,
    liquidation_price: Option<u128>,
}

#[derive(Parser, Debug)]
#[clap(
    author = "Diffuse",
    version = "v0.2",
    about = "ZK TLS Ethereum State Prover for multiple addresses"
)]
struct ZkTlsProverCli {
    #[clap(
        long,
        short = 'u',
        env = "RPC_URL",
        help = "Ethereum RPC endpoint URL (e.g., https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY)"
    )]
    rpc_url: String,
    #[clap(
        long,
        short = 'o',
        help = "Block offsets from latest as JSON array, e.g., '[0,-1,-5,-20,-25]'"
    )]
    block_offsets: String,
    #[clap(
        long,
        short = 't',
        help = "JSON array of proving tasks, e.g., '[{\"address\":\"0x123...\",\"slots\":[0,1],\"vault_address\":\"0xabc...\",\"position_id\":20,\"liquidation_price\":1000}]'"
    )]
    proving_tasks: String,
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

    let total_timer_start = std::time::Instant::now();
    let mut timings = Timings::default();

    match verify_attestation_with_timing(cli, &mut timings, total_timer_start) {
        Ok(result) => {
            tracing::info!("Proving process completed successfully.");

            // Always output timing data for debugging
            tracing::debug!("Timing breakdown: {:?}", result.timings);

            // Check if we should output clean JSON (for RUST_LOG=off or minimal logging)
            let should_output_clean = std::env::var("RUST_LOG")
                .map(|level| level == "off" || level == "error")
                .unwrap_or(false);

            if should_output_clean {
                // Output clean JSON without timings for easy parsing
                let clean_result = CleanProvingResultOutput {
                    attestation_payload: result.attestation_payload,
                    sgx_quote_hex: result.sgx_quote_hex,
                };
                match serde_json::to_string_pretty(&clean_result) {
                    Ok(json_output) => println!("{}", json_output),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to serialize clean result to JSON");
                        return SgxStatus::Unexpected;
                    }
                }
            } else {
                // Output full JSON with timings for debugging
                match serde_json::to_string_pretty(&result) {
                    Ok(json_output) => println!("{}", json_output),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to serialize proving result to JSON");
                        return SgxStatus::Unexpected;
                    }
                }
            }
            SgxStatus::Success
        }
        Err(e) => {
            tracing::error!(error = %e, "Proving process failed");

            // Check if we should output clean error (for RUST_LOG=off or minimal logging)
            let should_output_clean = std::env::var("RUST_LOG")
                .map(|level| level == "off" || level == "error")
                .unwrap_or(false);

            if should_output_clean {
                // Output clean error JSON without timings
                let clean_error = serde_json::json!({
                    "error": format!("{:?}", e),
                    "status": "failed"
                });
                let json_output = serde_json::to_string_pretty(&clean_error);
                println!(
                    "{}",
                    json_output.unwrap_or_else(|e| format!("Failed to serialize error output: {}", e))
                );
            } else {
                // Always output timing data, even on failure
                timings.total_ms = total_timer_start.elapsed().as_secs_f64() * 1000.0;
                let timing_output = TimingDebugOutput {
                    error: format!("{:?}", e),
                    timings,
                };

                let json_output = serde_json::to_string_pretty(&timing_output);
                println!(
                    "{}",
                    json_output.unwrap_or_else(|e| format!("Failed to serialize timing output: {}", e))
                );
            }

            SgxStatus::Unexpected
        }
    }
}

fn verify_attestation_with_timing(
    cli: ZkTlsProverCli,
    timings: &mut Timings,
    total_timer_start: std::time::Instant,
) -> anyhow::Result<ProvingResultOutput> {
    let proving_tasks: Vec<ProvingTask> = serde_json::from_str(&cli.proving_tasks)
        .map_err(|e| anyhow::anyhow!("Failed to parse proving tasks JSON: {}", e))?;

    if proving_tasks.is_empty() {
        anyhow::bail!("No proving tasks provided");
    }

    // Parse block offsets: e.g. [0, -1, -5, -20, -25]
    let block_offsets: Vec<i64> = serde_json::from_str(&cli.block_offsets)
        .map_err(|e| anyhow::anyhow!("Failed to parse block offsets JSON: {}", e))?;

    if block_offsets.is_empty() {
        anyhow::bail!("No block offsets provided");
    }

    tracing::info!(
        rpc_url = %cli.rpc_url,
        block_offsets = ?block_offsets,
        task_count = proving_tasks.len(),
        "Starting multi-block multi-address proving with {} tasks across {} blocks",
        proving_tasks.len(),
        block_offsets.len()
    );

    // Get latest block number first
    let lap_latest = Lap::new("get_latest_block_header");
    let latest_block_header = get_block_header_from_rpc(&cli.rpc_url, "latest", timings)?;
    lap_latest.stop(timings);
    let latest_block_number = latest_block_header.number;

    // Calculate target block numbers
    let target_blocks: Vec<u64> = block_offsets.iter()
        .map(|offset| (latest_block_number as i64 + offset) as u64)
        .filter(|&block_num| block_num > 0) // Ensure no negative block numbers
        .collect();

    if target_blocks.is_empty() {
        anyhow::bail!("All calculated block numbers are invalid (<=0)");
    }

    let mut all_blocks: Vec<(u64, B256)> = Vec::new();
    let mut all_vault_position_pairs: Vec<(Address, u64)> = Vec::new();
    let mut all_attested_slots: Vec<SlotProofData> = Vec::new();
    let mut all_non_existent_slots: Vec<(Address, B256)> = Vec::new();

    // For each target block
    for (block_idx, block_number) in target_blocks.iter().enumerate() {
        tracing::info!(
            block_index = block_idx,
            block_number = block_number,
            "Processing block"
        );

        // Fetch block header
        let lap_block = Lap::new(&format!("get_block_header_{}", block_idx));
        let block_header = get_block_header_from_rpc(
            &cli.rpc_url, 
            &format!("0x{:x}", block_number),
            timings
        )?;
        lap_block.stop(timings);

        // Store block info
        all_blocks.push((*block_number, block_header.hash()));

        // For each proving task in this block
        for (task_idx, task) in proving_tasks.iter().enumerate() {
            let contract_address = Address::from_str(&task.address).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid contract address format '{}' in task {}: {}",
                    task.address,
                    task_idx,
                    e
                )
            })?;

            let vault_address = Address::from_str(&task.vault_address).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid vault address format '{}' in task {}: {}",
                    task.vault_address,
                    task_idx,
                    e
                )
            })?;

            // Store vault_address and position_id for final positions hash calculation
            // Only add once per task (not per block)
            if block_idx == 0 {
                all_vault_position_pairs.push((vault_address, task.position_id));
            }

            let target_slot_keys = convert_slots_to_b256(&task.slots);

            tracing::info!(
                block_index = block_idx,
                block_number = block_number,
                task_index = task_idx,
                %contract_address,
                %vault_address,
                slot_count = target_slot_keys.len(),
                position_id = task.position_id,
                "Processing proving task"
            );

            // Get proof for this address in this block
            let lap_proof = Lap::new(&format!("get_proof_block_{}_task_{}", block_idx, task_idx));
            let proof_response = get_proof_from_rpc(
                &cli.rpc_url,
                contract_address,
                &target_slot_keys,
                *block_number,
                timings,
            )?;
            lap_proof.stop(timings);

            // Verify MPT proof for this address
            let lap_verify = Lap::new(&format!("verify_mpt_proof_block_{}_task_{}", block_idx, task_idx));
            let verified_slot_values =
                verify_proof(proof_response, block_header.state_root.as_ref(), timings).map_err(
                    |e| {
                        anyhow::anyhow!(
                            "MPT proof verification failed for block {} task {}: {:?}",
                            block_number,
                            task_idx,
                            e
                        )
                    },
                )?;
            lap_verify.stop(timings);

            // Process slot values for this address
            let lap_processing = Lap::new(&format!("slot_processing_block_{}_task_{}", block_idx, task_idx));
            let mut processed_semantic_values: HashMap<B256, [u8; 32]> = HashMap::new();
            let mut non_existent_slots: Vec<B256> = Vec::new();

            for (proved_key, opt_mpt_value) in verified_slot_values {
                if let Some(mpt_value_bytes) = opt_mpt_value {
                    tracing::debug!(
                        block_number = block_number,
                        task_index = task_idx,
                        slot_key = ?proved_key,
                        value_bytes_len = mpt_value_bytes.len(),
                        value_hex = %hex::encode(&mpt_value_bytes),
                        "Slot has value from MPT"
                    );
                    match get_semantic_u256_bytes(&mpt_value_bytes) {
                        Ok(semantic_bytes) => {
                            let is_zero = semantic_bytes == [0u8; 32];
                            tracing::debug!(
                                block_number = block_number,
                                task_index = task_idx,
                                slot_key = ?proved_key,
                                semantic_hex = %hex::encode(&semantic_bytes),
                                is_zero = is_zero,
                                "Processed semantic bytes"
                            );

                            if is_zero && mpt_value_bytes.is_empty() {
                                tracing::info!(
                                    block_number = block_number,
                                    task_index = task_idx,
                                    slot_key = ?proved_key,
                                    "Slot has empty MPT value, treating as non-existent"
                                );
                                non_existent_slots.push(proved_key);
                            } else {
                                processed_semantic_values.insert(proved_key, semantic_bytes);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                block_number = block_number,
                                task_index = task_idx,
                                slot_key = ?proved_key,
                                error = %e,
                                "Failed to get semantic uint256 bytes for slot"
                            );
                        }
                    }
                } else {
                    tracing::info!(
                        block_number = block_number,
                        task_index = task_idx,
                        slot_key = ?proved_key,
                        "Slot proven but does not exist (None)"
                    );
                    non_existent_slots.push(proved_key);
                }
            }
            lap_processing.stop(timings);

            // Collect non-existent slots with their address
            for slot in non_existent_slots {
                all_non_existent_slots.push((contract_address, slot));
            }

            // Create SlotProofData for existing slots from this task
            for target_slot_key in target_slot_keys.iter() {
                if let Some(semantic_bytes) = processed_semantic_values.get(target_slot_key) {
                    all_attested_slots.push(SlotProofData {
                        address: contract_address,
                        slot_key: *target_slot_key,
                        value_hash: keccak256(semantic_bytes).into(),
                        value: Some(*semantic_bytes), // Store actual value for price validation
                    });
                }
            }

            tracing::info!(
                block_number = block_number,
                task_index = task_idx,
                existing_slots = processed_semantic_values.len(),
                "Completed processing task"
            );
        }
    }

    // Log non-existent slots to tracing instead of stdout
    if !all_non_existent_slots.is_empty() {
        tracing::warn!(
            "Excluding {} non-existent slots from attestation",
            all_non_existent_slots.len()
        );
        for (addr, slot) in &all_non_existent_slots {
            tracing::debug!(
                "Non-existent slot: address=0x{}, slot=0x{}", 
                hex::encode(addr.as_ref()),
                hex::encode(slot.as_ref())
            );
        }
    }

    tracing::info!(
        total_attested_slots = all_attested_slots.len(),
        total_blocks = all_blocks.len(),
        task_count = proving_tasks.len(),
        "All blocks and tasks completed, validating liquidation prices"
    );

    // Validate liquidation prices for tasks that specify them
    for task in &proving_tasks {
        if let Some(liquidation_price) = task.liquidation_price {
            tracing::info!(
                vault_address = %task.vault_address,
                position_id = task.position_id,
                liquidation_price = liquidation_price,
                "Validating liquidation price"
            );

            // Collect price data from strategy slot 5 across all blocks
            let mut price_data: Vec<PriceData> = Vec::new();
            let strategy_address = Address::from_str(&task.address).map_err(|e| {
                anyhow::anyhow!("Invalid strategy address format '{}': {}", task.address, e)
            })?;

            // Check if slot 5 is included in the proving data
            if !task.slots.contains(&SLOT_TO_PROVE_MOCK) {
                anyhow::bail!(
                    "Task for address {} with liquidation_price requires slot {} to be proven",
                    task.address,
                    SLOT_TO_PROVE_MOCK
                );
            }

            let mut slot_5_key_bytes = [0u8; 32];
            slot_5_key_bytes[31] = SLOT_TO_PROVE_MOCK as u8;
            let slot_5_key = B256::from(slot_5_key_bytes);

            // Extract price data from each block for this strategy
            for (block_number, _) in &all_blocks {
                // Find matching attested slot data
                for slot_data in &all_attested_slots {
                    if slot_data.address == strategy_address && slot_data.slot_key == slot_5_key {
                        if let Some(slot_value) = slot_data.value {
                            // Parse price from actual slot value
                            let slot_b256 = B256::from(slot_value);
                            let price = parse_price_from_slot(&slot_b256);
                            price_data.push(PriceData {
                                block_number: *block_number,
                                price,
                            });
                            tracing::debug!(
                                block_number = block_number,
                                price = price,
                                "Extracted price from strategy slot"
                            );
                        } else {
                            tracing::warn!(
                                block_number = block_number,
                                "Slot data exists but no actual value stored"
                            );
                        }
                        break;
                    }
                }
            }

            // If we have no price data, validation fails
            if price_data.is_empty() {
                anyhow::bail!(
                    "No price data found for strategy {} slot {} across {} blocks - ensure slot is proven",
                    task.address,
                    SLOT_TO_PROVE_MOCK,
                    all_blocks.len()
                );
            }

            // Calculate TWAP and validate
            let validation = validate_liquidation_price(liquidation_price, &price_data)?;
            
            if !validation.is_valid {
                anyhow::bail!(
                    "Liquidation price validation failed for position {} in vault {}: {}",
                    task.position_id,
                    task.vault_address,
                    validation.reason.unwrap_or_else(|| "Unknown reason".to_string())
                );
            }

            tracing::info!(
                vault_address = %task.vault_address,
                position_id = task.position_id,
                liquidation_price = validation.liquidation_price,
                twap_price = validation.twap_price,
                price_difference_pct = validation.price_difference_pct * 100.0,
                "Liquidation price validation passed"
            );
        }
    }

    tracing::info!(
        "Liquidation price validation completed, preparing attestation payload"
    );

    // Calculate final hashes per DOC.md spec
    let lap_blocks_hash = Lap::new("calculate_final_blocks_hash");
    let final_blocks_hash = calculate_final_blocks_hash(&all_blocks);
    lap_blocks_hash.stop(timings);

    let lap_positions_hash = Lap::new("calculate_final_positions_hash");
    let final_positions_hash = calculate_final_positions_hash(&all_vault_position_pairs);
    lap_positions_hash.stop(timings);

    // Create single attestation payload with all proven slots
    let attestation_payload = AttestationPayload {
        blocks: all_blocks,
        vault_positions: all_vault_position_pairs,
        final_blocks_hash: final_blocks_hash.into(),
        final_positions_hash: final_positions_hash.into(),
        proven_slots: all_attested_slots,
    };

    let lap_report = Lap::new("construct_report_data");
    let report_data = construct_report_data(&attestation_payload)?;
    lap_report.stop(timings);
    tracing::debug!(
        report_data_hex = %hex::encode(report_data),
        final_blocks_hash_hex = %hex::encode(final_blocks_hash),
        final_positions_hash_hex = %hex::encode(final_positions_hash),
        "Constructed report_data for DCAP quote"
    );

    // Generate single SGX quote for all blocks/addresses/slots
    let lap_quote = Lap::new("dcap_quote_generation");
    let quote_bytes = automata_sgx_sdk::dcap::dcap_quote(report_data)
        .map_err(|e| anyhow::anyhow!("DCAP quote generation failed: {:?}", e))?;
    lap_quote.stop(timings);
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

fn get_block_header_from_rpc(
    rpc_url: &str,
    block_tag: &str,
    timings: &mut Timings,
) -> anyhow::Result<Header> {
    tracing::info!(block_tag, "Fetching block header");

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [block_tag, false],
        "id": 1
    })
    .to_string();

    let lap_tls = Lap::new("get_block_header::http_request");
    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("HTTP request for block header failed: {:?}", e))?;
    lap_tls.stop(timings);

    tracing::debug!(
        response_body_len = response_str.len(),
        "Received block header response body"
    );

    let lap_parse = Lap::new("get_block_header::json_parsing");
    let rpc_block_response: RpcResponse<Block> = serde_json::from_str(&response_str)
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
    rpc_url: &str,
    contract_address: Address,
    slot_keys: &[B256],
    block_number: u64,
    timings: &mut Timings,
) -> anyhow::Result<ProofResponse> {
    let slot_keys_hex: Vec<String> = slot_keys
        .iter()
        .map(|key| format!("0x{}", hex::encode(key.as_ref())))
        .collect();

    tracing::info!(%contract_address, block_number, "Fetching proof");

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getProof",
        "params": [
            format!("0x{}", hex::encode(contract_address.as_ref())),
            slot_keys_hex,
            format!("0x{:x}", block_number)
        ],
        "id": 1
    })
    .to_string();

    let lap_tls = Lap::new("get_proof::http_request");
    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("HTTP request for proof failed: {:?}", e))?;
    lap_tls.stop(timings);

    tracing::debug!(
        response_body_len = response_str.len(),
        "Received proof response body"
    );

    let lap_parse = Lap::new("get_proof::json_parsing");
    let rpc_proof_response: RpcResponse<ProofResponse> = serde_json::from_str(&response_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse proof RPC response: {}", e))?;
    lap_parse.stop(timings);

    tracing::info!("Proof received successfully");
    Ok(rpc_proof_response.result)
}
