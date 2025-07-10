mod attestation_data;
mod error;
pub(crate) mod eth;
mod mock_v0;
mod timing;
mod trie;
mod utils;

use std::str::FromStr;

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;

use crate::{
    attestation_data::{AttestationPayload, CleanProvingResultOutput, ProvingResultOutput},
    eth::primitives::{Address, B256, U256},
    mock_v0::{validate_liquidation_price, PriceData},
    timing::{Lap, Timings},
    utils::{
        calculate_final_blocks_hash, calculate_final_positions_hash, construct_report_data,
        get_block_header_from_rpc,
    },
};

#[derive(serde::Serialize)]
struct TimingDebugOutput {
    error: String,
    timings: Timings,
}

#[derive(serde::Deserialize, Debug)]
struct ProvingTask {
    address: String,
    vault_address: String,
    position_id: u64,
    liquidation_price: Option<u128>,
}

#[derive(Parser, Debug)]
struct CliParams {
    rpc_url: String,
    address: String,
    block_number: String,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum PoolType {
    Uniswap3,
    Pendle,
}

impl FromStr for PoolType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "uniswap3" => Ok(PoolType::Uniswap3),
            "pendle" => Ok(PoolType::Pendle),
            _ => Err(format!(
                "unknown pool type `{}`; valid: uniswap3, pendle",
                s
            )),
        }
    }
}

#[derive(Parser, Debug, Clone)]
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
    #[clap(long, short = 't', help = "tokens amount to swap in AMM")]
    pt_tokens_amount: U256,
    #[clap(
        long,
        short = 'p',
        default_value = "pendle",
        help = "Choose either pool type to calculate price impact(uniswap3, pendle)"
    )]
    pool_type: PoolType,
}

#[no_mangle]
pub unsafe extern "C" fn simple_proving() -> SgxStatus {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let cli = ZkTlsProverCli::parse();

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
                    json_output
                        .unwrap_or_else(|e| format!("Failed to serialize error output: {}", e))
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
                    json_output
                        .unwrap_or_else(|e| format!("Failed to serialize timing output: {}", e))
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
    let target_blocks: Vec<u64> = block_offsets
        .iter()
        .map(|offset| (latest_block_number as i64 + offset) as u64)
        .filter(|&block_num| block_num > 0) // Ensure no negative block numbers
        .collect();

    if target_blocks.is_empty() {
        anyhow::bail!("All calculated block numbers are invalid (<=0)");
    }

    let mut all_blocks: Vec<(u64, B256)> = Vec::new();
    let mut all_vault_position_pairs: Vec<(Address, u64)> = Vec::new();

    tracing::info!(
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

            // Extract price data from each block for this strategy
            for (block_number, _) in &all_blocks {
                let concrete_price_data = todo!("implement pendle logic");
                price_data.push(concrete_price_data);
            }

            // If we have no price data, validation fails
            if price_data.is_empty() {
                anyhow::bail!(
                    "No price data found for strategy {} across {} blocks", // todo rephrase
                    task.address,
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
                    validation
                        .reason
                        .unwrap_or_else(|| "Unknown reason".to_string())
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

    tracing::info!("Liquidation price validation completed, preparing attestation payload");

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
