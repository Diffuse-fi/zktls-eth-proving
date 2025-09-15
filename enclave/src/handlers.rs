use crate::{
    attestation_data::{AttestationPayloadLiquidation, ProvingResultOutputLiquidation},
    cli::{LiquidationArgs, PositionCreationArgs},
    eth::aliases::{Address, B256, I256},
    mock_v0::{validate_liquidation_price, PriceData},
    pendle::pendle_logic,
    utils::{
        calculate_final_blocks_hash, calculate_final_positions_hash, construct_report_data_liquidation,
        get_block_header_from_rpc, StorageProvingConfig,
    },
    request_stuff_from_dima_s_contract,
};
use std::str::FromStr;
use tracing::info;
use crate::attestation_data::{AttestationPayloadBorrowerPosition, ProvingResultOutputBorrowerPosition};
use crate::eth::aliases::U256;
use crate::pendle::PendleOutput;
use crate::utils::{calculate_hash_from_u256, construct_report_data_borrow_position};
use crate::vault_v1::get_pending_borrow_request_data;

pub fn handle_liquidation(
    args: LiquidationArgs,
) -> anyhow::Result<ProvingResultOutputLiquidation> {
    let proving_tasks: Vec<crate::ProvingTask> = serde_json::from_str(&args.proving_tasks)
        .map_err(|e| anyhow::anyhow!("Failed to parse proving tasks JSON: {}", e))?;

    if proving_tasks.is_empty() {
        anyhow::bail!("No proving tasks provided");
    }

    let block_offsets: Vec<i64> = serde_json::from_str(&args.block_offsets)
        .map_err(|e| anyhow::anyhow!("Failed to parse block offsets JSON: {}", e))?;

    if block_offsets.is_empty() {
        anyhow::bail!("No block offsets provided");
    }

    tracing::info!(
        rpc_url = %args.rpc_url,
        block_offsets = ?block_offsets,
        task_count = proving_tasks.len(),
        "Starting multi-block multi-address proving with {} tasks across {} blocks",
        proving_tasks.len(),
        block_offsets.len()
    );

    let target_blocks = calculate_target_blocks(&args.rpc_url, &block_offsets)?;

    let all_blocks: Vec<(u64, B256)> = Vec::new();
    let all_vault_position_pairs: Vec<(Address, u64)> = Vec::new();

    tracing::info!(
        total_blocks = all_blocks.len(),
        task_count = proving_tasks.len(),
        "All blocks and tasks completed, validating liquidation prices"
    );

    validate_all_liquidation_prices(&proving_tasks, &target_blocks, &args)?;

    tracing::info!("Liquidation price validation completed, preparing attestation payload");

    let attestation_payload = create_attestation_payload_liquidation(all_blocks, all_vault_position_pairs)?;
    let quote_bytes = generate_sgx_quote_liquidation(&attestation_payload)?;

    Ok(ProvingResultOutputLiquidation {
        attestation_payload,
        sgx_quote_hex: hex::encode(quote_bytes),
    })
}

pub fn handle_position_creation(
    args: PositionCreationArgs,
) -> anyhow::Result<ProvingResultOutputBorrowerPosition> {
    tracing::info!(
        vault_address = %args.vault_address,
        position_id = args.position_id,
        event_emitter_address = %args.event_emitter_address,
        threshold = %args.threshold,
        blocks = %args.block_offsets,
        "Starting position creation proving"
    );

    let block_offsets: Vec<i64> = serde_json::from_str(&args.block_offsets)
        .map_err(|e| anyhow::anyhow!("Failed to parse block offsets JSON: {}", e))?;

    if block_offsets.is_empty() {
        anyhow::bail!("No block offsets provided");
    }

    let target_blocks = calculate_target_blocks(&args.rpc_url, &block_offsets)?;
    let vault_address = Address::from_str(&args.vault_address)
        .map_err(|e| anyhow::anyhow!("Invalid vault address format: {}", e))?;

    let (collateral_amount, mut pendle_pool_address) = get_pending_borrow_request_data(&args.rpc_url, vault_address, args.position_id, None)?;

    pendle_pool_address = Address::from_str("0x0651c3f8ba59e312529d9a92fcebd8bb159cbaed")?;
    // core logic
    let mut yt_index_quote = Vec::with_capacity(target_blocks.len());
    let mut prices = Vec::with_capacity(target_blocks.len());
    let mut all_blocks = Vec::with_capacity(target_blocks.len());

    // todo: prove storage slots from event_emitter contract (collateralType, collateralAmount, ...)
    for block in target_blocks {
        let config = StorageProvingConfig {
            rpc_url: args.rpc_url.clone(),
            address: pendle_pool_address,
            storage_slots: vec![], // no need
            block_number: block,
            input_tokens_amount: U256::from_limbs([collateral_amount, 0, 0, 0]),
        };
        let hex_block_number = format!("0x{:x}", block);
        let block_header =
            get_block_header_from_rpc(&args.rpc_url.clone(), &hex_block_number)?;

        all_blocks.push((block, block_header.hash()));

        let PendleOutput {
            exact_pt_in,
            exact_sy_out,

            // should be const for any block, included in quote
            yt_index,
            ..
        } = pendle_logic(&config, block_header)?;

        yt_index_quote.push(yt_index);
        let e18 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
        let exact_pt_in_signed = I256::try_from(exact_pt_in.0).map_err(|e| anyhow::anyhow!("Failed to convert exact_pt_in to I256: {}", e))?;
        let current_price = (exact_sy_out * e18) / exact_pt_in_signed;
        prices.push(current_price);
    }

    let mut sum = I256::ZERO;
    let prices_count = I256::try_from(prices.len()).map_err(|e| anyhow::anyhow!("Failed to convert prices length to I256: {}", e))?;
    for price in &prices {
        sum += *price;
    }
    let twap_current_price = sum / prices_count;

    // todo: change to pendle liquidation price calculation using (twap_price, fee_liq, leverage)
    let liqudation_price = U256::from_str("1100000000000000000").unwrap();

    info!("Position creation validation completed, preparing attestation payload");

    if !yt_index_quote.windows(2).all(|w| w[0] == w[1]) {
        todo!("yt_index should be the same for all of the blocks in TWAP")
    }

    let attestation_payload = create_attestation_payload_borrow_position(all_blocks, yt_index_quote.first().expect("We don't have any yt_index").clone(), liqudation_price)?;
    let quote_bytes = generate_sgx_quote_borrower_position(&attestation_payload)?;

    Ok(ProvingResultOutputBorrowerPosition {
        attestation_payload,
        sgx_quote_hex: hex::encode(quote_bytes),
    })
}

fn calculate_target_blocks(
    rpc_url: &str,
    block_offsets: &[i64],
) -> anyhow::Result<Vec<u64>> {
    let latest_block_header = get_block_header_from_rpc(rpc_url, "latest")?;
    let latest_block_number = latest_block_header.number;

    let target_blocks: Vec<u64> = block_offsets
        .iter()
        .map(|offset| (latest_block_number as i64 + offset) as u64)
        .filter(|&block_num| block_num > 0)
        .collect();

    if target_blocks.is_empty() {
        anyhow::bail!("All calculated block numbers are invalid (<=0)");
    }

    tracing::info!("target blocks: {:?}", target_blocks);
    Ok(target_blocks)
}

fn collect_price_data_for_block(
    rpc_url: &str,
    block_number: u64,
    pendle_amm_address: Address,
    input_tokens_amount: crate::eth::aliases::U256,
) -> anyhow::Result<PriceData> {
    let hex_block_number = format!("0x{:x}", block_number);
    let block_header = get_block_header_from_rpc(rpc_url, &hex_block_number)?;

    let storage_proving_config = StorageProvingConfig {
        rpc_url: rpc_url.to_string(),
        address: pendle_amm_address,
        storage_slots: Vec::new(),
        block_number,
        input_tokens_amount,
    };

    let pendle_output = pendle_logic(&storage_proving_config, block_header)
        .map_err(|e| anyhow::anyhow!("Pendle logic failed: {}", e))?;

    let e18 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
    let input_tokens_amount_unsigned = I256::try_from(input_tokens_amount.0).unwrap();
    
    let price_from_pendle_amm = pendle_output.exact_sy_out * e18 / input_tokens_amount_unsigned;
    let price_from_pendle_amm_u128: u128 = price_from_pendle_amm.try_into().unwrap();

    tracing::debug!(
        "input_tokens_amount_unsigned: {}",
        input_tokens_amount_unsigned
    );
    tracing::debug!(
        "price_from_pendle_amm float: {}",
        price_from_pendle_amm_u128 as f64 / 1_000_000_000_000_000_000u128 as f64
    );

    Ok(PriceData {
        block_number,
        price: price_from_pendle_amm_u128,
    })
}

fn validate_position_liquidation(
    task: &crate::ProvingTask,
    position_id: u64,
    target_blocks: &[u64],
    args: &LiquidationArgs,
) -> anyhow::Result<()> {
    let (liquidation_price, pendle_amm_address_str) =
        request_stuff_from_dima_s_contract(&task.vault_address, &position_id);

    let pendle_amm_address = Address::from_str(&pendle_amm_address_str).map_err(|e| {
        anyhow::anyhow!(
            "Invalid strategy address format '{}': {}",
            pendle_amm_address_str,
            e
        )
    })?;

    let mut price_data: Vec<PriceData> = Vec::new();

    for &block_number in target_blocks {
        tracing::debug!("fetching price data for block {}", block_number);
        let data = collect_price_data_for_block(
            &args.rpc_url,
            block_number,
            pendle_amm_address,
            args.input_tokens_amount,
        )?;
        price_data.push(data);
    }

    if price_data.is_empty() {
        anyhow::bail!(
            "No price data found for strategy {} across {} blocks",
            pendle_amm_address_str,
            target_blocks.len()
        );
    }

    let validation = validate_liquidation_price(liquidation_price, &price_data)?;

    if !validation.is_valid {
        anyhow::bail!(
            "Liquidation price validation failed for position {} in vault {}: {}",
            position_id,
            task.vault_address,
            validation
                .reason
                .unwrap_or_else(|| "Unknown reason".to_string())
        );
    }

    tracing::info!(
        vault_address = %task.vault_address,
        position_id = position_id,
        liquidation_price = validation.liquidation_price,
        twap_price = validation.twap_price,
        price_difference_pct = validation.price_difference_pct * 100.0,
        "Liquidation price validation passed"
    );

    Ok(())
}

fn validate_all_liquidation_prices(
    proving_tasks: &[crate::ProvingTask],
    target_blocks: &[u64],
    args: &LiquidationArgs,
) -> anyhow::Result<()> {
    for task in proving_tasks {
        for &position_id in &task.position_ids {
            validate_position_liquidation(task, position_id, target_blocks, args)?;
        }
    }
    Ok(())
}

fn create_attestation_payload_liquidation(
    all_blocks: Vec<(u64, B256)>,
    all_vault_position_pairs: Vec<(Address, u64)>,
) -> anyhow::Result<AttestationPayloadLiquidation> {
    let final_blocks_hash = calculate_final_blocks_hash(&all_blocks);
    let final_positions_hash = calculate_final_positions_hash(&all_vault_position_pairs);

    Ok(AttestationPayloadLiquidation {
        blocks: all_blocks,
        vault_positions: all_vault_position_pairs,
        final_blocks_hash: final_blocks_hash.into(),
        final_positions_hash: final_positions_hash.into(),
    })
}

fn create_attestation_payload_borrow_position(
    all_blocks: Vec<(u64, B256)>,
    yt_index: U256,
    liquidation_price: U256,
) -> anyhow::Result<AttestationPayloadBorrowerPosition> {
    let final_blocks_hash = calculate_final_blocks_hash(&all_blocks);
    let payload_hash = calculate_hash_from_u256(liquidation_price);

    // todo: use yt_index
    Ok(AttestationPayloadBorrowerPosition {
        blocks: all_blocks,
        final_blocks_hash: final_blocks_hash.into(),
        payload_hash: payload_hash.into(),
    })
}

fn generate_sgx_quote_liquidation(
    attestation_payload: &AttestationPayloadLiquidation,
) -> anyhow::Result<Vec<u8>> {
    let report_data = construct_report_data_liquidation(attestation_payload)?;

    tracing::debug!(
        report_data_hex = %hex::encode(report_data),
        final_blocks_hash_hex = %hex::encode(attestation_payload.final_blocks_hash),
        final_positions_hash_hex = %hex::encode(attestation_payload.final_positions_hash),
        "Constructed report_data for DCAP quote"
    );

    let quote_bytes = automata_sgx_sdk::dcap::dcap_quote(report_data)
        .map_err(|e| anyhow::anyhow!("DCAP quote generation failed: {:?}", e))?;

    tracing::info!(
        quote_len = quote_bytes.len(),
        "DCAP quote generated successfully"
    );

    Ok(quote_bytes)
}

fn generate_sgx_quote_borrower_position(
    attestation_payload: &AttestationPayloadBorrowerPosition,
) -> anyhow::Result<Vec<u8>> {
    let report_data = construct_report_data_borrow_position(attestation_payload)?;

    tracing::debug!(
        report_data_hex = %hex::encode(report_data),
        final_blocks_hash_hex = %hex::encode(attestation_payload.final_blocks_hash),
        "Constructed report_data for DCAP quote"
    );

    let quote_bytes = automata_sgx_sdk::dcap::dcap_quote(report_data)
        .map_err(|e| anyhow::anyhow!("DCAP quote generation failed: {:?}", e))?;

    tracing::info!(
        quote_len = quote_bytes.len(),
        "DCAP quote generated successfully"
    );

    Ok(quote_bytes)
}