use std::str::FromStr;

use ruint::Uint;
use tracing::info;

use crate::{
    attestation_data::{
        AttestationPayloadBorrowerPosition, AttestationPayloadLiquidation,
        ProvingResultOutputBorrowerPosition, ProvingResultOutputLiquidation,
    },
    cli::{LiquidationArgs, PositionCreationArgs},
    eth::aliases::{Address, B256, I256, U256},
    math,
    math::{calculate_liquidation_price_base_collateral, LiquidationInputs},
    mock_v0::{validate_liquidation_price, PriceData},
    pendle::{pendle_logic, PendleOutput},
    utils::{
        calculate_final_blocks_hash, calculate_final_positions_hash, calculate_hash_from_u256,
        construct_report_data_borrow_position, construct_report_data_liquidation,
        get_block_header_from_rpc, StorageProvingConfig,
    },
    vault_v1::{
        get_borrower_position_from_rpc, get_pending_borrow_request_data, get_strategy_from_rpc,
    },
};
use crate::vault_v1::get_spread_fee_from_rpc;

pub fn handle_liquidation(args: LiquidationArgs) -> anyhow::Result<ProvingResultOutputLiquidation> {
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

    let mut all_blocks_duplicated: Vec<(u64, B256)> = Vec::new();
    let mut all_vault_position_pairs: Vec<(Address, u64, U256, U256)> = Vec::new();

    validate_all_liquidation_prices(
        &proving_tasks,
        &target_blocks,
        &args,
        &mut all_blocks_duplicated,
        &mut all_vault_position_pairs,
    )?;

    let all_blocks_size = all_blocks_duplicated.len() / all_vault_position_pairs.len();
    let all_blocks = all_blocks_duplicated
        .into_iter()
        .take(all_blocks_size)
        .collect::<Vec<_>>();

    tracing::info!(
        total_blocks = all_blocks.len(),
        task_count = proving_tasks.len(),
        "All blocks and tasks completed, validating liquidation prices"
    );

    for (b, h) in all_blocks.clone() {
        tracing::debug!("all_blocks: {} {}", b, h);
    }

    for (a, b, c, d) in all_vault_position_pairs.clone() {
        tracing::debug!("all_vault_position_pairs: {} {} {} {}", a, b, c, d);
    }

    tracing::info!("Liquidation price validation completed, preparing attestation payload");

    let attestation_payload =
        create_attestation_payload_liquidation(all_blocks, all_vault_position_pairs)?;
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
        "Starting position creation proving"
    );

    let block_offsets: Vec<i64> = serde_json::from_str(&args.block_offsets)
        .map_err(|e| anyhow::anyhow!("Failed to parse block offsets: {}", e))?;

    let target_blocks = calculate_target_blocks(&args.rpc_url, &block_offsets)?;
    let vault_address = Address::from_str(&args.vault_address)?;

    let position =
        get_borrower_position_from_rpc(&args.rpc_url, vault_address, args.position_id, None)?;

    let strategy = get_strategy_from_rpc(&args.rpc_url, vault_address, position.strategy_id, None)?;

    let pendle_pool_address = strategy.pool;

    let total_assets_to_swap_pt = U256(position.assets_borrowed.0 + position.collateral_given.0);

    // Calculate TWAP for deposit price
    let mut sy_amounts_sum = I256::ZERO;
    let mut all_blocks = Vec::with_capacity(target_blocks.len());
    let mut yt_indices = Vec::with_capacity(target_blocks.len());

    for &block in &target_blocks {
        let config = StorageProvingConfig {
            rpc_url: args.rpc_url.clone(),
            address: pendle_pool_address,
            storage_slots: vec![],
            block_number: block,
            input_tokens_amount: total_assets_to_swap_pt,
        };

        let hex_block_number = format!("0x{:x}", block);
        let block_header = get_block_header_from_rpc(&args.rpc_url, &hex_block_number)?;
        all_blocks.push((block, block_header.hash()));

        let PendleOutput {
            sy_amount: exact_sy_out,
            yt_index,
            ..
        } = pendle_logic(&config, block_header, false)?;

        sy_amounts_sum = sy_amounts_sum + exact_sy_out;
        yt_indices.push(yt_index);
    }

    let blocks_count = I256::try_from(Uint::<256, 4>::from(target_blocks.len()))
        .map_err(|e| anyhow::anyhow!("Failed to convert length: {}", e))?;
    let sy_received_twap = sy_amounts_sum / blocks_count;
    let sy_received_twap_u256 = math::i256_to_u256(sy_received_twap)?;

    let deposit_price_wad = math::div_wad(sy_received_twap_u256, total_assets_to_swap_pt);

    let latest_block_header = get_block_header_from_rpc(&args.rpc_url, "latest")?;
    let current_timestamp = latest_block_header.timestamp;
    let end_date_timestamp = strategy.end_date;

    let days_until_maturity = if current_timestamp < end_date_timestamp {
        (end_date_timestamp - current_timestamp) / 86400
    } else {
        0
    };

    let borrow_apr_u256 = U256(Uint::from(strategy.borrow_apr));
    let multiplier = U256(Uint::from(10u64).pow(Uint::from(14u64)));
    let borrowing_apy_wad = U256(borrow_apr_u256.0.saturating_mul(multiplier.0));

    let spread_fee_raw = get_spread_fee_from_rpc(
        &args.rpc_url,
        vault_address,
        None, // latest
    )?;

    let spread_fee_wad = U256(Uint::from(spread_fee_raw).saturating_mul(Uint::from(10u64).pow(Uint::from(14u64))));

    let inputs = LiquidationInputs {
        q_borrowed: position.assets_borrowed,
        q_collateral: position.collateral_given,
        deposit_price_wad,
        borrowing_apy_wad,
        spread_fee_wad,
        days_until_maturity,
        p_mint_wad: math::wad(),
        p_redeem_wad: math::wad(),
    };

    let liquidation_price = calculate_liquidation_price_base_collateral(&inputs)?;

    info!(
        liquidation_price = %liquidation_price.0,
        liquidation_price_f64 = liquidation_price.to_u128().unwrap_or(0) as f64 / 1e18,
        deposit_price_wad = %deposit_price_wad.0,
        deposit_price_f64 = deposit_price_wad.to_u128().unwrap_or(0) as f64 / 1e18,
        total_pt_swapped = %total_assets_to_swap_pt.0,
        sy_received_twap = %sy_received_twap_u256.0,
        "Calculated liquidation price"
    );

    // todo: verify all YT indices are the same
    // if !yt_indices.windows(2).all(|w| w[0].0 == w[1].0) {
    //     return Err(anyhow::anyhow!("YT index changed during TWAP period"));
    // }

    let attestation_payload =
        create_attestation_payload_borrow_position(all_blocks, yt_indices[0], liquidation_price)?;

    let quote_bytes = generate_sgx_quote_borrower_position(&attestation_payload)?;

    Ok(ProvingResultOutputBorrowerPosition {
        attestation_payload,
        sgx_quote_hex: hex::encode(quote_bytes),
        liquidation_price,
    })
}

fn calculate_target_blocks(rpc_url: &str, block_offsets: &[i64]) -> anyhow::Result<Vec<u64>> {
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
    all_blocks: &mut Vec<(u64, B256)>,
    latest_position: &mut (Address, u64, U256, U256),
) -> anyhow::Result<PriceData> {
    let hex_block_number = format!("0x{:x}", block_number);
    let block_header = get_block_header_from_rpc(rpc_url, &hex_block_number)?;
    all_blocks.push((block_number, block_header.hash()));

    let storage_proving_config = StorageProvingConfig {
        rpc_url: rpc_url.to_string(),
        address: pendle_amm_address,
        storage_slots: Vec::new(),
        block_number,
        input_tokens_amount,
    };

    let pendle_output = pendle_logic(&storage_proving_config, block_header, false)
        .map_err(|e| anyhow::anyhow!("Pendle logic failed: {}", e))?;
    // TODO it is ok if reverts because not enough liquidity in the pool, still need to liquidate, need to handle properly

    latest_position.2 = pendle_output.yt_index;
    latest_position.3 = U256::from_i256(
        pendle_output.sy_amount * I256::unchecked_from(9) / I256::unchecked_from(10),
    )
    .expect("unable to convert i256 to u256");

    let e18 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
    let input_tokens_amount_unsigned = I256::try_from(input_tokens_amount.0).unwrap();

    let price_from_pendle_amm = pendle_output.sy_amount * e18 / input_tokens_amount_unsigned;
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
    all_blocks: &mut Vec<(u64, B256)>,
    all_vault_position_pairs: &mut Vec<(Address, u64, U256, U256)>,
) -> anyhow::Result<()> {
    let mut price_data: Vec<PriceData> = Vec::new();

    let vault_address = Address::from_str(&task.vault_address)
        .map_err(|e| anyhow::anyhow!("Invalid vault address format: {}", e))?;

    all_vault_position_pairs.push((vault_address, position_id, U256::ZERO, U256::ZERO));

    let bp = get_borrower_position_from_rpc(
        &args.rpc_url,
        vault_address,
        position_id,
        Some(target_blocks[0]),
    )?;
    let input_tokens_amount = bp.strategy_balance;
    // todo: works on bera with emitter 0x6eD14bCe18F71cE214ED69d721823700810fB422,
    // only strategy_id = 1 contains real pendle amm address, workflow doesn't work with other values
    let strategy_id = U256::from_limbs([1, 0, 0, 0]);
    // let strategy_id = bp.strategy_id;
    let liquidation_price = bp
        .liquidation_price
        .to_u128()
        .expect("liquidation price conversion to u128 failed");

    let pendle_amm_address = get_strategy_from_rpc(
        &args.rpc_url,
        vault_address,
        strategy_id,
        Some(target_blocks[0]),
    )?
    .pool;

    for &block_number in target_blocks {
        tracing::debug!(
            "fetching price data for block {}, pendle amm adress {}, input_tokens_amount {}",
            block_number,
            pendle_amm_address,
            input_tokens_amount
        );
        let data = collect_price_data_for_block(
            &args.rpc_url,
            block_number,
            pendle_amm_address,
            input_tokens_amount,
            all_blocks,
            all_vault_position_pairs
                .last_mut()
                .expect("unable to get all_vault_position_pairs.last_mut()"),
        )?;
        price_data.push(data);
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
    all_blocks: &mut Vec<(u64, B256)>,
    all_vault_position_pairs: &mut Vec<(Address, u64, U256, U256)>,
) -> anyhow::Result<()> {
    for task in proving_tasks {
        for &position_id in &task.position_ids {
            validate_position_liquidation(
                task,
                position_id,
                target_blocks,
                args,
                all_blocks,
                all_vault_position_pairs,
            )?;
        }
    }
    Ok(())
}

fn create_attestation_payload_liquidation(
    all_blocks: Vec<(u64, B256)>,
    all_vault_position_pairs: Vec<(Address, u64, U256, U256)>,
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
