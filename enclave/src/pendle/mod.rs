mod market_math_core;

use crate::utils;
use crate::eth;

use std::collections::HashMap;

use crate::{
    eth::{
        aliases::I256,
        primitives::{Address, B256, U256},
    },
    timing::Timings,
    utils::{
        extract_storage_slots_with_merkle_proving,
        make_http_request,
        RpcResponse,
        StorageProvingConfig,
    },
};


struct ImmutablesFromMarketState {
    scalar_root_from_storage: I256,
    expiry_from_storage: U256,
    ln_fee_rate_root_from_storage: U256,
}

fn eth_call (
    to: &str,
    call_data: &str,
    storage_proving_config: &StorageProvingConfig,
) -> anyhow::Result<Vec<u8>> {

    let eth_call_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": to,
            "data": call_data
        }, storage_proving_config.block_number],
        "id": 1
    })
    .to_string();


    let eth_call_response_str = make_http_request(&storage_proving_config.rpc_url, "POST", eth_call_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("eth_call HTTP request failed: {:?}", e))?;

    println! ("eth_call_response_str: {}", eth_call_response_str);


    let rpc_proof_response: RpcResponse<String> = serde_json::from_str(&eth_call_response_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse proof RPC response: {}", e))?;
    tracing::info!("Request result parsing succeeded");
    let hex_data = rpc_proof_response.result;

    let data = hex::decode(&hex_data[2..])?;

    Ok(data)


}

fn get_immutables_from_market_state(
    storage_proving_config: utils::StorageProvingConfig,
) -> anyhow::Result<ImmutablesFromMarketState> {
    let selector = "794052f3"; // pendle-core-v2-public$ forge selectors list | grep readState(address)
    // pendle router v4 form here https://docs.pendle.finance/Developers/Contracts/PendleRouter
    let router_param = "000000000000000000000000888888888889758F76e7103c6CbF23ABbF58F946";
    let call_data = format!("{}{}", selector, router_param);

    let data = eth_call(
        &storage_proving_config.address,
        &call_data,
        &storage_proving_config
    )?;


    // struct MarketState {
        // int256 totalPt;
        // int256 totalSy;
        // int256 totalLp;
        // address treasury;
        // int256 scalarRoot; // slot 4
        // uint256 expiry; // slot 5
        // uint256 lnFeeRateRoot;
        // uint256 reserveFeePercent; // base 100
        // uint256 lastLnImpliedRate; // slot 8
    // }

    let scalar_root = I256::from_be_bytes::<32>(data[32*4..32*5].try_into()?);
    let expiry = U256::from_be_bytes::<32>(data[32*5..32*6].try_into()?);
    let last_ln_implied_rate = U256::from_be_bytes::<32>(data[32*8..32*9].try_into()?);

    tracing::debug! ("readState request, scalar_root: {}", scalar_root);
    tracing::debug! ("readState request, expiry: {}", expiry);
    tracing::debug! ("readState request, last_ln_implied_rate: {}", last_ln_implied_rate);

    let res = ImmutablesFromMarketState{
        scalar_root_from_storage: scalar_root,
        expiry_from_storage: expiry,
        ln_fee_rate_root_from_storage: last_ln_implied_rate,
    };

    Ok(res)

}

struct YtStruct {
    yt_address: Address,
    py_index_current: U256,
}

fn get_yt_index(
    storage_proving_config: utils::StorageProvingConfig,
) -> anyhow::Result<YtStruct> {
    let read_tokens_selector = "2c8ce6bc"; // pendle-core-v2-public$ forge selectors list | grep readTokens()

    let read_tokens_data = eth_call(
        &storage_proving_config.address,
        read_tokens_selector,
        &storage_proving_config
    )?;
    // returns (IStandardizedYield _SY, IPPrincipalToken _PT, IPYieldToken _YT)

    let yt_address_bytes: [u8; 20] = read_tokens_data[64+12..64+32].try_into()?;
    let yt_address = Address::from(yt_address_bytes);
    tracing::debug!("yt_address: {}", yt_address);

    let py_index_current_selector = "1d52edc4"; // forge selectors list | grep 'pyIndexCurrent()'
    let py_index_current_data = eth_call(
        &hex::encode(yt_address.0),
        py_index_current_selector,
        &storage_proving_config
    )?;

    let py_index_current = U256::from_be_bytes::<32>(py_index_current_data[0..32].try_into()?);

    tracing::debug! ("yt_index: {}", py_index_current);

    Ok(YtStruct{yt_address, py_index_current})

}

pub struct PendleOutput {
    exact_pt_in: U256,
    exact_sy_out: I256,
    yt_address: Address,
    yt_index: U256,
    scalar_root: I256,
    expiry: U256,
    ln_fee_rate_root: U256,
}

pub fn pendle_logic(
    storage_proving_config: &utils::StorageProvingConfig,
    timings: &mut Timings,
    total_timer_start: std::time::Instant,
) -> anyhow::Result<PendleOutput> {

    let market_storage_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: storage_proving_config.address.clone(),
        storage_slots: vec![B256::from_u8(10), B256::from_u8(11)],
        block_number: storage_proving_config.block_number.clone(),
    };


    let market_storage_storage_slots = extract_storage_slots_with_merkle_proving(market_storage_proving_config.clone(), timings, total_timer_start)?;

    let block_timestamp = U256::from_u64(market_storage_storage_slots.block_timestamp);

    let mut market_storage_hashmap: HashMap<i32, B256> = HashMap::new();
    market_storage_hashmap.insert(10, market_storage_storage_slots.proven_slots[0].value_unhashed);
    market_storage_hashmap.insert(11, market_storage_storage_slots.proven_slots[1].value_unhashed);

    //  struct MarketStorage {
    //     int128 totalPt;
    //     int128 totalSy;
    //     // 1 SLOT = 256 bits
    //     uint96 lastLnImpliedRate; // 12
    //     uint16 observationIndex; // 2
    //     uint16 observationCardinality; // 2
    //     uint16 observationCardinalityNext; // 2
    //     // 1 SLOT = 144 bits
    // }

    let raw_slot_10: [u8; 32] = market_storage_hashmap.get(&10)
        .ok_or_else(|| anyhow::anyhow!("error: slot 10 not found"))?
            .0;
    tracing::debug! ("raw_slot_10: {}", hex::encode(raw_slot_10));

    // int128 totalPt is first 16 bytes
    let mut pt_bytes = [0u8; 16];
    pt_bytes.copy_from_slice(&raw_slot_10[16..32]);
    let total_pt_from_storage: i128 = i128::from_be_bytes(pt_bytes);
    tracing::debug!("total_pt_from_storage = {}", total_pt_from_storage);

    // int128 totalSy is next 16 bytes
    let mut sy_bytes = [0u8; 16];
    sy_bytes.copy_from_slice(&raw_slot_10[0..16]);
    let total_sy_from_storage: i128 = i128::from_be_bytes(sy_bytes);
    tracing::debug!("total_sy_from_storage = {}", total_sy_from_storage);


    let raw_slot_11: [u8; 32] = market_storage_hashmap.get(&11)
        .ok_or_else(|| anyhow::anyhow!("error: slot 11 not found"))?
            .0;
    tracing::debug! ("raw_slot_11: {}", hex::encode(raw_slot_11));

    // uint96 lastLnImpliedRate is first 12 bytes
    let mut ln_rate_bytes = [0u8; 16];
    ln_rate_bytes[4..16].copy_from_slice(&raw_slot_11[32-12..32]);
    let ln_rate_from_storage: u128 = u128::from_be_bytes(ln_rate_bytes);
    tracing::debug!("ln_rate_from_storage = {}", ln_rate_from_storage);


    let immutables = get_immutables_from_market_state(market_storage_proving_config.clone())
        .map_err(|e| anyhow::anyhow!("Immutables request failed: {:?}", e))?;

    let scalar_root_from_storage = immutables.scalar_root_from_storage;
    let expiry_from_storage = immutables.expiry_from_storage;
    let ln_fee_rate_root_from_storage = immutables.ln_fee_rate_root_from_storage;


    // in solidity market is constructed in PendleParketV3.readState,
    // but here we access storage in mod.rs, so I decided to construct market here
    // and pass it to swap_exact_pt_for_sy as imput
    let market: market_math_core::MarketState = market_math_core::MarketState {
        total_pt: I256::try_from(total_pt_from_storage).unwrap(),
        total_sy: I256::try_from(total_sy_from_storage).unwrap(),
        scalar_root: scalar_root_from_storage,
        expiry: expiry_from_storage,
        ln_fee_rate_root: ln_fee_rate_root_from_storage,
        last_ln_implied_rate: U256::new(ln_rate_from_storage),
    };

    let yt_address_and_index = get_yt_index(market_storage_proving_config)
        .map_err(|e| anyhow::anyhow!("YT.newIndex() request failed: {:?}", e))?;


    let billion: U256 = U256::from_limbs([1_000_000_000, 0, 0, 0]); // TODO pass as cmd line arg or smth like that
    let exact_pt_in = billion * billion * U256::from_limbs([10_000_000, 0, 0, 0]);

    let exact_sy_out = market_math_core::swap_exact_pt_for_sy(
        market,
        yt_address_and_index.py_index_current,
        exact_pt_in,
        block_timestamp,
    );

    tracing::info! ("storage_proving_config.block_number: {}", storage_proving_config.block_number);
    tracing::info! ("exact_pt_in: {}", exact_pt_in);
    tracing::info! ("exact_pt_in / 10**18: {}", exact_pt_in / U256::from_limbs([1000_000_000_000_000_000u64, 0, 0, 0]));
    tracing::info! ("exact_sy_out: {}", exact_sy_out);
    tracing::info! ("exact_sy_out / 10**18: {}", exact_sy_out/ I256::from_limbs([1000_000_000_000_000_000u64, 0, 0, 0]));

    let output = PendleOutput {
        exact_pt_in: exact_pt_in,
        exact_sy_out: exact_sy_out,
        yt_address: yt_address_and_index.yt_address,
        yt_index: yt_address_and_index.py_index_current,
        scalar_root: immutables.scalar_root_from_storage,
        expiry: immutables.expiry_from_storage,
        ln_fee_rate_root: immutables.ln_fee_rate_root_from_storage,
    };

    Ok(output)
}
