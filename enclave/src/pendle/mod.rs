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

fn get_immutables_from_market_state(
    storage_proving_config: utils::StorageProvingConfig,
) -> anyhow::Result<ImmutablesFromMarketState> {
    let selector = "794052f3"; // pendle-core-v2-public$ forge selectors list | grep readState(address)
    // pendle router v4 form here https://docs.pendle.finance/Developers/Contracts/PendleRouter
    let router_param = "000000000000000000000000888888888889758F76e7103c6CbF23ABbF58F946";
    let call_data = format!("{}{}", selector, router_param);

    println! ("&storage_proving_config.block_number: {}", &storage_proving_config.block_number);
    let eth_call_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": &storage_proving_config.address,
            "data": call_data
        }, &storage_proving_config.block_number],
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

    // struct MarketState {
        // int256 totalPt;
        // int256 totalSy;
        // int256 totalLp;
        // address treasury;
        // int256 scalarRoot;
        // uint256 expiry;
        // uint256 lnFeeRateRoot;
        // uint256 reserveFeePercent; // base 100
        // uint256 lastLnImpliedRate;
    // }
    let data = hex::decode(&hex_data[2..])?;

    let total_pt = I256::from_be_bytes::<32>(data[0..32].try_into()?);
    let total_sy = I256::from_be_bytes::<32>(data[32..64].try_into()?);
    let total_lp = I256::from_be_bytes::<32>(data[64..96].try_into()?);

    let treasury_bytes: [u8; 20] = data[108..128].try_into()?;
    let treasury = Address::from(treasury_bytes);

    let scalar_root = I256::from_be_bytes::<32>(data[128..160].try_into()?);
    let expiry = U256::from_be_bytes::<32>(data[160..192].try_into()?);
    let ln_fee_rate_root = U256::from_be_bytes::<32>(data[192..224].try_into()?);
    let reserve_fee_percent = U256::from_be_bytes::<32>(data[224..256].try_into()?);
    let last_ln_implied_rate = U256::from_be_bytes::<32>(data[256..288].try_into()?);


    tracing::debug! ("readState request, total_pt: {}", total_pt);
    tracing::debug! ("readState request, total_sy: {}", total_sy);
    tracing::debug! ("readState request, total_lp: {}", total_lp);
    tracing::debug! ("readState request, treasury: {}", treasury);
    tracing::debug! ("readState request, scalar_root: {}", scalar_root);
    tracing::debug! ("readState request, expiry: {}", expiry);
    tracing::debug! ("readState request, ln_fee_rate_root: {}", ln_fee_rate_root);
    tracing::debug! ("readState request, reserve_fee_percent: {}", reserve_fee_percent);
    tracing::debug! ("readState request, last_ln_implied_rate: {}", last_ln_implied_rate);

    let res = ImmutablesFromMarketState{
        scalar_root_from_storage: scalar_root,
        expiry_from_storage: expiry,
        ln_fee_rate_root_from_storage: last_ln_implied_rate,
    };

    Ok(res)

}

fn get_yt_index(
    storage_proving_config: utils::StorageProvingConfig,
) -> anyhow::Result<U256> {
    let read_tokens_selector = "2c8ce6bc"; // pendle-core-v2-public$ forge selectors list | grep readTokens()

    let read_tokens_eth_call_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": &storage_proving_config.address,
            "data": read_tokens_selector
        }, &storage_proving_config.block_number],
        "id": 1
    })
    .to_string();

    let read_tokens_eth_call_response_str = make_http_request(&storage_proving_config.rpc_url, "POST", read_tokens_eth_call_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("eth_call HTTP request failed: {:?}", e))?;

    println! ("read_tokens_eth_call_response_str: {}", read_tokens_eth_call_response_str);


    let read_tokens_rpc_proof_response: RpcResponse<String> = serde_json::from_str(&read_tokens_eth_call_response_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse proof RPC response: {}", e))?;
    tracing::info!("Request result parsing succeeded");
    let read_tokens_hex_data = read_tokens_rpc_proof_response.result;

    // returns (IStandardizedYield _SY, IPPrincipalToken _PT, IPYieldToken _YT)
    let read_tokens_data = hex::decode(&read_tokens_hex_data[2..])?;

    let yt_address_bytes: [u8; 20] = read_tokens_data[64+12..64+32].try_into()?;
    let yt_address = Address::from(yt_address_bytes);

    println! ("yt_address: {}", yt_address);
//////////////////////
    let py_index_current_selector = "1d52edc4"; // forge selectors list | grep 'pyIndexCurrent()'

    let py_index_current_eth_call_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": "48bbbedc4d2491cc08915d7a5c7cc8a8edf165da", // TODO unhardcode
            "data": py_index_current_selector
        }, &storage_proving_config.block_number],
        "id": 1
    })
    .to_string();

    let py_index_current_eth_call_response_str = make_http_request(&storage_proving_config.rpc_url, "POST", py_index_current_eth_call_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("eth_call HTTP request failed: {:?}", e))?;

    println! ("py_index_current_eth_call_response_str: {}", py_index_current_eth_call_response_str);


    let py_index_current_rpc_proof_response: RpcResponse<String> = serde_json::from_str(&py_index_current_eth_call_response_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse proof RPC response: {}", e))?;
    tracing::info!("Request result parsing succeeded");
    let py_index_current_hex_data = py_index_current_rpc_proof_response.result;

    // returns (IStandardizedYield _SY, IPPrincipalToken _PT, IPYieldToken _YT)
    let py_index_current_data = hex::decode(&py_index_current_hex_data[2..])?;

    let py_index_current = U256::from_be_bytes::<32>(py_index_current_data[0..32].try_into()?);

    println! ("yt_index: {}", py_index_current);

    Ok(py_index_current) // TODO actually need to return also YT address

}



pub fn pendle_logic(
    storage_proving_config: &utils::StorageProvingConfig,
    timings: &mut Timings,
    total_timer_start: std::time::Instant,
) -> anyhow::Result<I256> { // TODO fugure out what to return from here

    let market_storage_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: storage_proving_config.address.clone(),
        // TODO maybe more beautyful way to declare than array
        storage_slots: vec![
            eth::primitives::FixedBytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10]),
            eth::primitives::FixedBytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,11]),
        ],
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

    // uint16 observationIndex is next 2 bytes
    let mut obs_index_bytes = [0u8; 16];
    obs_index_bytes[14..16].copy_from_slice(&raw_slot_11[32-12-2..32-12]);
    let obs_index_from_storage: i128 = i128::from_be_bytes(obs_index_bytes);
    tracing::debug!("obs_index_from_storage = {}", obs_index_from_storage);

    // uint16 observationCardinality is next 2 bytes
    let mut obs_card_bytes = [0u8; 16];
    obs_card_bytes[14..16].copy_from_slice(&raw_slot_11[32-12-2-2..32-12-2]);
    let obs_card_from_storage: i128 = i128::from_be_bytes(obs_card_bytes);
    tracing::debug!("obs_card_from_storage = {}", obs_card_from_storage);

    // uint16 observationCardinalityNext is next 2 bytes
    let mut obs_card_next_bytes = [0u8; 16];
    obs_card_next_bytes[14..16].copy_from_slice(&raw_slot_11[32-12-2-2-2..32-12-2-2]);
    let obs_card_next_from_storage: i128 = i128::from_be_bytes(obs_card_next_bytes);
    tracing::debug!("obs_card_next_from_storage = {}", obs_card_next_from_storage);

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

    let yt_index = get_yt_index(market_storage_proving_config)
        .map_err(|e| anyhow::anyhow!("YT.newIndex() request failed: {:?}", e))?;


    let billion: U256 = U256::from_limbs([1_000_000_000, 0, 0, 0]); // TODO pass as cmd line arg or smth like that
    let exact_pt_in = billion * billion * U256::from_limbs([10_000_000, 0, 0, 0]);

    let exact_sy_out = market_math_core::swap_exact_pt_for_sy(
        market,
        yt_index,
        exact_pt_in,
        block_timestamp,
    );

    tracing::info! ("storage_proving_config.block_number: {}", storage_proving_config.block_number);
    tracing::info! ("exact_pt_in: {}", exact_pt_in);
    tracing::info! ("exact_pt_in / 10**18: {}", exact_pt_in / U256::from_limbs([1000_000_000_000_000_000u64, 0, 0, 0]));
    tracing::info! ("exact_sy_out: {}", exact_sy_out);
    tracing::info! ("exact_sy_out / 10**18: {}", exact_sy_out/ I256::from_limbs([1000_000_000_000_000_000u64, 0, 0, 0]));

    Ok(exact_sy_out)
}
