// Implements function swapExactPtForSy from here:
// https://github.com/pendle-finance/pendle-core-v2-public/blob/6ca87b6e5a823d603cb8f66f983f5bc63b53218a/contracts/core/Market/v3/PendleMarketV3.sol

mod errors;
mod market_math_core;
mod math;

use std::str::FromStr;

use crate::utils;

use crate::{
    eth::aliases::{Address, B256, I256, U256},
    eth::header::Header,
    timing::{Lap, Timings},
    utils::{
        extract_storage_slots_with_merkle_proving, keccak256, make_http_request, RpcResponse,
        StorageProvingConfig,
    },
};

const PENDLE_ROUTER_V4: &str = "888888888889758F76e7103c6CbF23ABbF58F946";

struct ImmutablesFromMarketState {
    scalar_root_from_rpc: I256,
    expiry_from_rpc: U256,
    ln_fee_rate_root_from_rpc: U256,
}

fn eth_call(
    to: &str,
    call_data: &str,
    storage_proving_config: &StorageProvingConfig,
) -> anyhow::Result<Vec<u8>> {
    let hex_block_number = format!("0x{:x}", storage_proving_config.block_number);
    let hex_call_data = format!("0x{}", call_data);

    let eth_call_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": to,
            "data": hex_call_data
        }, hex_block_number],
        "id": 1
    })
    .to_string();

    tracing::debug!("eth_call_payload: {}", eth_call_payload);

    let eth_call_response_str = make_http_request(
        &storage_proving_config.rpc_url,
        "POST",
        eth_call_payload.as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("eth_call HTTP request failed: {:?}", e))?;

    tracing::debug!("eth_call_response_str: {}", eth_call_response_str);

    let rpc_proof_response: RpcResponse<String> = serde_json::from_str(&eth_call_response_str)
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse proof RPC response: \"{}\", response_str: {}",
                e,
                eth_call_response_str
            )
        })?;
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
    let router_param = format!("{}{}", "000000000000000000000000", PENDLE_ROUTER_V4);
    let call_data = format!("{}{}", selector, router_param);

    let data = eth_call(
        &format!("0x{}", hex::encode(storage_proving_config.address.0)),
        &call_data,
        &storage_proving_config,
    )?;

    // struct MarketState {
    // int256 totalPt;
    // int256 totalSy;
    // int256 totalLp;
    // address treasury;
    // int256 scalarRoot; // slot 4
    // uint256 expiry; // slot 5
    // uint256 lnFeeRateRoot; // slot 6
    // uint256 reserveFeePercent; // base 100
    // uint256 lastLnImpliedRate; // slot 8
    // }

    let scalar_root = I256::from_be_bytes::<32>(data[32 * 4..32 * 5].try_into()?);
    let expiry = U256::from_be_bytes::<32>(data[32 * 5..32 * 6].try_into()?);
    let ln_fee_rate_root = U256::from_be_bytes::<32>(data[32 * 6..32 * 7].try_into()?);

    tracing::debug!("readState request, scalar_root: {}", scalar_root);
    tracing::debug!("readState request, expiry: {}", expiry);
    tracing::debug!("readState request, ln_fee_rate_root: {}", ln_fee_rate_root);

    let res = ImmutablesFromMarketState {
        scalar_root_from_rpc: scalar_root,
        expiry_from_rpc: expiry,
        ln_fee_rate_root_from_rpc: ln_fee_rate_root,
    };

    Ok(res)
}

struct YtStruct {
    yt_address: Address,
    py_index_current: U256,
}

fn get_yt_index(storage_proving_config: utils::StorageProvingConfig) -> anyhow::Result<YtStruct> {
    let read_tokens_selector = "2c8ce6bc"; // pendle-core-v2-public$ forge selectors list | grep readTokens()

    let read_tokens_data = eth_call(
        &format!("0x{}", hex::encode(storage_proving_config.address.0)),
        read_tokens_selector,
        &storage_proving_config,
    )?;
    // returns (IStandardizedYield _SY, IPPrincipalToken _PT, IPYieldToken _YT)

    let yt_address_bytes: [u8; 20] = read_tokens_data[64 + 12..64 + 32].try_into()?;
    let yt_address = Address::from(yt_address_bytes);
    tracing::debug!("yt_address: {}", yt_address);
    let hex_yt_addr = &hex::encode(yt_address.0);

    let py_index_current_selector = "1d52edc4"; // forge selectors list | grep 'pyIndexCurrent()'
    let py_index_current_data = eth_call(
        &format!("0x{}", hex_yt_addr),
        py_index_current_selector,
        &storage_proving_config,
    )?;

    let py_index_current = U256::from_be_bytes::<32>(py_index_current_data[0..32].try_into()?);

    tracing::debug!("yt_index: {}", py_index_current);

    Ok(YtStruct {
        yt_address,
        py_index_current,
    })
}

// mapping(address => mapping(address => uint80)) internal overriddenFee;
// _overriddenFee = overriddenFee[router][market];
fn compute_overridden_fee_key(
    router: [u8; 20],
    market: [u8; 20],
    mapping_slot: u64,
) -> [u8; 32] {
    // keccak256(abi.encode(market, keccak256(abi.encode(router, mapping_slot))));

    // abi.encode(address, u64)
    let mut first_buffer = [0u8; 64];
    first_buffer[12..32].copy_from_slice(&router);
    let slot_bytes = mapping_slot.to_be_bytes();
    first_buffer[32 + (32 - 8)..64].copy_from_slice(&slot_bytes);

    // abi.encode(address, bytes32)
    let first_hash = keccak256(&first_buffer);
    let mut second_buffer = [0u8; 64];
    second_buffer[12..32].copy_from_slice(&market);
    second_buffer[32..64].copy_from_slice(&first_hash);

    keccak256(&second_buffer)
}

pub struct PendleOutput {
    pub exact_pt_in: U256,
    pub exact_sy_out: I256,
    pub yt_address: Address,
    pub yt_index: U256,
    pub scalar_root: I256,
    pub expiry: U256,
    pub ln_fee_rate_root: U256,
    // request fee from factory storage instead of requesting ln fee rate root overriden from function
    pub block_timestamp: u64,
    pub block_number: u64,
    pub block_hash: B256,
}

pub fn pendle_logic(
    storage_proving_config: &utils::StorageProvingConfig,
    timings: &mut Timings,
    total_timer_start: std::time::Instant,
    block_header: Header,
) -> anyhow::Result<PendleOutput> {
    let maket_data_extraction_from_storage_timing =
        Lap::new("maket_data_extraction_from_storage_timing");
    let market_storage_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: storage_proving_config.address.clone(),
        storage_slots: vec![B256::from_u8(10), B256::from_u8(11)],
        block_number: storage_proving_config.block_number.clone(),
        input_tokens_amount: storage_proving_config.input_tokens_amount,
    };

    let market_storage_storage_slots = extract_storage_slots_with_merkle_proving(
        &market_storage_proving_config,
        timings,
        total_timer_start,
        block_header.clone(),
    )?;
    let raw_slot_10 = market_storage_storage_slots.proven_slots[0]
        .value_unhashed
        .0;
    tracing::debug!("raw_slot_10: {}", hex::encode(raw_slot_10));

    let raw_slot_11 = market_storage_storage_slots.proven_slots[1]
        .value_unhashed
        .0;
    tracing::debug!("raw_slot_11: {}", hex::encode(raw_slot_11));

    let block_timestamp = U256::from_limbs([market_storage_storage_slots.block_timestamp, 0, 0, 0]);

    // slots 10, 11
    //  struct MarketStorage {
    //     int128 totalPt;
    //     int128 totalSy;
    //     1 SLOT = 256 bits
    //     uint96 lastLnImpliedRate;
    //     uint16 observationIndex;
    //     uint16 observationCardinality;
    //     uint16 observationCardinalityNext;
    //     1 SLOT = 144 bits
    // }

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

    let mut last_ln_implied_rate_bytes = [0u8; 32];
    last_ln_implied_rate_bytes[20..32].copy_from_slice(&raw_slot_11[32 - 12..32]);
    let last_ln_inplied_rate_from_storage: U256 = U256::from_be_bytes(last_ln_implied_rate_bytes);
    tracing::debug!(
        "last_ln_inplied_rate_from_storage = {}",
        last_ln_inplied_rate_from_storage
    );

    maket_data_extraction_from_storage_timing.stop(timings);

    let immutables_request_timing = Lap::new("immutables_request_timing");
    let immutables = get_immutables_from_market_state(market_storage_proving_config.clone())
        .map_err(|e| anyhow::anyhow!("Immutables request failed: {:?}", e))?;

    let scalar_root_from_rpc = immutables.scalar_root_from_rpc;
    let expiry_from_rpc = immutables.expiry_from_rpc;
    // todo request from dedicated function instead of readState, and later from our contract
    let ln_fee_rate_root_from_rpc = immutables.ln_fee_rate_root_from_rpc;
    tracing::debug!("ln_fee_rate_root_from_rpc: {}", ln_fee_rate_root_from_rpc);
    immutables_request_timing.stop(timings);

    let bera_factory_address = Address::from_str("0x8A09574b0401A856d89d1b583eE22E8cb0C5530B")?;
    println!("pendle_router_address");
    let pendle_router_address = Address::from_str(PENDLE_ROUTER_V4)?;
    println!("pendle_router_address");

    let mut factory_overriden_fee_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: bera_factory_address,
        storage_slots: Vec::new(),
        block_number: storage_proving_config.block_number,
        input_tokens_amount: storage_proving_config.input_tokens_amount,
    };

    // forge inspect contracts/core/Market/v3/PendleMarketFactoryV3.sol:PendleMarketFactoryV3 storageLayout
    // | Name          | Type                                           | Slot |
    // | overriddenFee | mapping(address => mapping(address => uint80)) | 51   |
    let factory_overriden_fee_storage_slot_key = compute_overridden_fee_key(
        pendle_router_address.0,
        storage_proving_config.address.0,
        51,
    );

    factory_overriden_fee_proving_config.storage_slots =
        vec![B256::from(factory_overriden_fee_storage_slot_key)];

    let factory_overriden_fee_storage_slot = extract_storage_slots_with_merkle_proving(
        &factory_overriden_fee_proving_config,
        timings,
        total_timer_start,
        block_header,
    )?
    .proven_slots[0]
        .value_unhashed
        .0;

    // uint80 is last 10 bytes of 32byte slot
    let mut overridden_fee_bytes = [0u8; 32];
    overridden_fee_bytes[22..32].copy_from_slice(&factory_overriden_fee_storage_slot[22..32]);
    let overridden_fee_from_storage: U256 = U256::from_be_bytes(overridden_fee_bytes);
    tracing::debug!(
        "overridden_fee_from_storage = {}",
        overridden_fee_from_storage
    );

    // market.lnFeeRateRoot = overriddenFee == 0 ? lnFeeRateRoot : overriddenFee;
    let ln_rate_root_overriden = if overridden_fee_bytes == [0u8; 32] {
        ln_fee_rate_root_from_rpc
    } else {
        overridden_fee_from_storage
    };

    // in solidity market is constructed in PendleParketV3.readState,
    // but here we access storage in mod.rs, so I decided to construct market here
    // and pass it to swap_exact_pt_for_sy as imput
    let market: market_math_core::MarketState = market_math_core::MarketState {
        total_pt: I256::try_from(total_pt_from_storage).unwrap(),
        total_sy: I256::try_from(total_sy_from_storage).unwrap(),
        scalar_root: scalar_root_from_rpc,
        expiry: expiry_from_rpc,
        ln_fee_rate_root: ln_rate_root_overriden,
        last_ln_implied_rate: last_ln_inplied_rate_from_storage,
    };

    let yt_request_timing = Lap::new("yt_request_timing");
    let yt_address_and_index = get_yt_index(market_storage_proving_config)
        .map_err(|e| anyhow::anyhow!("YT.newIndex() request failed: {:?}", e))?;
    yt_request_timing.stop(timings);

    let exact_pt_in = storage_proving_config.input_tokens_amount;

    tracing::debug!("block_timestamp: {}", block_timestamp);

    let solidity_logic_execution_timing = Lap::new("solidity_logic_execution_timing");
    let exact_sy_out = market_math_core::swap_exact_pt_for_sy(
        market,
        yt_address_and_index.py_index_current,
        exact_pt_in,
        block_timestamp,
    )?;
    solidity_logic_execution_timing.stop(timings);

    tracing::info!(
        "storage_proving_config.block_number: {}",
        storage_proving_config.block_number
    );
    tracing::info!("exact_pt_in: {}", exact_pt_in);
    tracing::info!(
        "exact_pt_in / 10**18: {}",
        exact_pt_in / U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0])
    );
    tracing::info!("exact_sy_out: {}", exact_sy_out);
    tracing::info!(
        "exact_sy_out / 10**18: {}",
        exact_sy_out / I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0])
    );

    let output = PendleOutput {
        exact_pt_in,
        exact_sy_out,
        yt_address: yt_address_and_index.yt_address,
        yt_index: yt_address_and_index.py_index_current,
        scalar_root: immutables.scalar_root_from_rpc,
        expiry: immutables.expiry_from_rpc,
        ln_fee_rate_root: immutables.ln_fee_rate_root_from_rpc,
        block_timestamp: market_storage_storage_slots.block_timestamp,
        block_number: market_storage_storage_slots.block_number,
        block_hash: market_storage_storage_slots.block_hash,
    };

    Ok(output)
}
