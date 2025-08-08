mod market_math_core;
mod pendle_market_v3;

use crate::utils;
use crate::eth;
use crate::timing;

use std::{collections::HashMap, ffi::CString, os::raw::c_char, str::FromStr};

use crate::{
    attestation_data::{AttestationPayload, ProvingResultOutput, SlotProofData},
    eth::{
        block::Block,
        header::Header,
        primitives::{Address, B256},
        proof::ProofResponse,
    },
    timing::{Lap, Timings},
    trie::verify_proof,
    utils::{
        construct_report_data, get_semantic_u256_bytes, keccak256, parse_slots_to_prove,
        extract_storage_slots_with_merkle_proving,
        RpcResponse,
        StorageProvingConfig,
    },
};






pub fn pendle_logic(
    storage_proving_config: utils::StorageProvingConfig,
    timings: &mut Timings,
    total_timer_start: std::time::Instant,
// ) -> Result<> {
) -> bool { // TODO fugure out what to return from here

    // looks like there will be requests form three storages: market, router, pendleERC20:
    // https://github.com/pendle-finance/pendle-core-v2-public/blob/6ca87b6e5a823d603cb8f66f983f5bc63b53218a/contracts/core/Market/v3/PendleMarketV3.sol#L278-L285
    // let's start with info only from market contract, it's the majority of the requested variables



    let market_storage_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: storage_proving_config.address.clone(),
        storage_slots: vec![
            eth::primitives::FixedBytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10]),
            eth::primitives::FixedBytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,11]),
        ],
        block_number: storage_proving_config.block_number.clone(),
    };


    let market_storage_storage_slots = match extract_storage_slots_with_merkle_proving(market_storage_proving_config, timings, total_timer_start) {
        Ok(res) => res,
        Err(err) => {
            println! ("extract_storage_slots_with_merkle_proving error {}", err);
            return false;
        }
    };

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

    // println!("Pendle contract storage slot 10: {}", market_storage_hashmap.get(&10));

    let raw_slot_10: [u8; 32] = match market_storage_hashmap.get(&10) {
        Some(bytes_ref) => (*bytes_ref).0,
        None => {
            println!("error: slot 10 not found");
            return false;
        }
    };

    // int128 totalPt is first 16 bytes
    let mut pt_bytes = [0u8; 16];
    pt_bytes.copy_from_slice(&raw_slot_10[16..32]);
    let total_pt_from_storage: i128 = i128::from_be_bytes(pt_bytes);
    println!("total_pt_from_storage = {}", total_pt_from_storage);

    // int128 totalSy is next 16 bytes
    let mut sy_bytes = [0u8; 16];
    sy_bytes.copy_from_slice(&raw_slot_10[0..16]);
    let total_sy_from_storage: i128 = i128::from_be_bytes(sy_bytes);
    println!("total_sy_from_storage = {}", total_sy_from_storage);


    let raw_slot_11: [u8; 32] = match market_storage_hashmap.get(&11) {
        Some(bytes_ref) => (*bytes_ref).0,
        None => {
            println!("error: slot 11 not found");
            return false;
        }
    };

    println! ("raw_slot_10: {}", hex::encode(raw_slot_10));
    println! ("raw_slot_11: {}", hex::encode(raw_slot_11));

    // uint96 lastLnImpliedRate is first 12 bytes
    let mut ln_rate_bytes = [0u8; 16];
    ln_rate_bytes[4..16].copy_from_slice(&raw_slot_11[32-12..32]);
    let ln_rate_from_storage: i128 = i128::from_be_bytes(ln_rate_bytes);
    println!("ln_rate_from_storage = {}", ln_rate_from_storage);

    // uint16 observationIndex is next 2 bytes
    let mut obs_index_bytes = [0u8; 16];
    obs_index_bytes[14..16].copy_from_slice(&raw_slot_11[32-12-2..32-12]);
    let obs_index_from_storage: i128 = i128::from_be_bytes(obs_index_bytes);
    println!("obs_index_from_storage = {}", obs_index_from_storage);

    // uint16 observationCardinality is next 2 bytes
    let mut obs_card_bytes = [0u8; 16];
    obs_card_bytes[14..16].copy_from_slice(&raw_slot_11[32-12-2-2..32-12-2]);
    let obs_card_from_storage: i128 = i128::from_be_bytes(obs_card_bytes);
    println!("obs_card_from_storage = {}", obs_card_from_storage);

    // uint16 observationCardinalityNext is next 2 bytes
    let mut obs_card_next_bytes = [0u8; 16];
    obs_card_next_bytes[14..16].copy_from_slice(&raw_slot_11[32-12-2-2-2..32-12-2-2]);
    let obs_card_next_from_storage: i128 = i128::from_be_bytes(obs_card_next_bytes);
    println!("obs_card_next_from_storage = {}", obs_card_next_from_storage);

    // in solidity market is constructed in PendleParketV3.readState,
    // but here we access storage in mod.rs, so I decided to construct market here
    // and pass it to swap_exact_pt_for_sy as imput
    let market: market_math_core::MarketState = market_math_core::MarketState {
        total_pt: total_pt_from_storage,
        total_sy: total_sy_from_storage,
        scalar_root: 0, // TODO immutable from contract code
        expiry: 0, // TODO immutable from contract code
        ln_fee_rate_root: 0, // TODO immutable or from other contract's (factory) storage IPMarketFactoryV3(factory).getMarketConfig(address(this),router);
        reserve_fee_percent: 0, // TODO: from other contract's (factory) storage IPMarketFactoryV3(factory).getMarketConfig(address(this),router);
        last_ln_implied_rate: ln_rate_from_storage,
    };

    let block_timestamp = 0; // TODO extract bock timestamp

    let exact_pt_in: B256 = 0;
    let index = 0;

    let exact_sy_out = market_math_core::swap_exact_pt_for_sy(
        market,
        index,
        exact_pt_in,
        block_timestamp
    );


    let price = exact_sy_out / exact_pt_in;

    return true;
}
