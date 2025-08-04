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



/*
forge inspect contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 storageLayout
╭-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------╮
| Name              | Type                                                                            | Slot | Offset | Bytes   | Contract                                                   |
+============================================================================================================================================================================================+
| _balances         | mapping(address => uint256)                                                     | 0    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| _allowances       | mapping(address => mapping(address => uint256))                                 | 1    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| _totalSupply      | uint248                                                                         | 2    | 0      | 31      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| _status           | uint8                                                                           | 2    | 31     | 1       | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| _name             | string                                                                          | 3    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| _symbol           | string                                                                          | 4    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| userReward        | mapping(address => mapping(address => struct RewardManagerAbstract.UserReward)) | 5    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| lastRewardBlock   | uint256                                                                         | 6    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| rewardState       | mapping(address => struct RewardManagerAbstract.RewardState)                    | 7    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| totalActiveSupply | uint256                                                                         | 8    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| activeBalance     | mapping(address => uint256)                                                     | 9    | 0      | 32      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| _storage          | struct PendleMarketV3.MarketStorage                                             | 10   | 0      | 64      | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
|-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------|
| observations      | struct OracleLib.Observation[65535]                                             | 12   | 0      | 2097120 | contracts/core/Market/v3/PendleMarketV3.sol:PendleMarketV3 |
╰-------------------+---------------------------------------------------------------------------------+------+--------+---------+------------------------------------------------------------╯
 */



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


    return true;
}
