// implements structs and functions from PendleMarketV3.sol
// https://github.com/pendle-finance/pendle-core-v2-public/blob/135d57209390e180f593220631df2b55f1352f8d/contracts/core/Market/v3/PendleMarketV3.sol

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



//     ///     /**
//      * @notice Pendle Market allows swaps between PT & SY it is holding. This function
//      * aims to swap an exact amount of PT to SY.
//      * @dev steps working of this contract
//        - The outcome amount of SY will be precomputed by MarketMathLib
//        - Release the calculated amount of SY to receiver
//        - Callback to msg.sender if data.length > 0
//        - Ensure exactPtIn amount of PT has been transferred to this address
//      * @dev will revert if PT is expired
//      * @param data bytes data to be sent in the callback (if any)
//      */
pub fn swapExactPtForSy(
    exactPtIn: B256,
    market: MarketState,
    block_timestamp: B256,
) -> B256 {
    let netSyOut: B256 = market_math_core::swap_exact_pt_for_sy(
            YT.newIndex(),
            exactPtIn,
            block.timestamp,
        );


    return true;
}
