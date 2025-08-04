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


#[derive(Debug)]
pub struct Slot0 { // https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L56
    pub sqrt_price_x96: [u8; 20],
    pub tick: i32,
    pub observation_index: u16,
    pub observation_cardinality: u16,
    pub observation_cardinality_next: u16,
    pub fee_protocol: u8,
    pub unlocked: bool,
}

impl Slot0 { // deserialize raw storage slot to struct
    pub fn from_bytes(raw: &[u8; 32]) -> Self {
        let mut sqrt_price_x96 = [0u8; 20];
        sqrt_price_x96.copy_from_slice(&raw[12..32]);

        let tick_bytes = &raw[9..12];
        let mut buf32 = [0u8; 4];
        buf32[0] = if tick_bytes[0] & 0x80 != 0 { 0xFF } else { 0x00 };
        buf32[1..4].copy_from_slice(tick_bytes);
        let tick = i32::from_be_bytes(buf32);

        let mut buf16 = [0u8; 2];
        buf16.copy_from_slice(&raw[7..9]);
        let observation_index = u16::from_be_bytes(buf16);

        buf16.copy_from_slice(&raw[5..7]);
        let observation_cardinality = u16::from_be_bytes(buf16);

        buf16.copy_from_slice(&raw[3..5]);
        let observation_cardinality_next = u16::from_be_bytes(buf16);

        let fee_protocol = raw[2];

        let unlocked = raw[1] != 0;

        Slot0 {
            sqrt_price_x96,
            tick,
            observation_index,
            observation_cardinality,
            observation_cardinality_next,
            fee_protocol,
            unlocked,
        }
    }
}


// keccak(abiEncoded(key, mappingSlot))
pub fn compute_mapping_slot_key(key: i32, mapping_slot: u64) -> [u8; 32] {
    let mut buffer = [0u8; 64];

    // i16: first 28 bytes are sign, next 4 are i16 value itself
    let sign_byte = if key < 0 { 0xFF } else { 0x00 };
    for byte in &mut buffer[0..28] {
        *byte = sign_byte;
    }
    let [highest, hi, lo, lowest] = key.to_be_bytes();
    buffer[28] = highest;
    buffer[29] = hi;
    buffer[30] = lo;
    buffer[31] = lowest;

    // uint256: 24 zero bytes, next 8 bytes u64
    let slot_bytes = mapping_slot.to_be_bytes();
    buffer[32 + (32 - 8)..64].copy_from_slice(&slot_bytes);

    tracing::debug!(abi_encoded = %hex::encode(buffer), "abi encoded values for mapping slot key calculation");

    keccak256(&buffer)
}


pub fn position(tick: i32) -> (i32, u8) {
    let word_pos = (tick.div_euclid(256)) as i32;
    let bit_pos  = tick.rem_euclid(256) as u8;
    (word_pos, bit_pos)
}


pub fn is_tick_initialized(compressed_tick: i32, tick_bitmap_hashmap: &HashMap<i32, B256>) -> bool {
    let (word_pos, bit_pos) = position(compressed_tick);
    let tick_bitmap = tick_bitmap_hashmap.get(&word_pos);

    let byte_index: usize = (31 - (bit_pos / 8)).into();
    let bit_in_byte = bit_pos % 8;

    let b = tick_bitmap.unwrap().0[byte_index];
    let mask = 1 << bit_in_byte;
    b & mask != 0
}

pub fn uniswap3_logic(
    storage_proving_config: utils::StorageProvingConfig,
    timings: &mut Timings,
    total_timer_start: std::time::Instant,
// ) -> Result<> {
) -> bool { // TODO fugure out what to return from here
        println! ("REQUESTING SLOT0\n=========================================================\n");

    // request slot 0
    let new_storage_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: storage_proving_config.address.clone(),
        storage_slots: vec![eth::primitives::FixedBytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])],
        block_number: storage_proving_config.block_number.clone(),
    };

    let attestation_payload: AttestationPayload = match extract_storage_slots_with_merkle_proving(new_storage_proving_config, timings, total_timer_start) {
        Ok(res) => res,
        Err(e) => {
            tracing::warn!(error = %e, "extract_storage_slots_with_merkle_proving error.");
            return false;
        }
    };
    let proofs: &Vec<SlotProofData> = &attestation_payload.proven_slots;
    let slot = &proofs[0];

    tracing::info!(slot.value_unhashed = %hex::encode(slot.value_unhashed), "Slot 0 unhashed value");

    let raw_bytes: &[u8; 32] = &slot.value_unhashed.0;
    let slot0 = Slot0::from_bytes(raw_bytes);

    tracing::info!(slot0.tick = slot0.tick, "Current tick");

    println! ("\n=========================================================\nREQUESTING TICK BITMAPS\n=========================================================\n");

    // TODO ugly hardcoded code
    let key_bitmap_neg1_slotkey = compute_mapping_slot_key(-1, 6);
    let key_bitmap_zero_slotkey = compute_mapping_slot_key(0, 6);



    let hex1 = hex::encode(key_bitmap_neg1_slotkey);
    let hex2 = hex::encode(key_bitmap_zero_slotkey);


    let bitmaps_slots_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: storage_proving_config.address.clone(),
        storage_slots: vec![
            eth::primitives::FixedBytes(key_bitmap_neg1_slotkey),
            eth::primitives::FixedBytes(key_bitmap_zero_slotkey)
        ],
        block_number: storage_proving_config.block_number.clone(),
    };


    let bitmaps_storage_slots = match extract_storage_slots_with_merkle_proving(bitmaps_slots_proving_config, timings, total_timer_start) {
        Ok(res) => res,
        Err(err) => {
            println! ("extract_storage_slots_with_merkle_proving error {}", err);
            return false;
        }
    };

    let mut tick_bitmaps_hashmap: HashMap<i32, B256> = HashMap::new();
    tick_bitmaps_hashmap.insert(-1, bitmaps_storage_slots.proven_slots[0].value_unhashed);
    tick_bitmaps_hashmap.insert(0, bitmaps_storage_slots.proven_slots[1].value_unhashed);


    // TODO figure out how to print it in the tracing
    // println! ("bitmaps_storage_slots.proven_slots[0].value_unhashed: {}", bitmaps_storage_slots.proven_slots[0].value_unhashed);
    // println! ("bitmaps_storage_slots.proven_slots[1].value_unhashed: {}", bitmaps_storage_slots.proven_slots[1].value_unhashed);

    let mut curr_tick = slot0.tick + 1;
    curr_tick += 1; // TODO this stuff with euclid
    let mut next_tick = curr_tick;

    let mut initialized_ticks: Vec<i32> = Vec::new();
    // TODO: skipping current range
    // initialized_ticks.push(curr_tick);

    while next_tick < 256 {
        curr_tick = next_tick;

        while next_tick < 256 && !is_tick_initialized(next_tick, &tick_bitmaps_hashmap) {
            next_tick += 1;
        }

        if next_tick >= 256 {
            break;
        }
        next_tick += 1;
        initialized_ticks.push(curr_tick - 1); // TODO: have no idea why I have to add -1 here, but curr_tick were uninitialized
        // maybe this stuff with euclid is wrong

        println! ("range: {} - {}", curr_tick, next_tick);
    }

    let mut tick_slot_keys: Vec<[u8;32]> = Vec::new();
    for initialized_tick in &initialized_ticks {
        let slot_key = compute_mapping_slot_key(*initialized_tick, 5/*ticks slot*/);
        println! ("initialized_tick {}, slot_key: {}", initialized_tick, hex::encode(slot_key));

        tick_slot_keys.push(slot_key);
    }

    tick_slot_keys.push([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4]); // current liquidity as last element


    let tick_slot_keys_fixedbytes: Vec<eth::primitives::FixedBytes<32>> = tick_slot_keys
        .into_iter()
        .map(|slot| eth::primitives::FixedBytes::<32>(slot))
        .collect();


    let initialized_ticks_proving_config = StorageProvingConfig {
        rpc_url: storage_proving_config.rpc_url.clone(),
        address: storage_proving_config.address.clone(),
        storage_slots: tick_slot_keys_fixedbytes,
        block_number: storage_proving_config.block_number.clone(),
    };


    let initialized_ticks_storage_slots = match extract_storage_slots_with_merkle_proving(initialized_ticks_proving_config, timings, total_timer_start) {
        Ok(res) => res,
        Err(err) => {
            println! ("extract_storage_slots_with_merkle_proving error {}", err);
            return false;
        }
    };

    let curr_liquidity_fixedbytes = initialized_ticks_storage_slots.proven_slots.last().expect("proven_slots is empty").value_unhashed;
    let mut net_bytes = [0u8; 16];
    net_bytes.copy_from_slice(&curr_liquidity_fixedbytes.0[16..32]);
    let mut curr_liquidity: i128 = i128::from_be_bytes(net_bytes);
    println! ("curr liquidity: {}", curr_liquidity);

    for (i, tick) in initialized_ticks.iter().enumerate() {
        println!("{}: {:?}", i, tick);
        println! ("initialized_ticks_storage_slots.proven_slots[i].value_unhashed: {}", initialized_ticks_storage_slots.proven_slots[i].value_unhashed);

        let raw: [u8; 32] = initialized_ticks_storage_slots.proven_slots[i].value_unhashed.0;
        // int128 liquidityNet is first 16 bytes
        let mut net_bytes = [0u8; 16];
        net_bytes.copy_from_slice(&raw[0..16]);
        let liquidity_net: i128 = i128::from_be_bytes(net_bytes);
        println!("liquidityNet = {}", liquidity_net);
        curr_liquidity += liquidity_net;
        println!("curr_liquidity = {}", curr_liquidity);

    }


    let lap_report = Lap::new("construct_report_data");

    let report_data: [u8; 64] = match construct_report_data(&attestation_payload) {
        Ok(res) => {
            res
        }
        Err(err) =>
        {
            println!("construct_report_data failed: {}", err);
            return false;
        }
    };
    lap_report.stop(timings);
    tracing::debug!(report_data_hex = %hex::encode(report_data), "Constructed report_data for DCAP quote");

    let lap4 = Lap::new("dcap_quote_generation");
    let quote_bytes = match automata_sgx_sdk::dcap::dcap_quote(report_data) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("DCAP quote generation failed: {:?}", e);
            return false;
        }
    };

    lap4.stop(timings);
    tracing::info!(
        quote_len = quote_bytes.len(),
        "DCAP quote generated successfully"
    );

    return true;
}
