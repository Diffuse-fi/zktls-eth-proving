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
        RpcResponse,
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

