mod attestation_data;
mod error;
pub(crate) mod eth;
mod timing;
mod trie;
mod utils;

use std::{collections::HashMap, ffi::CString, os::raw::c_char, str::FromStr};

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;

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

extern "C" {
    fn ocall_make_http_request(
        url: *const c_char,
        method: *const c_char,
        body: *const u8,
        body_len: usize,
        response: *mut c_char,
        max_response_len: usize,
        actual_response_len: *mut usize,
        http_status: *mut u16,
    );
}

fn make_http_request(url: &str, method: &str, body: &[u8]) -> anyhow::Result<String> {
    const MAX_RESPONSE_LEN: usize = 256 * 1024 * 4 * 4;
    let mut response_buffer = vec![0u8; MAX_RESPONSE_LEN];
    let mut actual_response_len: usize = 0;
    let mut http_status: u16 = 0;

    let url_cstring = CString::new(url)?;
    let method_cstring = CString::new(method)?;

    unsafe {
        ocall_make_http_request(
            url_cstring.as_ptr(),
            method_cstring.as_ptr(),
            body.as_ptr(),
            body.len(),
            response_buffer.as_mut_ptr() as *mut c_char,
            MAX_RESPONSE_LEN,
            &mut actual_response_len,
            &mut http_status,
        );
    }

    if http_status != 200 {
        return Err(anyhow::anyhow!(
            "HTTP request failed with status: {}",
            http_status
        ));
    }

    if actual_response_len == 0 {
        tracing::warn!("Empty response from HTTP request, but status was 200");
        return Ok(String::new());
    }

    let response_slice = &response_buffer[..actual_response_len];
    let response_str = String::from_utf8(response_slice.to_vec())?;
    Ok(response_str)
}

#[derive(serde::Serialize)]
struct TimingDebugOutput {
    error: String,
    timings: Timings,
}

#[derive(Parser, Debug, Clone)]
#[clap(
    author = "Diffuse",
    version = "v0.2",
    about = "ZK TLS Ethereum State Prover for specific contract message structure"
)]
struct ZkTlsProverCli {
    #[clap(
        long,
        short = 'u',
        env = "RPC_URL",
        help = "Ethereum RPC endpoint URL (e.g., https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY)"
    )]
    rpc_url: String,
    #[clap(
        long,
        short,
        env = "CONTRACT_ADDRESS",
        help = "Ethereum address of the target contract"
    )]
    address: String,
    #[clap(
        long,
        short = 's',
        help = "List of storage slots to prove (comma-separated, e.g., '0,1,2,3')"
    )]
    slots_to_prove: String,
    #[clap(
        long,
        short = 'B',
        default_value = "latest",
        help = "Block number (e.g., 'latest', '0x1234AB')"
    )]
    block_number: String,
}

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
fn compute_mapping_slot_key(key: i32, mapping_slot: u64) -> [u8; 32] {
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


fn position(tick: i32) -> (i32, u8) {
    let word_pos = (tick.div_euclid(256)) as i32;
    let bit_pos  = tick.rem_euclid(256) as u8;
    (word_pos, bit_pos)
}


fn is_tick_initialized(compressed_tick: i32, tick_bitmap_hashmap: &HashMap<i32, B256>) -> bool {
    let (word_pos, bit_pos) = position(compressed_tick);
    let tick_bitmap = tick_bitmap_hashmap.get(&word_pos);

    let byte_index: usize = (31 - (bit_pos / 8)).into();
    let bit_in_byte = bit_pos % 8;

    let b = tick_bitmap.unwrap().0[byte_index];
    let mask = 1 << bit_in_byte;
    b & mask != 0
}



#[no_mangle]
pub unsafe extern "C" fn simple_proving() -> SgxStatus {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let cli = ZkTlsProverCli::parse();
    tracing::info!(config = ?cli, "Starting proving process with configuration");

    let total_timer_start = std::time::Instant::now();
    let mut timings = Timings::default();

    println! ("REQUESTING SLOT0\n=========================================================\n");

    // request slot 0
    let my_slots = "0".to_string();
    // TODO rewrite to pass non string values
    let new_cli = ZkTlsProverCli {
        slots_to_prove: my_slots,
        ..cli.clone()
    };

    let attestation_payload: AttestationPayload = match extract_storage_slots_with_merkle_proving(new_cli, &mut timings, total_timer_start) {
        Ok(res) => res,
        Err(e) => {
            tracing::warn!(error = %e, "extract_storage_slots_with_merkle_proving error.");
            return SgxStatus::Unexpected;
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

    let bitmap_slotkeys = format!("0x{}, 0x{}", hex1, hex2);

    let bitmap_cli = ZkTlsProverCli {
        slots_to_prove: bitmap_slotkeys,
        ..cli.clone()
    };

    let bitmaps_storage_slots = match extract_storage_slots_with_merkle_proving(bitmap_cli, &mut timings, total_timer_start) {
        Ok(res) => res,
        Err(err) => {
            println! ("extract_storage_slots_with_merkle_proving error {}", err);
            return SgxStatus::Unexpected;
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


    let all_initialized_ticks_slotkeys = tick_slot_keys
        .iter()
        .map(|key| format!("0x{}", hex::encode(key)))
        .collect::<Vec<_>>()
        .join(", ");

    println!("all_initialized_ticks_slotkeys: {}", all_initialized_ticks_slotkeys);

    let initialized_ticks_cli = ZkTlsProverCli {
        slots_to_prove: all_initialized_ticks_slotkeys,
        ..cli.clone()
    };


    let initialized_ticks_storage_slots = match extract_storage_slots_with_merkle_proving(initialized_ticks_cli, &mut timings, total_timer_start) {
        Ok(res) => res,
        Err(err) => {
            println! ("extract_storage_slots_with_merkle_proving error {}", err);
            return SgxStatus::Unexpected;
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
            return SgxStatus::Unexpected;
        }
    };
    lap_report.stop(&mut timings);
    tracing::debug!(report_data_hex = %hex::encode(report_data), "Constructed report_data for DCAP quote");

    let lap4 = Lap::new("dcap_quote_generation");
    let quote_bytes = match automata_sgx_sdk::dcap::dcap_quote(report_data) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("DCAP quote generation failed: {:?}", e);
            return SgxStatus::Unexpected;
        }
    };

    lap4.stop(&mut timings);
    tracing::info!(
        quote_len = quote_bytes.len(),
        "DCAP quote generated successfully"
    );

    SgxStatus::Success

}

fn extract_storage_slots_with_merkle_proving(
    cli: ZkTlsProverCli,
    timings: &mut Timings,
    total_timer_start: std::time::Instant,
) -> anyhow::Result<AttestationPayload> {
    let contract_address = Address::from_str(&cli.address)
        .map_err(|e| anyhow::anyhow!("Invalid contract address format '{}': {}", cli.address, e))?;

    tracing::info!(rpc_url = %cli.rpc_url, %contract_address, block_tag = %cli.block_number, slots_to_prove = %cli.slots_to_prove, "Proving parameters");

    let target_slot_keys = parse_slots_to_prove(&cli.slots_to_prove)?;

    let lap1 = Lap::new("get_block_header");
    let block_header = get_block_header_from_rpc(&cli.rpc_url, &cli.block_number, timings)?;
    lap1.stop(timings);
    let block_number_val = block_header.number;

    let lap2 = Lap::new("get_proof");
    let proof_response = get_proof_from_rpc(
        &cli.rpc_url,
        contract_address,
        &target_slot_keys,
        block_number_val,
        timings,
    )?;
    lap2.stop(timings);
    let lap3 = Lap::new("verify_mpt_proof");
    let verified_slot_values =
        verify_proof(proof_response, block_header.state_root.as_ref(), timings)
            .map_err(|e| anyhow::anyhow!("MPT proof verification failed: {:?}", e))?;
    lap3.stop(timings);
    tracing::info!("MPT proof verification successful");

    let lap_processing = Lap::new("slot_processing");
    let mut processed_semantic_values: HashMap<B256, [u8; 32]> = HashMap::new();
    let mut non_existent_slots: Vec<B256> = Vec::new();

    for (proved_key, opt_mpt_value) in verified_slot_values {
        if let Some(mpt_value_bytes) = opt_mpt_value {
            tracing::debug!(slot_key = ?proved_key, value_bytes_len = mpt_value_bytes.len(), value_hex = %hex::encode(&mpt_value_bytes), "Slot has value from MPT");
            match get_semantic_u256_bytes(&mpt_value_bytes) {
                Ok(semantic_bytes) => {
                    let is_zero = semantic_bytes == [0u8; 32];
                    tracing::debug!(slot_key = ?proved_key, semantic_hex = %hex::encode(&semantic_bytes), is_zero = is_zero, "Processed semantic bytes");

                    // check if this is actually a zero value that should be considered non-existent
                    if is_zero && mpt_value_bytes.is_empty() {
                        tracing::info!(slot_key = ?proved_key, "Slot has empty MPT value, treating as non-existent. Excluding from attestation.");
                        non_existent_slots.push(proved_key);
                    } else {
                        processed_semantic_values.insert(proved_key, semantic_bytes);
                    }
                }
                Err(e) => {
                    tracing::warn!(slot_key = ?proved_key, error = %e, "Failed to get semantic uint256 bytes for slot. It will be excluded from attestation if it was a target slot.");
                }
            }
        } else {
            // non-existent storage slots are excluded from final attestation
            tracing::info!(slot_key = ?proved_key, "Slot proven but does not exist (None). Excluding from attestation.");
            non_existent_slots.push(proved_key);
        }
    }
    lap_processing.stop(timings);

    if !non_existent_slots.is_empty() {
        let non_existent_json = serde_json::json!({
            "non_existent_slots": non_existent_slots.iter().map(|slot| format!("0x{}", hex::encode(slot.as_ref()))).collect::<Vec<_>>(),
            "count": non_existent_slots.len(),
            "message": "These slots do not exist and are excluded from the final attestation"
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&non_existent_json)
                .unwrap_or_else(|_| "Failed to serialize non-existent slots".to_string())
        );
    }

    let mut attested_slots_data: Vec<SlotProofData> = Vec::with_capacity(target_slot_keys.len());

    // only include slots that actually exist
    for target_slot_key in target_slot_keys.iter() {
        if let Some(semantic_bytes) = processed_semantic_values.get(target_slot_key) {
            attested_slots_data.push(SlotProofData {
                slot_key: *target_slot_key,
                value_hash: keccak256(semantic_bytes).into(),
                value_unhashed: (*semantic_bytes).into(),
            });
        }
    }

    tracing::info!(
        count = attested_slots_data.len(),
        "Slots prepared for attestation payload"
    );

    timings.total_ms = total_timer_start.elapsed().as_secs_f64() * 1000.0;

    Ok (AttestationPayload {
        block_hash: block_header.hash(),
        block_number: block_number_val,
        proven_slots: attested_slots_data,
    })

}

fn get_block_header_from_rpc(
    rpc_url: &str,
    block_tag: &str,
    timings: &mut Timings,
) -> anyhow::Result<Header> {
    tracing::info!(block_tag, "Fetching block header");

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [block_tag, false],
        "id": 1
    })
    .to_string();

    let lap_tls = Lap::new("get_block_header::http_request");
    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("HTTP request for block header failed: {:?}", e))?;
    lap_tls.stop(timings);

    tracing::debug!(
        response_body_len = response_str.len(),
        "Received block header response body"
    );

    let lap_parse = Lap::new("get_block_header::json_parsing");
    let rpc_block_response: RpcResponse<Block> = serde_json::from_str(&response_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse block header RPC response: {}", e))?;
    lap_parse.stop(timings);

    let header = rpc_block_response.result.header;
    let rpc_block_hash = header.block_hash_untrusted;
    let calculated_block_hash = header.hash();

    if calculated_block_hash != rpc_block_hash {
        anyhow::bail!(
            "Block hash mismatch. Calculated: {:?}, RPC provided: {:?}",
            calculated_block_hash,
            rpc_block_hash
        );
    }
    tracing::info!(block_hash = ?calculated_block_hash, block_number = header.number, "Block header verified");
    Ok(header)
}

fn get_proof_from_rpc(
    rpc_url: &str,
    contract_address: Address,
    slot_keys: &[B256],
    block_number: u64,
    timings: &mut Timings,
) -> anyhow::Result<ProofResponse> {
    let slot_keys_hex: Vec<String> = slot_keys
        .iter()
        .map(|key| format!("0x{}", hex::encode(key.as_ref())))
        .collect();

    tracing::info!(%contract_address, block_number, "Fetching proof");

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_getProof",
        "params": [
            format!("0x{}", hex::encode(contract_address.as_ref())),
            slot_keys_hex,
            format!("0x{:x}", block_number)
        ],
        "id": 1
    })
    .to_string();

    let lap_tls = Lap::new("get_proof::http_request");
    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("HTTP request for proof failed: {:?}", e))?;
    lap_tls.stop(timings);

    tracing::debug!(
        response_body_len = response_str.len(),
        "Received proof response body"
    );

    let lap_parse = Lap::new("get_proof::json_parsing");
    let rpc_proof_response: RpcResponse<ProofResponse> = serde_json::from_str(&response_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse proof RPC response: {}", e))?;
    lap_parse.stop(timings);

    tracing::info!("Proof received successfully");
    Ok(rpc_proof_response.result)
}
