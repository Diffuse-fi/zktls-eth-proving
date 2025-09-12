use crate::eth::aliases::{Address, U256};
use anyhow::{anyhow, Result};
use ruint::Uint;
use serde_json::Value;
use crate::utils::make_http_request;

#[derive(Debug, Clone)]
pub enum CollateralType {
    USDC = 0,
    PT = 1,
}
#[derive(Debug, Clone)]
pub struct BorrowerPosition {
    pub user: Address,
    pub collateral_type: CollateralType,
    pub subject_to_liquidation: bool,
    pub strategy_id: U256,
    pub assets_borrowed: U256,
    pub collateral_given: U256,
    pub leverage: U256,
    pub strategy_balance: U256,
    pub id: U256,
    pub enter_time_or_deadline: u64,
    pub block_number: u64,
    pub liquidation_price: U256,
}

#[derive(Debug, Clone)]
pub struct StrategyData {
    pub addr: Address,
    pub is_set_up: bool,
    pub end_date: u64,
    pub borrow_apr: u64,
    pub balance: u64,
    pub assets: u64,
    pub name: String,
    pub pool: Address,
}

fn decode_u256_from_hex(hex_str: &str) -> Result<U256> {
    let bytes = hex::decode(hex_str)?;

    if bytes.len() != 32 {
        return Err(anyhow!("Invalid U256 hex string length: expected 32 bytes, got {}", bytes.len()));
    }

    let mut byte_array = [0u8; 32];
    byte_array.copy_from_slice(&bytes);

    let uint = Uint::<256, 4>::from_be_bytes(byte_array);
    Ok(U256(uint))
}

fn get_borrower_position_from_rpc(
    rpc_url: &str,
    vault_address: Address,
    position_id: u64,
    block_number: Option<u64>,
) -> Result<BorrowerPosition> {
    // function selector for getBorrowerPosition(uint256) = 0x9177db0a
    let function_selector = "0x9177db0a";
    let position_id_hex = format!("{:064x}", position_id);
    let calldata = format!("{}{}", function_selector, position_id_hex);

    let block_param = match block_number {
        Some(num) => format!("0x{:x}", num),
        None => "latest".to_string(),
    };

    let rpc_payload = serde_json::json!({
          "jsonrpc": "2.0",
          "method": "eth_call",
          "params": [{
              "to": format!("0x{}", hex::encode(vault_address.as_ref())),
              "data": calldata
          }, block_param],
          "id": 1
      })
        .to_string();

    tracing::info!(%vault_address, position_id, "Fetching borrower position");

    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow!("HTTP request for borrower position failed: {:?}", e))?;

    let rpc_response: Value = serde_json::from_str(&response_str)
        .map_err(|e| anyhow!("Failed to parse borrower position RPC response: {}", e))?;

    if let Some(error) = rpc_response.get("error") {
        return Err(anyhow!(
            "RPC call failed: {} (code: {}), data: {}",
            error.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error"),
            error.get("code").and_then(|v| v.as_i64()).unwrap_or(-1),
            error.get("data").and_then(|v| v.as_str()).unwrap_or("No data")
        ));
    }

    let result_hex = rpc_response["result"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing result in RPC response"))?;

    let result_hex = result_hex.strip_prefix("0x").unwrap_or(result_hex);

    if result_hex.len() < 64 * 12 {
        return Err(anyhow!("Response too short for BorrowerPosition struct"));
    }

    let mut offset = 0;

    let user_hex = &result_hex[offset + 24..offset + 64];
    let user_bytes = hex::decode(user_hex)?;
    let mut user_array = [0u8; 20];
    user_array.copy_from_slice(&user_bytes);
    let user = Address::from(user_array);
    offset += 64;

    let collateral_type_val = u8::from_str_radix(&result_hex[offset + 62..offset + 64], 16)?;
    let collateral_type = match collateral_type_val {
        0 => CollateralType::USDC,
        1 => CollateralType::PT,
        _ => return Err(anyhow!("Invalid collateral type: {}", collateral_type_val)),
    };
    offset += 64;

    let subject_to_liquidation = &result_hex[offset + 63..offset + 64] != "0";
    offset += 64;

    let strategy_id = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    offset += 64;

    let assets_borrowed = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    offset += 64;


    let collateral_given = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    offset += 64;

    let leverage = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    offset += 64;

    let strategy_balance = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    offset += 64;

    let id = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    offset += 64;

    let enter_time_or_deadline = u64::from_str_radix(&result_hex[offset + 54..offset + 64], 16)?;
    offset += 64;

    let block_number = u64::from_str_radix(&result_hex[offset + 54..offset + 64], 16)?;
    offset += 64;

    let liquidation_price = decode_u256_from_hex(&result_hex[offset..offset + 64])?;

    Ok(BorrowerPosition {
        user,
        collateral_type,
        subject_to_liquidation,
        strategy_id,
        assets_borrowed,
        collateral_given,
        leverage,
        strategy_balance,
        id,
        enter_time_or_deadline,
        block_number,
        liquidation_price,
    })
}

fn get_strategy_from_rpc(
    rpc_url: &str,
    vault_address: Address,
    strategy_id: U256,
    block_number: Option<u64>,
) -> Result<StrategyData> {
    // Function selector for getStrategy(uint256) = 0xcfc0cc34
    let function_selector = "0xcfc0cc34";
    let strategy_id_bytes: [u8; 32] = strategy_id.0.to_be_bytes();
    let strategy_id_hex = hex::encode(strategy_id_bytes);
    let calldata = format!("{}{}", function_selector, strategy_id_hex);

    let block_param = match block_number {
        Some(num) => format!("0x{:x}", num),
        None => "latest".to_string(),
    };

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{
            "to": format!("0x{}", hex::encode(vault_address.as_ref())),
            "data": calldata
        }, block_param],
        "id": 1
    })
        .to_string();

    tracing::info!(%vault_address, ?strategy_id, "Fetching strategy data");

    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow!("HTTP request for strategy failed: {:?}", e))?;

    let rpc_response: Value = serde_json::from_str(&response_str)
        .map_err(|e| anyhow!("Failed to parse strategy RPC response: {}", e))?;

    if let Some(error) = rpc_response.get("error") {
        return Err(anyhow!(
            "RPC call failed: {} (code: {}), data: {}",
            error.get("message").and_then(|v| v.as_str()).unwrap_or("Unknown error"),
            error.get("code").and_then(|v| v.as_i64()).unwrap_or(-1),
            error.get("data").and_then(|v| v.as_str()).unwrap_or("No data")
        ));
    }

    let result_hex = rpc_response["result"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing result in RPC response"))?;

    let result_hex = result_hex.strip_prefix("0x").unwrap_or(result_hex);

    let mut offset = 64;

    if result_hex.len() < 64 + (64 * 9) {
        return Err(anyhow!("Response too short for StrategyData struct"));
    }

    let addr_hex = &result_hex[offset + 24..offset + 64];
    let addr_bytes = hex::decode(addr_hex)?;
    let mut addr_array = [0u8; 20];
    addr_array.copy_from_slice(&addr_bytes);
    let addr = Address::from(addr_array);
    offset += 64;

    let is_set_up = &result_hex[offset + 63..offset + 64] != "0";
    offset += 64;

    let _is_disabled = &result_hex[offset + 63..offset + 64] != "0";
    offset += 64;

    let end_date = u64::from_str_radix(&result_hex[offset + 54..offset + 64], 16)?;
    offset += 64;

    let borrow_apr = u64::from_str_radix(&result_hex[offset + 54..offset + 64], 16)?;
    offset += 64;

    let balance_u256 = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    println!("DEBUG: balance_u256 = {:?}", balance_u256);

    let balance = match balance_u256.to_u64() {
        Some(val) => val,
        None => {
            println!("ERROR: Balance too large: {:?}", balance_u256);
            return Err(anyhow!("Balance value too large for u64: {:?}", balance_u256));
        }
    };
    offset += 64;

    let assets_u256 = decode_u256_from_hex(&result_hex[offset..offset + 64])?;
    println!("DEBUG: assets_u256 = {:?}", assets_u256);

    let assets = match assets_u256.to_u64() {
        Some(val) => val,
        None => {
            println!("ERROR: Assets too large: {:?}", assets_u256);
            return Err(anyhow!("Assets value too large for u64: {:?}", assets_u256));
        }
    };
    offset += 64;

    println!("here");
    let string_offset = usize::from_str_radix(&result_hex[offset..offset + 64], 16)?;
    offset += 64;

    let pool_hex = &result_hex[offset + 24..offset + 64];
    let pool_bytes = hex::decode(pool_hex)?;
    let mut pool_array = [0u8; 20];
    pool_array.copy_from_slice(&pool_bytes);
    let pool = Address::from(pool_array);

    println!("pool: {}", pool);
    let name = if string_offset > 0 && result_hex.len() > string_offset * 2 {
        let string_data_start = string_offset * 2;

        println!("DEBUG: String offset: {}, String data start position: {}", string_offset, string_data_start);
        println!("DEBUG: Result hex length: {}", result_hex.len());

        if result_hex.len() >= string_data_start + 64 {
            let string_length_hex = &result_hex[string_data_start..string_data_start + 64];
            println!("DEBUG: String length hex: {}", string_length_hex);

            match usize::from_str_radix(string_length_hex, 16) {
                Ok(string_length) if string_length < 10000 => {
                    println!("DEBUG: String length: {}", string_length);

                    let string_hex_start = string_data_start + 64;
                    let string_hex_end = string_hex_start + (string_length * 2);

                    if result_hex.len() >= string_hex_end {
                        let string_bytes = hex::decode(&result_hex[string_hex_start..string_hex_end])?;
                        String::from_utf8(string_bytes).unwrap_or_else(|_| String::new())
                    } else {
                        println!("WARN: String data extends beyond hex length");
                        String::new()
                    }
                }
                Ok(string_length) => {
                    println!("ERROR: String length too large: {}", string_length);
                    String::new()
                }
                Err(e) => {
                    println!("ERROR: Failed to parse string length: {}", e);
                    String::new()
                }
            }
        } else {
            println!("WARN: Not enough data for string length field");
            String::new()
        }
    } else {
        println!("DEBUG: String offset is 0 or insufficient data");
        String::new()
    };

    Ok(StrategyData {
        addr,
        is_set_up,
        end_date,
        borrow_apr,
        balance,
        assets,
        name,
        pool,
    })
}

pub fn get_pending_borrow_request_data(
    rpc_url: &str,
    vault_address: Address,
    position_id: u64,
    block_number: Option<u64>,
) -> Result<(u64, Address)> {
    // 1. get borrower position
    let position = get_borrower_position_from_rpc(rpc_url, vault_address, position_id, block_number)?;

    println!("position_id = {}", position_id);

    println!("strategy id: {:?}", position.strategy_id);
    println!("strategy id: 0x{}", hex::encode(position.strategy_id.0.to_be_bytes::<32>()));

    println!("position: {:?}", position);

    // 2. get strategy data
    let strategy = get_strategy_from_rpc(rpc_url, vault_address, position.strategy_id, block_number)?;

    println!("strategy: {:?}", strategy);

    // You'll also need to convert these U256 values to u64 if you want to return them
    let collateral_given = position.collateral_given.to_u64()
        .ok_or_else(|| anyhow!("Collateral given too large for u64"))?;

    Ok((collateral_given, strategy.pool))
}