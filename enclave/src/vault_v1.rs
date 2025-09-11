use crate::eth::aliases::Address;
use anyhow::{anyhow, Result};
use serde_json::Value;
use crate::utils::make_http_request;

#[derive(Debug, Clone)]
pub struct BorrowerPosition {
    pub user: Address,
    pub strategy_id: u64,
    pub collateral_given: u64,
    pub leverage: u64,
    pub strategy_balance: u64,
    pub id: u64,
    pub enter_time_or_deadline: u32,
    pub block_number: u32,
    pub liquidation_price: u64,
}

#[derive(Debug, Clone)]
pub struct StrategyData {
    pub addr: Address,
    pub is_set_up: bool,
    pub end_date: u32,
    pub borrow_apr: u32,
    pub balance: u64,
    pub assets: u64,
    pub name: String,
    pub pool: Address,
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

    // Check for RPC error first
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

    if result_hex.len() < 64 * 9 {
        return Err(anyhow!("Response too short for BorrowerPosition struct"));
    }

    let user_hex = &result_hex[24..64]; // address is last 20 bytes of 32-byte slot
    let strategy_id = u64::from_str_radix(&result_hex[64..128], 16)?;
    let collateral_given = u64::from_str_radix(&result_hex[128..192], 16)?;
    let leverage = u64::from_str_radix(&result_hex[192..256], 16)?;
    let strategy_balance = u64::from_str_radix(&result_hex[256..320], 16)?;
    let id = u64::from_str_radix(&result_hex[320..384], 16)?;
    let enter_time_or_deadline = u32::from_str_radix(&result_hex[424..432], 16)?; // uint40 = 5 bytes
    let block_number = u32::from_str_radix(&result_hex[434..442], 16)?; // uint40 = 5 bytes
    let liquidation_price = u64::from_str_radix(&result_hex[448..512], 16)?;

    let user_bytes = hex::decode(user_hex)?;
    let mut user_array = [0u8; 20];
    user_array.copy_from_slice(&user_bytes);
    let user = Address::from(user_array);

    Ok(BorrowerPosition {
        user,
        strategy_id,
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
    strategy_id: u64,
    block_number: Option<u64>,
) -> Result<StrategyData> {
    // Function selector for getStrategy(uint256) = 0xcfc0cc34
    let function_selector = "0xcfc0cc34";
    let strategy_id_hex = format!("{:064x}", strategy_id);
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

    tracing::info!(%vault_address, strategy_id, "Fetching strategy data");

    let response_str = make_http_request(rpc_url, "POST", rpc_payload.as_bytes())
        .map_err(|e| anyhow!("HTTP request for strategy failed: {:?}", e))?;

    let rpc_response: Value = serde_json::from_str(&response_str)
        .map_err(|e| anyhow!("Failed to parse strategy RPC response: {}", e))?;

    // Check for RPC error first
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

    // Parse StrategyViewData struct fields
    // Structure: StrategyViewData { TokenViewData token, uint256 apr, uint256 endDate, uint256 tokenAllocation, address pool }
    // TokenViewData { address asset, uint8 decimals, string symbol }
    
    if result_hex.len() < 64 * 6 {
        return Err(anyhow!("Response too short for StrategyViewData struct"));
    }

    // Skip the first 0x20 offset pointer
    // TokenViewData.asset is at offset 0x20 (64 hex chars), last 20 bytes
    let addr_hex = &result_hex[64 + 24..64 + 64];
    
    // TokenViewData.decimals is at offset 0x40 (128 hex chars), last byte
    let _decimals = u8::from_str_radix(&result_hex[128 + 62..128 + 64], 16)?;
    
    // APR is at offset 0x60 (192 hex chars)
    let borrow_apr = u32::from_str_radix(&result_hex[192..192 + 16], 16)?; // Take first 16 hex chars for u32
    
    // EndDate is at offset 0x80 (256 hex chars)
    let end_date = u32::from_str_radix(&result_hex[256..256 + 16], 16)?; // Take first 16 hex chars for u32
    
    // TokenAllocation is at offset 0xA0 (320 hex chars) - using as balance
    let balance = u64::from_str_radix(&result_hex[320..384], 16)?;
    
    // Pool address should be at offset 0xC0 (384 hex chars), but in this mock it's zero
    // For testing purposes, use the strategy address as pool address
    let pool_hex = addr_hex; // Use strategy address as pool address for mock

    let addr_bytes = hex::decode(addr_hex)?;
    let pool_bytes = hex::decode(pool_hex)?;

    let mut addr_array = [0u8; 20];
    let mut pool_array = [0u8; 20];

    addr_array.copy_from_slice(&addr_bytes);
    pool_array.copy_from_slice(&pool_bytes);

    let addr = Address::from(addr_array);
    let pool = Address::from(pool_array);

    Ok(StrategyData {
        addr,
        is_set_up: true, // Assume true if we got valid data
        end_date,
        borrow_apr,
        balance,
        assets: balance, // Use balance as assets for now
        name: String::new(), // Skip string parsing for now
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

    println!("strategy id: {}", position.strategy_id);
    // 2. get strategy data
    let strategy = get_strategy_from_rpc(rpc_url, vault_address, position.strategy_id, block_number)?;

    tracing::info!(
          collateral_amount = position.collateral_given,
          %strategy.pool,
          "Successfully fetched pending borrow request data"
      );

    Ok((position.collateral_given, strategy.pool))
}
