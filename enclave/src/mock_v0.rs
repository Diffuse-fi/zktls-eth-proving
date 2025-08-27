use anyhow::Result;

/// Price tolerance for liquidation validation (5% = 0.05)
const PRICE_TOLERANCE: f64 = 0.05;

#[derive(Debug, Clone)]
pub struct PriceData {
    pub block_number: u64,
    pub price: u128,
}

#[derive(Debug)]
pub struct LiquidationValidation {
    pub is_valid: bool,
    pub liquidation_price: u128,
    pub twap_price: u128,
    pub price_difference_pct: f64,
    pub reason: Option<String>,
}

/// Calculate TWAP (Time-Weighted Average Price) from multiple price data points
pub fn calculate_twap(price_data: &[PriceData]) -> Result<u128> {
    if price_data.is_empty() {
        anyhow::bail!("Cannot calculate TWAP with empty price data");
    }

    if price_data.len() == 1 {
        return Ok(price_data[0].price);
    }

    // Sort by block number to ensure chronological order
    let mut sorted_data = price_data.to_vec();
    sorted_data.sort_by_key(|data| data.block_number);

    // Calculate time-weighted average
    let mut weighted_sum: u128 = 0;
    let mut total_time_weight: u64 = 0;

    for i in 0..sorted_data.len() - 1 {
        let current = &sorted_data[i];
        let next = &sorted_data[i + 1];

        // Use block number difference as time weight
        let time_weight = next.block_number - current.block_number;

        if time_weight > 0 {
            weighted_sum =
                weighted_sum.saturating_add(current.price.saturating_mul(time_weight as u128));
            total_time_weight = total_time_weight.saturating_add(time_weight);
        }
    }

    // Add the last price point with weight 1 (current price)
    if let Some(last) = sorted_data.last() {
        weighted_sum = weighted_sum.saturating_add(last.price);
        total_time_weight = total_time_weight.saturating_add(1);
    }

    if total_time_weight == 0 {
        anyhow::bail!("Total time weight is zero, cannot calculate TWAP");
    }

    Ok(weighted_sum / total_time_weight as u128)
}

/// Validate liquidation price against TWAP
pub fn validate_liquidation_price(
    liquidation_price: u128,
    price_data: &[PriceData],
) -> Result<LiquidationValidation> {
    let twap_price = calculate_twap(price_data)?;

    // Calculate percentage difference
    let price_diff = if liquidation_price > twap_price {
        liquidation_price - twap_price
    } else {
        twap_price - liquidation_price
    };

    let price_difference_pct = if twap_price > 0 {
        (price_diff as f64) / (twap_price as f64)
    } else {
        1.0 // 100% difference if TWAP is zero
    };

    let is_valid = price_difference_pct <= PRICE_TOLERANCE;

    let reason = if !is_valid {
        Some(format!(
            "Price difference ({:.2}%) exceeds tolerance ({:.2}%)",
            price_difference_pct * 100.0,
            PRICE_TOLERANCE * 100.0
        ))
    } else {
        None
    };

    Ok(LiquidationValidation {
        is_valid,
        liquidation_price,
        twap_price,
        price_difference_pct,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_twap_single_price() {
        let price_data = vec![PriceData {
            block_number: 100,
            price: 1000,
        }];

        let twap = calculate_twap(&price_data).unwrap();
        assert_eq!(twap, 1000);
    }

    #[test]
    fn test_calculate_twap_multiple_prices() {
        let price_data = vec![
            PriceData {
                block_number: 100,
                price: 1000,
            },
            PriceData {
                block_number: 105,
                price: 1200,
            },
            PriceData {
                block_number: 110,
                price: 1100,
            },
        ];

        let twap = calculate_twap(&price_data).unwrap();
        // Expected: (1000*5 + 1200*5 + 1100*1) / (5+5+1) = 12100 / 11 ≈ 1100
        assert_eq!(twap, 1100);
    }

    #[test]
    fn test_validate_liquidation_price_valid() {
        let price_data = vec![
            PriceData {
                block_number: 100,
                price: 1000,
            },
            PriceData {
                block_number: 105,
                price: 1050,
            },
        ];

        let validation = validate_liquidation_price(1020, &price_data).unwrap();
        assert!(validation.is_valid);
        assert!(validation.reason.is_none());
    }

    #[test]
    fn test_validate_liquidation_price_invalid() {
        let price_data = vec![PriceData {
            block_number: 100,
            price: 1000,
        }];

        let validation = validate_liquidation_price(1200, &price_data).unwrap();
        assert!(!validation.is_valid);
        assert!(validation.reason.is_some());
    }
}
