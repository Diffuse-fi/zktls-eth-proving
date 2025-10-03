use anyhow::{anyhow, Result};
use ruint::Uint;

use crate::eth::aliases::{I256, U256};

pub(crate) const WAD_U128: u128 = 1_000_000_000_000_000_000;

#[inline]
pub fn wad() -> U256 {
    U256(Uint::from(WAD_U128))
}

#[inline]
pub fn mul_wad(a: U256, b: U256) -> U256 {
    let result = a.0.saturating_mul(b.0) / Uint::from(WAD_U128);
    U256(result)
}

#[inline]
pub fn div_wad(a: U256, b: U256) -> U256 {
    if b.0.is_zero() {
        return U256(Uint::ZERO);
    }
    let result = a.0.saturating_mul(Uint::from(WAD_U128)) / b.0;
    U256(result)
}

#[inline]
pub fn inv_wad(x: U256) -> U256 {
    if x.0.is_zero() {
        return U256(Uint::ZERO);
    }
    let wad_squared = Uint::from(WAD_U128).saturating_mul(Uint::from(WAD_U128));
    U256(wad_squared / x.0)
}

pub struct LiquidationInputs {
    pub q_borrowed: U256,
    pub q_collateral: U256,
    pub deposit_price_wad: U256,
    pub borrowing_apy_wad: U256,
    pub spread_fee_wad: U256,
    pub days_until_maturity: u64,
    pub p_mint_wad: U256,
    pub p_redeem_wad: U256,
}

pub fn calculate_liquidation_price_base_collateral(inputs: &LiquidationInputs) -> Result<U256> {
    let days_u256 = U256(Uint::from(inputs.days_until_maturity));
    let year_days = U256(Uint::from(365u64));

    let borrowing_factor_wad = U256(
        (inputs.borrowing_apy_wad.0 + inputs.spread_fee_wad.0).saturating_mul(days_u256.0)
            / year_days.0,
    );

    let one_plus_borrowing_factor = U256(wad().0 + borrowing_factor_wad.0);

    let redemption_factor_wad = mul_wad(inputs.p_redeem_wad, inputs.p_mint_wad);
    if redemption_factor_wad.0.is_zero() {
        return Err(anyhow!("Redemption/Mint factor cannot be zero"));
    }
    let inv_redemption_factor = inv_wad(redemption_factor_wad);

    let total_assets_in_strategy = U256(inputs.q_collateral.0 + inputs.q_borrowed.0);
    if total_assets_in_strategy.0.is_zero() {
        return Err(anyhow!("Total assets in strategy cannot be zero"));
    }
    let leverage_ratio = div_wad(inputs.q_borrowed, total_assets_in_strategy);

    if inputs.deposit_price_wad.0.is_zero() {
        return Err(anyhow!("Deposit price cannot be zero"));
    }
    let price_and_borrow_component = div_wad(one_plus_borrowing_factor, inputs.deposit_price_wad);

    let liq_price = mul_wad(
        mul_wad(inv_redemption_factor, leverage_ratio),
        price_and_borrow_component,
    );

    Ok(liq_price)
}

pub fn calculate_liquidation_price_pt_collateral(inputs: &LiquidationInputs) -> Result<U256> {
    let days_u256 = U256(Uint::from(inputs.days_until_maturity));
    let year_days = U256(Uint::from(365u64));

    let borrowing_factor_wad = U256(
        (inputs.borrowing_apy_wad.0 + inputs.spread_fee_wad.0).saturating_mul(days_u256.0)
            / year_days.0,
    );

    let one_plus_borrowing_factor = U256(wad().0 + borrowing_factor_wad.0);

    let redemption_factor_wad = mul_wad(inputs.p_redeem_wad, inputs.p_mint_wad);
    if redemption_factor_wad.0.is_zero() {
        return Err(anyhow!("Redemption/Mint factor cannot be zero"));
    }
    let inv_redemption_factor = inv_wad(redemption_factor_wad);

    if inputs.deposit_price_wad.0.is_zero() {
        return Err(anyhow!("Deposit price cannot be zero"));
    }

    let collateral_in_intermediate_terms = div_wad(
        inputs.q_collateral,
        mul_wad(inputs.p_mint_wad, inputs.deposit_price_wad),
    );

    let denominator = U256(collateral_in_intermediate_terms.0 + inputs.q_borrowed.0);
    if denominator.0.is_zero() {
        return Err(anyhow!("Denominator cannot be zero"));
    }

    let leverage_ratio = div_wad(inputs.q_borrowed, denominator);

    let price_and_borrow_component = div_wad(one_plus_borrowing_factor, inputs.deposit_price_wad);

    let liq_price = mul_wad(
        mul_wad(inv_redemption_factor, leverage_ratio),
        price_and_borrow_component,
    );

    Ok(liq_price)
}

pub fn abs_diff_u256(a: U256, b: U256) -> U256 {
    if a.0 > b.0 {
        U256(a.0 - b.0)
    } else {
        U256(b.0 - a.0)
    }
}

pub fn i256_to_u256(value: I256) -> Result<U256> {
    if value < I256::ZERO {
        return Err(anyhow!("Cannot convert negative I256 to U256"));
    }

    let uint_value = value.into_raw();
    Ok(U256(uint_value))
}

pub fn u256_from_u64(value: u64) -> U256 {
    U256(Uint::from(value))
}

pub fn u256_from_u128(value: u128) -> U256 {
    U256(Uint::from(value))
}
