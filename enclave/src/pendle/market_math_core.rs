// implements structs and functions from MarketMathCore.sol
// https://github.com/pendle-finance/pendle-core-v2-public/blob/6573ff85ca28b0f4fb5f6b7e2a1468fa7d0aa00b/contracts/core/Market/MarketMathCore.sol

use crate::{
    eth::aliases::{I256, U256},
    pendle::errors::*,
    pendle::math::{exp, ln},
};

pub const IMPLIED_RATE_TIME: U256 = U256::from_limbs([86400 * 365, 0, 0, 0]);
const IONE: I256 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
const ONE: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
const MAX_MARKET_PROPORTION: I256 = I256::from_limbs([960_000_000_000_000_000u64, 0, 0, 0]);

#[derive(Clone, Copy)]
pub(crate) struct MarketState {
    pub(crate) total_pt: I256, //int256 total_pt;
    pub(crate) total_sy: I256, //int256 total_sy;
    // int256 totalLp; // is used only in ad add liquidity and remove liquidity
    // address treasury; // remove because we don't anything anywhere, just calc price
    pub(crate) scalar_root: I256,      //int256 scalar_root;
    pub(crate) expiry: U256,           //uint256 expiry;
    pub(crate) ln_fee_rate_root: U256, //uint256 ln_fee_rate_root;
    // uint256 reserveFeePercent; is never used
    pub(crate) last_ln_implied_rate: U256, // uint256 last_ln_implied_rate; // maybe should remove too
}

struct MarketPreCompute {
    rate_scalar: I256,
    total_asset: I256,
    rate_anchor: I256,
    fee_rate: I256,
}

pub(super) fn swap_sy_for_exact_pt(
    market: MarketState,
    index: U256,
    exact_pt_to_market: U256,
    block_time: U256,
) -> anyhow::Result<I256> {
    let net_sy_to_account = execute_trade_core(
        market,
        index,
        I256::try_from(exact_pt_to_market.0)?, // function is the same for both directions, this var is neg for pt->sy
        block_time,
    )?;

    Ok(net_sy_to_account)
}

pub(super) fn swap_exact_pt_for_sy(
    market: MarketState,
    index: U256,
    exact_pt_to_market: U256,
    block_time: U256,
) -> anyhow::Result<I256> {
    //net_sy_to_account

    let neg1 = I256::MINUS_ONE;

    let i_exact_pt_to_market = I256::try_from(exact_pt_to_market.0)?;

    let neg_pt_to_market = neg1 * i_exact_pt_to_market;

    let net_sy_to_account = execute_trade_core(
        market,
        index,
        neg_pt_to_market, // function is the same for both directions, this var is neg for pt->sy
        block_time,
    )?;

    Ok(net_sy_to_account)
}

fn execute_trade_core(
    market: MarketState,
    index: U256,
    net_pt_to_account: I256, // * -1, // function is the same for both directions, this var is neg for pt->sy
    block_time: U256,
) -> anyhow::Result<I256> {
    if I256::try_from(market.expiry.0)? <= I256::try_from(block_time.0)? {
        return Err(MarketError::MarketExpired().into());
    }
    if market.total_pt <= net_pt_to_account {
        return Err(
            MarketError::MarketInsufficientPtForTrade(market.total_pt, net_pt_to_account).into(),
        );
    }

    let comp: MarketPreCompute = get_market_pre_compute(market, index, block_time)?;

    let net_sy_to_account = calc_trade(market, comp, index, net_pt_to_account)?;

    Ok(net_sy_to_account)
}

fn get_market_pre_compute(
    market: MarketState,
    index: U256,
    block_time: U256,
) -> anyhow::Result<MarketPreCompute> {
    if I256::try_from(market.expiry.0)? <= I256::try_from(block_time.0)? {
        return Err(MarketError::MarketExpired().into());
    }
    let time_to_expiry: U256 = market.expiry - block_time;
    let rate_scalar = get_rate_scalar(market, time_to_expiry)?;
    tracing::debug!("rate_scalar: {}", rate_scalar);
    let total_asset =
        I256::try_from(sy_to_asset(index, U256::from_i256(market.total_sy).unwrap()).0)?;

    tracing::debug!("market.total_pt: {}", market.total_pt);
    if market.total_pt == I256::ZERO {
        return Err(MarketError::MarketZeroTotalPtOrTotalAsset().into());
    }
    tracing::debug!("total_asset: {}", total_asset);
    if total_asset == I256::ZERO {
        return Err(MarketError::MarketZeroTotalPtOrTotalAsset().into());
    }

    let rate_anchor = get_rate_anchor(
        market.total_pt,
        market.last_ln_implied_rate,
        total_asset,
        rate_scalar,
        time_to_expiry,
    )?;

    let fee_rate = get_exchange_rate_from_implied_rate(market.ln_fee_rate_root, time_to_expiry)?;

    let res: MarketPreCompute = MarketPreCompute {
        rate_scalar,
        total_asset,
        rate_anchor,
        fee_rate,
    };

    Ok(res)
}

fn asset_to_sy_syutils(exchange_rate: U256, asset_amount: U256) -> U256 {
    (asset_amount * ONE) / exchange_rate
}

fn asset_to_sy_up_syutils(exchange_rate: U256, asset_amount: U256) -> U256 {
    (asset_amount * ONE + exchange_rate - U256::ONE) / exchange_rate
}

fn sy_to_asset(index: U256, sy_amount: U256) -> U256 {
    sy_to_asset_syutils(index, sy_amount)
}

fn sy_to_asset_syutils(exchange_rate: U256, sy_amount: U256) -> U256 {
    (sy_amount * exchange_rate) / ONE
}

fn asset_to_sy(index: U256, asset_amount: U256) -> U256 {
    asset_to_sy_syutils(index, asset_amount)
}

fn asset_to_sy_up(index: U256, asset_amount: U256) -> U256 {
    asset_to_sy_up_syutils(index, asset_amount)
}

fn calc_trade(
    market: MarketState,
    comp: MarketPreCompute,
    index: U256,
    net_pt_to_account: I256,
) -> anyhow::Result<I256> /*net_sy_to_account*/ {
    let pre_fee_exchange_rate = get_exchange_rate(
        market.total_pt,
        comp.total_asset,
        comp.rate_scalar,
        comp.rate_anchor,
        net_pt_to_account,
    )?;

    let pre_fee_asset_to_account: I256 =
        div_down(net_pt_to_account, pre_fee_exchange_rate) * I256::MINUS_ONE;
    let mut fee: I256 = comp.fee_rate;

    if net_pt_to_account > I256::ZERO {
        let post_fee_exchange_rate: I256 = div_down(pre_fee_exchange_rate, fee);
        if post_fee_exchange_rate < IONE {
            return Err(MarketError::MarketExchangeRateBelowOne(post_fee_exchange_rate).into());
        }
        fee = mul_down(pre_fee_asset_to_account, IONE - fee);
    } else {
        fee = ((pre_fee_asset_to_account * (IONE - fee)) / fee) * I256::MINUS_ONE;
    }

    let net_asset_to_account: I256 = pre_fee_asset_to_account - fee;

    let net_sy_to_account: U256 = if net_asset_to_account < I256::ZERO {
        asset_to_sy_up(index, U256::from_i256(net_asset_to_account * I256::MINUS_ONE).unwrap())
    } else {
        asset_to_sy(index, U256::from_i256(net_asset_to_account).unwrap())
    };

    Ok(I256::try_from(net_sy_to_account.0)?)
}

fn get_rate_scalar(market: MarketState, time_to_expiry: U256) -> anyhow::Result<I256> /*rate_scalar*/
{
    let rate_scalar = (market.scalar_root * I256::try_from(IMPLIED_RATE_TIME.0)?)
        / I256::try_from(time_to_expiry.0)?;
    if rate_scalar <= I256::ZERO {
        return Err(MarketError::MarketRateScalarBelowZero(rate_scalar).into());
    }
    Ok(rate_scalar)
}

fn div_down(a: I256, b: I256) -> I256 {
    let a_inflated = a * IONE;
    a_inflated / b
}

fn mul_down(a: I256, b: I256) -> I256 {
    let product: I256 = a * b;
    product / IONE
}

fn sub_no_neg(a: I256, b: I256) -> I256 {
    assert!(a >= b, "negative");
    if b < I256::ZERO {
        assert!(I256::MAX - a >= b, "overflow");
    }
    a - b
}

fn log_proportion(proportion: I256) -> anyhow::Result<I256> {
    if proportion == IONE {
        return Err(MarketError::MarketProportionMustNotEqualOne().into());
    }

    let logit_p: I256 = div_down(proportion, IONE - proportion);

    Ok(ln(logit_p))
}

fn get_rate_anchor(
    total_pt: I256,
    last_ln_implied_rate: U256,
    total_asset: I256,
    rate_scalar: I256,
    time_to_expiry: U256,
) -> anyhow::Result<I256> /*rate_anchor*/ {
    let new_exchange_rate: I256 =
        get_exchange_rate_from_implied_rate(last_ln_implied_rate, time_to_expiry)?;

    if new_exchange_rate < IONE {
        return Err(MarketError::MarketExchangeRateBelowOne(new_exchange_rate).into());
    }

    let proportion: I256 = div_down(total_pt, total_pt + total_asset);

    let ln_proportion = log_proportion(proportion)?;

    let rate_anchor = new_exchange_rate - div_down(ln_proportion, rate_scalar);

    Ok(rate_anchor)
}

/// @notice Converts an implied rate to an exchange rate given a time to expiry. The
/// formula is E = e^rt
fn get_exchange_rate_from_implied_rate(
    ln_implied_rate: U256,
    time_to_expiry: U256,
) -> anyhow::Result<I256> /*exchange_rate*/ {
    tracing::debug!("ln_implied_rate: {}", ln_implied_rate);
    tracing::debug!("time_to_expiry: {}", time_to_expiry);
    let rt: U256 = (ln_implied_rate * time_to_expiry) / IMPLIED_RATE_TIME;
    tracing::debug!("rt: {}", rt);

    let rt_signed = I256::try_from(rt.0)?;

    Ok(exp(rt_signed))
}

fn get_exchange_rate(
    total_pt: I256,
    total_asset: I256,
    rate_scalar: I256,
    rate_anchor: I256,
    net_pt_to_account: I256,
) -> anyhow::Result<I256> {
    let numerator: I256 = sub_no_neg(total_pt, net_pt_to_account);

    let proportion: I256 = div_down(numerator, total_pt + total_asset);

    if proportion > MAX_MARKET_PROPORTION {
        return Err(MarketError::MarketProportionTooHigh(proportion, MAX_MARKET_PROPORTION).into());
    }

    let ln_proportion: I256 = log_proportion(proportion)?;

    let exchange_rate = div_down(ln_proportion, rate_scalar) + rate_anchor;

    if exchange_rate < IONE {
        return Err(MarketError::MarketExchangeRateBelowOne(exchange_rate).into());
    }

    Ok(exchange_rate)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    struct TestSet {
        total_pt: I256,
        total_asset: I256,
        scalar_root: I256,
        rate_scalar: I256,
        last_ln_implied_rate: U256,
        expiry: U256,
        time_to_expiry: U256,
        ln_fee_rate_root: U256,
        block_timestamp: U256,
        index: U256,
    }

    fn test_set_1() -> TestSet {
        let total_pt: I256 = "43061868769152794457505491".parse::<I256>().unwrap();
        let total_asset: I256 = "64051752657933673759680199".parse::<I256>().unwrap();
        let scalar_root: I256 = "21902171029607772275".parse::<I256>().unwrap();
        let rate_scalar: I256 = "233101763445980867575".parse::<I256>().unwrap();
        let last_ln_implied_rate: U256 = U256::from_limbs([129369539002638335, 0, 0, 0]);
        let expiry: U256 = U256::from_limbs([1758758400, 0, 0, 0]);
        let time_to_expiry: U256 = U256::from_limbs([2963113, 0, 0, 0]);
        let ln_fee_rate_root: U256 = U256::from_limbs([129369539002638335, 0, 0, 0]);
        let block_timestamp: U256 = U256::from_limbs([1755795287, 0, 0, 0]);
        let index: U256 = U256::from_limbs([1000000000000000000, 0, 0, 0]);

        return TestSet {
            total_pt: total_pt,
            total_asset: total_asset,
            scalar_root: scalar_root,
            rate_scalar: rate_scalar,
            last_ln_implied_rate: last_ln_implied_rate,
            expiry: expiry,
            time_to_expiry: time_to_expiry,
            ln_fee_rate_root: ln_fee_rate_root,
            block_timestamp: block_timestamp,
            index: index,
        };
    }

    fn test_set_2() -> TestSet {
        let total_pt: I256 = "43061868769152794457505491".parse::<I256>().unwrap();
        let total_asset: I256 = "64051752657933673759680199".parse::<I256>().unwrap();
        let scalar_root: I256 = "21902171029607772275".parse::<I256>().unwrap();
        let rate_scalar: I256 = "233101763445980867575".parse::<I256>().unwrap();
        let last_ln_implied_rate: U256 = U256::from_limbs([129369539002638335, 0, 0, 0]);
        let expiry: U256 = U256::from_limbs([1758758400, 0, 0, 0]);
        let time_to_expiry: U256 = U256::from_limbs([2963113, 0, 0, 0]);
        let ln_fee_rate_root: U256 = U256::from_limbs([8959741371471904, 0, 0, 0]);

        let block_timestamp: U256 = U256::from_limbs([1755795287, 0, 0, 0]);
        let index: U256 = U256::from_limbs([1000000000000000000, 0, 0, 0]);

        return TestSet {
            total_pt: total_pt,
            total_asset: total_asset,
            scalar_root: scalar_root,
            rate_scalar: rate_scalar,
            last_ln_implied_rate: last_ln_implied_rate,
            expiry: expiry,
            time_to_expiry: time_to_expiry,
            ln_fee_rate_root: ln_fee_rate_root,
            block_timestamp: block_timestamp,
            index: index,
        };
    }

    #[test]
    fn test_get_rate_anchor() {
        let test_set = test_set_1();
        let enclave_result = get_rate_anchor(
            test_set.total_pt,
            test_set.last_ln_implied_rate,
            test_set.total_asset,
            test_set.rate_scalar,
            test_set.time_to_expiry,
        )
        .unwrap();
        let expected_result = "1013933049627235902".parse::<I256>().unwrap();
        println!("enclave_result: {}", enclave_result);
        println!("expected_result: {}", expected_result);
        assert!(enclave_result == expected_result);
    }

    #[test]
    fn test_get_exchange_rate_from_implied_rate() {
        let test_set = test_set_1();
        let enclave_result = match get_exchange_rate_from_implied_rate(
            test_set.last_ln_implied_rate,
            test_set.time_to_expiry,
        ) {
            Ok(res) => res,
            Err(e) => panic!("get_exchange_rate_from_implied_rate returned error {}", e),
        };
        let expected_result = "1012229701287799987".parse::<I256>().unwrap();
        println!("enclave_result: {}", enclave_result);
        println!("expected_result: {}", expected_result);
        assert!(enclave_result == expected_result);
    }

    #[test]
    fn test_div_down() {
        let test_set = test_set_1();
        let enclave_result = div_down(test_set.total_pt, test_set.total_pt + test_set.total_asset);

        let expected_result = "402020473170777135".parse::<I256>().unwrap();

        println!("enclave_result: {}", enclave_result);
        println!("expected_result: {}", expected_result);
        assert!(enclave_result == expected_result);
    }

    fn swap_pt_for_sy(test_set: TestSet, pt_to_market: U256, expected: &str) {
        let market: MarketState = MarketState {
            total_pt: test_set.total_pt,
            total_sy: test_set.total_asset,
            scalar_root: test_set.scalar_root,
            expiry: test_set.expiry,
            ln_fee_rate_root: test_set.ln_fee_rate_root,
            last_ln_implied_rate: test_set.last_ln_implied_rate,
        };

        let enclave_result = match swap_exact_pt_for_sy(
            market,
            test_set.index,
            pt_to_market,
            test_set.block_timestamp,
        ) {
            Ok(res) => res,
            Err(e) => {
                panic!("Unexpected error in swap_exact_pt_for_sy: {:?}", e);
            }
        };

        let expected_result = expected.parse::<I256>().unwrap();
        println!("enclave_result: {}", enclave_result);
        println!("expected_result: {}", expected_result);
        assert!(enclave_result == expected_result);
    }

    #[test]
    fn test_pendle_logic_e06() {
        swap_pt_for_sy(test_set_1(), U256::from_str("1_000_000").unwrap(), "975983");
    }
    #[test]
    fn test_pendle_logic_e09() {
        swap_pt_for_sy(
            test_set_1(),
            U256::from_str("1_000_000_000").unwrap(),
            "975982088",
        );
    }
    #[test]
    fn test_pendle_logic_e25_1() {
        swap_pt_for_sy(
            test_set_1(),
            U256::from_str("10_000_000_000_000_000_000_000_000").unwrap(),
            "9744186980348718103428778",
        );
    }
    #[test]
    fn test_pendle_logic_e25_2() {
        swap_pt_for_sy(
            test_set_2(),
            U256::from_str("10_000_000_000_000_000_000_000_000").unwrap(),
            "9855055459591525524920205",
        );
    }
}
