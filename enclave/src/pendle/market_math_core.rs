// implements structs and functions from MarketMathCore.sol
// https://github.com/pendle-finance/pendle-core-v2-public/blob/6573ff85ca28b0f4fb5f6b7e2a1468fa7d0aa00b/contracts/core/Market/MarketMathCore.sol

use crate::utils;
use crate::eth;
use crate::timing;
// use crate::eth::signed::I256;
// use crate::eth::signed::int::I256;


use std::{collections::HashMap, ffi::CString, os::raw::c_char, str::FromStr};

use crate::{
    attestation_data::{AttestationPayload, ProvingResultOutput, SlotProofData},
    eth::{
        block::Block,
        header::Header,
        signed::int::I256,
        math::{ln, exp},
        primitives::{Address, U256},
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

const ONE_17: I256 = I256::from_limbs([100_000_000_000_000_000u64, 0, 0, 0]);
const ONE_20: I256 = I256::from_limbs([0x6bc75e2d63100000, 0x5, 0, 0]);
const ONE_36: I256 = I256::from_limbs([0x2b878fe800000000, 0x13426172c74d82, 0, 0]);



pub const IMPLIED_RATE_TIME: U256 = U256::from_limbs([86400*365, 0, 0, 0]);
const IONE: I256 = I256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
const ONE: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);
const MAX_MARKET_PROPORTION: I256 = I256::from_limbs([960_000_000_000_000_000u64, 0, 0, 0]);


#[derive(Clone, Copy)]
pub(crate) struct MarketState {
    pub(crate) total_pt: I256, //int256 total_pt;
    pub(crate) total_sy: I256, //int256 total_sy;
    // int256 totalLp; // is used only in ad add liquidity and remove liquidity
    // address treasury; // remove because we don't anything anywhere, just calc price
    /// immutable variables ///
    pub(crate) scalar_root: I256, //int256 scalar_root;
    pub(crate) expiry: U256, //uint256 expiry;
    /// fee data ///
    pub(crate) ln_fee_rate_root: U256, //uint256 ln_fee_rate_root;
    pub(crate) reserve_fee_percent: U256, //uint256 reserveFeePercent; // base 100
    /// last trade data ///
    pub(crate) last_ln_implied_rate: U256, // uint256 last_ln_implied_rate; // maybe should remove too
}

struct MarketPreCompute {
    rate_scalar: I256,
    total_asset: I256,
    rate_anchor: I256,
    fee_rate: I256,
}



pub(super) fn swap_exact_pt_for_sy(
    market: MarketState,
    index: U256,
    exact_pt_to_market: U256,
    block_time: U256
) -> I256 { //net_sy_to_account

    println! ("execute_trade_core start");

    println! ("let neg1");
    // TODO: enclave crases on I256::unchecked_from(-1) for some reason
    let neg1 = I256::MINUS_ONE;

    println! ("let i_exact_pt_to_market");
    let i_exact_pt_to_market = I256::from_raw(exact_pt_to_market.0);

    println! ("let neg_pt_to_market");
    let neg_pt_to_market = neg1 * i_exact_pt_to_market;

    let net_sy_to_account = execute_trade_core(
        market,
        index,
        // TODO think if we should update this logic to be get rid of ints and use uint instead
        neg_pt_to_market, // function is the same for both directions, this var is neg for pt->sy
        block_time
    );

    println! ("execute_trade_core end");

    return net_sy_to_account;

}


fn execute_trade_core(
        market: MarketState,
        index: U256,
        // TODO think if we should update this logic to be get rid of ints and use uint instead
        net_pt_to_account: I256, // * -1, // function is the same for both directions, this var is neg for pt->sy
        block_time: U256
//         MarketState memory market,
//         PYIndex index,
//         int256 net_pt_to_account,
//         uint256 blockTime
) -> I256 { //net_sy_to_account
    // todo do we need this check here?
//         if (MiniHelpers.isExpired(market.expiry, blockTime)) revert Errors.MarketExpired();
    // todo do we need this check here?
//         if (market.total_pt <= net_pt_to_account) revert Errors.MarketInsufficientPtForTrade(market.total_pt, net_pt_to_account);

//         /// ------------------------------------------------------------
//         /// MATH
//         /// ------------------------------------------------------------
    println! ("let comp");
    let comp: MarketPreCompute = get_market_pre_compute(
        market,
        index,
        block_time
    );

    println! ("let net_sy_to_account");

    let net_sy_to_account = calc_trade(market, comp, index, net_pt_to_account);

    net_sy_to_account

//         /// ------------------------------------------------------------
//         /// WRITE
//         /// ------------------------------------------------------------
//         _setNewMarketStateTrade(market, comp, index, net_pt_to_account, net_sy_to_account, netSyToReserve, blockTime); // doesn't affect trade price but has revert, so maybe need to implement too
//     }
//     ////MATH

}

fn get_market_pre_compute(
    market: MarketState,
    index: U256,
    block_time: U256,
) -> MarketPreCompute {


    // assert! (market.expiry <= block_time); // TODO implement <= and uncomment
    let time_to_expiry: U256 = market.expiry - block_time;
    let rate_scalar = get_rate_scalar(market, time_to_expiry);
    let total_asset = I256::from_raw(sy_to_asset(index, U256::from_i256(market.total_sy).unwrap()).0);

    assert! (market.total_pt != I256::ZERO, "revert Errors.MarketZeroTotalPtOrTotalAsset");
    assert! (total_asset != I256::ZERO, "revert Errors.MarketZeroTotalPtOrTotalAsset");

    let rate_anchor = get_rate_anchor(
        market.total_pt,
        market.last_ln_implied_rate,
        total_asset,
        rate_scalar,
        time_to_expiry
    );

    let fee_rate = get_exchange_rate_from_implied_rate(market.ln_fee_rate_root, time_to_expiry);

    let res: MarketPreCompute = MarketPreCompute {
        rate_scalar,
        total_asset,
        rate_anchor,
        fee_rate,
    };

    return res;
}




fn asset_to_sy_syutils(exchange_rate: U256, asset_amount: U256) -> U256 {
    return (asset_amount * ONE) / exchange_rate;
}

fn asset_to_sy_up_syutils(exchange_rate: U256, asset_amount: U256) -> U256 {
    return (asset_amount * ONE + exchange_rate - U256::ONE) / exchange_rate;
}

fn sy_to_asset(index: U256, sy_amount: U256) -> U256 {
    return sy_to_asset_syutils(index, sy_amount);
}

fn sy_to_asset_syutils(exchange_rate: U256, sy_amount: U256) -> U256 {
    return (sy_amount * exchange_rate) / ONE;
}


fn asset_to_sy(index: U256, asset_amount: U256) -> U256 {
    return asset_to_sy_syutils(index, asset_amount);
}

fn asset_to_sy_up(index: U256, asset_amount: U256) -> U256 {
    return asset_to_sy_up_syutils(index, asset_amount);
}


fn calc_trade(
    market: MarketState,
    comp: MarketPreCompute,
    index: U256,
    net_pt_to_account: I256,
) -> I256 /*net_sy_to_account*/ {
    let pre_fee_exchange_rate = get_exchange_rate(
        market.total_pt,
        comp.total_asset,
        comp.rate_scalar,
        comp.rate_anchor,
        net_pt_to_account
    );

    let pre_fee_asset_to_account: I256 = div_down(net_pt_to_account, pre_fee_exchange_rate) * I256::MINUS_ONE;
    let mut fee: I256 = comp.fee_rate;

    if net_pt_to_account > I256::ZERO {
        let post_fee_exchange_rate: I256 = div_down(pre_fee_exchange_rate, fee);

        assert! (post_fee_exchange_rate >= IONE, "revert Errors.MarketExchangeRateBelowOne({})", post_fee_exchange_rate);
        fee = mul_down(pre_fee_asset_to_account, IONE - fee);
    } else {
        fee = ((pre_fee_asset_to_account * (IONE - fee)) / fee) * I256::MINUS_ONE;
    }

    let net_asset_to_account: I256 = pre_fee_asset_to_account - fee;

    let net_sy_to_account: U256 = if net_asset_to_account < I256::ZERO {
        asset_to_sy_up(index, U256::from_i256(net_asset_to_account).unwrap())
    } else {
        asset_to_sy(index, U256::from_i256(net_asset_to_account).unwrap())
    };

    I256::from_raw(net_sy_to_account.0)
}

fn get_rate_scalar(
    market: MarketState,
    time_to_expiry: U256
) -> I256 /*rate_scalar*/ {
    let rate_scalar = (market.scalar_root * I256::from_raw(IMPLIED_RATE_TIME.0)) / I256::from_raw(time_to_expiry.0);
    assert! (rate_scalar > I256::ZERO, "revert Errors.MarketRateScalarBelowZero({})", rate_scalar);
    rate_scalar
}

fn div_down(a: I256, b: I256) -> I256 {
    let a_inflated = a * IONE;
    return  a_inflated / b;
}

fn mul_down(a: I256, b: I256) -> I256 {
    let product: I256 = a * b;
    return product / I256::from_raw(ONE.0);
}


fn sub_no_neg(a: I256, b: I256) -> I256 {
    assert! (a >= b, "negative");
    if b < I256::ZERO {
        assert! (I256::MAX - a >= b, "overflow");
    }
    return a - b;
}


fn log_proportion(proportion: I256) -> I256 {
    assert! (proportion != IONE, "revert Errors.MarketProportionMustNotEqualOne();");

    let logit_p: I256 = div_down(proportion, IONE - proportion);

    ln(logit_p)
}



fn get_rate_anchor(
    total_pt: I256,
    last_ln_implied_rate: U256,
    total_asset: I256,
    rate_scalar: I256,
    time_to_expiry: U256
) -> I256 /*rate_anchor*/ {
    let new_exchange_rate: I256 = get_exchange_rate_from_implied_rate(last_ln_implied_rate, time_to_expiry);

    assert! (new_exchange_rate >= IONE, "revert Errors.MarketExchangeRateBelowOne({});", new_exchange_rate);

    let proportion: I256 = div_down(total_pt, total_asset);

    let ln_proportion = log_proportion(proportion);

    let rate_anchor = new_exchange_rate - div_down(ln_proportion, rate_scalar);

    return rate_anchor;
}

/// @notice Converts an implied rate to an exchange rate given a time to expiry. The
/// formula is E = e^rt
fn get_exchange_rate_from_implied_rate(
    ln_implied_rate: U256,
    time_to_expiry: U256
) -> I256 /*exchange_rate*/ {
    let rt: U256 = (ln_implied_rate * time_to_expiry) / IMPLIED_RATE_TIME;

    let rt_signed = I256::from_raw(rt.0);

    exp(rt_signed)
}

fn get_exchange_rate(
    total_pt: I256,
    total_asset: I256,
    rate_scalar: I256,
    rate_anchor: I256,
    net_pt_to_account: I256
) -> I256 {
    let numerator: I256 = sub_no_neg(total_pt, net_pt_to_account);

    let proportion: I256 = div_down(numerator, total_pt + total_asset);

    assert! (proportion <= MAX_MARKET_PROPORTION, "revert Errors.MarketProportionTooHigh({}, {});", proportion, MAX_MARKET_PROPORTION);

    let ln_proportion: I256 = log_proportion(proportion);

    let exchange_rate = div_down(ln_proportion, rate_scalar) + rate_anchor;

    assert! (exchange_rate >= IONE, "revert Errors.MarketExchangeRateBelowOne({})", exchange_rate);

    exchange_rate
}
