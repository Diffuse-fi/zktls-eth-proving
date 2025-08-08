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

pub const DAY: B256 = 86400;
pub const IMPLIED_RATE_TIME: B256 = 365 * DAY;
pub const IONE: I256 = 1e18;
const ONE: B256 = 1e18;
const MAX_MARKET_PROPORTION: I256 = (1e18 * 96) / 100;



pub(crate) struct MarketState {
    pub(crate) total_pt: B256, //int256 total_pt;
    pub(crate) total_sy: B256, //int256 total_sy;
    // int256 totalLp; // is used only in ad add liquidity and remove liquidity
    // address treasury; // remove because we don't anything anywhere, just calc price
    /// immutable variables ///
    pub(crate) scalar_root: B256, //int256 scalar_root;
    pub(crate) expiry: B256, //uint256 expiry;
    /// fee data ///
    pub(crate) ln_fee_rate_root: B256, //uint256 ln_fee_rate_root;
    pub(crate) reserve_fee_percent: B256, //uint256 reserveFeePercent; // base 100
    /// last trade data ///
    pub(crate) last_ln_implied_rate: B256, // uint256 last_ln_implied_rate; // maybe should remove too
}

struct MarketPreCompute {
    rate_scalar: I256,
    total_asset: I256,
    rate_anchor: I256,
    fee_rate: I256,
}



pub(super) fn swap_exact_pt_for_sy(
    market: MarketState,
    index: B256,
    exact_pt_to_market: B256,
    block_time: B256
) -> I256 { //net_sy_to_account

    let net_sy_to_account = execute_trade_core(
        market,
        index,
        // TODO think if we should update this logic to be get rid of ints and use uint instead
        exact_pt_to_market * -1, // function is the same for both directions, this var is neg for pt->sy
        block_time
    );

    return net_sy_to_account;

}


fn execute_trade_core(
        market: MarketState,
        index: B256,
        // TODO think if we should update this logic to be get rid of ints and use uint instead
        exact_pt_to_market: B256, // * -1, // function is the same for both directions, this var is neg for pt->sy
        block_time: B256
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
    let comp: MarketPreCompute = get_market_pre_compute(
        market,
        index,
        block_time
    );

//         (net_sy_to_account, netSyFee, netSyToReserve) = calcTrade(market, comp, index, net_pt_to_account);

//         /// ------------------------------------------------------------
//         /// WRITE
//         /// ------------------------------------------------------------
//         _setNewMarketStateTrade(market, comp, index, net_pt_to_account, net_sy_to_account, netSyToReserve, blockTime); // doesn't affect trade price but has revert, so maybe need to implement too
//     }
//     ////MATH

}

fn get_market_pre_compute(
    market: MarketState,
    index: B256,
    block_time: B256,
) -> MarketPreCompute {

    let res: MarketPreCompute;

    assert! (market.expiry <= block_time);
    let time_to_expiry: B256 = market.expiry - block_time;
    res.rate_scalar = get_rate_scalar(market, time_to_expiry);
    res.total_asset = index.syToAsset(market.total_sy);

    assert! (market.total_pt != 0, "revert Errors.MarketZeroTotalPtOrTotalAsset");
    assert! (res.total_asset != 0, "revert Errors.MarketZeroTotalPtOrTotalAsset");

    res.rate_anchor = get_rate_anchor(
        market.total_pt,
        market.last_ln_implied_rate,
        res.total_asset,
        res.rate_scalar,
        time_to_expiry
    );

    res.fee_rate = get_exchange_rate_from_implied_rate(market.ln_fee_rate_root, time_to_expiry);

    return res;
}




fn asset_to_sy_syutils(exchange_rate: B256, asset_amount: B256) -> B256 {
    return (asset_amount * ONE) / exchange_rate;
}

fn asset_to_sy_up_syutils(exchange_rate: B256, asset_amount: B256) -> B256 {
    return (asset_amount * ONE + exchange_rate - 1) / exchange_rate;
}

fn asset_to_sy(index: B256, asset_amount: B256) -> B256 {
    return asset_to_sy_syutils(index, asset_amount);
}

fn asset_to_sy_up(index: B256, asset_amount: B256) -> B256 {
    return asset_to_sy_up_syutils(index, asset_amount);
}


fn calc_trade(
    market: MarketState,
    comp: MarketPreCompute,
    index: B256,
    net_pt_to_account: I256,
) -> I256 /*net_sy_to_account*/ {
    let pre_fee_exchange_rate = get_exchange_rate(
        market.total_pt,
        comp.total_asset,
        comp.rate_scalar,
        comp.rate_anchor,
        net_pt_to_account
    );

    let pre_fee_asset_to_account: I256 = net_pt_to_account.div_down(pre_fee_exchange_rate).neg();
    let fee: I256 = comp.fee_rate;

    if (net_pt_to_account > 0) {
        let post_fee_exchange_rate: I256 = div_down(pre_fee_exchange_rate, fee);

        assert! (post_fee_exchange_rate >= IONE, "revert Errors.MarketExchangeRateBelowOne({})", post_fee_exchange_rate);
        fee = pre_fee_asset_to_account.mulDown(IONE - fee);
    } else {
        fee = ((pre_fee_asset_to_account * (IONE - fee)) / fee).neg();
    }

    let net_asset_to_account: I256 = pre_fee_asset_to_account - fee;

    let net_sy_to_account = if (net_asset_to_account < 0) {
        asset_to_sy_up(index, net_asset_to_account);
    } else {
        asset_to_sy(index, net_asset_to_account);
    };

    net_sy_to_account
}

fn get_rate_scalar(
    market: MarketState,
    time_to_expiry: B256
) -> I256 /*rate_scalar*/ {
    let rate_scalar = (market.scalar_root * IMPLIED_RATE_TIME.Int()) / time_to_expiry;
    assert! (rate_scalar > 0, "revert Errors.MarketRateScalarBelowZero({})", rate_scalar);
}

fn div_down(a: I256, b: I256) -> I256 {
    let a_inflated = a * IONE;
    return  a_inflated / b;
}

fn sub_no_neg(a: I256, b: I256) -> I256 {
    assert! (a >= b, "negative");
    if b < 0 {
        assert! (I256::MAX - a >= b, "overflow");
    }
    return a - b;
}


fn log_proportion(proportion: I256) -> I256 {
    assert! (proportion != IONE, "revert Errors.MarketProportionMustNotEqualOne();");

    let logit_p: I256 = div_down(proportion, IONE - proportion);

    ln(logit_p);
}



fn get_rate_anchor(
    total_pt: I256,
    last_ln_implied_rate: B256,
    total_asset: I256,
    rate_scalar: I256,
    time_to_expiry: B256
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
    ln_implied_rate: B256,
    time_to_expiry: B256
) -> I256 /*exchange_rate*/ {
    let rt: B256 = (ln_implied_rate * time_to_expiry) / IMPLIED_RATE_TIME;

    let rt_signed = I256::try_from(rt).unwrap();

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
