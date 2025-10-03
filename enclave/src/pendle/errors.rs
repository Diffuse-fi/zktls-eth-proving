use crate::eth::aliases::I256;

#[derive(Debug)]
pub enum MarketError {
    MarketProportionTooHigh(I256, I256),
    MarketExpired(),
    MarketInsufficientPtForTrade(I256, I256),
    MarketZeroTotalPtOrTotalAsset(),
    MarketExchangeRateBelowOne(I256),
    MarketRateScalarBelowZero(I256),
    MarketProportionMustNotEqualOne(),
}

impl std::fmt::Display for MarketError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MarketError::MarketProportionTooHigh(prop, max_prop) => {
                write!(f, "MarketProportionTooHigh({}, {})", prop, max_prop)
            }
            MarketError::MarketExpired() => {
                write!(f, "MarketExpired()")
            }
            MarketError::MarketInsufficientPtForTrade(total_pt, net_pt_to_account) => {
                write!(
                    f,
                    "MarketInsufficientPtForTrade({}, {})",
                    total_pt, net_pt_to_account
                )
            }
            MarketError::MarketZeroTotalPtOrTotalAsset() => {
                write!(f, "MarketZeroTotalPtOrTotalAsset()")
            }
            MarketError::MarketExchangeRateBelowOne(exc_rate) => {
                write!(f, "MarketExchangeRateBelowOne({})", exc_rate)
            }
            MarketError::MarketRateScalarBelowZero(rate_scalar) => {
                write!(f, "MarketRateScalarBelowZero({})", rate_scalar)
            }
            MarketError::MarketProportionMustNotEqualOne() => {
                write!(f, "MarketProportionMustNotEqualOne()")
            }
        }
    }
}

impl std::error::Error for MarketError {}
