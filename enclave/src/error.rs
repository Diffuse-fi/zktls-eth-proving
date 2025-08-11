use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum ProofVerificationError {
    #[error("Account proof verification failed unexpectedly")]
    AccountProofFailed,

    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("Storage proof verification failed: Unexpected node structure at depth {0}")]
    StorageProofInvalidNode(usize),

    #[error("Liquidation price validation failed: {reason}")]
    LiquidationPriceValidationFailed { reason: String },

    #[error(transparent)]
    Rlp(#[from] rlp::DecoderError),
}

pub(crate) type ProofVerificationResult<T> = Result<T, ProofVerificationError>;
