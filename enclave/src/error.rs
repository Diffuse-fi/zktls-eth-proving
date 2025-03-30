use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum ZkTlsStateHeaderError {
    #[error(transparent)]
    Sgx(#[from] automata_sgx_sdk::types::SgxStatus),

    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Ffi(#[from] std::ffi::NulError),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
}

pub(crate) type ZkTlsStateHeaderResult<T> = Result<T, ZkTlsStateHeaderError>;
