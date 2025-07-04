use core::fmt;
use std::str::FromStr;

use hex::FromHexError;
use rlp::{Encodable, RlpStream};
use ruint::Uint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl<const N: usize> fmt::Display for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug)]
pub enum FixedBytesFromStrError {
    Hex(FromHexError),
    InvalidLength { expected: usize, got: usize },
}

impl fmt::Display for FixedBytesFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FixedBytesFromStrError::Hex(e) => write!(f, "Hex decoding error: {}", e),
            FixedBytesFromStrError::InvalidLength { expected, got } => {
                write!(f, "Invalid length: expected {}, got {}", expected, got)
            }
        }
    }
}
impl std::error::Error for FixedBytesFromStrError {}

impl From<FromHexError> for FixedBytesFromStrError {
    fn from(e: FromHexError) -> Self {
        FixedBytesFromStrError::Hex(e)
    }
}

impl<const N: usize> FromStr for FixedBytes<N> {
    type Err = FixedBytesFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_trimmed = s.trim_start_matches("0x");
        let decoded_bytes = hex::decode(s_trimmed)?;

        if decoded_bytes.len() != N {
            return Err(FixedBytesFromStrError::InvalidLength {
                expected: N,
                got: decoded_bytes.len(),
            });
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(&decoded_bytes);
        Ok(Self(bytes))
    }
}

impl<const N: usize> Encodable for FixedBytes<N> {
    #[inline]
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.0.as_slice());
    }
}

#[derive(Clone, Copy, Hash, Debug)]
pub struct U256(pub Uint<256, 4>);

impl Encodable for U256 {
    fn rlp_append(&self, s: &mut RlpStream) {
        if self.0.is_zero() {
            s.append_empty_data();
        } else {
            let be_bytes = self.0.to_be_bytes::<32>();
            if let Some(first_nz_idx) = be_bytes.iter().position(|&b| b != 0) {
                let data_slice: &[u8] = &be_bytes[first_nz_idx..];
                s.append(&data_slice);
            } else {
                s.append_empty_data();
            }
        }
    }
}

pub type B64 = FixedBytes<8>;
pub type B256 = FixedBytes<32>;
pub type Address = FixedBytes<20>;
pub type Bloom256 = FixedBytes<256>;

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    #[inline]
    fn from(v: [u8; N]) -> Self {
        Self(v)
    }
}

impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for U256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        crate::eth::de::hex_u256(deserializer)
    }
}
