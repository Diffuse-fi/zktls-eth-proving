//! Type aliases for common primitive types.

use crate::eth::{primitives::FixedBytes, signed::Signed};
use ruint::Uint;

#[derive(Clone, Copy, Hash, Debug)]
pub struct U256(pub Uint<256, 4>);
pub type I256 = Signed<256, 4>;

pub type B64 = FixedBytes<8>;
pub type B256 = FixedBytes<32>;
pub type Address = FixedBytes<20>;
pub type Bloom256 = FixedBytes<256>;


impl U256 {
    pub fn to_u64(&self) -> Option<u64> {
        let bytes: [u8; 32] = self.0.to_be_bytes();
        if bytes[0..24].iter().all(|&b| b == 0) {
            Some(u64::from_be_bytes(bytes[24..32].try_into().unwrap()))
        } else {
            None
        }
    }

    pub fn to_u128(&self) -> Option<u128> {
        let bytes: [u8; 32] = self.0.to_be_bytes();
        if bytes[0..16].iter().all(|&b| b == 0) {
            Some(u128::from_be_bytes(bytes[16..32].try_into().unwrap()))
        } else {
            None
        }
    }
}