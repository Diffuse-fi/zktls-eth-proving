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
