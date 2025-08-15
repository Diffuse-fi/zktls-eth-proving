//! Type aliases for common primitive types.

use crate::eth::{
    primitives::FixedBytes,
    signed::Signed,
};
use ruint::Uint;

macro_rules! int_aliases {
    ($($unsigned:ident, $signed:ident<$BITS:literal, $LIMBS:literal>),* $(,)?) => {$(
        #[doc = concat!($BITS, "-bit [unsigned integer type][Uint], consisting of ", $LIMBS, ", 64-bit limbs.")]
        #[cfg(test)]
        pub type $unsigned = Uint<$BITS, $LIMBS>;

        #[doc = concat!($BITS, "-bit [signed integer type][Signed], consisting of ", $LIMBS, ", 64-bit limbs.")]
        #[cfg(test)]
        pub type $signed = Signed<$BITS, $LIMBS>;

        const _: () = assert!($LIMBS == ruint::nlimbs($BITS));
    )*};
}


/// The 0-bit signed integer type, capable of representing 0.
#[cfg(test)]
pub type I0 = Signed<0, 0>;

/// The 1-bit signed integer type, capable of representing 0 and -1.
#[cfg(test)]
pub type I1 = Signed<1, 1>;

int_aliases! {
     U24,  I24< 24, 1>,
     U56,  I56< 56, 1>,
    U128, I128<128, 2>,
    U160, I160<160, 3>,
    U192, I192<192, 3>,
}

pub type U256 = Uint<256, 4>;
pub type I256 = Signed<256, 4>;

pub type B256 = FixedBytes<32>;


// /// A block hash.
// pub type BlockHash = B256;

// /// A block number.
// pub type BlockNumber = u64;

// /// A block timestamp.
// pub type BlockTimestamp = u64;

// /// A transaction hash is a keccak hash of an RLP encoded signed transaction.
// #[doc(alias = "TransactionHash")]
// pub type TxHash = B256;

// /// The sequence number of all existing transactions.
// #[doc(alias = "TransactionNumber")]
// pub type TxNumber = u64;

// /// The nonce of a transaction.
// #[doc(alias = "TransactionNonce")]
// pub type TxNonce = u64;

// /// The index of transaction in a block.
// #[doc(alias = "TransactionIndex")]
// pub type TxIndex = u64;

// /// Chain identifier type (introduced in EIP-155).
// pub type ChainId = u64;

// /// An account storage key.
// pub type StorageKey = B256;

// /// An account storage value.
// pub type StorageValue = U256;

// /// Solidity contract functions are addressed using the first four bytes of the
// /// Keccak-256 hash of their signature.
// pub type Selector = FixedBytes<4>;
