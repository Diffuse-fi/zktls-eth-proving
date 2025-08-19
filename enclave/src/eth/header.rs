use bytes::Bytes;
use rlp::encode;
use serde::Deserialize;

use crate::{
    eth::{de, primitives::*},
    utils::{keccak256, rlp_encode_list},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    #[serde(alias = "hash")]
    pub block_hash_untrusted: B256,
    pub parent_hash: B256,
    #[serde(alias = "sha3Uncles")]
    pub ommers_hash: B256,
    #[serde(alias = "miner")]
    pub beneficiary: Address,

    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,

    pub logs_bloom: Bloom256,
    #[serde(deserialize_with = "de::hex_u256")]
    pub difficulty: U256,
    #[serde(deserialize_with = "de::hex_u64")]
    pub number: u64,
    #[serde(deserialize_with = "de::hex_u64")]
    pub gas_limit: u64,
    #[serde(deserialize_with = "de::hex_u64")]
    pub gas_used: u64,
    #[serde(deserialize_with = "de::hex_u64")]
    pub timestamp: u64,
    #[serde(deserialize_with = "de::hex_bytes")]
    pub extra_data: Bytes,
    pub mix_hash: B256,
    pub nonce: B64,

    #[serde(default, deserialize_with = "de::opt_hex_u64")]
    pub base_fee_per_gas: Option<u64>,
    #[serde(default)]
    pub withdrawals_root: Option<B256>,
    #[serde(default, deserialize_with = "de::opt_hex_u64")]
    pub blob_gas_used: Option<u64>,
    #[serde(default, deserialize_with = "de::opt_hex_u64")]
    pub excess_blob_gas: Option<u64>,
    #[serde(default)]
    pub parent_beacon_block_root: Option<B256>,
    #[serde(default)]
    pub requests_hash: Option<B256>, // EIP-7685

    #[serde(flatten)]
    pub other: Option<serde_json::Value>,
}

impl Header {
    pub fn hash(&self) -> B256 {
        let mut rlp_items_concatenated: Vec<u8> = Vec::new();

        let append_encoded_item = |buffer: &mut Vec<u8>, item_rlp: bytes::BytesMut| {
            buffer.extend_from_slice(&item_rlp);
        };

        append_encoded_item(&mut rlp_items_concatenated, encode(&self.parent_hash));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.ommers_hash));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.beneficiary));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.state_root));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.transactions_root));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.receipts_root));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.logs_bloom));

        if self.difficulty.0.is_zero() {
            let difficulty_val: u64 = 0;
            append_encoded_item(&mut rlp_items_concatenated, encode(&difficulty_val));
        } else {
            append_encoded_item(&mut rlp_items_concatenated, encode(&self.difficulty));
        }

        append_encoded_item(&mut rlp_items_concatenated, encode(&self.number));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.gas_limit));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.gas_used));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.timestamp));
        append_encoded_item(
            &mut rlp_items_concatenated,
            encode(&self.extra_data.as_ref()),
        );
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.mix_hash));
        append_encoded_item(&mut rlp_items_concatenated, encode(&self.nonce));

        // TODO: reconsider, why is it breaking
        if let Some(fee) = &self.base_fee_per_gas {
            append_encoded_item(&mut rlp_items_concatenated, encode(fee));
        } else {
            rlp_items_concatenated.push(0x80);
        }

        if let Some(w) = &self.withdrawals_root {
            append_encoded_item(&mut rlp_items_concatenated, encode(w));
        }
        if let Some(b) = self.blob_gas_used {
            append_encoded_item(&mut rlp_items_concatenated, encode(&b));
        }
        if let Some(x) = self.excess_blob_gas {
            append_encoded_item(&mut rlp_items_concatenated, encode(&x));
        }
        if let Some(p) = &self.parent_beacon_block_root {
            append_encoded_item(&mut rlp_items_concatenated, encode(p));
        }
        if let Some(r) = &self.requests_hash {
            append_encoded_item(&mut rlp_items_concatenated, encode(r));
        }

        let final_rlp_full_header = rlp_encode_list(rlp_items_concatenated);
        let calculated_hash = keccak256(&final_rlp_full_header);
        calculated_hash.into()
    }
}

