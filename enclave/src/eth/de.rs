use bytes::Bytes;
use ruint::Uint;
use serde::{self, Deserialize, Deserializer};

use crate::eth::primitives::{FixedBytes, U256};

pub fn hex_u64<'de, D>(de: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
}

pub fn opt_hex_u64<'de, D>(de: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(de)?
        .map(|s| {
            u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(serde::de::Error::custom)
        })
        .transpose()
}

pub fn hex_u256<'de, D>(de: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    let mut hex = s.trim_start_matches("0x").to_string();

    if hex.is_empty() || hex == "0" {
        return Ok(U256(Uint::ZERO));
    }

    if hex.len() % 2 == 1 {
        let mut padded = String::with_capacity(hex.len() + 1);
        padded.push('0');
        padded.push_str(&hex);
        hex = padded;
    }

    let raw = hex::decode(hex).map_err(serde::de::Error::custom)?;
    Ok(U256(Uint::from_be_slice(&raw)))
}

pub fn hex_bytes<'de, D>(de: D) -> Result<Bytes, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    let raw = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
    Ok(Bytes::from(raw))
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(de)?;
        let raw = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        if raw.len() != N {
            return Err(serde::de::Error::custom(format!(
                "Wrong byte length for FixedBytes<{}>. Expected {}, got {} from hex '{}'",
                N,
                N,
                raw.len(),
                s
            )));
        }
        let mut tmp = [0u8; N];
        tmp.copy_from_slice(&raw);
        Ok(Self(tmp))
    }
}
