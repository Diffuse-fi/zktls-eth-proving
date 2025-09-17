mod attestation_data;
mod cli;
mod error;
pub(crate) mod eth;
mod handlers;
mod mock_v0;
mod pendle;
mod trie;
mod utils;
pub(crate) mod vault_v1;

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;

pub use pendle::pendle_logic;

use crate::{
    cli::{CliMode, ZkTlsProverCli},
    handlers::{handle_liquidation, handle_position_creation},
};


#[derive(serde::Deserialize, Debug)]
pub struct ProvingTask {
    pub vault_address: String,
    #[serde(deserialize_with = "hex_strings_to_u64")]
    pub position_ids: Vec<u64>,
}

fn hex_strings_to_u64<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Deserialize;
    
    let strings = <Vec<String>>::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(serde::de::Error::custom)
}

#[no_mangle]
pub unsafe extern "C" fn simple_proving() -> SgxStatus {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let cli = ZkTlsProverCli::parse();
    let mode = match CliMode::try_from(cli) {
        Ok(mode) => mode,
        Err(e) => {
            tracing::error!("CLI parsing failed: {}", e);
            return SgxStatus::InvalidParameter;
        }
    };

    match mode {
        CliMode::Liquidation(args) => {
            match handle_liquidation(args) {
                Err(e) => {
                    eprintln!("Error during liquidation validation: {}", e);
                    SgxStatus::Unexpected
                },
                Ok(proving_result) => {
                    let output = serde_json::to_string_pretty(&proving_result).expect("serde_json::to_string_pretty liquidation");
                    println!("{}", output);
                    SgxStatus::Success
                },
            }
        },
        CliMode::PositionCreation(args) => {
            match handle_position_creation(args) {
                Err(e) => {
                    eprintln!("Error during position creation: {}", e);
                    SgxStatus::Unexpected
                },
                Ok(proving_result) => {
                    let output = serde_json::to_string_pretty(&proving_result).expect("serde_json::to_string_pretty liquidation");
                    println!("{}", output);
                    SgxStatus::Success
                },
            }
        },
    }
}
