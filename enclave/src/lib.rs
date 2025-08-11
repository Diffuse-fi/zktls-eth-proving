mod attestation_data;
mod error;
pub(crate) mod eth;
mod timing;
mod trie;
mod utils;

use std::str::FromStr;

use automata_sgx_sdk::types::SgxStatus;
use clap::Parser;

use crate::{
    eth::aliases::{B256, U256},
    timing::Timings,
    utils::{
        construct_report_data, extract_storage_slots_with_merkle_proving, parse_slots_to_prove,
        StorageProvingConfig,
    },
};

#[derive(serde::Serialize)]
struct TimingDebugOutput {
    error: String,
    timings: Timings,
}

struct CliParams {
    rpc_url: String,
    address: String,
    block_number: String,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum PoolType {
    Uniswap3,
    Pendle,
    Slots,
}

impl FromStr for PoolType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "uniswap3" => Ok(PoolType::Uniswap3),
            "pendle" => Ok(PoolType::Pendle),
            "slots" => Ok(PoolType::Slots),
            _ => Err(format!(
                "unknown pool type `{}`; valid: uniswap3, pendle, slots",
                s
            )),
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(
    author = "Diffuse",
    version = "v0.2",
    about = "ZK TLS Ethereum State Prover for specific contract message structure"
)]
struct ZkTlsProverCli {
    #[clap(
        long,
        short = 'u',
        env = "RPC_URL",
        help = "Ethereum RPC endpoint URL (e.g., https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY)"
    )]
    rpc_url: String,
    #[clap(
        long,
        short,
        env = "CONTRACT_ADDRESS",
        help = "Ethereum address of the target contract"
    )]
    address: String,
    #[clap(
        long,
        short = 's',
        help = "List of storage slots to prove (comma-separated, e.g., '0,1,2,3')"
    )]
    slots_to_prove: Option<String>,
    #[clap(
        long,
        short = 'B',
        default_value = "latest",
        help = "Block number (e.g., 'latest', '0x1234AB')"
    )]
    block_number: String,
    #[clap(
        long,
        short = 'p',
        default_value = "slots",
        help = "Choose either pool type to calculate price impact(uniswap3, pendle) or just prove storage slots (slots)"
    )]
    pool_type: PoolType,
}

impl ZkTlsProverCli {
    fn get_storage_proving_config(&self) -> Result<StorageProvingConfig, clap::Error> {
        let params_helper = |storage_slots: Vec<B256>| StorageProvingConfig {
            rpc_url: self.rpc_url.clone(),
            address: self.address.clone(),
            storage_slots,
            block_number: self.block_number.clone(),
        };

        if self.pool_type == PoolType::Slots {
            if self
                .slots_to_prove
                .as_ref()
                .map(|s| s.trim().is_empty())
                .unwrap_or(true)
            {
                return Err(clap::Error::raw(
                    clap::ErrorKind::MissingRequiredArgument,
                    "`--slots-to-prove` is required when `--pool-type=slots`",
                ));
            }

            let raw = self.slots_to_prove.as_ref().unwrap();
            let storage_slots = parse_slots_to_prove(raw).map_err(|e| {
                clap::Error::raw(
                    clap::ErrorKind::InvalidValue,
                    format!("failed to parse slots from `{}`: {e}", raw),
                )
            })?;

            Ok(params_helper(storage_slots))
        } else {
            if self.slots_to_prove.is_some() {
                tracing::warn!(
                    "--slots-to-prove passed but pool-type is {:?}; ignoring slots",
                    self.pool_type
                );
            }
            Ok(params_helper(Vec::new()))
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn simple_proving() -> SgxStatus {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();

    let cli = ZkTlsProverCli::parse();

    let storage_proving_config = match ZkTlsProverCli::get_storage_proving_config(&cli) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "Error occured during storage proving config extraction: {}",
                e
            );
            return SgxStatus::InvalidParameter;
        }
    };

    let total_timer_start = std::time::Instant::now();
    let mut timings = Timings::default();
    tracing::info!(config = ?cli, "Starting proving process with configuration");

    let mut report_data = [0u8; 64];

    match cli.pool_type {
        PoolType::Uniswap3 => {
            todo!("implement uniswap3 logic");
            // uniswap3_logic(&storage_proving_config, &mut timings, total_timer_start);
        }
        PoolType::Pendle => {
            todo!("implement pendle logic");
            // pendle_logic(&storage_proving_config, &mut timings, total_timer_start);
        }
        PoolType::Slots => {
            let slots_proving_output = match extract_storage_slots_with_merkle_proving(
                &storage_proving_config,
                &mut timings,
                total_timer_start,
            ) {
                Ok(res) => res,
                Err(e) => {
                    tracing::warn!("Error occured during pendle logic execution: {}", e);
                    return SgxStatus::Unexpected;
                }
            };
            report_data = match construct_report_data(&slots_proving_output) {
                Ok(res) => res,
                Err(e) => {
                    tracing::warn!("Error occured during report data construction: {}", e);
                    return SgxStatus::Unexpected;
                }
            };
        }
    }

    tracing::debug!(report_data_hex = %hex::encode(report_data), "Constructed report_data for DCAP quote");
    let quote_bytes = match automata_sgx_sdk::dcap::dcap_quote(report_data) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("DCAP quote generation failed: {:?}", e);
            return SgxStatus::Unexpected;
        }
    };

    tracing::info!(
        quote_len = quote_bytes.len(),
        "DCAP quote generated successfully"
    );

    timings.total_ms = total_timer_start.elapsed().as_secs_f64() * 1000.0;
    tracing::debug!("Timing breakdown (if function is called multiple times, timings are measured in the last call): {:#?}", timings);

    SgxStatus::Success
}
