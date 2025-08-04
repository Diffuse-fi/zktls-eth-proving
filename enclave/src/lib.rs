mod attestation_data;
mod error;
pub(crate) mod eth;
mod pendle;
mod timing;
mod trie;
mod uniswap3;
mod utils;

use std::{collections::HashMap, ffi::CString, os::raw::c_char, str::FromStr};

use automata_sgx_sdk::types::SgxStatus;
use clap::{Parser, ErrorKind};
// use clap::Parser;

pub use pendle::{
    pendle_logic
};

pub use uniswap3::{
    compute_mapping_slot_key,
    position,
    is_tick_initialized,
    uniswap3_logic
};

use crate::{
    attestation_data::{AttestationPayload, ProvingResultOutput, SlotProofData},
    eth::{
        block::Block,
        header::Header,
        primitives::{Address, B256},
        proof::ProofResponse,
    },
    timing::{Lap, Timings},
    trie::verify_proof,
    utils::{
        construct_report_data, get_semantic_u256_bytes, keccak256, parse_slots_to_prove,
        RpcResponse, StorageProvingConfig
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
            _ => Err(format!("unknown pool type `{}`; valid: uniswap3, pendle, slots", s)),
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
            eprintln!("{}", e); // TODO tracing::warn!
            return SgxStatus::InvalidParameter;
        }
    };

    let total_timer_start = std::time::Instant::now();
    let mut timings = Timings::default();

    // match cli.pool_type {
    //     uniswap3 => uniswap3_logic(storage_proving_config, timings, total_timer_start),
    //     // pendle => pendle_logic(storage_proving_config, timings),
    //     // slots => slots_logic(storage_proving_config, timings)
    // }
    // uniswap3_logic(storage_proving_config, &mut timings, total_timer_start);
    pendle_logic(storage_proving_config, &mut timings, total_timer_start);


    // tracing::info!(config = ?cli, "Starting proving process with configuration");


    SgxStatus::Success

}

