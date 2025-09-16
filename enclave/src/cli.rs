use std::str::FromStr;
use clap::Parser;
use crate::eth::aliases::U256;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PoolType {
    Uniswap3,
    Pendle,
}

impl FromStr for PoolType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "uniswap3" => Ok(PoolType::Uniswap3),
            "pendle" => Ok(PoolType::Pendle),
            _ => Err(format!(
                "unknown pool type `{}`; valid: uniswap3, pendle",
                s
            )),
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(
    author = "Diffuse",
    version = "v0.2",
    about = "ZK TLS Ethereum State Prover"
)]
pub struct ZkTlsProverCli {
    #[clap(long, help = "Enable position creation mode")]
    pub position_creation: bool,
    
    #[clap(
        long,
        short = 'u',
        env = "RPC_URL",
        help = "Ethereum RPC endpoint URL (e.g., https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY)"
    )]
    pub rpc_url: Option<String>,
    
    #[clap(
        long,
        short = 'o',
        help = "Block offsets from latest as JSON array, e.g., '[0,-1,-5,-20,-25]'"
    )]
    pub block_offsets: Option<String>,
    
    #[clap(
        long,
        short = 't',
        help = "JSON array of proving tasks, e.g., '[{\"vault_address\":\"0xabc...\",\"position_ids\":[0, 1, 20]}]'"
    )]
    pub proving_tasks: Option<String>,
    
    #[clap(
        long,
        short = 'p',
        default_value = "pendle",
        help = "Choose either pool type to calculate price impact(uniswap3, pendle)"
    )]
    pub pool_type: PoolType,
    
    #[clap(long, help = "Vault address for position creation mode")]
    pub vault_address: Option<String>,
    
    #[clap(long, help = "Position ID for position creation mode")]
    pub position_id: Option<u64>,
    
    #[clap(long, help = "Event emitter address for position creation mode")]
    pub event_emitter_address: Option<String>,
    
    #[clap(long, help = "Threshold for position creation mode")]
    pub threshold: Option<String>,
    
    #[clap(long, help = "Blocks configuration for position creation mode")]
    pub blocks: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LiquidationArgs {
    pub rpc_url: String,
    pub block_offsets: String,
    pub proving_tasks: String,
    pub pool_type: PoolType,
}

#[derive(Debug, Clone)]
pub struct PositionCreationArgs {
    pub rpc_url: String,
    pub block_offsets: String,
    pub position_id: u64,
    pub vault_address: String,
    pub event_emitter_address: String,
    pub threshold: String,
}

#[derive(Debug)]
pub enum CliMode {
    Liquidation(LiquidationArgs),
    PositionCreation(PositionCreationArgs),
}

impl TryFrom<ZkTlsProverCli> for CliMode {
    type Error = anyhow::Error;
    
    fn try_from(cli: ZkTlsProverCli) -> Result<Self, Self::Error> {
        if cli.position_creation {
            Ok(CliMode::PositionCreation(PositionCreationArgs {
                vault_address: cli.vault_address
                    .ok_or_else(|| anyhow::anyhow!("vault-address is required for position creation mode"))?,
                position_id: cli.position_id
                    .ok_or_else(|| anyhow::anyhow!("position-id is required for position creation mode"))?,
                event_emitter_address: cli.event_emitter_address
                    .ok_or_else(|| anyhow::anyhow!("event-emitter-address is required for position creation mode"))?,
                threshold: cli.threshold
                    .ok_or_else(|| anyhow::anyhow!("threshold is required for position creation mode"))?,
                block_offsets: cli.block_offsets
                    .ok_or_else(|| anyhow::anyhow!("block-offsets is required for position creation mode"))?,
                rpc_url: cli.rpc_url
                    .ok_or_else(|| anyhow::anyhow!("rpc-url is required for position creation mode"))?,
            }))
        } else {
            Ok(CliMode::Liquidation(LiquidationArgs {
                rpc_url: cli.rpc_url
                    .ok_or_else(|| anyhow::anyhow!("rpc-url is required for liquidation mode"))?,
                block_offsets: cli.block_offsets
                    .ok_or_else(|| anyhow::anyhow!("block-offsets is required for liquidation mode"))?,
                proving_tasks: cli.proving_tasks
                    .ok_or_else(|| anyhow::anyhow!("proving-tasks is required for liquidation mode"))?,
                pool_type: cli.pool_type,
            }))
        }
    }
}