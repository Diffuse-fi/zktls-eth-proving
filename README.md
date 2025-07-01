# ZK-TLS Ethereum State Prover

This repository implements a ZK-TLS Ethereum State Prover built with Intel SGX enclaves. The project proves the state of Ethereum contract storage slots using zero-knowledge TLS and SGX attestation, providing cryptographic guarantees about on-chain data.

## Project Structure
<pre>
zktls-eth-proving
├── app/                      # Main application
│   ├── build.rs              # Build script for the application
│   ├── Cargo.toml            # Application configuration
│   ├── sgx/                  # SGX enclave configurations and definitions
│   │   ├── config.xml        # Enclave configuration parameters
│   │   ├── enclave.edl       # Enclave Definition Language file
│   │   ├── enclave.lds       # Linker script for the enclave
│   │   └── private.pem       # Developer key (do not use in production)
│   └── src/main.rs           # Application entrypoint
├── enclave/                  # SGX enclave implementation
│   ├── Cargo.toml            # Enclave crate configuration
│   └── src/
│       ├── lib.rs            # Main library file for the enclave
│       ├── attestation_data.rs # SGX attestation structures
│       ├── error.rs          # Error types and result handling
│       ├── eth/              # Ethereum primitives
│       │   ├── block.rs      # Block structures
│       │   ├── header.rs     # Block header handling
│       │   ├── primitives.rs # Basic Ethereum types
│       │   ├── proof.rs      # Proof structures
│       │   └── de.rs         # Custom deserialization
│       ├── tls.rs            # ZK-TLS request handling
│       ├── trie.rs           # Merkle Patricia Trie verification
│       └── utils.rs          # Storage calculations and utilities
├── Cargo.toml                # Workspace configuration
├── Cargo.lock
└── README.md                 # This file
</pre>

## How It Works

The ZK-TLS Ethereum State Prover performs the following workflow:

1. **Parse Configuration**: Accepts RPC endpoint, contract address, and storage slot keys via CLI
2. **Fetch Block Header**: Uses ZK-TLS to securely retrieve block header from Ethereum RPC
3. **Fetch Storage Proofs**: Obtains Merkle proofs for specified contract storage slots
4. **Verify Proofs**: Validates Merkle Patricia Trie proofs against the block's state root
5. **Generate Attestation**: Creates SGX DCAP quote with proven slot data as attestation payload
6. **Output Results**: Returns JSON with proven storage values and cryptographic attestation

## Prerequisites

- **SGX-Supported Machine**: A machine with SGX support is required
- **SGX and DCAP SDK**: Ensure you have the Intel SGX SDK and DCAP SDK installed. Refer to the [Automata SGX SDK repository](https://github.com/automata-network/automata-sgx-sdk) for the latest supported versions

## Building the Enclave

### Manual Build

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Diffuse-fi/zktls-eth-proving.git
    cd zktls-eth-proving
    ```

2. **Install `cargo-sgx`**:
    ```bash
    cargo install cargo-sgx
    ```
   To see all available commands, run:
    ```bash
    cargo sgx --help
    ```

3. **Generate a New Signing Key** (if needed):
    ```bash
    cargo sgx gen-key app/sgx/private.pem
    ```

4. **Set the SGX SDK Environment Variable**:
   (Update the path if you installed the SGX SDK elsewhere)
    ```bash
    export SGX_SDK=/opt/intel/sgxsdk
    ```

5. **Build the Enclave**:
    ```bash
    cargo sgx build
    ```
   Or run the enclave directly:
    ```bash
    cargo sgx run
    ```

### Building as a Standard Rust Application

If you do not have SGX hardware or prefer to run the enclave as a normal Rust application, disable SGX-specific features:
```bash
cargo sgx run --std
```

## Usage

### Command Line Arguments

```bash
./zktls-eth-proving --help

enclave v0.2
Diffuse
ZK TLS Ethereum State Prover for specific contract message structure

USAGE:
    app-template [OPTIONS] --rpc-domain <RPC_DOMAIN> --address <ADDRESS>

OPTIONS:
    -a, --address <ADDRESS>
            Ethereum address of the target contract [env: CONTRACT_ADDRESS=]

        --alchemy-api-key <ALCHEMY_API_KEY>
            [env: ALCHEMY_API_KEY=UqTkk1rVlG9MASzW3tAa9Zu4s4H3rLZV]

    -B, --block-number <BLOCK_NUMBER>
            Block number (e.g., 'latest', '0x1234AB') [default: latest]

    -h, --help
            Print help information

    -P, --rpc-path <RPC_PATH>
            [env: RPC_PATH=]

    -r, --rpc-domain <RPC_DOMAIN>
            [env: RPC_DOMAIN=]

    -s, --storage-keys <STORAGE_KEYS>
            Storage slot keys in hex format (0x...)

    -V, --version
            Print version information
```

### Example Usage

Prove storage slots for a contract on Ethereum mainnet:

```bash
RUST_LOG=debug cargo sgx run -- \
    --rpc-domain eth-mainnet.g.alchemy.com \
    --alchemy-api-key YOUR_API_KEY \
    --address 0x435664008F38B0650fBC1C9fc971D0A3Bc2f1e47 \
    --storage-keys 0xd125646815f22659353459f7af7afa81e2e69f1ada9ecb591b60ce87cfdbfcf0
```

Or with a custom RPC path:

```bash
cargo sgx run -- \
    --rpc-domain your-rpc-provider.com \
    --rpc-path /your/custom/path \
    --address 0x435664008F38B0650fBC1C9fc971D0A3Bc2f1e47 \
    --storage-keys 0xd125646815f22659353459f7af7afa81e2e69f1ada9ecb591b60ce87cfdbfcf0 \
    --block-number latest
```

### Output Format

The prover outputs a JSON structure containing:

```json
{
  "attestation_payload": {
    "block_hash": "0x...",
    "block_number": 12345678,
    "proven_slots": [
      {
        "slot_key": "0xd125646815f22659353459f7af7afa81e2e69f1ada9ecb591b60ce87cfdbfcf0",
        "value_hash": "0x..."
      }
    ]
  },
  "sgx_quote_hex": "..."
}
```

## Environment Variables

You can use environment variables instead of command line flags:

- `RPC_DOMAIN`: RPC domain
- `RPC_PATH`: RPC path
- `ALCHEMY_API_KEY`: Alchemy API key
- `CONTRACT_ADDRESS`: Target contract address


### Testing

Check the code without building:
```bash
cargo check --workspace
```

Build with debug logging:
```bash
RUST_LOG=debug cargo sgx build
```

## Security Considerations

- The provided `private.pem` key is for development only
- Generate a new signing key for production deployments
- Ensure proper SGX platform configuration for production use
- Storage slot keys must be exactly 32 bytes (64 hex characters)

## Community and Support

For questions, discussions, or contributions, join our [Telegram Channel](https://t.me/zkdiffuse). We're active there and ready to help!
