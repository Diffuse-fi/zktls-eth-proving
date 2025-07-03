extern crate mock_lib;

use automata_sgx_sdk::types::SgxStatus;

automata_sgx_sdk::enclave! {
    name: Enclave,
    ecall: {
        fn simple_proving() -> SgxStatus;
    }
}

fn main() -> anyhow::Result<()> {
    let result = Enclave::new()
        .simple_proving()
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;
    if !result.is_success() {
        println!("{:?}", result);
    }
    Ok(())
}
