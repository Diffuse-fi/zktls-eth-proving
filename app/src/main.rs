extern crate untrusted_app_ocalls;

use std::{
    ffi::{CStr, CString},
    fs,
    os::raw::c_char,
    slice,
};

use automata_sgx_sdk::types::SgxStatus;
use reqwest::blocking::Client;

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
