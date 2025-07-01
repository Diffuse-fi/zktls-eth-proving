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

#[no_mangle]
pub extern "C" fn ocall_make_http_request(
    url: *const c_char,
    method: *const c_char,
    body: *const u8,
    body_len: usize,
    response: *mut c_char,
    max_response_len: usize,
    actual_response_len: *mut usize,
    http_status: *mut u16,
) {
    let url_str = unsafe { CStr::from_ptr(url).to_str().unwrap() };
    let method_str = unsafe { CStr::from_ptr(method).to_str().unwrap() };
    let body_slice = unsafe { slice::from_raw_parts(body, body_len) };

    let client = Client::new();
    let res = match method_str.to_uppercase().as_str() {
        "POST" => client.post(url_str).body(body_slice.to_vec()).send(),
        "GET" => client.get(url_str).send(),
        _ => {
            eprintln!("Unsupported HTTP method: {}", method_str);
            unsafe {
                *http_status = 400;
            }
            return;
        }
    };

    match res {
        Ok(resp) => {
            unsafe {
                *http_status = resp.status().as_u16();
            }
            match resp.text() {
                Ok(text) => {
                    let c_string = CString::new(text).unwrap();
                    let bytes = c_string.as_bytes_with_nul();
                    if bytes.len() > max_response_len {
                        eprintln!("HTTP response body is too large for the buffer.");
                        unsafe {
                            *http_status = 500;
                        }
                        return;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            response as *mut u8,
                            bytes.len(),
                        );
                        *actual_response_len = bytes.len();
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read response text: {}", e);
                    unsafe {
                        *http_status = 500;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("HTTP request failed: {}", e);
            unsafe {
                *http_status = e.status().map_or(500, |s| s.as_u16());
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn ocall_write_to_file(
    response_json_bytes: *mut c_char,
    response_json_len: usize,
    filename_bytes: *mut c_char,
    filename_len: usize,
) {
    let response_slice =
        unsafe { slice::from_raw_parts(response_json_bytes as *const u8, response_json_len) };
    let filename_slice =
        unsafe { slice::from_raw_parts(filename_bytes as *const u8, filename_len) };

    let filename_str = std::str::from_utf8(filename_slice)
        .unwrap()
        .trim_end_matches('\0');

    if let Err(e) = fs::write(filename_str, response_slice) {
        eprintln!("Failed to write to file '{}': {}", filename_str, e);
    }
}
