use std::{ffi::CStr, os::raw::c_char, slice};

use reqwest::blocking::Client;

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
    std::panic::set_hook(Box::new(|info| {
        println!("[OCALL-LIB PANIC] Panic occurred: {:?}", info);
    }));

    println!("[OCALL-LIB] Entered ocall_make_http_request.");

    let url_str = unsafe { CStr::from_ptr(url).to_str().unwrap() };
    let method_str = unsafe { CStr::from_ptr(method).to_str().unwrap() };
    let body_slice = unsafe { slice::from_raw_parts(body, body_len) };

    println!("[OCALL-LIB] Request URL: {}", url_str);

    let client = Client::new();
    println!("[OCALL-LIB] Reqwest client created. About to send request...");

    let res = match method_str.to_uppercase().as_str() {
        "POST" => client.post(url_str).body(body_slice.to_vec()).send(),
        "GET" => client.get(url_str).send(),
        _ => {
            eprintln!("[OCALL-LIB] Unsupported HTTP method: {}", method_str);
            unsafe {
                *http_status = 400;
            }
            return;
        }
    };

    println!("[OCALL-LIB] Request sent. Processing response...");

    match res {
        Ok(resp) => {
            println!("[OCALL-LIB] Response received, status: {}", resp.status());
            unsafe {
                *http_status = resp.status().as_u16();
            }
            match resp.text() {
                Ok(text) => {
                    let bytes = text.as_bytes();
                    if bytes.len() >= max_response_len {
                        eprintln!("[OCALL-LIB] Response body too large.");
                        unsafe {
                            *http_status = 500;
                            *actual_response_len = 0;
                        }
                        return;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            response as *mut u8,
                            bytes.len(),
                        );
                        *(response as *mut u8).add(bytes.len()) = 0;
                        *actual_response_len = bytes.len();
                    }
                }
                Err(e) => {
                    eprintln!("[OCALL-LIB] Failed to read response text: {}", e);
                    unsafe {
                        *http_status = 500;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[OCALL-LIB] HTTP request failed: {}", e);
            unsafe {
                *http_status = e.status().map_or(500, |s| s.as_u16());
            }
        }
    }
    println!("[OCALL-LIB] Finished ocall_make_http_request.");
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

    if let Err(e) = std::fs::write(filename_str, response_slice) {
        eprintln!(
            "[OCALL-LIB] Failed to write to file '{}': {}",
            filename_str, e
        );
    }
}
