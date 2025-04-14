use std::{ffi::CString, fmt::Debug, ptr};

use serde_json::json;
use sgx_ocalls::{
    bindings::{ocall_get_tcp_stream, UntrustedTcpStreamPtr},
    tcp_stream::TcpStreamOc,
};
use tls_enclave::{
    error::TlsResult,
    traits::{RequestProvider, TcpProvider},
};

#[derive(Debug, Clone)]
pub(crate) struct RpcInfo {
    pub(crate) domain: String,
    pub(crate) path: String,
}

#[derive(Debug)]
pub(crate) struct ZkTlsStateHeader {
    pub(crate) rpc_info: RpcInfo,
    pub(crate) stream_ptr: TcpStreamOc,
    pub(crate) block_number: String,
}

impl ZkTlsStateHeader {
    pub fn new(rpc_info: RpcInfo, block_number: String) -> Self {
        let server_address = rpc_info.domain.clone();
        let address_cstr =
            CString::new(format!("{server_address}:443")).expect("Failed to create CString");
        let mut stream_ptr: UntrustedTcpStreamPtr = ptr::null_mut();

        unsafe {
            ocall_get_tcp_stream(
                address_cstr.as_ptr() as *const u8,
                &mut stream_ptr as *mut UntrustedTcpStreamPtr,
            );
        }

        if stream_ptr.is_null() {
            panic!("Failed to create TCP stream");
        }

        ZkTlsStateHeader {
            rpc_info,
            stream_ptr: TcpStreamOc::new(stream_ptr),
            block_number,
        }
    }
}

impl<S: AsRef<str>> RequestProvider<S> for ZkTlsStateHeader {
    fn get_request(&self, _server_name: S) -> Vec<u8> {
        let payload = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["{}", false],"id":1}}"#,
            self.block_number
        );
        format!(
            "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
            self.rpc_info.path,
            self.rpc_info.domain,
            payload.len(),
            payload
        )
        .into_bytes()
    }
}

impl<S: AsRef<str>> TcpProvider<S> for ZkTlsStateHeader {
    type Stream = TcpStreamOc;

    fn get(&mut self, server_address: S) -> TlsResult<Self::Stream> {
        assert_eq!(
            self.rpc_info.domain,
            server_address.as_ref(),
            "Server address mismatch"
        );
        Ok(std::mem::take(&mut self.stream_ptr))
    }
}

#[derive(Debug)]
pub(crate) struct ZkTlsStateProof {
    pub(crate) rpc_info: RpcInfo,
    pub(crate) stream_ptr: TcpStreamOc,
    pub(crate) eth_address: String,
    pub(crate) storage_keys: Vec<String>,
    pub(crate) block_number: String,
}

impl ZkTlsStateProof {
    pub fn new(
        rpc_info: RpcInfo,
        eth_address: String,
        storage_keys: Vec<String>,
        block_number: String,
    ) -> Self {
        let server_address = rpc_info.domain.clone();
        let address_cstr =
            CString::new(format!("{server_address}:443")).expect("Failed to create CString");
        let mut stream_ptr: UntrustedTcpStreamPtr = ptr::null_mut();

        unsafe {
            ocall_get_tcp_stream(
                address_cstr.as_ptr() as *const u8,
                &mut stream_ptr as *mut UntrustedTcpStreamPtr,
            );
        }

        if stream_ptr.is_null() {
            panic!("Failed to create TCP stream");
        }

        ZkTlsStateProof {
            rpc_info,
            stream_ptr: TcpStreamOc::new(stream_ptr),
            eth_address,
            storage_keys,
            block_number,
        }
    }
}

impl<S: AsRef<str>> RequestProvider<S> for ZkTlsStateProof {
    fn get_request(&self, _server_name: S) -> Vec<u8> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getProof",
            "params": [
                self.eth_address,
                self.storage_keys,
                self.block_number
            ],
            "id": 1
        });
        let payload_str = payload.to_string();

        format!(
            "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
            self.rpc_info.path,
            self.rpc_info.domain,
            payload_str.len(),
            payload_str
        )
        .into_bytes()
    }
}

impl<S: AsRef<str>> TcpProvider<S> for ZkTlsStateProof {
    type Stream = TcpStreamOc;

    fn get(&mut self, server_address: S) -> TlsResult<Self::Stream> {
        assert_eq!(
            self.rpc_info.domain,
            server_address.as_ref(),
            "Server address mismatch"
        );
        Ok(std::mem::take(&mut self.stream_ptr))
    }
}
