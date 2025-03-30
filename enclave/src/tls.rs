use std::{ffi::CString, fmt::Debug, ptr};

use sgx_ocalls::{
    bindings::{ocall_get_tcp_stream, UntrustedTcpStreamPtr},
    tcp_stream::TcpStreamOc,
};
use tls_enclave::{
    error::TlsResult,
    traits::{RequestProvider, TcpProvider},
};

// eth.drpc.org
// eth.llamarpc.com
pub(crate) const RPC_DOMAIN: &str = "eth.llamarpc.com";
pub(crate) const RPC_PATH: &str = "/";

#[derive(Debug)]
pub(crate) struct ZkTlsStateHeader {
    pub(crate) server_address: String,
    pub(crate) stream_ptr: TcpStreamOc,
    pub(crate) block_number: String,
}

impl ZkTlsStateHeader {
    pub fn new(server_address: String, block_number: String) -> Self {
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
            server_address,
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
            RPC_PATH,
            RPC_DOMAIN,
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
            self.server_address,
            server_address.as_ref(),
            "Server address mismatch"
        );
        Ok(std::mem::take(&mut self.stream_ptr))
    }
}

#[derive(Debug)]
pub(crate) struct ZkTlsStateProof {
    pub(crate) server_address: String,
    pub(crate) stream_ptr: TcpStreamOc,
    pub(crate) eth_address: String,
    pub(crate) storage_key: String,
    pub(crate) block_number: String,
}

impl ZkTlsStateProof {
    pub fn new(
        server_address: String,
        eth_address: String,
        storage_key: String,
        block_number: String,
    ) -> Self {
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

        crate::tls::ZkTlsStateProof {
            server_address,
            stream_ptr: TcpStreamOc::new(stream_ptr),
            eth_address,
            storage_key,
            block_number,
        }
    }
}

impl<S: AsRef<str>> RequestProvider<S> for crate::tls::ZkTlsStateProof {
    fn get_request(&self, _server_name: S) -> Vec<u8> {
        let payload = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getProof","params":["{}",["{}"],"{}"],"id":1}}"#,
            self.eth_address, self.storage_key, self.block_number
        );
        format!(
            "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
            RPC_PATH,
            RPC_DOMAIN,
            payload.len(),
            payload
        )
        .into_bytes()
    }
}

impl<S: AsRef<str>> TcpProvider<S> for ZkTlsStateProof {
    type Stream = TcpStreamOc;

    fn get(&mut self, server_address: S) -> TlsResult<Self::Stream> {
        assert_eq!(
            self.server_address,
            server_address.as_ref(),
            "Server address mismatch"
        );
        Ok(std::mem::take(&mut self.stream_ptr))
    }
}
