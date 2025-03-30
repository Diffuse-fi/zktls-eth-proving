use serde::Deserialize;

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct RpcResponse<T> {
    jsonrpc: String,
    id: u32,
    pub(crate) result: T,
}
