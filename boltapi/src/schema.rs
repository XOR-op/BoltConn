use super::base64ext;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSchema {
    pub conn_id: u64,
    pub destination: String,
    pub protocol: String,
    pub proxy: String,
    pub process: Option<String>,
    pub upload: u64,
    pub download: u64,
    pub start_time: u64,
    pub active: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct SessionSchema {
    pub pair: String,
    pub time: String,
    pub tcp_open: Option<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct HttpMitmSchema {
    pub mitm_id: u64,
    pub client: Option<String>,
    pub uri: String,
    pub method: String,
    pub status: u16,
    pub size: u64,
    pub time: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyData {
    pub name: String,
    pub proto: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetGroupRespSchema {
    pub name: String,
    pub selected: String,
    pub list: Vec<ProxyData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct SetGroupReqSchema {
    pub selected: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetMitmRangeReq {
    pub start: u32,
    pub end: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetMitmDataReq {
    pub id: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetMitmDataResp {
    pub req_header: Vec<String>,
    #[serde(with = "base64ext")]
    pub req_body: Vec<u8>,
    pub resp_header: Vec<String>,
    #[serde(with = "base64ext")]
    pub resp_body: Vec<u8>,
}
