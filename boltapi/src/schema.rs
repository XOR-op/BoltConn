use super::base64ext;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProcessSchema {
    pub pid: i32,
    pub path: String,
    pub name: String,
    pub cmdline: String,
    pub parent_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSchema {
    pub conn_id: u64,
    pub inbound: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub proxy: String,
    pub process: Option<ProcessSchema>,
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
pub struct HttpInterceptSchema {
    pub intercept_id: u64,
    pub client: Option<String>,
    pub uri: String,
    pub method: String,
    pub status: u16,
    pub size: Option<u64>,
    pub start_time: u64,
    pub duration: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProxyData {
    pub name: String,
    pub proto: String,
    pub latency: Option<String>,
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
pub struct GetInterceptRangeReq {
    pub start: u32,
    pub end: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetInterceptDataReq {
    pub id: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, tag = "type")]
pub enum CapturedBodySchema {
    #[serde(rename = "empty")]
    Empty,
    #[serde(rename = "warning")]
    Warning { content: String },
    #[serde(rename = "body")]
    Body {
        #[serde(with = "base64ext")]
        content: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetInterceptDataResp {
    pub req_header: Vec<String>,
    pub req_body: CapturedBodySchema,
    pub resp_header: Vec<String>,
    pub resp_body: CapturedBodySchema,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrafficResp {
    pub upload: u64,
    pub download: u64,
    pub upload_speed: Option<u64>,
    pub download_speed: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TunStatusSchema {
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct MasterConnectionStatus {
    pub name: String,
    pub alive: bool,
    pub last_active: u64,
    pub last_handshake: u64,
    pub hand_shake_is_expired: bool,
}
