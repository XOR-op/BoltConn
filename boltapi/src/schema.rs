use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSchema {
    pub destination: String,
    pub protocol: String,
    pub proxy: String,
    pub process: Option<String>,
    pub upload: String,
    pub download: String,
    pub time: String,
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
pub struct HttpCaptureSchema {
    pub uri: String,
    pub method: String,
    pub status: u16,
    pub size: String,
    pub time: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct GetGroupRespSchema {
    pub name: String,
    pub selected: String,
    pub list: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct SetGroupReqSchema {
    pub group: String,
    pub selected: String,
}
