use serde::{Deserialize, Serialize};

/// Wire format for instrumentation data.
#[derive(Debug, Clone)]
pub struct InstrumentData {
    /// Unique identifier for the instrument.
    pub id: u64,
    /// Message to be sent.
    pub message: String,
}

impl InstrumentData {
    pub fn encode_string(&self) -> String {
        format!("{}:{}", self.id, self.message)
    }

    pub fn decode_string(encoded: &str) -> Option<Self> {
        let mut parts = encoded.splitn(2, ':');
        let id = parts.next()?.parse::<u64>().ok()?;
        let message = parts.next()?.to_string();
        Some(Self { id, message })
    }
}

/// Payload sent inside `InstrumentData.message` (as JSON) for `.REQUEST` actions.
#[derive(Serialize)]
pub struct RequestPayload {
    pub sub_id: u64,
    pub request_id: u64,
    pub suggested_route: String,
    pub addr_src: String,
    pub addr_dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr_resolved_dst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_local: Option<String>,
    pub inbound_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inbound_user: Option<String>,
    pub conn_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_cmdline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_tag: Option<String>,
    pub process_parent_all: serde_json::Value,
    pub time_hms_ms: String,
}

/// Sent by a client over WebSocket to respond to a `.REQUEST` action.
#[derive(Deserialize)]
pub struct RequestResponse {
    pub sub_id: u64,
    pub request_id: u64,
    pub route: String,
}

#[test]
fn test_instrument_data() {
    let data = InstrumentData {
        id: 1234,
        message: "hello".to_string(),
    };
    let encoded = data.encode_string();
    assert_eq!(encoded, "1234:hello");
    let decoded = InstrumentData::decode_string(&encoded).unwrap();
    assert_eq!(decoded.id, data.id);
    assert_eq!(decoded.message, data.message);
}
