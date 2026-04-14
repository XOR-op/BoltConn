use crate::ProcessParentSchema;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPayload {
    pub sub_id: u64,
    pub request_id: u64,
    pub suggested_route: String,
    /// Seconds until the server applies the rule fallback if no reply is received.
    pub timeout: u64,
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
    pub process_cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_tag: Option<String>,
    pub process_parent_all: Vec<ProcessParentSchema>,
    pub time_hms_ms: String,
}

/// Sent by a client over WebSocket to respond to a `.REQUEST` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponse {
    pub sub_id: u64,
    pub request_id: u64,
    /// Valid values are CONTINUE, REJECT, BLACKHOLE, and FALLBACK.
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

#[test]
fn test_request_payload_round_trip() {
    let payload = RequestPayload {
        sub_id: 7,
        request_id: 11,
        suggested_route: "CONTINUE".to_string(),
        timeout: 30,
        addr_src: "127.0.0.1:12345".to_string(),
        addr_dst: "example.com:443".to_string(),
        addr_resolved_dst: Some("93.184.216.34:443".to_string()),
        ip_local: Some("192.168.1.10".to_string()),
        inbound_type: "tun".to_string(),
        inbound_port: None,
        inbound_user: None,
        conn_type: "tcp".to_string(),
        process_name: Some("curl".to_string()),
        process_cmdline: Some("curl https://example.com".to_string()),
        process_path: Some("/usr/bin/curl".to_string()),
        process_cwd: Some("/tmp".to_string()),
        process_pid: Some(1234),
        process_tag: Some("tagged".to_string()),
        process_parent_all: vec![ProcessParentSchema {
            pid: 999,
            name: Some("bash".to_string()),
            path: Some("/bin/bash".to_string()),
            cmdline: Some("bash".to_string()),
            cwd: Some("/tmp".to_string()),
        }],
        time_hms_ms: "10:11:12.123".to_string(),
    };

    let encoded = serde_json::to_string(&payload).unwrap();
    let decoded: RequestPayload = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.sub_id, payload.sub_id);
    assert_eq!(decoded.timeout, payload.timeout);
    assert_eq!(decoded.process_cwd.as_deref(), Some("/tmp"));
    assert_eq!(decoded.process_parent_all.len(), 1);
    assert_eq!(decoded.process_parent_all[0].pid, 999);
}

#[test]
fn test_request_response_round_trip() {
    let response = RequestResponse {
        sub_id: 7,
        request_id: 11,
        route: "FALLBACK".to_string(),
    };

    let encoded = serde_json::to_string(&response).unwrap();
    let decoded: RequestResponse = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.sub_id, response.sub_id);
    assert_eq!(decoded.request_id, response.request_id);
    assert_eq!(decoded.route, "FALLBACK");
}
