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
        format!("{:x}:{}", self.id, self.message)
    }

    pub fn decode_string(encoded: &str) -> Option<Self> {
        let mut parts = encoded.splitn(2, ':');
        let id = u64::from_str_radix(parts.next()?, 16).ok()?;
        let message = parts.next()?.to_string();
        Some(Self { id, message })
    }
}

#[test]
fn test_instrument_data() {
    let data = InstrumentData {
        id: 0x1234,
        message: "hello".to_string(),
    };
    let encoded = data.encode_string();
    assert_eq!(encoded, "1234:hello");
    let decoded = InstrumentData::decode_string(&encoded).unwrap();
    assert_eq!(decoded.id, data.id);
    assert_eq!(decoded.message, data.message);
}
