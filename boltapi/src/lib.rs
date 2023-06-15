pub mod multiplex;
pub mod rpc;
mod schema;

pub use schema::*;

pub(crate) mod base64ext {
    use serde::Deserialize;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(base64::encode(data).as_str())
    }

    pub fn deserialize<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        use serde::de::Error;
        String::deserialize(deserializer)
            .and_then(|string| base64::decode(string).map_err(|err| Error::custom(err.to_string())))
    }
}
