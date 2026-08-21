use bytes::{Bytes, BytesMut};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Display;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use tokio_serde::{Deserializer, Serializer};

/// A `tokio-serde` codec backed by `ciborium`.
///
/// Serde's buffered deserializer for internally tagged enums defaults to a
/// human-readable representation. Network types such as `SocketAddr` choose a
/// different representation for binary serializers, so using ciborium
/// directly makes encoding and decoding disagree when those types are nested
/// in a tagged enum. Converting through `serde_json::Value` makes that choice
/// explicit and consistent while ciborium still supplies the CBOR wire format.
/// The control contract is already JSON-shaped because the REST and UDS APIs
/// share the same types, so this does not narrow the values accepted by an RPC.
#[derive(Debug)]
pub struct CborCodec<Item, SinkItem> {
    marker: PhantomData<fn() -> (Item, SinkItem)>,
}

impl<Item, SinkItem> Default for CborCodec<Item, SinkItem> {
    fn default() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<Item, SinkItem> Deserializer<Item> for CborCodec<Item, SinkItem>
where
    Item: DeserializeOwned,
{
    type Error = io::Error;

    fn deserialize(self: Pin<&mut Self>, source: &BytesMut) -> Result<Item, Self::Error> {
        let mut unread = source.as_ref();
        let value: serde_json::Value = ciborium::from_reader(&mut unread).map_err(invalid_data)?;
        if !unread.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing data after CBOR value",
            ));
        }
        serde_json::from_value(value).map_err(invalid_data)
    }
}

impl<Item, SinkItem> Serializer<SinkItem> for CborCodec<Item, SinkItem>
where
    SinkItem: Serialize,
{
    type Error = io::Error;

    fn serialize(self: Pin<&mut Self>, item: &SinkItem) -> Result<Bytes, Self::Error> {
        let value = serde_json::to_value(item).map_err(invalid_data)?;
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).map_err(invalid_data)?;
        Ok(encoded.into())
    }
}

fn invalid_data(error: impl Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::CborCodec;
    use boltapi::multiplex::TwoWayMessage;
    use boltapi::{
        CapturedBodySchema, DnsEndpoint, DnsProtocol, DnsResolverSummary, DnsScope,
        GetInterceptDataResp, NetworkAddr, RouteEgress, Snapshot,
    };
    use bytes::BytesMut;
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use std::pin::Pin;
    use tokio_serde::{Deserializer, Serializer};

    fn round_trip<T>(value: &T) -> T
    where
        T: Serialize + DeserializeOwned,
    {
        let mut codec = CborCodec::<T, T>::default();
        let encoded = Pin::new(&mut codec).serialize(value).unwrap();
        Pin::new(&mut codec)
            .deserialize(&BytesMut::from(encoded.as_ref()))
            .unwrap()
    }

    fn resolver(endpoint: DnsEndpoint) -> DnsResolverSummary {
        DnsResolverSummary {
            id: "0123456789abcdef".to_string(),
            scopes: vec![DnsScope::Global { order: 0 }],
            protocol: DnsProtocol::Udp,
            endpoint,
            via: RouteEgress::Direct,
            lookups: 0,
            p50_latency_ms: None,
            last_result: None,
            last_active_at_ms: None,
        }
    }

    #[test]
    fn round_trips_socket_addresses_inside_tagged_enums() {
        let response =
            TwoWayMessage::<(), Snapshot<DnsResolverSummary>>::Response(tarpc::Response {
                request_id: 7,
                message: Ok(Snapshot {
                    observed_at_ms: 1,
                    items: vec![
                        resolver(DnsEndpoint::Network {
                            addresses: vec![NetworkAddr::Socket {
                                address: "1.1.1.1:53".parse().unwrap(),
                            }],
                        }),
                        resolver(DnsEndpoint::Dhcp {
                            interface: "eth0".to_string(),
                            current_server: Some("[2001:db8::1]:53".parse().unwrap()),
                        }),
                    ],
                }),
            });
        let decoded = round_trip(&response);
        let TwoWayMessage::Response(tarpc::Response {
            message: Ok(decoded),
            ..
        }) = decoded
        else {
            panic!("expected a successful RPC response");
        };

        assert!(matches!(
            decoded.items[0].endpoint,
            DnsEndpoint::Network { ref addresses }
                if matches!(addresses.as_slice(), [NetworkAddr::Socket { address }]
                    if *address == "1.1.1.1:53".parse().unwrap())
        ));
        assert!(matches!(
            decoded.items[1].endpoint,
            DnsEndpoint::Dhcp { ref current_server, .. }
                if *current_server == Some("[2001:db8::1]:53".parse().unwrap())
        ));
    }

    #[test]
    fn round_trips_existing_binary_body_contract() {
        let response = GetInterceptDataResp {
            req_header: vec!["content-type: application/octet-stream".to_string()],
            req_body: CapturedBodySchema::Body {
                content: vec![0, 1, 127, 128, 255],
            },
            resp_header: Vec::new(),
            resp_body: CapturedBodySchema::Empty,
        };

        let decoded = round_trip(&response);
        assert!(matches!(
            decoded.req_body,
            CapturedBodySchema::Body { content }
                if content == vec![0, 1, 127, 128, 255]
        ));
    }

    #[test]
    fn rejects_trailing_cbor_values() {
        let mut codec = CborCodec::<u64, u64>::default();
        let first = Pin::new(&mut codec).serialize(&1).unwrap();
        let second = Pin::new(&mut codec).serialize(&2).unwrap();
        let mut joined = BytesMut::from(first.as_ref());
        joined.extend_from_slice(&second);

        let error = Pin::new(&mut codec).deserialize(&joined).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("trailing data"));
    }
}
