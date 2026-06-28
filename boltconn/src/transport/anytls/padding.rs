use super::{Command, HEADER_LEN};
use crate::proxy::error::TransportError;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::collections::BTreeMap;
use std::io;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaddingScheme {
    raw_scheme: Bytes,
    stop: u32,
    records: BTreeMap<u32, Vec<PaddingItem>>,
    md5_hex: String,
}

impl PaddingScheme {
    pub fn parse(raw_scheme: &[u8]) -> Result<Self, TransportError> {
        let text = std::str::from_utf8(raw_scheme)
            .map_err(|_| TransportError::Anytls("AnyTLS padding scheme is not UTF-8"))?;
        let mut stop = None;
        let mut records = BTreeMap::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            if key == "stop" {
                stop = Some(value.parse::<u32>().map_err(|_| {
                    TransportError::Anytls("AnyTLS padding scheme has invalid stop")
                })?);
                continue;
            }
            let Ok(record_id) = key.parse::<u32>() else {
                continue;
            };
            let plan = parse_padding_items(value);
            if !plan.is_empty() {
                records.insert(record_id, plan);
            }
        }

        let stop = stop.ok_or(TransportError::Anytls(
            "AnyTLS padding scheme missing stop value",
        ))?;
        Ok(Self {
            raw_scheme: Bytes::copy_from_slice(raw_scheme),
            stop,
            records,
            md5_hex: format!("{:x}", md5::compute(raw_scheme)),
        })
    }

    pub fn raw_scheme(&self) -> &[u8] {
        &self.raw_scheme
    }

    pub fn md5_hex(&self) -> &str {
        &self.md5_hex
    }

    fn generated_record_payload_sizes(&self, record_id: u32) -> Vec<GeneratedPaddingItem> {
        self.records
            .get(&record_id)
            .map(|items| {
                items
                    .iter()
                    .map(|item| match item {
                        PaddingItem::Check => GeneratedPaddingItem::Check,
                        PaddingItem::Range { min, max } if min == max => {
                            GeneratedPaddingItem::Size(*min)
                        }
                        PaddingItem::Range { min, max } => {
                            GeneratedPaddingItem::Size(fastrand::usize(*min..*max))
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn auth_padding_len(&self) -> usize {
        self.generated_record_payload_sizes(0)
            .into_iter()
            .find_map(|item| match item {
                GeneratedPaddingItem::Size(size) => Some(size),
                GeneratedPaddingItem::Check => None,
            })
            .unwrap_or_default()
    }
}

impl Default for PaddingScheme {
    fn default() -> Self {
        Self::parse(DEFAULT_PADDING_SCHEME).expect("default AnyTLS padding scheme is valid")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PaddingItem {
    Range { min: usize, max: usize },
    Check,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeneratedPaddingItem {
    Size(usize),
    Check,
}

fn parse_padding_items(value: &str) -> Vec<PaddingItem> {
    value
        .split(',')
        .filter_map(|item| {
            let item = item.trim();
            if item == "c" {
                return Some(PaddingItem::Check);
            }
            let (left, right) = item.split_once('-')?;
            let left = left.trim().parse::<usize>().ok()?;
            let right = right.trim().parse::<usize>().ok()?;
            let min = min(left, right);
            let max = left.max(right);
            if min == 0 || max == 0 {
                return None;
            }
            Some(PaddingItem::Range { min, max })
        })
        .collect()
}

pub(super) struct PaddingWriter {
    scheme: PaddingScheme,
    packet_counter: u32,
    send_padding: bool,
}

impl PaddingWriter {
    pub(super) fn new(scheme: PaddingScheme) -> Self {
        Self {
            scheme,
            packet_counter: 0,
            send_padding: true,
        }
    }

    pub(super) async fn write_packet<W>(&mut self, writer: &mut W, data: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if data.is_empty() {
            return Ok(());
        }

        if !self.send_padding {
            writer.write_all(data).await?;
            return Ok(());
        }

        self.packet_counter = self.packet_counter.saturating_add(1);
        if self.packet_counter >= self.scheme.stop {
            self.send_padding = false;
            writer.write_all(data).await?;
            return Ok(());
        }

        let sizes = self
            .scheme
            .generated_record_payload_sizes(self.packet_counter);
        if sizes.is_empty() {
            writer.write_all(data).await?;
            return Ok(());
        }

        // The upstream writer treats one logical session write as a padding unit:
        // split payload first, then use cmdWaste frames only when payload runs out.
        let mut offset = 0usize;
        for item in sizes {
            let remaining = data.len().saturating_sub(offset);
            match item {
                GeneratedPaddingItem::Check => {
                    if remaining == 0 {
                        break;
                    }
                }
                GeneratedPaddingItem::Size(size) if remaining > size => {
                    writer.write_all(&data[offset..offset + size]).await?;
                    offset += size;
                }
                GeneratedPaddingItem::Size(size) if remaining > 0 => {
                    let mut packet = Vec::with_capacity(size.max(remaining));
                    packet.extend(&data[offset..]);
                    if size > remaining + HEADER_LEN {
                        append_waste_frame(&mut packet, size - remaining - HEADER_LEN)?;
                    }
                    writer.write_all(&packet).await?;
                    offset = data.len();
                }
                GeneratedPaddingItem::Size(size) => {
                    let mut packet = Vec::with_capacity(HEADER_LEN + size);
                    append_waste_frame(&mut packet, size)?;
                    writer.write_all(&packet).await?;
                }
            }
        }

        if offset < data.len() {
            writer.write_all(&data[offset..]).await?;
        }
        Ok(())
    }
}

fn append_waste_frame(packet: &mut Vec<u8>, padding_len: usize) -> io::Result<()> {
    let padding_len = u16::try_from(padding_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "AnyTLS waste frame exceeded u16::MAX",
        )
    })?;
    packet.push(Command::Waste.wire_value());
    packet.extend(0u32.to_be_bytes());
    packet.extend(padding_len.to_be_bytes());
    packet.resize(packet.len() + padding_len as usize, 0);
    Ok(())
}

pub(super) fn build_authentication_request(
    password: &str,
    padding_scheme: &PaddingScheme,
) -> Result<Vec<u8>, TransportError> {
    let padding_len = padding_scheme.auth_padding_len();
    let padding_len = u16::try_from(padding_len)
        .map_err(|_| TransportError::Anytls("AnyTLS auth padding exceeded u16::MAX"))?;
    let mut request = Vec::with_capacity(32 + 2 + padding_len as usize);
    request.extend(Sha256::digest(password.as_bytes()));
    request.extend(padding_len.to_be_bytes());
    request.resize(request.len() + padding_len as usize, 0);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_package_matches_known_vectors() {
        assert_eq!(
            format!("{:x}", md5::compute(b"")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            format!("{:x}", md5::compute(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn parses_default_padding_scheme() {
        let scheme = PaddingScheme::default();
        assert_eq!(scheme.stop, 8);
        assert_eq!(scheme.auth_padding_len(), 30);
        assert!(!scheme.md5_hex().is_empty());
    }
}
