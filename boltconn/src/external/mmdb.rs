use maxminddb::geoip2;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::path::Path;

pub struct MmdbReader {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl MmdbReader {
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self, maxminddb::MaxMindDBError> {
        let reader = maxminddb::Reader::open_readfile(path)?;
        Ok(Self { reader })
    }

    pub fn search_asn(&self, ip: IpAddr) -> Option<u32> {
        let asn: geoip2::Asn = self.reader.lookup(ip).ok()?;
        asn.autonomous_system_number
    }

    pub fn search_country(&self, ip: IpAddr) -> Option<&str> {
        let country: geoip2::Country = self.reader.lookup(ip).ok()?;
        country
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .or_else(|| country.registered_country.as_ref().and_then(|c| c.iso_code))
    }
}

impl Debug for MmdbReader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("MMDB")
    }
}
