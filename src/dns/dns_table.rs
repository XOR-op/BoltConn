use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use ipnet::Ipv4Net;

pub struct DnsRecord {
    pub domain_name: String,
    pub ip: IpAddr,
    last_time: Instant,
}

impl DnsRecord {
    fn update(&mut self) {
        self.last_time = Instant::now();
    }
}

struct DnsTableInner {
    dn_table: HashMap<String, Arc<DnsRecord>>,
    ip_table: HashMap<IpAddr, Arc<DnsRecord>>,
    available_ips: Vec<IpAddr>,
}

impl DnsTableInner {
    fn new() -> DnsTableInner {
        let mut ip_vec = Vec::<IpAddr>::with_capacity(2 << 16);
        let range: Ipv4Net = "198.19.0.0/16".parse().unwrap();
        for i in range.hosts() {
            ip_vec.push(IpAddr::V4(i))
        };
        DnsTableInner {
            dn_table: Default::default(),
            ip_table: Default::default(),
            available_ips: ip_vec,
        }
    }
}

pub struct DnsTable {
    inner: Mutex<DnsTableInner>,
    stale_time: Duration,
}

impl DnsTable {
    pub fn new() -> DnsTable {
        DnsTable {
            inner: Mutex::new(DnsTableInner::new()),
            stale_time: Duration::from_secs(3600),
        }
    }

    pub fn query_by_ip(&self, addr: IpAddr) -> Option<Arc<DnsRecord>> {
        let inner = self.inner.lock().unwrap();
        inner.ip_table.get_mut(&addr).map(|rec| {
            rec.update();
            rec.clone()
        })
    }

    pub fn query_by_domain_name(&self, domain: String) -> Arc<DnsRecord> {
        let mut inner = self.inner.lock().unwrap();
        if inner.available_ips.len() < 1024 {
            Self::flush_expiration(&mut inner, self.stale_time);
            if inner.available_ips.len() < 1024 {
                Self::flush_older(&mut inner);
            }
        }
        match inner.dn_table.get_mut(&domain) {
            None => {
                let ip = inner.available_ips.pop().unwrap();
                let record = Arc::new(DnsRecord {
                    domain_name: domain.clone(),
                    ip,
                    last_time: Instant::now(),
                });
                inner.dn_table.insert(domain, record.clone());
                inner.ip_table.insert(ip, record.clone());
                record
            }
            Some(rec) => {
                rec.update();
                rec.clone()
            }
        }
    }

    pub fn flush(&self) {
        let mut inner = self.inner.lock().unwrap();
        Self::flush_expiration(&mut inner, self.stale_time);
    }

    fn flush_expiration(inner: &mut MutexGuard<DnsTableInner>, threshold: Duration) {
        let now = Instant::now();
        inner.dn_table.retain(|_, v| now - v.last_time > threshold);
        inner.ip_table.retain(|_, v| {
            let cond = now - v.last_time > threshold;
            if !cond {
                inner.available_ips.push(v.ip);
            }
            cond
        })
    }

    // remove at least 1 entry
    fn flush_older(inner: &mut MutexGuard<DnsTableInner>) {
        let stop = inner.ip_table.len() * 0.3;
        let mut cnt = 0;
        let mut min_ts = Instant::now();
        for pair in inner.ip_table.iter() {
            if cnt < stop {
                // find mininum of first 30%
                cnt += 1;
                if pair.1.last_time < min_ts {
                    min_ts = pair.1.last_time;
                }
            }
        }
        // remove those older than that
        inner.dn_table.retain(|_, v| v.last_time > min_ts);
        inner.ip_table.retain(|_, v| {
            let cond = v.last_time > min_ts;
            if !cond {
                inner.available_ips.push(v.ip);
            }
            cond
        })
    }
}
