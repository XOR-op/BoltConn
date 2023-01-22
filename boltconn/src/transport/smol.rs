use crate::adapter::Connector;
use dashmap::DashMap;
use std::sync::Arc;

pub struct SmolStack {
    tcp_conn: DashMap<u16, Arc<Connector>>,
    udp_conn: DashMap<u16, Arc<Connector>>,
}

impl SmolStack {
    pub fn new() -> Self {
        todo!()
    }
}
