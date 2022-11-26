use crate::common::duplex_chan::DuplexChan;
use http::{Request, Response};
use hyper::client::conn;
use hyper::Body;

mod http_sniffer;
mod https_sniffer;
mod modifier;
mod pkt_coll;

pub use http_sniffer::HttpSniffer;
pub use https_sniffer::HttpsSniffer;
