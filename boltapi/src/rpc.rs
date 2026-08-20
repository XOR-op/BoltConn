use crate::{
    ApiError, ConnDetail, ConnListRequest, ConnStopResult, ConnSummary, DnsLookupRequest,
    DnsLookupResponse, DnsResolverDetail, DnsResolverSummary, FakeIpMapping, GetGroupRespSchema,
    GetInterceptDataResp, HttpInterceptSchema, LinkDetail, LinkSummary, Snapshot, TrafficResp,
    TunStatusSchema,
};
use std::net::IpAddr;

pub const MAX_CODEC_FRAME_LENGTH: usize = 512 * 1024 * 1024;

#[tarpc::service]
pub trait ControlService {
    // Proxies
    async fn get_all_proxies() -> Vec<GetGroupRespSchema>;

    async fn get_proxy_group(group: String) -> Vec<GetGroupRespSchema>;

    async fn set_proxy_for(group: String, proxy: String) -> bool;

    async fn update_group_latency(group: String) -> bool;

    // Interceptions
    async fn get_all_interceptions() -> Vec<HttpInterceptSchema>;

    async fn get_range_interceptions(start: u32, end: Option<u32>) -> Vec<HttpInterceptSchema>;

    async fn get_intercepted_payload(id: u32) -> Option<GetInterceptDataResp>;

    // Observability
    async fn list_conn(request: ConnListRequest) -> Snapshot<ConnSummary>;

    async fn show_conn(id: u64) -> Result<ConnDetail, ApiError>;

    async fn stop_conn(id: u64) -> Result<ConnStopResult, ApiError>;

    async fn stop_all_conn() -> ConnStopResult;

    async fn get_conn_history_limit() -> u32;

    async fn set_conn_history_limit(limit: u32) -> u32;

    async fn list_link() -> Snapshot<LinkSummary>;

    async fn show_link(name: String) -> Result<LinkDetail, ApiError>;

    async fn stop_link(name: String) -> Result<(), ApiError>;

    async fn list_dns() -> Snapshot<DnsResolverSummary>;

    async fn show_dns(id: String) -> Result<DnsResolverDetail, ApiError>;

    async fn lookup_dns(request: DnsLookupRequest) -> Result<DnsLookupResponse, ApiError>;

    async fn get_dns_mapping(fake_ip: IpAddr) -> Result<FakeIpMapping, ApiError>;

    // Temporary rules
    async fn add_temporary_rule(rule_literal: String) -> bool;

    async fn delete_temporary_rule(rule_literal_prefix: String) -> bool;

    async fn list_temporary_rule() -> Vec<String>;

    async fn clear_temporary_rule();

    // General
    async fn get_tun() -> TunStatusSchema;

    async fn set_tun(enabled: TunStatusSchema) -> bool;

    async fn get_traffic() -> TrafficResp;

    async fn reload() -> bool;

    // Streaming
    async fn request_traffic_stream(ctx_id: u64);

    async fn request_connection_stream(ctx_id: u64);

    async fn request_log_stream(ctx_id: u64);
}

#[tarpc::service]
// Used for streaming response from server
// Achieved by setting a listener in client side
// When such methods return invalid ctx_id, we can safely terminate posting.
pub trait ClientStreamService {
    async fn post_traffic(traffic: TrafficResp) -> u64;

    async fn post_connections(snapshot: Snapshot<ConnSummary>) -> u64;

    async fn post_log(log: String) -> u64;
}
