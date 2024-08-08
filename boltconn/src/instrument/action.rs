use crate::config::{ConfigError, InstrumentConfigError};
use crate::dispatch::RuleImpl;
use crate::dispatch::{ConnInfo, InboundInfo};
use crate::instrument::bus::{BusMessage, BusPublisher};
use interpolator::Formattable;
use std::collections::HashMap;

//----------------------------------------------------------------------
pub struct InstrumentAction {
    rule: RuleImpl,
    sub_id: u64,
    fmt_obj: FormattingObject,
    bus_publisher: BusPublisher,
}

impl InstrumentAction {
    pub fn new(
        rule: RuleImpl,
        sub_id: u64,
        fmt_template: String,
        bus_publisher: BusPublisher,
    ) -> Result<Self, ConfigError> {
        let fmt_obj = FormattingObject::new(fmt_template)?;
        Ok(Self {
            rule,
            sub_id,
            fmt_obj,
            bus_publisher,
        })
    }

    pub async fn execute(&self, info: &ConnInfo) {
        if self.rule.matches(info) {
            let str = self.fmt_obj.format(info);
            self.bus_publisher
                .publish(BusMessage::new(self.sub_id, str));
        }
    }
}

struct FormattingObject {
    usr_template: String,
}

impl FormattingObject {
    pub fn new(usr_template: String) -> Result<Self, ConfigError> {
        let mock_info = ConnInfo {
            src: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(127, 0, 0, 1),
                8080,
            )),
            dst: crate::proxy::NetworkAddr::DomainName {
                domain_name: "example.com".to_string(),
                port: 443,
            },
            local_ip: None,
            inbound: InboundInfo::Tun,
            resolved_dst: None,
            connection_type: crate::platform::process::NetworkType::Tcp,
            process_info: None,
        };
        if let Err(e) = Self::format_inner(usr_template.as_str(), &mock_info) {
            return Err(ConfigError::Instrument(InstrumentConfigError::BadTemplate(
                usr_template.to_string(),
                e.to_string(),
            )));
        }
        Ok(Self { usr_template })
    }

    pub fn format(&self, info: &ConnInfo) -> String {
        Self::format_inner(self.usr_template.as_str(), info).expect("Infallible after check")
    }

    fn format_inner(template: &str, info: &ConnInfo) -> Result<String, interpolator::Error> {
        let na_str = "N/A";

        let now = chrono::Local::now();
        let time_rfc3389 = now.to_rfc3339();
        let time_hms_ms = now.format("%H:%M:%S%.3f").to_string();
        let time_datetime = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let time_datetime_ms = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();

        let local_ip = info
            .local_ip
            .map_or_else(|| na_str.to_string(), |ip| ip.to_string());
        let resolved_dst = info
            .resolved_dst
            .map_or_else(|| na_str.to_string(), |addr| addr.to_string());

        // inbound info
        let inbound_type = match &info.inbound {
            InboundInfo::Tun => "tun",
            InboundInfo::Http(_) => "http",
            InboundInfo::Socks5(_) => "socks5",
        };
        let inbound_port = match &info.inbound {
            InboundInfo::Tun => None,
            InboundInfo::Http(user) | InboundInfo::Socks5(user) => user.port,
        }
        .map_or_else(|| na_str.to_string(), |port| port.to_string());
        let inbound_username = match &info.inbound {
            InboundInfo::Tun => None,
            InboundInfo::Http(user) | InboundInfo::Socks5(user) => user.user.clone(),
        }
        .unwrap_or("N/A".to_string());

        // process info
        let process_name = info
            .process_info
            .as_ref()
            .map_or_else(|| na_str.to_string(), |info| info.name.clone());
        let process_cmdline = info
            .process_info
            .as_ref()
            .map_or_else(|| na_str.to_string(), |info| info.cmdline.clone());
        let process_path = info
            .process_info
            .as_ref()
            .map_or_else(|| na_str.to_string(), |info| info.path.clone());
        let process_pid = info
            .process_info
            .as_ref()
            .map_or_else(|| na_str.to_string(), |info| info.pid.to_string());
        let process_ppid = info
            .process_info
            .as_ref()
            .map_or_else(|| na_str.to_string(), |info| info.ppid.to_string());
        let process_pname = info.process_info.as_ref().map_or_else(
            || na_str.to_string(),
            |info| {
                info.parent_name
                    .clone()
                    .unwrap_or_else(|| na_str.to_string())
            },
        );

        // Collect to hashmap; needed to be exported to end user, so consistency of key name is important here.
        let mapping = [
            ("addr.src", Formattable::display(&info.src)),
            ("addr.dst", Formattable::display(&info.dst)),
            ("addr.resolved_dst", Formattable::display(&resolved_dst)),
            ("ip.local", Formattable::display(&local_ip)),
            ("inbound.type", Formattable::display(&inbound_type)),
            ("inbound.port", Formattable::display(&inbound_port)),
            ("inbound.user", Formattable::display(&inbound_username)),
            ("conn.type", Formattable::display(&info.connection_type)),
            ("process.name", Formattable::display(&process_name)),
            ("process.cmdline", Formattable::display(&process_cmdline)),
            ("process.path", Formattable::display(&process_path)),
            ("process.pid", Formattable::display(&process_pid)),
            ("process.ppid", Formattable::display(&process_ppid)),
            ("process.parent_name", Formattable::display(&process_pname)),
            ("time.rfc3389", Formattable::display(&time_rfc3389)),
            ("time.hms_ms", Formattable::display(&time_hms_ms)),
            ("time.datetime", Formattable::display(&time_datetime)),
            ("time.datetime_ms", Formattable::display(&time_datetime_ms)),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();
        interpolator::format(template, &mapping)
    }
}

#[test]
fn test_instrument_formatting() {
    let template = "src: {addr.src}, dst: {addr.dst}, resolved_dst: {addr.resolved_dst}, \
    local_ip: {ip.local}, conn_type: {conn.type}, \
     inbound_type: {inbound.type}, inbound_port: {inbound.port}, inbound_user: {inbound.user}, \
     process_name: {process.name}, process_cmdline: {process.cmdline}, process_path: {process.path}, \
     process_pid: {process.pid}, process_ppid: {process.ppid}, process_parent_name: {process.parent_name}\
     time: [{time.rfc3389}, {time.hms_ms}, {time.datetime}, {time.datetime_ms}]";
    let info = ConnInfo {
        src: std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::new(192, 168, 0, 1),
            8080,
        )),
        dst: crate::proxy::NetworkAddr::DomainName {
            domain_name: "example.com".to_string(),
            port: 443,
        },
        local_ip: None,
        inbound: InboundInfo::Tun,
        resolved_dst: None,
        connection_type: crate::platform::process::NetworkType::Tcp,
        process_info: None,
    };
    let fmt_obj = FormattingObject::new(template.to_string()).unwrap();
    let _ = fmt_obj.format(&info);
}
