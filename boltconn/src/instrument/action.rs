use crate::config::{ConfigError, InstrumentConfigError};
use crate::dispatch::RuleImpl;
use crate::dispatch::{ConnInfo, InboundInfo};
use crate::instrument::bus::{BusMessage, BusPublisher};
use crate::platform::process::{ParentProcess, ProcessInfo};
use boltapi::ProcessParentSchema;
use interpolator::Formattable;

static NA_STR: &str = "N/A";

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
        let context = InstrumentContext::new(info);
        interpolator::format(template, &context)
    }
}

#[derive(Clone, Copy)]
enum ProcessAncestor<'a> {
    Info(&'a ProcessInfo),
    Pid(&'a i32),
}

struct InstrumentContext<'a> {
    info: &'a ConnInfo,
    inbound_type: &'static str,
    local_ip: String,
    resolved_dst: String,
    inbound_port: String,
    inbound_username: String,
    time_rfc3389: String,
    time_hms_ms: String,
    time_datetime: String,
    time_datetime_ms: String,
    process_parent_all_json: String,
}

impl<'a> InstrumentContext<'a> {
    fn new(info: &'a ConnInfo) -> Self {
        let now = chrono::Local::now();
        Self {
            info,
            inbound_type: match &info.inbound {
                InboundInfo::Tun => "tun",
                InboundInfo::Http(_) => "http",
                InboundInfo::Socks5(_) => "socks5",
            },
            local_ip: info
                .local_ip
                .map_or_else(|| NA_STR.to_string(), |ip| ip.to_string()),
            resolved_dst: info
                .resolved_dst
                .map_or_else(|| NA_STR.to_string(), |addr| addr.to_string()),
            inbound_port: match &info.inbound {
                InboundInfo::Tun => None,
                InboundInfo::Http(user) | InboundInfo::Socks5(user) => user.port,
            }
            .map_or_else(|| NA_STR.to_string(), |port| port.to_string()),
            inbound_username: match &info.inbound {
                InboundInfo::Tun => None,
                InboundInfo::Http(user) | InboundInfo::Socks5(user) => user.user.clone(),
            }
            .unwrap_or_else(|| NA_STR.to_string()),
            time_rfc3389: now.to_rfc3339(),
            time_hms_ms: now.format("%H:%M:%S%.3f").to_string(),
            time_datetime: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            time_datetime_ms: now.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            process_parent_all_json: Self::serialize_all_parents(info.process_info.as_ref()),
        }
    }

    fn na<'b>() -> Formattable<'b> {
        Formattable::display(&NA_STR)
    }

    fn process_ancestor(&self, index: usize) -> Option<ProcessAncestor<'a>> {
        let mut current = &self.info.process_info.as_ref()?.parent;
        let mut remaining = index;
        loop {
            match current {
                ParentProcess::None => return None,
                ParentProcess::Ppid(ppid) => {
                    return if remaining == 0 {
                        Some(ProcessAncestor::Pid(ppid))
                    } else {
                        None
                    };
                }
                ParentProcess::Process(parent) => {
                    if remaining == 0 {
                        return Some(ProcessAncestor::Info(parent.as_ref()));
                    }
                    remaining -= 1;
                    current = &parent.parent;
                }
            }
        }
    }

    fn process_parent_field(&self, index: usize, field: &str) -> Option<Formattable<'_>> {
        match self.process_ancestor(index) {
            Some(ProcessAncestor::Info(info)) => match field {
                "pid" => Some(Formattable::display(&info.pid)),
                "name" => Some(Formattable::display(&info.name)),
                "path" => Some(Formattable::display(&info.path)),
                "cmdline" => Some(Formattable::display(&info.cmdline)),
                _ => None,
            },
            Some(ProcessAncestor::Pid(pid)) => match field {
                "pid" => Some(Formattable::display(pid)),
                "name" | "path" | "cmdline" => Some(Self::na()),
                _ => None,
            },
            None => match field {
                "pid" | "name" | "path" | "cmdline" => Some(Self::na()),
                _ => None,
            },
        }
    }

    fn indexed_parent_field(&self, key: &str) -> Option<Formattable<'_>> {
        let mut parts = key.split('.');
        match (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) {
            (Some("process"), Some("parents"), Some(index), Some(field), None) => index
                .parse::<usize>()
                .ok()
                .and_then(|idx| self.process_parent_field(idx, field)),
            _ => None,
        }
    }

    fn collect_all_parents(info: Option<&ProcessInfo>) -> Vec<ProcessParentSchema> {
        let mut parents = Vec::new();
        let Some(info) = info else {
            return parents;
        };
        let mut current = &info.parent;
        loop {
            match current {
                ParentProcess::None => break,
                ParentProcess::Ppid(ppid) => {
                    parents.push(ProcessParentSchema {
                        pid: *ppid,
                        name: None,
                        path: None,
                        cmdline: None,
                        cwd: None,
                    });
                    break;
                }
                ParentProcess::Process(parent) => {
                    parents.push(ProcessParentSchema {
                        pid: parent.pid,
                        name: Some(parent.name.clone()),
                        path: Some(parent.path.clone()),
                        cmdline: Some(parent.cmdline.clone()),
                        cwd: Some(parent.cwd.clone()),
                    });
                    current = &parent.parent;
                }
            }
        }
        parents
    }

    fn serialize_all_parents(info: Option<&ProcessInfo>) -> String {
        serde_json::to_string(&Self::collect_all_parents(info)).unwrap_or_else(|_| "[]".to_string())
    }
}

impl interpolator::Context for InstrumentContext<'_> {
    fn get(&self, key: &str) -> Option<Formattable<'_>> {
        match key {
            "addr.src" => Some(Formattable::display(&self.info.src)),
            "addr.dst" => Some(Formattable::display(&self.info.dst)),
            "addr.resolved_dst" => Some(Formattable::display(&self.resolved_dst)),
            "ip.local" => Some(Formattable::display(&self.local_ip)),
            "inbound.type" => Some(Formattable::display(&self.inbound_type)),
            "inbound.port" => Some(Formattable::display(&self.inbound_port)),
            "inbound.user" => Some(Formattable::display(&self.inbound_username)),
            "conn.type" => Some(Formattable::display(&self.info.connection_type)),
            "process.name" => Some(
                self.info
                    .process_info
                    .as_ref()
                    .map_or_else(Self::na, |info| Formattable::display(&info.name)),
            ),
            "process.cmdline" => Some(
                self.info
                    .process_info
                    .as_ref()
                    .map_or_else(Self::na, |info| Formattable::display(&info.cmdline)),
            ),
            "process.path" => Some(
                self.info
                    .process_info
                    .as_ref()
                    .map_or_else(Self::na, |info| Formattable::display(&info.path)),
            ),
            "process.pid" => Some(
                self.info
                    .process_info
                    .as_ref()
                    .map_or_else(Self::na, |info| Formattable::display(&info.pid)),
            ),
            "process.parent.pid" => self.process_parent_field(0, "pid"),
            "process.parent.name" => self.process_parent_field(0, "name"),
            "process.parent.path" => self.process_parent_field(0, "path"),
            "process.parent.cmdline" => self.process_parent_field(0, "cmdline"),
            "process.parent.all.json" => Some(Formattable::display(&self.process_parent_all_json)),
            "time.rfc3389" => Some(Formattable::display(&self.time_rfc3389)),
            "time.hms_ms" => Some(Formattable::display(&self.time_hms_ms)),
            "time.datetime" => Some(Formattable::display(&self.time_datetime)),
            "time.datetime_ms" => Some(Formattable::display(&self.time_datetime_ms)),
            _ => self.indexed_parent_field(key),
        }
    }
}

#[test]
fn test_instrument_formatting() {
    let template = "src: {addr.src}, dst: {addr.dst}, resolved_dst: {addr.resolved_dst}, \
local_ip: {ip.local}, conn_type: {conn.type}, \
inbound_type: {inbound.type}, inbound_port: {inbound.port}, inbound_user: {inbound.user}, \
process_name: {process.name}, process_cmdline: {process.cmdline}, process_path: {process.path}, \
process_pid: {process.pid}, process_parent_pid: {process.parent.pid}, \
process_parent_name: {process.parent.name}, process_parent_path: {process.parent.path}, \
process_parent_cmdline: {process.parent.cmdline}, process_parent_indexed_name: {process.parents.0.name}, \
process_parent_all_json: {process.parent.all.json}, \
time: {time.hms_ms}";
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
    let rendered = fmt_obj.format(&info);
    let (prefix, time_suffix) = rendered.split_once("time: ").unwrap();
    assert_eq!(
        prefix,
        "src: 192.168.0.1:8080, dst: example.com:443, resolved_dst: N/A, \
local_ip: N/A, conn_type: tcp, \
inbound_type: tun, inbound_port: N/A, inbound_user: N/A, \
process_name: N/A, process_cmdline: N/A, process_path: N/A, \
process_pid: N/A, process_parent_pid: N/A, \
process_parent_name: N/A, process_parent_path: N/A, \
process_parent_cmdline: N/A, process_parent_indexed_name: N/A, \
process_parent_all_json: [], "
    );
    assert!(chrono::NaiveTime::parse_from_str(time_suffix, "%H:%M:%S%.3f").is_ok());
}

fn mock_process(pid: i32, name: &str, parent: ParentProcess) -> ProcessInfo {
    ProcessInfo {
        pid,
        parent,
        path: format!("/bin/{name}"),
        name: name.to_string(),
        cmdline: format!("{name} --serve"),
        cwd: format!("/tmp/{name}"),
    }
}

fn mock_conn_info(process_info: Option<ProcessInfo>) -> ConnInfo {
    ConnInfo {
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
        process_info,
    }
}

#[test]
fn test_instrument_formatting_supports_deep_parent_chain() {
    let process_info = mock_process(
        10,
        "curl",
        ParentProcess::Process(Box::new(mock_process(
            20,
            "python",
            ParentProcess::Process(Box::new(mock_process(
                30,
                "bash",
                ParentProcess::Process(Box::new(mock_process(40, "launchd", ParentProcess::None))),
            ))),
        ))),
    );
    let info = mock_conn_info(Some(process_info));
    let template = "\
process={process.name} \
parent={process.parent.name}/{process.parents.0.name}/{process.parents.0.pid} \
grandparent={process.parents.1.name}/{process.parents.1.cmdline} \
great={process.parents.2.path} \
all={process.parent.all.json}";

    let rendered = FormattingObject::format_inner(template, &info).unwrap();

    assert_eq!(
        rendered,
        "process=curl parent=python/python/20 grandparent=bash/bash --serve great=/bin/launchd all=[{\"pid\":20,\"name\":\"python\",\"path\":\"/bin/python\",\"cmdline\":\"python --serve\",\"cwd\":\"/tmp/python\"},{\"pid\":30,\"name\":\"bash\",\"path\":\"/bin/bash\",\"cmdline\":\"bash --serve\",\"cwd\":\"/tmp/bash\"},{\"pid\":40,\"name\":\"launchd\",\"path\":\"/bin/launchd\",\"cmdline\":\"launchd --serve\",\"cwd\":\"/tmp/launchd\"}]"
    );
}

#[test]
fn test_instrument_formatting_handles_pid_only_parent_leaf() {
    let process_info = mock_process(
        10,
        "curl",
        ParentProcess::Process(Box::new(mock_process(
            20,
            "python",
            ParentProcess::Ppid(999),
        ))),
    );
    let info = mock_conn_info(Some(process_info));
    let template = "\
parent={process.parents.0.name}/{process.parents.0.pid} \
ancestor_pid_only={process.parents.1.pid}/{process.parents.1.name}/{process.parents.1.path} \
missing={process.parents.2.pid} \
all={process.parent.all.json}";

    let rendered = FormattingObject::format_inner(template, &info).unwrap();

    assert_eq!(
        rendered,
        "parent=python/20 ancestor_pid_only=999/N/A/N/A missing=N/A all=[{\"pid\":20,\"name\":\"python\",\"path\":\"/bin/python\",\"cmdline\":\"python --serve\",\"cwd\":\"/tmp/python\"},{\"pid\":999,\"name\":null,\"path\":null,\"cmdline\":null,\"cwd\":null}]"
    );
}

#[test]
fn test_instrument_template_validation_accepts_high_parent_index() {
    let template = "ancestor={process.parents.9.name}";
    assert!(FormattingObject::new(template.to_string()).is_ok());
}

#[test]
fn test_instrument_formatting_handles_empty_parent_json() {
    let info = mock_conn_info(None);
    let rendered = FormattingObject::format_inner("all={process.parent.all.json}", &info).unwrap();
    assert_eq!(rendered, "all=[]");
}

#[test]
fn test_instrument_template_validation_accepts_parent_json() {
    let template = "ancestor={process.parent.all.json}";
    assert!(FormattingObject::new(template.to_string()).is_ok());
}
