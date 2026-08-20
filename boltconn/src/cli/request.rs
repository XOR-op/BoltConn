use crate::cli::request_uds::UdsConnector;
use crate::cli::request_web::WebConnector;
use crate::cli::{conn, dns, format, link};
use anyhow::{Result, anyhow};
use boltapi::{ApiError, ApiErrorCode, CapturedBodySchema, ConnListRequest, DnsLookupRequest};
use colored::Colorize;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use tabular::{Row, Table};

enum Inner {
    Web(WebConnector),
    Uds(UdsConnector),
}

pub struct Requester {
    inner: Inner,
}

#[derive(Debug)]
pub(super) struct ControlApiError {
    pub(super) code: ApiErrorCode,
    message: String,
}

impl From<ApiError> for ControlApiError {
    fn from(error: ApiError) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }
}

impl Display for ControlApiError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {}",
            format::enum_name(&self.code),
            self.message
        )
    }
}

impl std::error::Error for ControlApiError {}

pub(super) fn api_error(error: ApiError) -> anyhow::Error {
    ControlApiError::from(error).into()
}

impl Requester {
    pub fn new_web(url: String) -> Result<Self> {
        if let Err(err) = reqwest::Url::parse(url.as_str()) {
            return Err(anyhow!("{}", err));
        }
        Ok(Self {
            inner: Inner::Web(WebConnector::new(url)),
        })
    }

    pub async fn new_uds(path: &str) -> Result<Self> {
        Ok(Self {
            inner: Inner::Uds(UdsConnector::new(path).await?.0),
        })
    }

    pub async fn get_group_list(&self, full: bool) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.get_group_list().await,
            Inner::Uds(c) => c.get_group_list().await,
        }?;
        for entry in result {
            println!(
                "{}: {}",
                entry.name.bold().green(),
                if full {
                    entry.selected.blue()
                } else {
                    entry.selected.white()
                }
            );
            if full {
                for i in entry.list {
                    println!("  - {}", i.name)
                }
            }
        }
        Ok(())
    }

    pub async fn get_group_proxy(&self, group: String) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.get_proxy_for(&group).await,
            Inner::Uds(c) => c.get_proxy_for(&group).await,
        }?;
        match result {
            Some(proxy) => {
                println!("{}: {}", group.bold().green(), proxy.selected.blue());
                for i in proxy.list {
                    println!("  - {}", i.name)
                }
            }
            None => {
                println!("{}: {}", group.bold().green(), "Not found".red());
            }
        }
        Ok(())
    }

    pub async fn set_group_proxy(&self, group: String, proxy: String) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.set_proxy_for(group, proxy).await,
            Inner::Uds(c) => c.set_proxy_for(group, proxy).await,
        }?;
        if result {
            println!("{}", "Success".green());
            Ok(())
        } else {
            println!("{}", "Failed".red());
            Err(anyhow!("Failed to set proxy"))
        }
    }

    pub async fn conn_list(&self, link_name: Option<String>) -> Result<()> {
        let request = ConnListRequest { link: link_name };
        let snapshot = match &self.inner {
            Inner::Web(connector) => connector.list_conn(request).await,
            Inner::Uds(connector) => connector.list_conn(request).await,
        }?;
        print!("{}", conn::render_list(snapshot));
        Ok(())
    }

    pub async fn conn_show(&self, id: u64) -> Result<()> {
        let (detail, resolvers) = match &self.inner {
            Inner::Web(connector) => (
                connector.show_conn(id).await?,
                connector.list_dns().await?.items,
            ),
            Inner::Uds(connector) => (
                connector.show_conn(id).await?,
                connector.list_dns().await?.items,
            ),
        };
        print!("{}", conn::render_detail(detail, &resolvers));
        Ok(())
    }

    pub async fn conn_stop(&self, id: u64) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(connector) => connector.stop_conn(id).await,
            Inner::Uds(connector) => connector.stop_conn(id).await,
        }?;
        println!("Stopped {} connection.", result.stopped_connections);
        Ok(())
    }

    pub async fn conn_stop_all(&self) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(connector) => connector.stop_all_conn().await,
            Inner::Uds(connector) => connector.stop_all_conn().await,
        }?;
        println!("Stopped {} connections.", result.stopped_connections);
        Ok(())
    }

    pub async fn get_tun(&self) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.get_tun().await,
            Inner::Uds(c) => c.get_tun().await,
        }?;
        println!("TUN: {}", if result.enabled { "ON" } else { "OFF" });
        Ok(())
    }

    pub async fn set_tun(&self, enabled: bool) -> Result<()> {
        let enabled = boltapi::TunStatusSchema { enabled };
        match &self.inner {
            Inner::Web(c) => c.set_tun(enabled).await,
            Inner::Uds(c) => c.set_tun(enabled).await,
        }
    }

    pub async fn intercept(&self, range: Option<(u32, Option<u32>)>) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.intercept(range).await,
            Inner::Uds(c) => c.intercept(range).await,
        }?;
        let mut table = Table::new("{:<} {:<} {:<} {:<} {:<} {:<}");
        table.add_row(
            Row::new()
                .with_cell("Client")
                .with_cell("Url")
                .with_cell("Method")
                .with_cell("Status")
                .with_cell("Size")
                .with_cell("Time"),
        );
        for ele in result {
            table.add_row(
                Row::new()
                    .with_cell(ele.client.unwrap_or_default())
                    .with_cell(ele.uri)
                    .with_cell(ele.method)
                    .with_cell(format!("{}", ele.status))
                    .with_cell(ele.size.map_or("N/A".to_string(), format::bytes))
                    .with_cell(ele.duration),
            );
        }
        println!("{}", table);
        Ok(())
    }

    pub async fn get_intercept_payload(&self, id: u32) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.get_intercept_payload(id).await,
            Inner::Uds(c) => c.get_intercept_payload(id).await,
        }?;
        println!("==================  Request  ===================");
        println!("Header:");
        result.req_header.iter().for_each(|l| println!("{}", l));
        println!();
        fn get_text_body(body: &CapturedBodySchema) {
            if let CapturedBodySchema::Body { content } = body {
                if let Ok(data) = std::str::from_utf8(content.as_slice()) {
                    println!("Body:");
                    println!("{}", data);
                } else {
                    println!("Body is not UTF-8 encoded");
                }
            } else {
                println!("Body is not fully captured");
            }
        }
        get_text_body(&result.req_body);
        println!();
        println!("==================  Response ==================");
        println!("Header:");
        result.resp_header.iter().for_each(|l| println!("{}", l));
        println!();
        get_text_body(&result.resp_body);
        Ok(())
    }

    pub async fn add_temporary_rule(&self, rule_literal: String) -> Result<()> {
        if match &self.inner {
            Inner::Web(_) => Err(anyhow::anyhow!(
                "Add-Temporary-Rule: Not supported by RESTful API"
            )),
            Inner::Uds(c) => c.add_temporary_rule(rule_literal).await,
        }? {
            println!("{}", "Success".green());
            Ok(())
        } else {
            println!("{}", "Failed".red());
            Err(anyhow!("Failed to add temporary rule"))
        }
    }

    pub async fn delete_temporary_rule(&self, rule_literal_prefix: String) -> Result<()> {
        if match &self.inner {
            Inner::Web(_) => Err(anyhow::anyhow!(
                "Delete-Temporary-Rule: Not supported by RESTful API"
            )),
            Inner::Uds(c) => c.delete_temporary_rule(rule_literal_prefix).await,
        }? {
            println!("{}", "Success".green());
            Ok(())
        } else {
            println!("{}", "Failed".red());
            Err(anyhow!("Failed to delete rule prefix"))
        }
    }

    pub async fn list_temporary_rule(&self) -> Result<()> {
        let list = match &self.inner {
            Inner::Web(_) => Err(anyhow::anyhow!(
                "List-Temporary-Rule: Not supported by RESTful API"
            )),
            Inner::Uds(c) => c.list_temporary_rule().await,
        }?;
        if list.is_empty() {
            println!("{}", "Empty rule list".yellow());
        } else {
            list.into_iter().for_each(|l| println!("{}", l));
        }
        Ok(())
    }

    pub async fn clear_temporary_rule(&self) -> Result<()> {
        match &self.inner {
            Inner::Web(_) => Err(anyhow::anyhow!(
                "Clear-Temporary-Rule: Not supported by RESTful API"
            )),
            Inner::Uds(c) => c.clear_temporary_rule().await,
        }
    }

    pub async fn conn_limit_get(&self) -> Result<()> {
        let limit = match &self.inner {
            Inner::Web(connector) => connector.get_conn_history_limit().await,
            Inner::Uds(connector) => connector.get_conn_history_limit().await,
        }?;
        println!("{limit}");
        Ok(())
    }

    pub async fn conn_limit_set(&self, limit: u32) -> Result<()> {
        let effective = match &self.inner {
            Inner::Web(connector) => connector.set_conn_history_limit(limit).await,
            Inner::Uds(connector) => connector.set_conn_history_limit(limit).await,
        }?;
        println!("History limit set to {effective}.");
        Ok(())
    }

    pub async fn link_list(&self) -> Result<()> {
        let snapshot = match &self.inner {
            Inner::Web(connector) => connector.list_link().await,
            Inner::Uds(connector) => connector.list_link().await,
        }?;
        print!("{}", link::render_list(snapshot));
        Ok(())
    }

    pub async fn link_show(&self, name: String) -> Result<()> {
        let (detail, resolvers) = match &self.inner {
            Inner::Web(connector) => (
                connector.show_link(&name).await?,
                connector.list_dns().await?.items,
            ),
            Inner::Uds(connector) => (
                connector.show_link(name).await?,
                connector.list_dns().await?.items,
            ),
        };
        print!("{}", link::render_detail(detail, &resolvers));
        Ok(())
    }

    pub async fn link_stop(&self, name: String) -> Result<()> {
        match &self.inner {
            Inner::Web(connector) => connector.stop_link(&name).await?,
            Inner::Uds(connector) => connector.stop_link(name.clone()).await?,
        }
        println!("Stopped {name}.");
        Ok(())
    }

    pub async fn dns_list(&self) -> Result<()> {
        let snapshot = match &self.inner {
            Inner::Web(connector) => connector.list_dns().await,
            Inner::Uds(connector) => connector.list_dns().await,
        }?;
        print!("{}", dns::render_list(snapshot));
        Ok(())
    }

    pub async fn dns_show(&self, id: String) -> Result<()> {
        let detail = match &self.inner {
            Inner::Web(connector) => connector.show_dns(&id).await,
            Inner::Uds(connector) => connector.show_dns(id).await,
        }?;
        print!("{}", dns::render_detail(detail));
        Ok(())
    }

    pub async fn dns_lookup(&self, domain: String, resolver_id: Option<String>) -> Result<()> {
        let request = DnsLookupRequest {
            domain,
            resolver_id,
        };
        let (response, resolvers) = match &self.inner {
            Inner::Web(connector) => (
                connector.lookup_dns(request).await?,
                connector.list_dns().await?.items,
            ),
            Inner::Uds(connector) => (
                connector.lookup_dns(request).await?,
                connector.list_dns().await?.items,
            ),
        };
        print!("{}", dns::render_lookup(response, &resolvers));
        Ok(())
    }

    pub async fn dns_mapping(&self, fake_ip: IpAddr) -> Result<()> {
        let mapping = match &self.inner {
            Inner::Web(connector) => connector.get_dns_mapping(fake_ip).await,
            Inner::Uds(connector) => connector.get_dns_mapping(fake_ip).await,
        }?;
        print!("{}", dns::render_mapping(mapping));
        Ok(())
    }

    pub async fn reload_config(&self) -> Result<()> {
        let is_success = match &self.inner {
            Inner::Web(c) => c.reload_config().await?,
            Inner::Uds(c) => c.reload_config().await?,
        };
        if is_success {
            println!("{}", "Success".green());
        } else {
            println!("{}", "Failed".red());
        }
        Ok(())
    }
}
