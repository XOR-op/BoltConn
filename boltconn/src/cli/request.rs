use crate::cli::request_uds::UdsConnector;
use crate::cli::request_web::WebConnector;
use anyhow::{anyhow, Result};
use colored::Colorize;
use std::ops::Add;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tabular::{Row, Table};

enum Inner {
    Web(WebConnector),
    Uds(UdsConnector),
}

pub struct Requester {
    inner: Inner,
}

impl Requester {
    pub fn new_web(url: String) -> Result<Self> {
        if let Err(err) = reqwest::Url::parse(url.as_str()) {
            return Err(anyhow!("{}", err));
        }
        Ok(Self {
            inner: Inner::Web(WebConnector { url }),
        })
    }

    pub async fn new_uds(path: PathBuf) -> Result<Self> {
        Ok(Self {
            inner: Inner::Uds(UdsConnector::new(path).await?),
        })
    }

    pub async fn get_group_list(&self) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.get_group_list().await,
            Inner::Uds(c) => c.get_group_list().await,
        }?;
        for entry in result {
            println!("{}: {}", entry.name.bold().red(), entry.selected.blue());
            for i in entry.list {
                println!("  - {}", i.name)
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

    pub async fn get_connections(&self) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.get_connections().await,
            Inner::Uds(c) => c.get_connections().await,
        }?;
        for conn in result {
            println!(
                "{} ({},{}) {}\t [up:{},down:{},time:{}] [{}]",
                conn.destination.cyan(),
                conn.protocol,
                conn.proxy.italic(),
                match conn.process {
                    Some(s) => format!("<{}>", s.name),
                    None => "".to_string(),
                },
                pretty_size(conn.upload),
                pretty_size(conn.download),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH.add(Duration::from_secs(conn.start_time)))
                    .map(|t| pretty_time(t.as_secs()))
                    .unwrap_or("N/A".to_string()),
                if conn.active { "open" } else { "closed" }
            );
        }
        Ok(())
    }
    pub async fn stop_connections(&self, nth: Option<usize>) -> Result<()> {
        let result = match &self.inner {
            Inner::Web(c) => c.stop_connections(nth).await,
            Inner::Uds(c) => c.stop_connections(nth).await,
        }?;
        if result {
            println!("Success");
        } else {
            println!("Failed");
        }
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

    pub async fn set_tun(&self, content: &str) -> Result<()> {
        let enabled = boltapi::TunStatusSchema {
            enabled: match content.to_lowercase().as_str() {
                "on" => true,
                "off" => false,
                _ => return Err(anyhow::anyhow!("Unknown TUN setting: {}", content)),
            },
        };
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
                    .with_cell(ele.size.map_or("N/A".to_string(), pretty_size))
                    .with_cell(ele.time),
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
        if let Ok(data) = std::str::from_utf8(result.req_body.as_slice()) {
            println!("Body:");
            println!("{}", data);
        } else {
            println!("Body is not UTF-8 encoded");
        }
        println!();
        println!("==================  Response ==================");
        println!("Header:");
        result.resp_header.iter().for_each(|l| println!("{}", l));
        println!();
        if let Ok(data) = std::str::from_utf8(result.resp_body.as_slice()) {
            println!("Body:");
            println!("{}", data);
        } else {
            println!("Body is not UTF-8 encoded");
        }
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

    pub async fn clear_temporary_rule(&self) -> Result<()> {
        match &self.inner {
            Inner::Web(_) => Err(anyhow::anyhow!(
                "Clear-Temporary-Rule: Not supported by RESTful API"
            )),
            Inner::Uds(c) => c.clear_temporary_rule().await,
        }
    }

    pub async fn reload_config(&self) -> Result<()> {
        match &self.inner {
            Inner::Web(c) => c.reload_config().await,
            Inner::Uds(c) => c.reload_config().await,
        }
    }
}

fn pretty_size(data: u64) -> String {
    if data < 1024 {
        format!("{} Bytes", data)
    } else if data < 1024 * 1024 {
        format!("{} KB", data / 1024)
    } else {
        format!("{} MB", data / 1024 / 1024)
    }
}

fn pretty_time(elapsed: u64) -> String {
    if elapsed < 60 {
        format!("{} seconds ago", elapsed)
    } else if elapsed < 60 * 60 {
        format!("{} mins ago", elapsed / 60)
    } else {
        format!("{} hours ago", elapsed / 3600)
    }
}
