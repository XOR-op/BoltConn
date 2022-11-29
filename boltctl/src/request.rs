use anyhow::{anyhow, Result};
use colored::Colorize;

pub struct Requester {
    pub port: u16,
}

impl Requester {
    pub async fn get_group_list(&self) -> Result<()> {
        let data = reqwest::get(self.route("/groups")).await?.text().await?;
        let result: Vec<boltapi::GetGroupRespSchema> = serde_json::from_str(data.as_str())?;
        for entry in result {
            println!("{}: {}", entry.name.bold().red(), entry.selected.blue());
            for i in entry.list {
                println!("  - {}", i)
            }
        }
        Ok(())
    }

    pub async fn set_group_proxy(&self, group: String, proxy: String) -> Result<()> {
        let req = boltapi::SetGroupReqSchema {
            group,
            selected: proxy,
        };
        let result = reqwest::Client::new()
            .put(self.route("/groups"))
            .json(&req)
            .send()
            .await?
            .text()
            .await?;
        match result.as_str() {
            "true" => {
                println!("{}", "Success".green());
                Ok(())
            }
            "false" => {
                println!("{}", "Failed".red());
                Err(anyhow!("Failed to set proxy"))
            }
            x => {
                println!("{}", format!("Unknown: {}", x).red());
                Err(anyhow!("Unknown response"))
            }
        }
    }

    pub async fn get_active_conn(&self) -> Result<()> {
        let data = reqwest::get(self.route("/active")).await?.text().await?;
        let result: Vec<boltapi::ConnectionSchema> = serde_json::from_str(data.as_str())?;
        for conn in result {
            println!(
                "{} ({},{}) {} [up:{},down:{},time:{}]",
                conn.destination.cyan(),
                conn.protocol,
                conn.proxy.italic(),
                match conn.process {
                    Some(s) => format!("<{}>", s),
                    None => "".to_string(),
                },
                conn.upload,
                conn.download,
                conn.time
            );
        }
        Ok(())
    }

    pub async fn get_sessions(&self) -> Result<()> {
        let data = reqwest::get(self.route("/sessions")).await?.text().await?;
        let result: Vec<boltapi::SessionSchema> = serde_json::from_str(data.as_str())?;
        for sess in result {
            println!(
                "{} [{}{}]",
                sess.pair,
                sess.time,
                match sess.tcp_open {
                    None => "".to_string(),
                    Some(n) => {
                        ", ".to_string()
                            + match n {
                                0 => "closed",
                                1 => "half-closed",
                                2 => "established",
                                _ => "",
                            }
                    }
                }
            );
        }
        Ok(())
    }

    fn route(&self, s: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, s)
    }
}
