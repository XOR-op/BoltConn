use crate::proxy::{ConnContext, HttpInterceptData};
use anyhow::anyhow;
use rusqlite::{params, Error, ErrorCode, OpenFlags};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

pub struct DatabaseHandle {
    conn: rusqlite::Connection,
}

impl DatabaseHandle {
    const CONN_TABLE_SCHEMA: &'static str = "CREATE TABLE Conn (
                    id INTEGER PRIMARY KEY,
                    dest TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    proxy TEXT NOT NULL,
                    process TEXT,
                    upload INTEGER NOT NULL,
                    download INTEGER NOT NULL,
                    start_time INTEGER NOT NULL
                )";

    const INTERCEPT_TABLE_SCHEMA: &'static str = "CREATE TABLE Intercept (
                    id INTEGER PRIMARY KEY,
                    process TEXT,
                    uri TEXT NOT NULL,
                    method TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    size INTEGER NOT NULL,
                    time INTEGER NOT NULL,
                    req_header TEXT,
                    req_body BLOB,
                    resp_header TEXT,
                    resp_body BLOB
                )";

    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let conn =
            match rusqlite::Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE) {
                Ok(c) => {
                    Self::verify(&c)?;
                    c
                }
                Err(err) => {
                    let Error::SqliteFailure(e, _) = err else{Err(err)?};
                    if e.code == ErrorCode::CannotOpen {
                        // create with open
                        let conn = rusqlite::Connection::open_with_flags(
                            path,
                            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
                        )?;
                        Self::create_db_table(&conn)?;
                        conn
                    } else {
                        Err(e)?
                    }
                }
            };
        Ok(Self { conn })
    }

    fn verify(conn: &rusqlite::Connection) -> anyhow::Result<()> {
        let mut stmt = conn.prepare("SELECT name,sql FROM sqlite_master WHERE type='table'")?;
        let result = stmt.query_map([], |row| {
            Ok((row.get::<usize, String>(0)?, row.get::<usize, String>(1)?))
        })?;
        let mut has_conn = false;
        let mut has_intercept = false;
        for x in result {
            let (name, sql) = x?;
            match name.as_str() {
                "Conn" => {
                    if sql != Self::CONN_TABLE_SCHEMA {
                        return Err(anyhow!("Invalid table schema 'Conn'"));
                    }
                    has_conn = true;
                }
                "Intercept" => {
                    if sql != Self::INTERCEPT_TABLE_SCHEMA {
                        return Err(anyhow!("Invalid table schema 'Intercept'"));
                    }
                    has_intercept = true;
                }
                _ => continue,
            }
        }
        if !(has_conn && has_intercept) {
            return Err(anyhow!(
                "Missing table: {}",
                if has_conn {
                    "Intercept"
                } else if has_intercept {
                    "Conn"
                } else {
                    "Conn & Intercept"
                }
            ));
        }
        Ok(())
    }

    fn create_db_table(conn: &rusqlite::Connection) -> anyhow::Result<()> {
        conn.execute(Self::CONN_TABLE_SCHEMA, ())?;
        conn.execute(Self::INTERCEPT_TABLE_SCHEMA, ())?;
        Ok(())
    }

    pub fn add_connections(&mut self, conns: &[Arc<ConnContext>]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx
            .prepare_cached("INSERT INTO Conn (dest,protocol,proxy,process,upload,download,start_time) VALUES (?1,?2,?3,?4,?5,?6,?7)")?;
        for c in conns.iter() {
            stmt.execute(params![
                c.dest.to_string().as_str(),
                c.session_proto.read().unwrap().to_string().as_str(),
                format!("{:?}", c.rule).to_ascii_lowercase(),
                c.process_info.as_ref().map(|i| i.name.clone()),
                c.upload_traffic.load(Ordering::Relaxed),
                c.download_traffic.load(Ordering::Relaxed),
                c.start_time.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    pub fn add_interceptions(&mut self, intes: &[HttpInterceptData]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx
            .prepare_cached("INSERT INTO Conn (client,uri,method,status,size,time,req_header,req_body,resp_header,resp_body) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)")?;
        for c in intes.iter() {
            stmt.execute(params![
                c.process_info.as_ref().map(|proc| &proc.name),
                c.get_full_uri().as_str(),
                c.req.method.as_str(),
                c.resp.status.as_u16(),
                c.resp.body.len(),
                (c.resp.time - c.req.time).as_millis() as u64,
                c.req.collect_headers().join("\n"),
                c.req.body.as_ref(),
                c.resp.collect_headers().join("\n"),
                c.resp.body.as_ref(),
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }
}
