use crate::platform::get_user_info;
use crate::proxy::{BodyOrWarning, ConnContext, HttpInterceptData};
use anyhow::anyhow;
use rusqlite::{params, Error, ErrorCode, OpenFlags};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone, Debug)]
pub struct DatabaseHandle {
    conn_sender: UnboundedSender<Vec<Arc<ConnContext>>>,
    intercept_sender: UnboundedSender<Vec<HttpInterceptData>>,
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
                    size INTEGER,
                    time INTEGER NOT NULL,
                    req_header TEXT,
                    req_body BLOB,
                    resp_header TEXT,
                    resp_body BLOB
                )";

    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let mut conn =
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
                            &path,
                            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
                        )?;
                        if let Some((_, uid, gid)) = get_user_info() {
                            nix::unistd::chown(&path, Some(uid.into()), Some(gid.into()))?;
                        }
                        Self::create_db_table(&conn)?;
                        conn
                    } else {
                        Err(e)?
                    }
                }
            };
        let (conn_send, mut conn_recv) = mpsc::unbounded_channel();
        let (inte_send, mut inte_recv) = mpsc::unbounded_channel();
        // Standalone thread for asynchronous database insert
        thread::spawn(move || {
            let thread_rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("Failed to create database thread");
            let result: anyhow::Result<()> = thread_rt.block_on(async move {
                let conn_may_available = loop {
                    let s = tokio::time::sleep(Duration::from_secs(30 * 60));
                    tokio::select! {
                        dat = conn_recv.recv() =>{
                            if let Some(dat) = dat{
                                Self::insert_connections(&mut conn,dat)?;
                            }else{
                                break false;
                            }
                        }
                        dat = inte_recv.recv() =>{
                            if let Some(dat) = dat{
                                Self::insert_interceptions(&mut conn,dat)?;
                            }else{
                                break true;
                            }
                        }
                        _ = s =>{
                            Self::vacuum_oldest(&conn, 40000, 5000);
                            tracing::trace!("Vacuum database")
                        }
                    }
                };
                if conn_may_available {
                    while let Some(dat) = conn_recv.recv().await {
                        Self::insert_connections(&mut conn, dat)?;
                    }
                } else {
                    while let Some(dat) = inte_recv.recv().await {
                        Self::insert_interceptions(&mut conn, dat)?;
                    }
                }
                Ok(())
            });
            if let Err(err) = result {
                tracing::error!("Database write failed: {:?}", err);
            }
        });
        Ok(Self {
            conn_sender: conn_send,
            intercept_sender: inte_send,
        })
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
    pub fn add_connections(&mut self, conns: Vec<Arc<ConnContext>>) {
        let _ = self.conn_sender.send(conns);
    }
    pub fn add_interceptions(&mut self, intes: Vec<HttpInterceptData>) {
        let _ = self.intercept_sender.send(intes);
    }

    fn insert_connections(
        conn: &mut rusqlite::Connection,
        data: Vec<Arc<ConnContext>>,
    ) -> anyhow::Result<()> {
        let tx = conn.transaction()?;
        let mut stmt = tx
            .prepare_cached("INSERT INTO Conn (dest,protocol,proxy,process,upload,download,start_time) VALUES (?1,?2,?3,?4,?5,?6,?7)")?;
        for c in data.iter() {
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

    fn insert_interceptions(
        conn: &mut rusqlite::Connection,
        intes: Vec<HttpInterceptData>,
    ) -> anyhow::Result<()> {
        let tx = conn.transaction()?;
        let mut stmt = tx
            .prepare_cached("INSERT INTO Intercept (process,uri,method,status,size,time,req_header,req_body,resp_header,resp_body) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)")?;
        for c in intes.iter() {
            let resp_body = match &c.resp.body {
                BodyOrWarning::Body(b) => Some(b.as_ref()),
                BodyOrWarning::Warning(_) => None,
            };
            stmt.execute(params![
                c.process_info.as_ref().map(|proc| &proc.name),
                c.get_full_uri().as_str(),
                c.req.method.as_str(),
                c.resp.status.as_u16(),
                c.resp.body_len(),
                (c.resp.time - c.req.time).as_millis() as u64,
                c.req.collect_headers().join("\n"),
                c.req.body.as_ref(),
                c.resp.collect_headers().join("\n"),
                resp_body
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    fn vacuum_oldest(conn: &rusqlite::Connection, conn_limit: usize, inte_limit: usize) {
        if let Err(err) = conn.execute(
            format!(
                "DELETE FROM {} where ID not in (SELECT id from {} order by ID DESC LIMIT {})",
                "Conn", "Conn", conn_limit
            )
            .as_str(),
            [],
        ) {
            tracing::error!("Vacuum table 'Conn' failed: {}", err);
        } else if let Err(err) = conn.execute(
            format!(
                "DELETE FROM {} where ID not in (SELECT id from {} order by ID DESC LIMIT {})",
                "Intercept", "Intercept", inte_limit
            )
            .as_str(),
            [],
        ) {
            tracing::error!("Vacuum table 'Intercept' failed: {}", err);
        }
    }
}
