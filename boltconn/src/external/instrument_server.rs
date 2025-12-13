use crate::common::as_io_err;
use crate::external::web_common::{get_cors_layer, parse_cors_allow, web_auth};
use crate::instrument::bus::{BusSubscriber, MessageBus};
use crate::proxy::error::{RuntimeError, SystemError};
use axum::Router;
use axum::extract::ws::WebSocket;
use axum::extract::{Query, State, WebSocketUpgrade, ws};
use axum::middleware::map_request;
use axum::response::IntoResponse;
use axum::routing::get;
use boltapi::instrument::InstrumentData;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::select;

#[derive(Clone)]
pub struct InstrumentServer {
    secret: Option<String>,
    msg_bus: Arc<MessageBus>,
}

impl InstrumentServer {
    pub fn new(secret: Option<String>, msg_bus: Arc<MessageBus>) -> Self {
        Self { secret, msg_bus }
    }

    pub async fn run(
        self,
        listen_addr: SocketAddr,
        cors_allowed_list: &[String],
    ) -> Result<(), RuntimeError> {
        let secret = Arc::new(None); // We verify the secret in the subscribe parameters
        let cors_vec = parse_cors_allow(cors_allowed_list);
        let auth_wrapper = move |r| web_auth(secret.clone(), r, cors_vec.clone());

        let mut app = Router::new()
            .route("/subscribe", get(Self::subscribe))
            .route_layer(map_request(auth_wrapper))
            .with_state(self);
        if let Some(origin) = super::web_controller::parse_api_cors_origin(cors_allowed_list) {
            app = app.layer(get_cors_layer(origin));
        }

        let listener = TcpListener::bind(&listen_addr).await.map_err(|e| {
            tracing::error!(
                "[Instrument] service failed to bind to {}: {}",
                listen_addr,
                e
            );
            SystemError::InstrumentServer(e)
        })?;
        tracing::info!("[Instrument] Listening on {}", listen_addr);
        axum::serve(listener, app.into_make_service())
            .await
            .map_err(|e| SystemError::InstrumentServer(as_io_err(e)))?;
        Ok(())
    }

    async fn subscribe(
        State(server): State<Self>,
        Query(params): Query<HashMap<String, String>>,
        ws: WebSocketUpgrade,
    ) -> impl IntoResponse {
        if let Some(secret) = server.secret.as_ref()
            && params.get("secret") != Some(secret)
        {
            return refusal_resp(http::StatusCode::UNAUTHORIZED);
        }
        // parse hex-encoded topics from url params
        let ids = {
            let mut arr = Vec::new();
            let Some(s) = params.get("id") else {
                tracing::debug!("No id parameter in request");
                return refusal_resp(http::StatusCode::BAD_REQUEST);
            };
            for id in s.split(',') {
                if let Ok(val) = id.parse::<u64>() {
                    arr.push(val);
                } else {
                    tracing::debug!("Invalid id parameter in request: {} in {}", id, s);
                    return refusal_resp(http::StatusCode::BAD_REQUEST);
                }
            }
            arr
        };
        let Some(sub) = server.msg_bus.create_subscriber(ids.iter().copied()) else {
            return refusal_resp(http::StatusCode::CONFLICT);
        };
        ws.on_upgrade(move |socket| Self::subscribe_inner(socket, sub))
    }

    async fn subscribe_inner(mut socket: WebSocket, sub: BusSubscriber) {
        loop {
            let msg = select! {
                r = socket.recv() => {
                    // client disconnected
                    if r.is_none(){
                        return;
                    }
                    // some messages, maybe error
                    continue;
                }
                Some(msg) = sub.recv() => msg,
            };
            let wire_msg = InstrumentData {
                id: msg.sub_id,
                message: msg.msg,
            };
            let _ = socket
                .send(ws::Message::Text(wire_msg.encode_string()))
                .await;
        }
    }
}

fn refusal_resp(code: http::StatusCode) -> http::Response<axum::body::Body> {
    http::Response::builder()
        .status(code)
        .body(axum::body::Body::empty())
        .unwrap()
}
