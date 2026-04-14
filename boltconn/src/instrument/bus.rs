use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::oneshot;

pub type SubId = u64;

pub struct MessageBus {
    // Only used for cloning
    ingress_sender_handle: flume::Sender<BusMessage>,
    ingress_receiver: flume::Receiver<BusMessage>,
    egress_senders: Mutex<HashMap<SubId, SubscriberEntry>>,
    pending_responses: Mutex<HashMap<u64, PendingResponse>>,
    next_request_id: AtomicU64,
    next_subscriber_token: AtomicU64,
}

impl MessageBus {
    pub fn new() -> Self {
        let (ingress_sender, ingress_receiver) = flume::bounded(4096);
        Self {
            ingress_sender_handle: ingress_sender,
            ingress_receiver,
            egress_senders: Mutex::new(HashMap::new()),
            pending_responses: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(0),
            next_subscriber_token: AtomicU64::new(1),
        }
    }

    pub fn has_subscriber(&self, sub_id: SubId) -> bool {
        self.egress_senders
            .lock()
            .unwrap()
            .get(&sub_id)
            .map(|s| !s.sender.is_disconnected())
            .unwrap_or(false)
    }

    pub fn alloc_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn register_pending_response(
        &self,
        sub_id: SubId,
        request_id: u64,
    ) -> Option<oneshot::Receiver<String>> {
        // `request_id` identifies a single `.REQUEST` round-trip, while `token` ties that
        // waiter to the currently connected subscriber so disconnect cleanup does not affect
        // a later reconnect that reuses the same `sub_id`.
        let token = self
            .egress_senders
            .lock()
            .unwrap()
            .get(&sub_id)
            .and_then(|entry| {
                if entry.sender.is_disconnected() {
                    None
                } else {
                    Some(entry.token)
                }
            })?;
        let (tx, rx) = oneshot::channel();
        self.pending_responses
            .lock()
            .unwrap()
            .insert(request_id, PendingResponse { sub_id, token, tx });
        Some(rx)
    }

    pub fn resolve_pending_response(&self, sub_id: SubId, request_id: u64, route: String) {
        let mut map = self.pending_responses.lock().unwrap();
        if let Entry::Occupied(e) = map.entry(request_id)
            && e.get().sub_id == sub_id
        {
            let PendingResponse { tx, .. } = e.remove();
            let _ = tx.send(route);
        }
    }

    pub fn remove_pending_response(&self, request_id: u64) {
        // Normal request completion path: response received, timeout fired, or fallback chosen.
        self.pending_responses.lock().unwrap().remove(&request_id);
    }

    pub fn remove_subscriber(&self, sub_ids: &[SubId], token: u64) {
        // Remove only the subscriber entries that belonged to the WebSocket session that just
        // ended; the same `sub_id` may already have been reclaimed by a newer connection.
        let mut egress_senders = self.egress_senders.lock().unwrap();
        for sub_id in sub_ids {
            if let Entry::Occupied(entry) = egress_senders.entry(*sub_id)
                && entry.get().token == token
            {
                entry.remove();
            }
        }
    }

    pub fn cancel_pending_responses_for_token(&self, token: u64) {
        // Connection teardown path: drop all waiters that were registered through this specific
        // subscriber session so `.REQUEST` falls back immediately on disconnect.
        let mut pending = self.pending_responses.lock().unwrap();
        let request_ids: Vec<u64> = pending
            .iter()
            .filter_map(|(request_id, response)| {
                if response.token == token {
                    Some(*request_id)
                } else {
                    None
                }
            })
            .collect();
        for request_id in request_ids {
            pending.remove(&request_id);
        }
    }

    pub async fn run(&self) {
        while let Ok(msg) = self.ingress_receiver.recv_async().await {
            if let Some(sender) = self.egress_senders.lock().unwrap().get(&msg.sub_id) {
                let _ = sender.sender.try_send(msg);
            }
        }
    }

    pub fn create_publisher(&self, sub_id: SubId) -> BusPublisher {
        let sender = self.ingress_sender_handle.clone();
        BusPublisher::new(sub_id, sender)
    }

    /// Returns None if any of the sub_ids already exists
    pub fn create_subscriber<I>(&self, sub_ids: I) -> Option<BusSubscriber>
    where
        I: Iterator<Item = SubId>,
    {
        let sub_ids: Vec<SubId> = sub_ids.collect();
        if sub_ids.is_empty() {
            return None;
        }
        let (sender, receiver) = flume::unbounded();
        let token = self.next_subscriber_token.fetch_add(1, Ordering::Relaxed);
        let mut egress_senders = self.egress_senders.lock().unwrap();
        for sub_id in sub_ids.iter().copied() {
            if egress_senders.contains_key(&sub_id) {
                match egress_senders.entry(sub_id) {
                    Entry::Occupied(e) => {
                        if e.get().sender.is_disconnected() {
                            e.remove();
                        } else {
                            return None;
                        }
                    }
                    Entry::Vacant(_) => unreachable!(),
                }
            }
        }
        for sub_id in sub_ids.iter().copied() {
            egress_senders.insert(
                sub_id,
                SubscriberEntry {
                    sender: sender.clone(),
                    token,
                },
            );
        }
        Some(BusSubscriber::new(sub_ids, token, receiver))
    }
}

struct SubscriberEntry {
    sender: flume::Sender<BusMessage>,
    // Token distinguishes successive subscribers that reuse the same sub_id after reconnect.
    token: u64,
}

struct PendingResponse {
    sub_id: SubId,
    // `request_id` chooses the pending request; `token` chooses the subscriber connection that
    // owned it when the wait started.
    token: u64,
    tx: oneshot::Sender<String>,
}

#[derive(Debug, Clone)]
pub struct BusMessage {
    pub sub_id: SubId,
    pub msg: String,
}

impl BusMessage {
    pub fn new(sub_id: SubId, msg: String) -> Self {
        Self { sub_id, msg }
    }
}

pub struct BusPublisher {
    sub_id: SubId,
    sender: flume::Sender<BusMessage>,
}

impl BusPublisher {
    pub fn new(sub_id: SubId, sender: flume::Sender<BusMessage>) -> Self {
        Self { sub_id, sender }
    }

    pub fn publish(&self, msg: BusMessage) {
        // drop on full channel
        let _ = self.sender.try_send(msg);
    }
}

pub struct BusSubscriber {
    sub_ids: Vec<SubId>,
    token: u64,
    receiver: flume::Receiver<BusMessage>,
}

impl BusSubscriber {
    pub fn new(sub_ids: Vec<SubId>, token: u64, receiver: flume::Receiver<BusMessage>) -> Self {
        Self {
            sub_ids,
            token,
            receiver,
        }
    }

    pub fn sub_ids(&self) -> &[SubId] {
        self.sub_ids.as_slice()
    }

    pub fn token(&self) -> u64 {
        self.token
    }

    pub async fn recv(&self) -> Option<BusMessage> {
        self.receiver.recv_async().await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::MessageBus;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_cancel_pending_responses_is_scoped_to_connection_token() {
        let bus = MessageBus::new();
        let first = bus.create_subscriber(std::iter::once(7)).unwrap();
        let first_token = first.token();
        let first_request_id = bus.alloc_request_id();
        let first_rx = bus.register_pending_response(7, first_request_id).unwrap();

        drop(first);

        let ids = vec![7];
        let second = bus.create_subscriber(ids.iter().copied()).unwrap();
        let second_token = second.token();
        assert_ne!(first_token, second_token);

        let second_request_id = bus.alloc_request_id();
        let second_rx = bus.register_pending_response(7, second_request_id).unwrap();

        bus.remove_subscriber(ids.as_slice(), first_token);
        assert!(bus.has_subscriber(7));

        bus.cancel_pending_responses_for_token(first_token);
        assert!(first_rx.await.is_err());

        assert!(timeout(Duration::from_millis(20), second_rx).await.is_err());
    }

    #[tokio::test]
    async fn test_remove_pending_response_clears_timeout_waiter() {
        let bus = MessageBus::new();
        let _sub = bus.create_subscriber(std::iter::once(8)).unwrap();
        let request_id = bus.alloc_request_id();
        let rx = bus.register_pending_response(8, request_id).unwrap();

        bus.remove_pending_response(request_id);
        assert!(rx.await.is_err());
    }
}
