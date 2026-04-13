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
    egress_senders: Mutex<HashMap<SubId, flume::Sender<BusMessage>>>,
    pending_responses: Mutex<HashMap<u64, (SubId, oneshot::Sender<String>)>>,
    next_request_id: AtomicU64,
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
        }
    }

    pub fn has_subscriber(&self, sub_id: SubId) -> bool {
        self.egress_senders
            .lock()
            .unwrap()
            .get(&sub_id)
            .map(|s| !s.is_disconnected())
            .unwrap_or(false)
    }

    pub fn alloc_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn register_pending_response(
        &self,
        sub_id: SubId,
        request_id: u64,
    ) -> oneshot::Receiver<String> {
        let (tx, rx) = oneshot::channel();
        self.pending_responses
            .lock()
            .unwrap()
            .insert(request_id, (sub_id, tx));
        rx
    }

    pub fn resolve_pending_response(&self, sub_id: SubId, request_id: u64, route: String) {
        let mut map = self.pending_responses.lock().unwrap();
        if let Entry::Occupied(e) = map.entry(request_id)
            && e.get().0 == sub_id
        {
            let (_, tx) = e.remove();
            let _ = tx.send(route);
        }
    }

    pub async fn run(&self) {
        while let Ok(msg) = self.ingress_receiver.recv_async().await {
            if let Some(sender) = self.egress_senders.lock().unwrap().get(&msg.sub_id) {
                let _ = sender.try_send(msg);
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
        I: Iterator<Item = SubId> + Clone,
    {
        let (sender, receiver) = flume::unbounded();
        let iter2 = sub_ids.clone();
        let mut egress_senders = self.egress_senders.lock().unwrap();
        for sub_id in iter2 {
            if egress_senders.contains_key(&sub_id) {
                match egress_senders.entry(sub_id) {
                    Entry::Occupied(e) => {
                        if e.get().is_disconnected() {
                            e.remove();
                        } else {
                            return None;
                        }
                    }
                    Entry::Vacant(_) => unreachable!(),
                }
            }
        }
        for sub_id in sub_ids {
            egress_senders.insert(sub_id, sender.clone());
        }
        Some(BusSubscriber::new(receiver))
    }
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
    receiver: flume::Receiver<BusMessage>,
}

impl BusSubscriber {
    pub fn new(receiver: flume::Receiver<BusMessage>) -> Self {
        Self { receiver }
    }

    pub async fn recv(&self) -> Option<BusMessage> {
        self.receiver.recv_async().await.ok()
    }
}
