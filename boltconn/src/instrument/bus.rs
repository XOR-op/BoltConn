use std::collections::HashMap;
use std::sync::Mutex;

pub type SubId = u64;

pub struct Bus {
    // Only used for cloning
    ingress_sender_handle: flume::Sender<BusMessage>,
    ingress_receiver: flume::Receiver<BusMessage>,
    egress_senders: Mutex<HashMap<SubId, flume::Sender<BusMessage>>>,
}

impl Bus {
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
                return None;
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
    sub_id: SubId,
    msg: String,
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
