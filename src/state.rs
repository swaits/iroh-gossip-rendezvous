//! Observable runtime state exposed via [`Rendezvous::state`](crate::Rendezvous::state).

use std::time::Instant;

use iroh_gossip::TopicId;

/// Snapshot of rendezvous state at a point in time. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RendezvousState {
    /// The gossip topic this rendezvous is bootstrapping.
    pub topic_id: TopicId,
    /// Number of currently-connected gossip neighbors.
    pub neighbor_count: usize,
    /// Status of the underlying DHT client.
    pub dht_status: DhtStatus,
    /// When we last published a record to any slot, if ever.
    pub last_publish: Option<Instant>,
    /// When the heal loop last ran, if ever.
    pub last_heal: Option<Instant>,
    /// Number of shards (K) the rendezvous is sharding across.
    pub active_shards: usize,
}

/// Health of the underlying DHT client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhtStatus {
    /// Initial state before any DHT operation has succeeded.
    Bootstrapping,
    /// At least one DHT operation has succeeded recently.
    Ready,
    /// The most recent DHT publish failed.
    PublishFailing,
}

impl std::fmt::Display for DhtStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrapping => write!(f, "Bootstrapping"),
            Self::Ready => write!(f, "Ready"),
            Self::PublishFailing => write!(f, "PublishFailing"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DhtStatus;

    #[test]
    fn dht_status_display() {
        assert_eq!(format!("{}", DhtStatus::Bootstrapping), "Bootstrapping");
        assert_eq!(format!("{}", DhtStatus::Ready), "Ready");
        assert_eq!(format!("{}", DhtStatus::PublishFailing), "PublishFailing");
    }
}
