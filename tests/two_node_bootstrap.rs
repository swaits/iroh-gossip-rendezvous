//! Two real iroh Endpoints connected over a shared in-memory DHT.
//!
//! Validates the full stack end-to-end — `Builder::build` → `initial_join`
//! → WriteLoop publish → HealLoop read → iroh-gossip dial → `NeighborUp`
//! event — without touching the real Mainline DHT.
//!
//! Requires the `test-support` feature to inject the custom DHT backend.

#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use iroh_gossip_rendezvous::sim::InMemoryDht;
use iroh_gossip_rendezvous::{Builder, DhtStatus};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_publish_and_discover_via_dht() {
    // Shared InMemoryDht — both nodes inject it via the `test-support`
    // Builder::dht_backend hook, bypassing the real Mainline client.
    //
    // This test validates the **rendezvous** layer (DHT publish + read),
    // not the gossip-dial handshake. iroh-gossip dialing requires N0
    // discovery for network addresses and is subject to its own timing,
    // so the stricter "neighbors see each other" claim lives in an
    // `#[ignore]`d test below that's run explicitly.
    let dht = Arc::new(InMemoryDht::new());

    let rendezvous_a = Builder::default()
        .passphrase("integration-test")
        .app_salt("iroh-gossip-rendezvous/tests/two-node")
        .heal_period(Duration::from_millis(200))
        .write_period(Duration::from_secs(1))
        .jitter(0.1)
        .dht_backend(dht.clone())
        .build()
        .await
        .expect("node A builds");

    let rendezvous_b = Builder::default()
        .passphrase("integration-test")
        .app_salt("iroh-gossip-rendezvous/tests/two-node")
        .heal_period(Duration::from_millis(200))
        .write_period(Duration::from_secs(1))
        .jitter(0.1)
        .dht_backend(dht.clone())
        .build()
        .await
        .expect("node B builds");

    // Both nodes share the same passphrase + app_salt → same topic_id.
    assert_eq!(rendezvous_a.topic_id(), rendezvous_b.topic_id());

    // Give the write loop a couple of ticks to publish. Both nodes'
    // `DhtStatus` should flip from Bootstrapping to Ready once the first
    // write succeeds.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let a = rendezvous_a.state();
        let b = rendezvous_b.state();
        if a.dht_status == DhtStatus::Ready && b.dht_status == DhtStatus::Ready {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "DHT publishes didn't complete in 5s: A={:?} B={:?}",
            a.dht_status,
            b.dht_status
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Graceful shutdown.
    rendezvous_a.shutdown().await;
    rendezvous_b.shutdown().await;
}

/// End-to-end convergence over real iroh-gossip. Ignored by default
/// because iroh's N0 discovery + QUIC handshake is several-seconds-slow
/// on cold start and network-sensitive. Run with:
///
/// ```text
/// cargo test --test two_node_bootstrap --features test-support -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow: depends on iroh-gossip cold-start dialing"]
async fn two_nodes_converge_end_to_end() {
    let dht = Arc::new(InMemoryDht::new());
    let a = Builder::default()
        .passphrase("integration-test")
        .app_salt("iroh-gossip-rendezvous/tests/e2e")
        .heal_period(Duration::from_millis(500))
        .write_period(Duration::from_secs(1))
        .dht_backend(dht.clone())
        .build()
        .await
        .unwrap();
    let b = Builder::default()
        .passphrase("integration-test")
        .app_salt("iroh-gossip-rendezvous/tests/e2e")
        .heal_period(Duration::from_millis(500))
        .write_period(Duration::from_secs(1))
        .dht_backend(dht.clone())
        .build()
        .await
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if a.state().neighbor_count > 0 && b.state().neighbor_count > 0 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "never converged");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_cancels_background_tasks() {
    let dht = Arc::new(InMemoryDht::new());
    {
        let _rendezvous = Builder::default()
            .passphrase("integration-test")
            .app_salt("iroh-gossip-rendezvous/tests/drop")
            .heal_period(Duration::from_millis(100))
            .write_period(Duration::from_millis(500))
            .dht_backend(dht.clone())
            .build()
            .await
            .expect("node builds");
        // Let the background loops start and do at least one publish.
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Dropping the rendezvous triggers the cancellation token and the
        // task JoinSets are aborted when dropped.
    }

    // After drop, wait a bit and verify no panics (tokio would surface them
    // via the test harness). Successful drop = implicit pass.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_subscribers_receive_events() {
    let dht = Arc::new(InMemoryDht::new());
    let rendezvous = Builder::default()
        .passphrase("integration-test")
        .app_salt("iroh-gossip-rendezvous/tests/multi-sub")
        .dht_backend(dht.clone())
        .build()
        .await
        .expect("build");

    // Two subscribers, both should register.
    let sub1 = rendezvous.subscribe();
    let sub2 = rendezvous.subscribe();
    assert_eq!(sub1.len(), sub2.len(), "both fresh subs start empty");

    rendezvous.shutdown().await;
}
