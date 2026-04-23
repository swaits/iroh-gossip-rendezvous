//! Minimal end-to-end demo: join a swarm, broadcast a message every few
//! seconds, print everything received. Run two instances with the same
//! passphrase + app_salt on two machines and they'll find each other.
//!
//! ```text
//! cargo run --example quickstart -- --passphrase my-secret --app my-app/v1
//! ```

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use iroh_gossip_rendezvous::Rendezvous;
use tokio::sync::broadcast::error::RecvError;

#[derive(Parser)]
struct Args {
    /// Shared passphrase. All instances with the same passphrase+app salt meet.
    #[arg(long, default_value = "quickstart-demo")]
    passphrase: String,

    /// Application salt — opaque label identifying your app + version.
    #[arg(long, default_value = "iroh-gossip-rendezvous/quickstart/v1")]
    app: String,

    /// Broadcast a message every N seconds.
    #[arg(long, default_value_t = 5)]
    broadcast_interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    println!(
        "joining rendezvous (passphrase=\"{}\", app=\"{}\")",
        args.passphrase, args.app
    );
    let rendezvous = Rendezvous::join(&args.passphrase, &args.app).await?;
    println!("node id: {}", rendezvous.node_id().fmt_short());
    println!(
        "topic:   {}",
        hex::encode(&rendezvous.topic_id().as_bytes()[..8])
    );

    // Subscriber for incoming events.
    let mut rx = rendezvous.subscribe();

    // Broadcaster loop.
    let sender = rendezvous.sender().clone();
    let my_id = rendezvous.node_id().fmt_short();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(args.broadcast_interval_secs));
        let mut counter: u64 = 0;
        loop {
            tick.tick().await;
            counter += 1;
            let msg = format!("hello from {my_id} (#{counter})");
            if let Err(e) = sender.broadcast(bytes::Bytes::from(msg)).await {
                eprintln!("broadcast error: {e}");
                break;
            }
        }
    });

    // Periodic state print.
    let state_handle = {
        let r = &rendezvous;
        async {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let s = r.state();
                println!(
                    "[state] neighbors={} dht={} shards={}",
                    s.neighbor_count, s.dht_status, s.active_shards,
                );
            }
        }
    };

    // Receive loop.
    let recv_handle = async {
        loop {
            match rx.recv().await {
                Ok(iroh_gossip::api::Event::Received(msg)) => {
                    let delivered = String::from_utf8_lossy(&msg.content);
                    println!("[recv] from={} {delivered}", msg.delivered_from.fmt_short());
                }
                Ok(iroh_gossip::api::Event::NeighborUp(id)) => {
                    println!("[neighbor up] {}", id.fmt_short());
                }
                Ok(iroh_gossip::api::Event::NeighborDown(id)) => {
                    println!("[neighbor down] {}", id.fmt_short());
                }
                Ok(iroh_gossip::api::Event::Lagged) => {
                    eprintln!("[warn] event stream lagged");
                }
                Err(RecvError::Lagged(n)) => {
                    eprintln!("[warn] subscription lagged; dropped {n}");
                }
                Err(RecvError::Closed) => break,
            }
        }
    };

    tokio::select! {
        () = recv_handle => {}
        () = state_handle => {}
        _ = tokio::signal::ctrl_c() => {
            println!("\nshutting down...");
        }
    }

    rendezvous.shutdown().await;
    Ok(())
}
