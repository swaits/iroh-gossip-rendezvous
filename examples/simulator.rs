//! Discrete-event simulator for the rendezvous algorithm.
//!
//! Runs the protocol (Merge + heal-read) directly against an in-memory DHT —
//! no iroh-gossip, no network. Drives the partition-healing and cold-start
//! scenarios from §8 of the design doc.
//!
//! ```text
//! cargo run --release --example simulator --features sim -- \
//!     --scenario cold-start --nodes 10 --runs 50
//! cargo run --release --example simulator --features sim -- \
//!     --scenario partition --nodes 10 --runs 50
//! cargo run --release --example simulator --features sim -- \
//!     --scenario asymmetric --minority 1 --majority 50 --runs 50
//! ```

use anyhow::Result;
use clap::{Parser, ValueEnum};
use iroh_gossip_rendezvous::sim::{self, Outcome, Scenario, SimConfig};

#[derive(Parser)]
#[command(about = "iroh-gossip-rendezvous discrete-event simulator")]
struct Args {
    /// Scenario to run.
    #[arg(long, value_enum, default_value_t = ScenarioArg::ColdStart)]
    scenario: ScenarioArg,

    /// Number of runs.
    #[arg(long, default_value_t = 50)]
    runs: usize,

    /// Max rounds per run before declaring it unhealed.
    #[arg(long, default_value_t = 30)]
    max_rounds: usize,

    /// Total nodes (cold-start) or per-partition (partition).
    #[arg(long, default_value_t = 6)]
    nodes: usize,

    /// Minority size (asymmetric only).
    #[arg(long, default_value_t = 1)]
    minority: usize,

    /// Majority size (asymmetric only).
    #[arg(long, default_value_t = 20)]
    majority: usize,

    /// Shard count K.
    #[arg(long, default_value_t = 3)]
    shards: usize,

    /// Base passphrase. Per-run seeding appends the run index.
    #[arg(long, default_value = "simulator")]
    passphrase: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScenarioArg {
    ColdStart,
    Partition,
    Asymmetric,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(args))
}

async fn run(args: Args) -> Result<()> {
    let cfg = SimConfig {
        shards: args.shards,
        max_rounds: args.max_rounds,
        ..SimConfig::default()
    };

    let scenario = match args.scenario {
        ScenarioArg::ColdStart => Scenario::ColdStart { nodes: args.nodes },
        ScenarioArg::Partition => Scenario::Partition {
            a: args.nodes / 2,
            b: args.nodes - args.nodes / 2,
        },
        ScenarioArg::Asymmetric => Scenario::Asymmetric {
            minority: args.minority,
            majority: args.majority,
        },
    };

    let mut outcomes: Vec<Outcome> = Vec::with_capacity(args.runs);
    for run_idx in 0..args.runs {
        let pass = format!("{}-{run_idx}", args.passphrase);
        let outcome = sim::run(&pass, scenario, &cfg).await;
        outcomes.push(outcome);
    }
    report(&args, scenario, &outcomes);
    Ok(())
}

fn report(args: &Args, scenario: Scenario, outcomes: &[Outcome]) {
    let total = outcomes.len();
    let healed: Vec<usize> = outcomes.iter().filter_map(|o| o.healed_in).collect();
    let unhealed = total - healed.len();
    let pct = healed.len() as f64 / total as f64 * 100.0;

    println!("scenario:    {scenario:?}");
    println!("shards (K):  {}", args.shards);
    println!("max rounds:  {}", args.max_rounds);
    println!("runs:        {total}");
    println!("healed:      {} ({:.1}%)", healed.len(), pct);
    println!("unhealed:    {unhealed}");
    if !healed.is_empty() {
        let mut sorted = healed.clone();
        sorted.sort_unstable();
        let min = sorted[0];
        let max = sorted[sorted.len() - 1];
        let p50 = sorted[sorted.len() / 2];
        let p95_idx = ((sorted.len() * 95) / 100)
            .saturating_sub(1)
            .min(sorted.len() - 1);
        let p95 = sorted[p95_idx];
        let mean = sorted.iter().sum::<usize>() as f64 / sorted.len() as f64;
        println!("rounds:      min={min} p50={p50} p95={p95} max={max} mean={mean:.1}");
    }
    let avg_reads = outcomes.iter().map(|o| o.dht_reads as f64).sum::<f64>() / total as f64;
    let avg_writes = outcomes.iter().map(|o| o.dht_writes as f64).sum::<f64>() / total as f64;
    println!("dht ops:     avg reads {avg_reads:.1}, avg writes {avg_writes:.1}");
}
