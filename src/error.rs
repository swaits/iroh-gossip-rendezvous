//! Error types for the rendezvous crate.

/// Boxed dynamic error used for wrapping upstream failures without leaking
/// a specific upstream error type into our public API.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Errors returned by the public API.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("passphrase is empty")]
    EmptyPassphrase,

    #[error("app_salt is empty")]
    EmptyAppSalt,

    #[error("shard count must be >= 1")]
    InvalidShardCount,

    #[error("max_age must be in 1..=255")]
    InvalidMaxAge,

    #[error("iroh endpoint error: {0}")]
    Endpoint(#[source] BoxError),

    #[error("iroh-gossip error: {0}")]
    Gossip(#[source] BoxError),

    #[error("DHT error: {0}")]
    Dht(#[source] BoxError),

    #[error("receiver already taken")]
    ReceiverTaken,

    #[error("crypto error: {0}")]
    Crypto(&'static str),

    #[error("malformed record: {0}")]
    MalformedRecord(&'static str),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
