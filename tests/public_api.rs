//! Smoke tests for the public API surface — compile-and-dispatch checks
//! that the public types are shaped as advertised. No network required.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iroh_gossip_rendezvous::{Builder, Error, Rendezvous};

/// `Rendezvous::join` rejects an empty passphrase before any network IO.
#[tokio::test]
async fn join_empty_passphrase_errors() {
    let r = Rendezvous::join("", "my-app/v1").await;
    assert!(matches!(r, Err(Error::EmptyPassphrase)));
}

/// Same for an empty app_salt.
#[tokio::test]
async fn join_empty_app_salt_errors() {
    let r = Rendezvous::join("passphrase", "").await;
    assert!(matches!(r, Err(Error::EmptyAppSalt)));
}

/// The builder enforces the same checks.
#[tokio::test]
async fn builder_requires_passphrase() {
    let r = Builder::default().app_salt("my-app/v1").build().await;
    assert!(matches!(r, Err(Error::EmptyPassphrase)));
}

#[tokio::test]
async fn builder_requires_app_salt() {
    let r = Builder::default().passphrase("pass").build().await;
    assert!(matches!(r, Err(Error::EmptyAppSalt)));
}

#[tokio::test]
async fn builder_rejects_zero_shards() {
    let r = Builder::default()
        .passphrase("pass")
        .app_salt("my-app/v1")
        .shards(0)
        .build()
        .await;
    assert!(matches!(r, Err(Error::InvalidShardCount)));
}

#[tokio::test]
async fn builder_rejects_zero_max_age() {
    let r = Builder::default()
        .passphrase("pass")
        .app_salt("my-app/v1")
        .max_age(0)
        .build()
        .await;
    assert!(matches!(r, Err(Error::InvalidMaxAge)));
}

/// Public re-exports compile as documented.
#[test]
fn public_types_exist() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<Rendezvous>();
    assert_sync::<Rendezvous>();
    assert_send::<Builder>();
}
