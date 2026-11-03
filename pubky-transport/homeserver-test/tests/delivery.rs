//! Local homeserver delivery validation and read/poll measurements, against pubky 0.16.2.
//!
//! Needs Docker for Postgres, or `TEST_PUBKY_CONNECTION_STRING`. Run with
//! `cargo test --manifest-path pubky-transport/homeserver-test/Cargo.toml`.

use futures::{stream, StreamExt};
use pubky_testnet::{docker_postgres::DockerPostgres, Testnet};
use pubky_transport::test_util::{
    self,
    pubky_messenger::{Keypair, PrivateMessengerClient, PublicKey, RequestCounts, RequestStats},
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// A local DHT whose homeservers keep their data in the Postgres that
/// `TEST_PUBKY_CONNECTION_STRING` names, or else in one Docker Postgres per test binary.
async fn testnet() -> Testnet {
    if std::env::var_os("TEST_PUBKY_CONNECTION_STRING").is_some() {
        return Testnet::new().await.expect("testnet");
    }
    let postgres = DockerPostgres::shared()
        .await
        .connection_string()
        .expect("Docker Postgres connection string");
    Testnet::new_with_custom_postgres(postgres)
        .await
        .expect("testnet")
}

/// A homeserver with open sign-up.
async fn homeserver(testnet: &mut Testnet) -> PublicKey {
    testnet
        .create_random_homeserver()
        .await
        .expect("homeserver")
        .public_key()
        .into_inner()
}

async fn signed_up(testnet: &Testnet, homeserver: &PublicKey) -> PrivateMessengerClient {
    let client = PrivateMessengerClient::with_client(
        Keypair::random(),
        testnet.client_builder().build().unwrap(),
    );
    client.sign_up(homeserver, None).await.unwrap();
    client
}

fn restored(testnet: &Testnet, keypair: Keypair) -> PrivateMessengerClient {
    PrivateMessengerClient::with_client(keypair, testnet.client_builder().build().unwrap())
}

#[tokio::test]
async fn durable_publication_restarts_and_cleans_only_completed_scope() {
    let mut testnet = testnet().await;
    let homeserver = homeserver(&mut testnet).await;
    let alice = signed_up(&testnet, &homeserver).await;
    let bob = signed_up(&testnet, &homeserver).await;
    let alice_keypair = alice.keypair().clone();
    let alice_public = alice.public_key();
    let bob_public = bob.public_key_string();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("outbox.json");
    let transport = test_util::wrap(alice).with_outbox(&path).unwrap();
    transport
        .enqueue_with_scope(&bob_public, "swap:complete", &7_u32)
        .unwrap();
    transport
        .enqueue_with_scope(&bob_public, "swap:active", &8_u32)
        .unwrap();
    assert_eq!(transport.request_stats().put.attempts, 0);
    assert_eq!(transport.request_stats().session.attempts, 0);
    let reserved = test_util::outbox(&transport)
        .unwrap()
        .due_pending(0, 4)
        .unwrap();
    assert_eq!(reserved.len(), 2);
    drop(transport);

    let transport = test_util::wrap(restored(&testnet, alice_keypair))
        .with_outbox(&path)
        .unwrap();
    let reopened = test_util::outbox(&transport)
        .unwrap()
        .due_pending(0, 4)
        .unwrap();
    for (before, after) in reserved.iter().zip(&reopened) {
        assert_eq!(before.id(), after.id());
        assert_eq!(before.payload(), after.payload());
    }
    transport
        .process_outbox(test_util::unix_time(), 4)
        .await
        .unwrap();
    assert_eq!(transport.request_stats().put.attempts, 2);
    assert_eq!(bob.get_messages(&alice_public).await.unwrap().len(), 2);

    // Explicit replay reuses the saved resource after the original publication succeeded.
    transport
        .send_with_scope(&bob_public, "swap:complete", &7_u32)
        .await
        .unwrap();
    assert_eq!(bob.get_messages(&alice_public).await.unwrap().len(), 2);
    transport
        .complete_scope(&bob_public, "swap:complete", test_util::unix_time())
        .unwrap();
    transport
        .process_outbox(test_util::unix_time(), 4)
        .await
        .unwrap();
    let remaining = bob.get_messages(&alice_public).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].content, "8");
    assert!(remaining[0].verified);
    assert!(transport
        .send_with_scope(&bob_public, "swap:active", &8_u32)
        .await
        .is_ok());
    assert_eq!(bob.get_messages(&alice_public).await.unwrap().len(), 1);
    assert_eq!(transport.request_stats().delete.attempts, 1);
}

#[tokio::test]
async fn changed_ephemeral_replies_keep_distinct_stable_resources() {
    let mut testnet = testnet().await;
    let homeserver = homeserver(&mut testnet).await;
    let alice = signed_up(&testnet, &homeserver).await;
    let bob = signed_up(&testnet, &homeserver).await;
    let alice_public = alice.public_key();
    let bob_public = bob.public_key_string();
    let directory = tempfile::tempdir().unwrap();
    let transport = test_util::wrap(alice)
        .with_outbox(directory.path().join("outbox.json"))
        .unwrap();
    for value in [1_u32, 2, 1] {
        transport
            .enqueue_with_scope(&bob_public, "ephemeral:status:request", &value)
            .unwrap();
    }
    assert_eq!(
        test_util::outbox(&transport)
            .unwrap()
            .due_pending(0, 4)
            .unwrap()
            .len(),
        2
    );
    transport
        .process_outbox(test_util::unix_time(), 4)
        .await
        .unwrap();
    let mut received: Vec<_> = bob
        .get_messages(&alice_public)
        .await
        .unwrap()
        .into_iter()
        .map(|message| message.content)
        .collect();
    received.sort();
    assert_eq!(received, ["1", "2"]);
    assert_eq!(transport.request_stats().put.attempts, 2);
}

fn counts_delta(before: RequestCounts, after: RequestCounts) -> Value {
    json!({
        "attempts": after.attempts.saturating_sub(before.attempts),
        "request_body_bytes": after.request_body_bytes.saturating_sub(before.request_body_bytes),
        "response_body_bytes": after.response_body_bytes.saturating_sub(before.response_body_bytes),
    })
}

fn stats_delta(before: RequestStats, after: RequestStats) -> Value {
    json!({
        "list": counts_delta(before.list, after.list),
        "get": counts_delta(before.get, after.get),
        "put": counts_delta(before.put, after.put),
        "delete": counts_delta(before.delete, after.delete),
        "session": counts_delta(before.session, after.session),
        "retries": after.retries.saturating_sub(before.retries),
        "timeouts": after.timeouts.saturating_sub(before.timeouts),
        "queue_wait_ms": after.queue_wait.saturating_sub(before.queue_wait).as_secs_f64() * 1000.0,
    })
}

fn percentile(samples: &[Duration], percentile: usize) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[index].as_secs_f64() * 1000.0
}

fn report(
    phase: &str,
    history: usize,
    samples: &[Duration],
    before: RequestStats,
    after: RequestStats,
    journal_bytes: u64,
) {
    println!(
        "{}",
        json!({
            "benchmark": "local_homeserver_read_poll",
            "phase": phase,
            "history_layout": "incoming messages in one conversation",
            "fixture_body": "JSON object with 128-byte data field",
            "acknowledged_history": history,
            "samples": samples.len(),
            "p50_ms": percentile(samples, 50),
            "p95_ms": percentile(samples, 95),
            "sample_ms": samples.iter().map(|value| value.as_secs_f64() * 1000.0).collect::<Vec<_>>(),
            "request_totals": stats_delta(before, after),
            "receive_journal_bytes": journal_bytes,
        })
    );
}

/// Measures reads of already handled history. No swap, Lightning payment or funded negotiation
/// runs here. Setup writes real encrypted resources to an isolated local homeserver with open
/// sign-up, on the testnet's Postgres, bounded to 16 concurrent publications. Identities are
/// generated only for this run. Warmups and fixture acknowledgment are excluded from samples.
#[tokio::test]
#[ignore = "local homeserver read/poll benchmark seeds 10,000 encrypted resources"]
async fn local_homeserver_read_poll_benchmark() {
    let mut testnet = testnet().await;
    let homeserver = homeserver(&mut testnet).await;
    for history in [0_usize, 200, 10_000] {
        let sender = signed_up(&testnet, &homeserver).await;
        let baseline = signed_up(&testnet, &homeserver).await;
        let recipient = baseline.public_key();
        let seed_before = sender.request_stats();
        let seed_started = Instant::now();
        let completed = std::sync::atomic::AtomicUsize::new(0);
        let seeded = stream::iter(0..history)
            .map(|sequence| {
                let sender = &sender;
                let completed = &completed;
                let recipient = &recipient;
                async move {
                    let payload = json!({
                        "sequence": sequence,
                        "kind": "read-poll-fixture",
                        "data": "x".repeat(128),
                    })
                    .to_string();
                    sender.send_message(recipient, &payload).await.unwrap();
                    let count = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    if count.is_multiple_of(1000) {
                        println!("{}", json!({"phase": "fixture_seed_progress", "history": history, "completed": count}));
                    }
                }
            })
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(seeded.len(), history);
        println!(
            "{}",
            json!({
                "benchmark": "local_homeserver_read_poll",
                "phase": "fixture_seed",
                "history": history,
                "history_layout": "incoming messages in one conversation",
                "fixture_body": "JSON object with 128-byte data field",
                "elapsed_ms": seed_started.elapsed().as_secs_f64() * 1000.0,
                "request_totals": stats_delta(seed_before, sender.request_stats()),
            })
        );

        let peer = sender.public_key();
        assert_eq!(baseline.get_messages(&peer).await.unwrap().len(), history);
        let before = baseline.request_stats();
        let mut samples = Vec::new();
        for _ in 0..3 {
            let started = Instant::now();
            assert_eq!(baseline.get_messages(&peer).await.unwrap().len(), history);
            samples.push(started.elapsed());
        }
        report(
            "full_history",
            history,
            &samples,
            before,
            baseline.request_stats(),
            0,
        );

        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("receive.json");
        let incremental = test_util::wrap(restored(&testnet, baseline.keypair().clone()))
            .with_receive_journal(&journal)
            .unwrap();
        // Fixture history is known to have been handled. Listing acknowledgment avoids
        // including initial migration and body downloads in a warm incremental measurement.
        assert_eq!(
            test_util::acknowledge_listed(&incremental, &peer)
                .await
                .unwrap(),
            history
        );
        let peer = peer.to_string();
        assert!(incremental
            .poll_from::<Value>(&peer)
            .await
            .unwrap()
            .is_empty());
        let before = incremental.request_stats();
        let mut samples = Vec::new();
        for _ in 0..7 {
            let started = Instant::now();
            assert!(incremental
                .poll_from::<Value>(&peer)
                .await
                .unwrap()
                .is_empty());
            samples.push(started.elapsed());
        }
        let after = incremental.request_stats();
        assert_eq!(after.get.attempts, before.get.attempts);
        report(
            "incremental_acknowledged",
            history,
            &samples,
            before,
            after,
            std::fs::metadata(&journal).unwrap().len(),
        );
    }
}
