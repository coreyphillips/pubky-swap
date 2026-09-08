//! `BeignetWallet` against a mock daemon.

use beignet_backend::{BeignetConfig, BeignetHttp, BeignetWallet};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use std::str::FromStr;
use std::sync::Arc;
use swap_common::wallet::OnchainWallet;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ok(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true, "result": body }))
}

fn err(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({
        "ok": false, "error": { "code": code, "message": code }
    }))
}

/// A regtest P2WPKH the mock hands out as the sweep destination.
const SWEEP_ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

fn htlc_spk() -> ScriptBuf {
    // A P2WSH, which is what a real HTLC is.
    ScriptBuf::from_hex("0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap()
}

/// A funding transaction paying `amount` to the HTLC script at vout 1, with a change output
/// first, so a test proves the vout is found rather than assumed.
fn funding_tx(amount: u64) -> Transaction {
    Transaction {
        version: 2,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![
            TxOut {
                value: 5_000,
                script_pubkey: ScriptBuf::from_hex("0014cccccccccccccccccccccccccccccccccccccccc")
                    .unwrap(),
            },
            TxOut {
                value: amount,
                script_pubkey: htlc_spk(),
            },
        ],
    }
}

async fn mount_address(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/address/new"))
        .respond_with(ok(serde_json::json!({ "address": SWEEP_ADDRESS })))
        .mount(server)
        .await;
}

async fn wallet(server: &MockServer) -> BeignetWallet {
    let http = Arc::new(
        BeignetHttp::new(BeignetConfig::new(server.uri()).with_token(Some("t".into()))).unwrap(),
    );
    BeignetWallet::connect(http, Network::Regtest, 5, None)
        .await
        .unwrap()
}

#[tokio::test]
async fn funding_finds_the_right_output_in_the_returned_transaction() {
    let server = MockServer::start().await;
    mount_address(&server).await;
    let tx = funding_tx(100_000);
    let txid = tx.txid();
    Mock::given(method("POST"))
        .and(path("/send"))
        .and(body_partial_json(serde_json::json!({
            "amountSats": 100_000,
            "satsPerVbyte": 5,
        })))
        .respond_with(ok(serde_json::json!({
            "txid": txid.to_string(),
            "hex": hex::encode(bitcoin::consensus::serialize(&tx)),
        })))
        .expect(1)
        .mount(&server)
        .await;

    let w = wallet(&server).await;
    let outpoint = tokio::task::spawn_blocking(move || w.fund_htlc(&htlc_spk(), 100_000))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outpoint, OutPoint { txid, vout: 1 });
}

/// Matching on the script alone would accept a change output that happens to pay the same
/// script. The chain watcher matches on exact value, so a value mismatch has to fail loudly
/// rather than return an outpoint the rest of the engine will not recognise.
#[tokio::test]
async fn funding_rejects_a_transaction_whose_value_is_wrong() {
    let server = MockServer::start().await;
    mount_address(&server).await;
    let tx = funding_tx(99_999);
    Mock::given(method("POST"))
        .and(path("/send"))
        .respond_with(ok(serde_json::json!({
            "txid": tx.txid().to_string(),
            "hex": hex::encode(bitcoin::consensus::serialize(&tx)),
        })))
        .mount(&server)
        .await;

    let w = wallet(&server).await;
    let result = tokio::task::spawn_blocking(move || w.fund_htlc(&htlc_spk(), 100_000))
        .await
        .unwrap();
    assert!(
        result.is_err(),
        "a 99_999 sat output must not pass as 100_000"
    );
}

/// `/send` is the call that moves the money, and beignet does not honour an idempotency key on
/// it (beignet#745), so a lost response is indistinguishable from a lost request. Repeating it
/// would spend twice.
#[tokio::test]
async fn funding_is_never_retried() {
    let server = MockServer::start().await;
    mount_address(&server).await;
    Mock::given(method("POST"))
        .and(path("/send"))
        .respond_with(err(503, "UNAVAILABLE"))
        .expect(1)
        .mount(&server)
        .await;

    let w = wallet(&server).await;
    let result = tokio::task::spawn_blocking(move || w.fund_htlc(&htlc_spk(), 100_000))
        .await
        .unwrap();
    assert!(result.is_err());
    // The `.expect(1)` above is the real assertion: exactly one attempt, even though a 503 is
    // otherwise the most retryable answer there is.
}

/// `receive_destination` is infallible and is called from async code with no bridge, so it has to
/// be resolved once and cached.
#[tokio::test]
async fn the_sweep_destination_is_resolved_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/address/new"))
        .respond_with(ok(serde_json::json!({ "address": SWEEP_ADDRESS })))
        .expect(1)
        .mount(&server)
        .await;

    let w = wallet(&server).await;
    let expected = Address::from_str(SWEEP_ADDRESS)
        .unwrap()
        .assume_checked()
        .script_pubkey();
    for _ in 0..10 {
        assert_eq!(w.receive_destination(), expected);
    }
}

#[tokio::test]
async fn balance_is_reported_for_the_provider_preflight() {
    let server = MockServer::start().await;
    mount_address(&server).await;
    Mock::given(method("GET"))
        .and(path("/balance"))
        .respond_with(ok(
            serde_json::json!({ "onchain": 250_000, "lightning": 10 }),
        ))
        .mount(&server)
        .await;

    let w = wallet(&server).await;
    let balance = tokio::task::spawn_blocking(move || w.spendable_balance_sat())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(balance, Some(250_000));
}

/// A claim or refund is a transaction beignet did not send, so it cannot replace it; `/tx/boost`
/// takes the CPFP path, which is what is wanted.
#[tokio::test]
async fn cpfp_refreshes_the_wallet_then_boosts() {
    let server = MockServer::start().await;
    mount_address(&server).await;
    Mock::given(method("POST"))
        .and(path("/wallet/refresh"))
        .respond_with(ok(serde_json::json!({ "refreshed": true })))
        .expect(1)
        .mount(&server)
        .await;
    let child = "1111111111111111111111111111111111111111111111111111111111111111";
    Mock::given(method("POST"))
        .and(path("/tx/boost"))
        .respond_with(ok(
            serde_json::json!({ "txid": child, "boostType": "cpfp" }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let w = wallet(&server).await;
    let parent = OutPoint {
        txid: Txid::from_str("2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap(),
        vout: 0,
    };
    let result = tokio::task::spawn_blocking(move || w.cpfp_bump(parent, 50))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.map(|t| t.to_string()).as_deref(), Some(child));
}

/// Both call sites treat a bump as best effort, so a refusal is `Ok(None)` with a log rather than
/// an error they would swallow identically.
#[tokio::test]
async fn an_unboostable_transaction_is_not_an_error() {
    let server = MockServer::start().await;
    mount_address(&server).await;
    Mock::given(method("POST"))
        .and(path("/wallet/refresh"))
        .respond_with(ok(serde_json::json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tx/boost"))
        .respond_with(err(409, "NOT_BOOSTABLE"))
        .mount(&server)
        .await;

    let w = wallet(&server).await;
    let parent = OutPoint {
        txid: Txid::from_str("3333333333333333333333333333333333333333333333333333333333333333")
            .unwrap(),
        vout: 0,
    };
    let result = tokio::task::spawn_blocking(move || w.cpfp_bump(parent, 50))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, None);
}

/// Sweeping to an address on another chain would be a very quiet way to lose money.
#[tokio::test]
async fn a_mainnet_address_is_refused_on_regtest() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/address/new"))
        .respond_with(ok(
            serde_json::json!({ "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" }),
        ))
        .mount(&server)
        .await;
    let http = Arc::new(
        BeignetHttp::new(BeignetConfig::new(server.uri()).with_token(Some("t".into()))).unwrap(),
    );
    let result = BeignetWallet::connect(http, Network::Regtest, 5, None).await;
    assert!(
        result.is_err(),
        "a mainnet address must not be accepted on regtest"
    );
}
