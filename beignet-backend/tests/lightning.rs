//! `BeignetLightningBackend` against a mock daemon.
//!
//! Call counts matter as much as responses here: several of these assert that a request was
//! *not* repeated, which is the property that keeps a lost response from spending money twice.

use beignet_backend::{BeignetConfig, BeignetHttp, BeignetLightningBackend};
use lightning_backend::{HoldInvoiceRequest, InvoiceState, LightningBackend, PaymentStatus};
use std::sync::Arc;
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ok(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true, "result": body }))
}

fn err(status: u16, code: &str, message: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_json(serde_json::json!({
        "ok": false,
        "error": { "code": code, "message": message }
    }))
}

async fn backend(server: &MockServer) -> BeignetLightningBackend {
    let http =
        BeignetHttp::new(BeignetConfig::new(server.uri()).with_token(Some("test-token".into())))
            .unwrap();
    BeignetLightningBackend::new(Arc::new(http))
}

const HASH: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
const PREIMAGE: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

fn hash_bytes() -> [u8; 32] {
    hex::decode(HASH).unwrap().try_into().unwrap()
}

/// A decode reply, so the CLTV verification has something to check.
fn decoded(amount_sats: u64, cltv: u32) -> serde_json::Value {
    serde_json::json!({
        "paymentHash": HASH,
        "amountSats": amount_sats,
        "minFinalCltvExpiry": cltv,
    })
}

#[tokio::test]
async fn node_info_combines_info_and_health() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ok(
            serde_json::json!({ "nodeId": "02ab", "alias": "n", "network": "regtest" }),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ok(
            serde_json::json!({ "status": "ready", "electrumConnected": true }),
        ))
        .mount(&server)
        .await;

    let info = backend(&server).await.node_info().await.unwrap();
    assert_eq!(info.pubkey, "02ab");
    assert_eq!(info.chain_network.as_deref(), Some("regtest"));
    assert!(info.synced_to_chain);
}

/// A daemon that cannot reach Electrum is not synced, whatever else it says.
#[tokio::test]
async fn a_daemon_without_electrum_is_not_synced() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ok(
            serde_json::json!({ "nodeId": "02ab", "network": "regtest" }),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ok(
            serde_json::json!({ "status": "ready", "electrumConnected": false }),
        ))
        .mount(&server)
        .await;
    assert!(
        !backend(&server)
            .await
            .node_info()
            .await
            .unwrap()
            .synced_to_chain
    );
}

#[tokio::test]
async fn creating_a_hold_invoice_sends_the_expected_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/invoices/held"))
        .respond_with(ok(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/create-hold"))
        // amountMsat as a string: the daemon parses it with BigInt.
        .and(body_partial_json(serde_json::json!({
            "paymentHash": HASH,
            "amountMsat": "100000000",
            "minFinalCltvExpiry": 216,
        })))
        .respond_with(ok(
            serde_json::json!({ "bolt11": "lnbcrt1", "paymentHash": HASH }),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/decode"))
        .respond_with(ok(decoded(100_000, 216)))
        .mount(&server)
        .await;

    let invoice = backend(&server)
        .await
        .create_hold_invoice(HoldInvoiceRequest {
            payment_hash: hash_bytes(),
            amount_msat: 100_000_000,
            expiry_secs: 3600,
            cltv_expiry_delta: 216,
            memo: "swap".into(),
        })
        .await
        .unwrap();
    assert_eq!(invoice.bolt11, "lnbcrt1");
}

/// The gap that makes beignet unable to serve reverse swaps today.
///
/// The daemon ignores the requested delta and issues an invoice with its own default. Trusting
/// the request would leave the Lightning leg expiring before the on-chain refund, which lets the
/// payer take both legs. So the invoice is decoded, the realised value checked, and the invoice
/// cancelled rather than used.
#[tokio::test]
async fn refuses_a_hold_invoice_whose_cltv_is_too_short() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/invoices/held"))
        .respond_with(ok(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/create-hold"))
        .respond_with(ok(
            serde_json::json!({ "bolt11": "lnbcrt1", "paymentHash": HASH }),
        ))
        .mount(&server)
        .await;
    // The node applied 80, not the 216 we asked for.
    Mock::given(method("POST"))
        .and(path("/invoice/decode"))
        .respond_with(ok(decoded(100_000, 80)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/cancel-hold"))
        .respond_with(ok(serde_json::json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let err = backend(&server)
        .await
        .create_hold_invoice(HoldInvoiceRequest {
            payment_hash: hash_bytes(),
            amount_msat: 100_000_000,
            expiry_secs: 3600,
            cltv_expiry_delta: 216,
            memo: "swap".into(),
        })
        .await
        .expect_err("an 80-block CLTV against a 216-block requirement must be refused");
    let message = err.to_string();
    assert!(message.contains("80"), "{message}");
    assert!(message.contains("216"), "{message}");
}

/// Creating a hold invoice is not idempotent upstream, so a lost response would otherwise mint a
/// second invoice for the same swap.
#[tokio::test]
async fn an_existing_hold_invoice_is_reused_rather_than_recreated() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/invoices/held"))
        .respond_with(ok(serde_json::json!([{
            "paymentHash": HASH,
            "bolt11": "lnbcrt-existing",
            "state": "OPEN",
        }])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/create-hold"))
        .respond_with(ok(serde_json::json!({})))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/decode"))
        .respond_with(ok(decoded(100_000, 216)))
        .mount(&server)
        .await;

    let invoice = backend(&server)
        .await
        .create_hold_invoice(HoldInvoiceRequest {
            payment_hash: hash_bytes(),
            amount_msat: 100_000_000,
            expiry_secs: 3600,
            cltv_expiry_delta: 216,
            memo: "swap".into(),
        })
        .await
        .unwrap();
    assert_eq!(invoice.bolt11, "lnbcrt-existing");
}

#[tokio::test]
async fn invoice_status_maps_hold_states() {
    for (reported, expected) in [
        ("OPEN", InvoiceState::Open),
        ("ACCEPTED", InvoiceState::Accepted),
        ("SETTLED", InvoiceState::Settled),
        ("CANCELLED", InvoiceState::Cancelled),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/invoices/held"))
            .respond_with(ok(serde_json::json!([{
                "paymentHash": HASH,
                "state": reported,
                "heldAmountMsat": "100000000",
            }])))
            .mount(&server)
            .await;
        let status = backend(&server)
            .await
            .invoice_status(hash_bytes())
            .await
            .unwrap();
        assert_eq!(status.state, expected, "for {reported}");
    }
}

/// A plain invoice the submarine client issued never appears in the hold list, so the payment
/// record is the only place to look.
#[tokio::test]
async fn invoice_status_falls_back_to_the_payment_record() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/invoices/held"))
        .respond_with(ok(serde_json::json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/payment"))
        .and(query_param("paymentHash", HASH))
        .respond_with(ok(
            serde_json::json!({ "paymentHash": HASH, "status": "COMPLETED" }),
        ))
        .mount(&server)
        .await;
    let status = backend(&server)
        .await
        .invoice_status(hash_bytes())
        .await
        .unwrap();
    assert_eq!(status.state, InvoiceState::Settled);
}

/// A settle that fails because it already happened is success. Failing it would fail a completed
/// swap on a retried call after a lost response.
#[tokio::test]
async fn settling_an_already_settled_invoice_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/invoice/settle-hold"))
        .respond_with(err(404, "NOT_FOUND", "no such hold invoice"))
        .mount(&server)
        .await;
    let preimage: [u8; 32] = hex::decode(PREIMAGE).unwrap().try_into().unwrap();
    let hash = swap_common::htlc::payment_hash(&preimage);
    Mock::given(method("GET"))
        .and(path("/invoices/held"))
        .respond_with(ok(serde_json::json!([{
            "paymentHash": hex::encode(hash),
            "state": "SETTLED",
        }])))
        .mount(&server)
        .await;

    backend(&server)
        .await
        .settle_hold_invoice(preimage)
        .await
        .expect("an already-settled invoice is the outcome we wanted");
}

#[tokio::test]
async fn cancelling_a_missing_invoice_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/invoice/cancel-hold"))
        .respond_with(err(404, "NOT_FOUND", "gone"))
        .mount(&server)
        .await;
    backend(&server)
        .await
        .cancel_hold_invoice(hash_bytes())
        .await
        .unwrap();
}

#[tokio::test]
async fn paying_extracts_the_preimage_and_converts_the_fee() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/invoice/decode"))
        .respond_with(ok(decoded(100_000, 80)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/pay"))
        // A sub-satoshi budget must round UP, or it becomes zero and forbids all routing fees.
        .and(body_partial_json(serde_json::json!({ "maxFeeSats": 1 })))
        .respond_with(ok(serde_json::json!({
            "paymentHash": HASH,
            "status": "COMPLETED",
            "preimage": PREIMAGE,
            "feeSats": 3,
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = backend(&server)
        .await
        .pay_invoice("lnbcrt1", 999, None)
        .await
        .unwrap();
    assert_eq!(hex::encode(result.preimage), PREIMAGE);
    assert_eq!(result.fee_msat, 3_000);
}

/// The preimage is what settles the other leg, so if the payment record does not carry it the
/// proof route is asked rather than the swap failing.
#[tokio::test]
async fn a_missing_preimage_is_recovered_from_the_proof() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/invoice/decode"))
        .respond_with(ok(decoded(100_000, 80)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/pay"))
        .respond_with(ok(
            serde_json::json!({ "paymentHash": HASH, "status": "COMPLETED", "feeSats": 0 }),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/payment/proof"))
        .respond_with(ok(serde_json::json!({ "preimage": PREIMAGE })))
        .expect(1)
        .mount(&server)
        .await;

    let result = backend(&server)
        .await
        .pay_invoice("lnbcrt1", 10_000, None)
        .await
        .unwrap();
    assert_eq!(hex::encode(result.preimage), PREIMAGE);
}

/// An amountless invoice lets the payee choose what we send, which is not a swap.
#[tokio::test]
async fn refuses_an_amountless_invoice() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/invoice/decode"))
        .respond_with(ok(serde_json::json!({ "paymentHash": HASH })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invoice/pay"))
        .respond_with(ok(serde_json::json!({})))
        .expect(0)
        .mount(&server)
        .await;

    assert!(backend(&server)
        .await
        .pay_invoice("lnbcrt1", 10_000, None)
        .await
        .is_err());
}

#[tokio::test]
async fn payment_status_maps_the_node_answer() {
    for (reported, check) in [
        ("COMPLETED", "succeeded"),
        ("PENDING", "inflight"),
        ("FAILED", "failed"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payment"))
            .respond_with(ok(serde_json::json!({
                "paymentHash": HASH,
                "status": reported,
                "preimage": PREIMAGE,
                "feeSats": 0,
            })))
            .mount(&server)
            .await;
        let status = backend(&server)
            .await
            .payment_status(hash_bytes())
            .await
            .unwrap();
        let matched = matches!(
            (&status, check),
            (PaymentStatus::Succeeded(_), "succeeded")
                | (PaymentStatus::InFlight, "inflight")
                | (PaymentStatus::Failed(_), "failed")
        );
        assert!(matched, "{reported} mapped to {status:?}");
    }
}

/// A hash the node has never seen is `Unknown`, not an error: the caller uses that to decide
/// whether it is safe to pay.
#[tokio::test]
async fn an_unknown_payment_hash_is_unknown_not_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/payment"))
        .respond_with(err(404, "NOT_FOUND", "no such payment"))
        .mount(&server)
        .await;
    assert!(matches!(
        backend(&server)
            .await
            .payment_status(hash_bytes())
            .await
            .unwrap(),
        PaymentStatus::Unknown
    ));
}

/// A read is retried; a typed refusal is not, because repeating a request the daemon has already
/// declined only delays finding out.
#[tokio::test]
async fn transient_failures_retry_but_refusals_do_not() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/invoices/held"))
        .respond_with(err(503, "UNAVAILABLE", "busy"))
        .expect(3)
        .mount(&server)
        .await;
    assert!(backend(&server)
        .await
        .invoice_status(hash_bytes())
        .await
        .is_err());
    drop(server);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/invoices/held"))
        .respond_with(err(400, "INVALID_PARAMS", "no"))
        .expect(1)
        .mount(&server)
        .await;
    assert!(backend(&server)
        .await
        .invoice_status(hash_bytes())
        .await
        .is_err());
}
