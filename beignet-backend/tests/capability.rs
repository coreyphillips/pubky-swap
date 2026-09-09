//! The startup probe, against a mock daemon's OpenAPI document.
//!
//! This is the thing standing between an operator and a provider that advertises a swap it cannot
//! serve safely. Two directions gate on it and each gate is a fund-loss defect if it opens by
//! mistake: reverse swaps on a hold invoice whose final CLTV cannot be set (beignet#744), and
//! submarine swaps on a payment whose total CLTV cannot be bounded (beignet#751).
//!
//! The gates open by themselves when a daemon advertises the field, which is the right behaviour
//! and also the reason to pin it: nothing else would notice if the probe stopped finding one.

use beignet_backend::{capability, BeignetConfig, BeignetHttp};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ok(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true, "result": body }))
}

/// An OpenAPI document declaring exactly the request fields named.
fn openapi(hold_fields: &[&str], pay_fields: &[&str]) -> serde_json::Value {
    let props = |fields: &[&str]| {
        let mut m = serde_json::Map::new();
        for f in fields {
            m.insert((*f).to_string(), serde_json::json!({ "type": "integer" }));
        }
        serde_json::Value::Object(m)
    };
    serde_json::json!({
        "paths": {
            "/invoice/create-hold": {
                "post": { "requestBody": { "content": { "application/json": {
                    "schema": { "properties": props(hold_fields) } } } } }
            },
            "/invoice/pay": {
                "post": { "requestBody": { "content": { "application/json": {
                    "schema": { "properties": props(pay_fields) } } } } }
            }
        }
    })
}

async fn probe_against(spec: serde_json::Value) -> capability::Preflight {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ok(serde_json::json!({
            "nodeId": "02aa", "network": "regtest", "blockHeight": 1
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ok(serde_json::json!({ "status": "ok" })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/balance"))
        .respond_with(ok(serde_json::json!({ "onchain": 0, "lightning": 0 })))
        .mount(&server)
        .await;
    // The document itself is what the probe is really reading.
    Mock::given(method("GET"))
        .and(path("/openapi.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(spec))
        .mount(&server)
        .await;

    let http = BeignetHttp::new(BeignetConfig::new(server.uri())).unwrap();
    capability::probe(&http).await.expect("probe")
}

#[tokio::test]
async fn a_daemon_advertising_both_fields_can_serve_both_directions() {
    let p = probe_against(openapi(&["minFinalCltvExpiry"], &["cltvLimit"])).await;
    assert!(p.can_serve_reverse_swaps());
    assert!(p.can_serve_submarine_swaps());
}

/// beignet#744, before it landed. A hold invoice whose final CLTV cannot be set lets the payer
/// reclaim its sats over Lightning and then claim the on-chain HTLC as well.
#[tokio::test]
async fn a_daemon_without_the_hold_cltv_field_cannot_serve_reverse_swaps() {
    let p = probe_against(openapi(&["expiry"], &["cltvLimit"])).await;
    assert!(!p.can_serve_reverse_swaps());
    assert!(p.can_serve_submarine_swaps());
}

/// beignet#751. A payment whose total CLTV cannot be bounded lets the payee hold it past its own
/// on-chain refund height, take those coins back, and settle afterwards.
#[tokio::test]
async fn a_daemon_without_the_pay_cltv_limit_cannot_serve_submarine_swaps() {
    let p = probe_against(openapi(&["minFinalCltvExpiry"], &["maxFeeSats"])).await;
    assert!(p.can_serve_reverse_swaps());
    assert!(!p.can_serve_submarine_swaps());
}

/// A document that says nothing about a route says "no" for it. Guessing the other way would
/// advertise a swap on a daemon that cannot honour it.
#[tokio::test]
async fn an_unreadable_document_refuses_both() {
    let p = probe_against(serde_json::json!({ "paths": {} })).await;
    assert!(!p.can_serve_reverse_swaps());
    assert!(!p.can_serve_submarine_swaps());
}
