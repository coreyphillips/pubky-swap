//! Live smoke test for the LND gRPC backend (feature `lnd`).
//!
//! `#[ignore]`d; requires a reachable LND node. Provide its endpoint + credentials via env:
//!
//! ```bash
//! LND_GRPC_URL=https://127.0.0.1:10011 \
//! LND_CERT=/path/tls.cert LND_MACAROON=/path/admin.macaroon \
//! cargo test -p lightning-backend --features lnd --test lnd_smoke -- --ignored --nocapture
//! ```

#![cfg(feature = "lnd")]

use lightning_backend::{InvoiceState, LightningBackend, LndBackend, LndConfig};

#[tokio::test]
#[ignore = "requires a running LND node"]
async fn lnd_hold_invoice_lifecycle() {
    let cfg = LndConfig {
        address: std::env::var("LND_GRPC_URL").unwrap_or_else(|_| "https://127.0.0.1:10011".into()),
        tls_cert_path: std::env::var("LND_CERT").expect("set LND_CERT"),
        macaroon_path: std::env::var("LND_MACAROON").expect("set LND_MACAROON"),
    };
    let lnd = LndBackend::connect(cfg).await.expect("connect to LND");

    let info = lnd.node_info().await.expect("node_info");
    println!("connected to LND {} (alias {})", info.pubkey, info.alias);
    assert!(!info.pubkey.is_empty());

    // A unique payment hash per run (avoids "invoice already exists").
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut payment_hash = [0u8; 32];
    payment_hash[..16].copy_from_slice(&nanos.to_le_bytes());

    // Create a hold invoice (invoicesrpc.AddHoldInvoice).
    let hold = lnd
        .create_hold_invoice(lightning_backend::HoldInvoiceRequest {
            payment_hash,
            amount_msat: 50_000_000,
            expiry_secs: 3600,
            // Non-zero, because the trait requires it and LND substitutes its own default for a
            // zero: the very thing that made a reverse swap's Lightning leg expire first.
            cltv_expiry_delta: 200,
            memo: "pubky-swap smoke".into(),
        })
        .await
        .expect("create hold invoice");
    println!("hold invoice: {}", hold.bolt11);
    assert!(
        hold.bolt11.starts_with("lnbcrt"),
        "expected a regtest invoice, got {}",
        hold.bolt11
    );

    // A fresh, unpaid hold invoice is Open.
    assert_eq!(
        lnd.invoice_state(payment_hash)
            .await
            .expect("invoice_state"),
        InvoiceState::Open
    );

    // Cancel it and confirm the transition.
    lnd.cancel_hold_invoice(payment_hash)
        .await
        .expect("cancel hold invoice");
    assert_eq!(
        lnd.invoice_state(payment_hash)
            .await
            .expect("invoice_state after cancel"),
        InvoiceState::Cancelled
    );
}
