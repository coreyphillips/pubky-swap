//! Reverse and submarine swaps negotiated in the signed `paykit-cap.*` kinds (#102).
//!
//! Unlike the other regtest suites, which call the engines directly, this one runs the provider
//! daemon (`swap_provider::run`, iroh only, no homeserver) and negotiates with it the way the CLI
//! does with `--negotiation paykit-cap`: quotes and contracts come back signed and are checked
//! against the provider's key before anything is paid. One reverse swap has its provider restart
//! between the quote and the commit (#103), so the commit is honoured on the signed quote it
//! carries. Each test ends by verifying the signed contract the provider stored, as a third party
//! would.
//!
//! The client finds the provider by its key through iroh's n0 discovery, so this needs network
//! access besides the regtest backplane. `#[ignore]`d; run with the same environment as
//! `full_swap_regtest`, one test at a time (they share both LND nodes and the funding wallet):
//!
//! ```bash
//! LND_A_URL=... LND_A_CERT=... LND_A_MAC=... LND_B_URL=... LND_B_CERT=... LND_B_MAC=... \
//! REGTEST_ELECTRUM_URL=tcp://127.0.0.1:60001 \
//! cargo test -p swap-provider --features full --test cap_swap_regtest -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(all(
    feature = "lnd",
    feature = "bdk-wallet",
    feature = "chain",
    feature = "iroh"
))]

use bitcoin::{Address, Network, PublicKey, ScriptBuf};
use lightning_backend::{InvoiceState, LightningBackend, LndBackend, LndConfig};
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use swap_client::negotiate::{connect, DmChannel, Negotiation, Negotiator, Preferred};
use swap_client::reverse::{execute_reverse_swap, ReverseClaim};
use swap_client::submarine::{execute_submarine_swap, SubmarineFunding};
use swap_common::chain::{ChainWatcher, ElectrumWatcher};
use swap_common::htlc::{build_htlc_script, generate_preimage, payment_hash};
use swap_common::messages::{
    QuoteRequest, SwapAccept, SwapRequest, SwapScript, PAYKIT_CAP_FEATURE, PROTOCOL_VERSION,
};
use swap_common::store::{JsonFileSwapStore, Resume, SwapStore};
use swap_common::validate::verify_contract;
use swap_common::wallet::OnchainWallet;
use swap_common::{random_keypair, SwapDirection, SwapState};
use swap_config::{Identity, Secret, SecretSource};
use swap_provider::wallet::BdkWallet;
use swap_provider::ProviderConfig;
use uuid::Uuid;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const AMOUNT_SAT: u64 = 50_000;
/// Long enough for discovery to publish the provider and for its backends to answer.
const READY_WITHIN: Duration = Duration::from_secs(180);
/// Long enough for either swap to settle with a block every 1.5 seconds.
const SWAP_WITHIN: Duration = Duration::from_secs(180);

fn env(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}

fn cli(args: &[&str]) -> String {
    let mut full = vec![
        "exec".to_string(),
        env("REGTEST_BTC_CONTAINER", "bitcoin"),
        "bitcoin-cli".to_string(),
        "-regtest".to_string(),
        "-rpcport=43782".to_string(),
        "-rpcuser=polaruser".to_string(),
        "-rpcpassword=polarpass".to_string(),
    ];
    full.extend(args.iter().map(|s| s.to_string()));
    let out = Command::new("docker")
        .args(&full)
        .output()
        .expect("docker exec");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn mine(n: u32) {
    let addr = cli(&["getnewaddress", "", "bech32"]);
    cli(&["generatetoaddress", &n.to_string(), &addr]);
}

fn spk_of(addr: &str) -> ScriptBuf {
    Address::from_str(addr)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey()
}

fn lnd_cfg(prefix: &str) -> LndConfig {
    LndConfig {
        address: std::env::var(format!("LND_{prefix}_URL")).expect("LND url env"),
        tls_cert_path: std::env::var(format!("LND_{prefix}_CERT")).expect("LND cert env"),
        macaroon_path: std::env::var(format!("LND_{prefix}_MAC")).expect("LND macaroon env"),
    }
}

fn temp_dir(what: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("pubky-swap-cap-{what}-{}", Uuid::new_v4()))
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

fn phrase_identity(phrase: &str) -> Identity {
    Identity {
        method: "phrase",
        value: phrase.to_string(),
        passphrase: String::new(),
    }
}

fn pubky_of(phrase: &str) -> String {
    pubky_transport::Transport::unsigned_from_recovery("phrase", phrase, "")
        .expect("identity from phrase")
        .public_key_string()
}

/// The provider daemon, on a thread and runtime of its own: `swap_provider::run` is not `Send`,
/// as it is not in the binary either, which runs it on the main task.
struct Daemon {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(|thread| thread.is_finished())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A provider daemon on LND A that funds from LND A's own wallet, reachable only over iroh.
fn start_provider(phrase: &str, data_dir: &std::path::Path) -> Daemon {
    let config = ProviderConfig {
        recovery_phrase: SecretSource {
            value: Secret::new(phrase),
            file: String::new(),
        },
        network: "regtest".into(),
        lnd_address: lnd_cfg("A").address,
        lnd_cert_path: lnd_cfg("A").tls_cert_path,
        lnd_macaroon_path: lnd_cfg("A").macaroon_path,
        electrum_url: env("REGTEST_ELECTRUM_URL", "tcp://127.0.0.1:60001"),
        wallet_backend: "lnd".into(),
        htlc_timeout_blocks: 200,
        required_confirmations: 1,
        data_dir: data_dir.to_string_lossy().into_owned(),
        homeserver: false,
        rendezvous_iroh: true,
        ..ProviderConfig::default()
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("provider runtime");
        runtime.block_on(async move {
            tokio::select! {
                result = swap_provider::run(config) => {
                    if let Err(error) = result {
                        eprintln!("provider stopped: {error:#}");
                    }
                }
                _ = stopped => {}
            }
        });
        // A blocking Electrum call in flight cannot be cancelled; do not wait on it for long.
        runtime.shutdown_timeout(Duration::from_secs(10));
    });
    Daemon {
        stop: Some(stop),
        thread: Some(thread),
    }
}

/// A `paykit-cap` negotiator once the provider is discoverable and execution-capable.
///
/// A fresh negotiator per attempt: one whose only channel failed before sending treats that
/// channel as gone for the rest of its life, which is what a run wants and a startup race does
/// not.
async fn negotiator_when_ready(
    client_phrase: &str,
    provider: &str,
    daemon: &Daemon,
) -> (Negotiator<Preferred, DmChannel>, String) {
    negotiator_for(client_phrase, provider, daemon, Negotiation::PaykitCap).await
}

/// [`negotiator_when_ready`] in either `paykit-cap` wire.
async fn negotiator_for(
    client_phrase: &str,
    provider: &str,
    daemon: &Daemon,
    negotiation: Negotiation,
) -> (Negotiator<Preferred, DmChannel>, String) {
    let deadline = Instant::now() + READY_WITHIN;
    loop {
        assert!(!daemon.is_finished(), "the provider daemon exited");
        let (negotiator, client) = connect(
            &phrase_identity(client_phrase),
            provider,
            negotiation,
            false,
        )
        .await
        .expect("bind the client endpoint");
        match negotiator.offer().await {
            Ok(offer) if offer.features.iter().any(|f| f == PAYKIT_CAP_FEATURE) => {
                return (negotiator, client)
            }
            Ok(offer) => println!("provider not ready yet: features {:?}", offer.features),
            Err(error) => println!("provider not reachable yet: {error:#}"),
        }
        negotiator.close().await;
        assert!(
            Instant::now() < deadline,
            "the provider was not ready in {READY_WITHIN:?}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Mine a block every 1.5 seconds until the returned flag is set.
fn start_miner() -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let miner = std::thread::spawn(move || {
        while !flag.load(Ordering::Relaxed) {
            mine(1);
            std::thread::sleep(Duration::from_millis(1500));
        }
    });
    (stop, miner)
}

/// The provider's record of `swap_id` once it reaches `state`.
async fn provider_record(
    data_dir: &std::path::Path,
    swap_id: Uuid,
    state: SwapState,
) -> swap_common::store::SwapRecord {
    let store = JsonFileSwapStore::new(data_dir.join("swaps")).expect("open provider store");
    let deadline = Instant::now() + SWAP_WITHIN;
    loop {
        if let Some(record) = store.get(swap_id).expect("read provider record") {
            if record.state == state {
                return record;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the provider's swap {swap_id} never reached {state:?}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// What a third party checks: the stored contract verifies under the provider's key, and it
/// is the contract the owner was given.
fn assert_signed_contract(
    record: &swap_common::store::SwapRecord,
    accept: &SwapAccept,
    provider: &str,
) {
    let reply = record
        .cap_contract
        .as_ref()
        .expect("the provider stored a signed contract");
    reply.signed.verify().expect("the stored contract verifies");
    let provider_key = pubky_transport::p2p::pubky_to_endpoint_id(provider).unwrap();
    assert_eq!(reply.signed.signer, hex::encode(provider_key.as_bytes()));
    let unsigned = SwapAccept {
        invoice: None,
        ..accept.clone()
    };
    assert_eq!(reply.signed.contract.accept, unsigned);
}

fn quote_request(client: &str, direction: SwapDirection) -> QuoteRequest {
    QuoteRequest {
        request_id: Some(Uuid::new_v4()),
        offer_id: Uuid::nil(),
        client_pkarr: client.to_string(),
        direction,
        amount_sat: AMOUNT_SAT,
        protocol_version: PROTOCOL_VERSION,
        features: Vec::new(),
    }
}

/// The owner's keys for one reverse swap.
struct ReverseKeys {
    claim_sk: bitcoin::secp256k1::SecretKey,
    claim_pk: PublicKey,
    preimage: [u8; 32],
    payment_hash: [u8; 32],
}

fn reverse_keys() -> ReverseKeys {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (claim_sk, claim_pk) = random_keypair(&secp);
    let preimage = generate_preimage();
    ReverseKeys {
        claim_sk,
        claim_pk,
        preimage,
        payment_hash: payment_hash(&preimage),
    }
}

fn reverse_request(client: &str, quote_id: Uuid, keys: &ReverseKeys) -> SwapRequest {
    SwapRequest {
        script_type: SwapScript::P2wsh,
        quote_id,
        client_pkarr: client.to_string(),
        direction: SwapDirection::Reverse,
        payment_hash_hex: hex::encode(keys.payment_hash),
        client_claim_pubkey_hex: Some(hex::encode(keys.claim_pk.to_bytes())),
        client_refund_pubkey_hex: None,
        invoice: None,
        owner_ref: None,
    }
}

/// Pay the hold invoice from LND B and claim, then check what the provider did: claimed, settled
/// its hold invoice, and stored the contract a third party can verify.
async fn finish_reverse(
    accept: &SwapAccept,
    keys: ReverseKeys,
    data_dir: &std::path::Path,
    provider: &str,
) {
    let record = settle_reverse(accept, keys, data_dir).await;
    assert_signed_contract(&record, accept, provider);
}

/// [`finish_reverse`] without the stored contract, which only the older wire keeps.
async fn settle_reverse(
    accept: &SwapAccept,
    keys: ReverseKeys,
    data_dir: &std::path::Path,
) -> swap_common::store::SwapRecord {
    let htlc_spk = verify_contract(
        accept,
        SwapDirection::Reverse,
        &keys.payment_hash,
        &keys.claim_pk,
        Network::Regtest,
    )
    .expect("the contract pays our claim key under our payment hash");
    let provider_pk: PublicKey = accept.provider_pubkey_hex.parse().unwrap();
    let claim = ReverseClaim {
        htlc_script: build_htlc_script(
            &keys.payment_hash,
            &keys.claim_pk,
            &provider_pk,
            accept.timeout_block_height,
        ),
        htlc_spk,
        onchain_amount_sat: accept.onchain_amount_sat,
        timeout_height: accept.timeout_block_height,
        invoice: accept.invoice.clone().expect("the hold invoice, unsealed"),
        preimage: keys.preimage,
        claim_key: keys.claim_sk,
        dest_spk: spk_of(&cli(&["getnewaddress", "", "bech32"])),
        fee_rate_sat_vb: 2,
    };

    let electrum = env("REGTEST_ELECTRUM_URL", "tcp://127.0.0.1:60001");
    let client_ln: Arc<dyn LightningBackend> =
        Arc::new(LndBackend::connect(lnd_cfg("B")).await.expect("client LND"));
    let chain: Arc<dyn ChainWatcher> = Arc::new(ElectrumWatcher::new(&electrum).unwrap());
    let (stop, miner) = start_miner();
    let claimed = tokio::time::timeout(
        SWAP_WITHIN,
        execute_reverse_swap(
            client_ln,
            chain,
            claim,
            100_000,
            1,
            Duration::from_secs(1),
            &Resume::default(),
            &(),
        ),
    )
    .await;
    let record = match claimed {
        Ok(Ok(txid)) => {
            println!("client claim {txid}");
            provider_record(data_dir, accept.swap_id, SwapState::Claimed).await
        }
        Ok(Err(error)) => panic!("client execution failed: {error:#}"),
        Err(_) => panic!("client execution timed out"),
    };
    stop.store(true, Ordering::Relaxed);
    let _ = miner.join();

    let provider_ln = LndBackend::connect(lnd_cfg("A"))
        .await
        .expect("provider LND");
    assert_eq!(
        provider_ln
            .invoice_state(keys.payment_hash)
            .await
            .expect("invoice state"),
        InvoiceState::Settled,
        "the provider settled its hold invoice with the revealed preimage"
    );
    record
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two LND nodes with a channel + bitcoind + electrs, and n0 discovery"]
async fn cap_reverse_swap_two_nodes() {
    init_tracing();
    // Keys of their own, so a daemon from another test never answers for this one.
    let provider_phrase =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let client_phrase =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
    let provider = pubky_of(provider_phrase);
    let data_dir = temp_dir("reverse-provider");
    let daemon = start_provider(provider_phrase, &data_dir);
    let (negotiator, client) = negotiator_when_ready(client_phrase, &provider, &daemon).await;

    // Signed quote, then signed contract: `CapChannel` checks both against the provider's key.
    let quote = negotiator
        .quote(&quote_request(&client, SwapDirection::Reverse))
        .await
        .expect("signed quote");
    let keys = reverse_keys();
    let accept = negotiator
        .create(&reverse_request(&client, quote.quote_id, &keys))
        .await
        .expect("signed contract");
    negotiator.close().await;

    finish_reverse(&accept, keys, &data_dir, &provider).await;
    drop(daemon);
    println!("paykit-cap reverse swap: claimed, invoice settled, signed contract verified");
}

/// #130: the same reverse swap in the `version` wire of Capabilities §13.1. The client checks
/// the quote's terms and the contract's hashes under the provider's key for the generation each
/// names, and the provider takes the claimable hint without any `features`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two LND nodes with a channel + bitcoind + electrs, and n0 discovery"]
async fn cap_v1_reverse_swap_two_nodes() {
    init_tracing();
    let provider_phrase =
        "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge";
    let client_phrase = "creek office smoke grid creek office smoke grid creek office smoke guard";
    let provider = pubky_of(provider_phrase);
    let data_dir = temp_dir("v1-reverse-provider");
    let daemon = start_provider(provider_phrase, &data_dir);
    let (negotiator, client) = negotiator_for(
        client_phrase,
        &provider,
        &daemon,
        Negotiation::PaykitCapCore,
    )
    .await;
    let quote = negotiator
        .quote(&quote_request(&client, SwapDirection::Reverse))
        .await
        .expect("signed quote");
    assert_eq!(quote.fee_sat, quote.service_fee_sat + quote.onchain_fee_sat);
    let keys = reverse_keys();
    let mut request = reverse_request(&client, quote.quote_id, &keys);
    request.owner_ref = Some("k".repeat(58));
    let accept = negotiator.create(&request).await.expect("signed contract");
    negotiator.close().await;

    let record = settle_reverse(&accept, keys, &data_dir).await;
    assert!(
        record.claimable_hint,
        "every reverse owner on this wire takes the hint"
    );
    assert_eq!(
        record.swap_request.and_then(|r| r.owner_ref),
        request.owner_ref
    );
    drop(daemon);
    println!("paykit-cap v1 reverse swap: claimed, invoice settled, quote and contract verified");
}

/// #103: the provider restarts between the quote and the commit. Its quote book is empty after
/// the restart, and the commit is honoured on the signed quote it carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two LND nodes with a channel + bitcoind + electrs, and n0 discovery"]
async fn cap_reverse_swap_survives_a_provider_restart() {
    init_tracing();
    let provider_phrase =
        "scheme spot photo card baby mountain device kick cradle pact join borrow";
    let client_phrase =
        "cat swing flag economy stadium alone churn speed unique patch report train";
    let probe_phrase =
        "vessel ladder alter error federal sibling chat ability sun glass valve picture";
    let provider = pubky_of(provider_phrase);
    let data_dir = temp_dir("restart-provider");
    let daemon = start_provider(provider_phrase, &data_dir);
    let (negotiator, client) = negotiator_when_ready(client_phrase, &provider, &daemon).await;
    let quote = negotiator
        .quote(&quote_request(&client, SwapDirection::Reverse))
        .await
        .expect("signed quote");
    let quoted_at = Instant::now();

    drop(daemon);
    let daemon = start_provider(provider_phrase, &data_dir);
    let (probe, _) = negotiator_when_ready(probe_phrase, &provider, &daemon).await;
    probe.close().await;
    // The client's pooled connection went with the old process. Once it has been idle past
    // the pool's 20 s, the next request dials the new one.
    tokio::time::sleep(Duration::from_secs(21).saturating_sub(quoted_at.elapsed())).await;

    let keys = reverse_keys();
    let accept = negotiator
        .create(&reverse_request(&client, quote.quote_id, &keys))
        .await
        .expect("the restarted provider honours the signed quote");
    negotiator.close().await;
    assert_eq!(accept.quote_id, quote.quote_id);

    finish_reverse(&accept, keys, &data_dir, &provider).await;
    drop(daemon);
    println!("paykit-cap reverse swap across a provider restart: claimed, contract verified");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two LND nodes with a channel + bitcoind + electrs, and n0 discovery"]
async fn cap_submarine_swap_two_nodes() {
    init_tracing();
    let provider_phrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    let client_phrase =
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
    let provider = pubky_of(provider_phrase);
    let data_dir = temp_dir("submarine-provider");
    let daemon = start_provider(provider_phrase, &data_dir);

    // The client funds the lockup, so its wallet needs coins first.
    let electrum = env("REGTEST_ELECTRUM_URL", "tcp://127.0.0.1:60001");
    let client_wallet = BdkWallet::from_mnemonic(
        &env("WALLET_MNEMONIC", MNEMONIC),
        Network::Regtest,
        &electrum,
        5,
        &temp_dir("submarine-wallet"),
    )
    .expect("client funding wallet");
    if client_wallet.balance().unwrap() < AMOUNT_SAT + 50_000 {
        let deposit = client_wallet.deposit_address().unwrap().to_string();
        cli(&["sendtoaddress", &deposit, "0.5"]);
        mine(1);
        for _ in 0..30 {
            if client_wallet.balance().unwrap() >= AMOUNT_SAT + 50_000 {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    let client_wallet: Arc<dyn OnchainWallet> = Arc::new(client_wallet);

    let (negotiator, client) = negotiator_when_ready(client_phrase, &provider, &daemon).await;
    let client_ln: Arc<dyn LightningBackend> =
        Arc::new(LndBackend::connect(lnd_cfg("B")).await.expect("client LND"));
    let invoice = client_ln
        .create_invoice(
            AMOUNT_SAT * 1000,
            3600,
            "pubky-swap paykit-cap submarine test",
        )
        .await
        .expect("client invoice");

    let quote = negotiator
        .quote(&quote_request(&client, SwapDirection::Submarine))
        .await
        .expect("signed quote");
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (refund_sk, refund_pk) = random_keypair(&secp);
    let accept = negotiator
        .create(&SwapRequest {
            script_type: SwapScript::P2wsh,
            quote_id: quote.quote_id,
            client_pkarr: client.clone(),
            direction: SwapDirection::Submarine,
            payment_hash_hex: hex::encode(invoice.payment_hash),
            client_claim_pubkey_hex: None,
            client_refund_pubkey_hex: Some(hex::encode(refund_pk.to_bytes())),
            invoice: Some(invoice.bolt11.clone()),
            owner_ref: None,
        })
        .await
        .expect("signed contract");
    negotiator.close().await;

    let htlc_spk = verify_contract(
        &accept,
        SwapDirection::Submarine,
        &invoice.payment_hash,
        &refund_pk,
        Network::Regtest,
    )
    .expect("the contract refunds to our key under our payment hash");
    let provider_pk: PublicKey = accept.provider_pubkey_hex.parse().unwrap();
    let funding = SubmarineFunding {
        htlc_script: build_htlc_script(
            &invoice.payment_hash,
            &provider_pk,
            &refund_pk,
            accept.timeout_block_height,
        ),
        htlc_spk,
        onchain_amount_sat: accept.onchain_amount_sat,
        payment_hash: invoice.payment_hash,
        refund_key: refund_sk,
        timeout_height: accept.timeout_block_height,
        fee_rate_sat_vb: 2,
    };

    let chain: Arc<dyn ChainWatcher> = Arc::new(ElectrumWatcher::new(&electrum).unwrap());
    let (stop, miner) = start_miner();
    let outcome = tokio::time::timeout(
        SWAP_WITHIN,
        execute_submarine_swap(
            client_ln.clone(),
            chain,
            client_wallet,
            funding,
            Duration::from_secs(1),
            &Resume::default(),
            &(),
        ),
    )
    .await;
    let record = match outcome {
        Ok(Ok(state)) => {
            assert_eq!(state, SwapState::Claimed, "the client saw its invoice paid");
            provider_record(&data_dir, accept.swap_id, SwapState::Claimed).await
        }
        Ok(Err(error)) => panic!("client execution failed: {error:#}"),
        Err(_) => panic!("client execution timed out"),
    };
    stop.store(true, Ordering::Relaxed);
    let _ = miner.join();

    assert_eq!(
        client_ln
            .invoice_state(invoice.payment_hash)
            .await
            .expect("invoice state"),
        InvoiceState::Settled,
        "the provider paid the client's invoice"
    );
    assert_signed_contract(&record, &accept, &provider);
    drop(daemon);
    println!(
        "paykit-cap submarine swap: provider claimed, invoice settled, signed contract verified"
    );
}
