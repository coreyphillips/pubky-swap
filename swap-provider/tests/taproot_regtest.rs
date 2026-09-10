//! Taproot provider integration against two LND nodes, Bitcoin Core and Electrum.
//!
//! Run on the configured regtest backplane with the usual LND_A/LND_B credentials:
//! `cargo test -p swap-provider --features full --test taproot_regtest -- --ignored`.
//! Each test serializes its mining activity with the other tests in this binary.

#![cfg(all(feature = "lnd", feature = "chain"))]

use bitcoin::{Address, Network, OutPoint, ScriptBuf, Transaction, Txid};
use lightning_backend::{
    HoldInvoiceRequest, InvoiceState, LightningBackend, LndBackend, LndConfig, LndWallet,
};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use swap_common::chain::{run_blocking, ChainWatcher, ElectrumWatcher};
use swap_common::htlc::{generate_preimage, payment_hash};
use swap_common::onchain::extract_preimage;
use swap_common::taproot::BoltzTaprootSwap;
use swap_common::timelock::TimelockParams;
use swap_common::wallet::OnchainWallet;
use swap_common::{random_keypair, SwapDirection, SwapState};
use swap_provider::reverse::{drive_reverse_swap, init_reverse_swap, Resume, ReverseSwap};
use swap_provider::submarine::{drive_submarine_swap, init_submarine_swap};
use tokio::task::JoinHandle;

const AMOUNT: u64 = 50_000;
const SERVICE_FEE: u64 = 1_000;
const FEE_RATE: u64 = 5;
const POLL: Duration = Duration::from_millis(500);
const DEADLINE: Duration = Duration::from_secs(150);
static REGTEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn environment(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn cli(arguments: &[&str]) -> String {
    let output = Command::new("docker")
        .args([
            "exec",
            &environment("REGTEST_BTC_CONTAINER", "bitcoin"),
            "bitcoin-cli",
            "-regtest",
            "-rpcport=43782",
            "-rpcuser=polaruser",
            "-rpcpassword=polarpass",
        ])
        .args(arguments)
        .output()
        .expect("run regtest Bitcoin RPC");
    assert!(
        output.status.success(),
        "Bitcoin RPC failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn mine(blocks: u32) {
    let address = cli(&["getnewaddress", "", "bech32"]);
    cli(&["generatetoaddress", &blocks.to_string(), &address]);
}

fn destination() -> ScriptBuf {
    cli(&["getnewaddress", "", "bech32"])
        .parse::<Address<_>>()
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
        .script_pubkey()
}

fn lnd_config(node: &str) -> LndConfig {
    let required =
        |suffix| std::env::var(format!("LND_{node}_{suffix}")).expect("LND test configuration");
    LndConfig {
        address: required("URL"),
        tls_cert_path: required("CERT"),
        macaroon_path: required("MAC"),
    }
}

struct Backplane {
    provider: Arc<dyn LightningBackend>,
    client: Arc<dyn LightningBackend>,
    chain: Arc<dyn ChainWatcher>,
    wallet: Arc<dyn OnchainWallet>,
}

impl Backplane {
    async fn connect() -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("swap_provider=info")
            .try_init();
        Self {
            provider: Arc::new(LndBackend::connect(lnd_config("A")).await.unwrap()),
            client: Arc::new(LndBackend::connect(lnd_config("B")).await.unwrap()),
            chain: Arc::new(
                ElectrumWatcher::new(&environment(
                    "REGTEST_ELECTRUM_URL",
                    "tcp://127.0.0.1:60001",
                ))
                .unwrap(),
            ),
            wallet: Arc::new(LndWallet::connect(lnd_config("A"), FEE_RATE).await.unwrap()),
        }
    }

    fn reverse_driver(&self, swap: ReverseSwap) -> Task<anyhow::Result<SwapState>> {
        let (ln, chain, wallet) = (
            self.provider.clone(),
            self.chain.clone(),
            self.wallet.clone(),
        );
        Task::new(tokio::spawn(async move {
            drive_reverse_swap(
                ln.as_ref(),
                chain.as_ref(),
                wallet.as_ref(),
                &swap,
                1,
                POLL,
                &Resume::default(),
                &(),
            )
            .await
        }))
    }

    fn pay(
        &self,
        invoice: String,
    ) -> Task<lightning_backend::Result<lightning_backend::PaymentResult>> {
        let client = self.client.clone();
        Task::new(tokio::spawn(async move {
            client.pay_invoice(&invoice, 100_000, None).await
        }))
    }
}

struct Miner {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Miner {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                mine(1);
                std::thread::sleep(Duration::from_millis(750));
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Miner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Task<T> {
    handle: JoinHandle<T>,
}

impl<T> Task<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self { handle }
    }

    async fn finish(mut self) -> T {
        tokio::time::timeout(DEADLINE, &mut self.handle)
            .await
            .expect("swap task deadline")
            .expect("swap task panicked")
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn funding(chain: &dyn ChainWatcher, script: &ScriptBuf, value: u64) -> OutPoint {
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some(output) = run_blocking(|| chain.find_funding(script, value)).unwrap() {
                if output.confirmations >= 1 {
                    return output.outpoint;
                }
                run_blocking(|| mine(1));
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("confirmed Taproot funding deadline")
}

async fn spend(chain: &dyn ChainWatcher, script: &ScriptBuf, outpoint: OutPoint) -> Transaction {
    tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some(transaction) = run_blocking(|| chain.find_spend(script, &outpoint)).unwrap()
            {
                return transaction;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .expect("Taproot spend deadline")
}

fn timelocks(blocks: u32) -> TimelockParams {
    TimelockParams {
        htlc_timeout_blocks: blocks,
        required_confirmations: 1,
        ..TimelockParams::default()
    }
}

async fn reverse_swap(
    backplane: &Backplane,
    blocks: u32,
) -> (ReverseSwap, bitcoin::secp256k1::SecretKey, [u8; 32]) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (claim_key, claim_public) = random_keypair(&secp);
    let (refund_key, refund_public) = random_keypair(&secp);
    let preimage = generate_preimage();
    let timeout = run_blocking(|| backplane.chain.tip_height()).unwrap() + blocks;
    let invoice_request = HoldInvoiceRequest {
        payment_hash: payment_hash(&preimage),
        amount_msat: (AMOUNT + SERVICE_FEE) * 1000,
        expiry_secs: swap_common::timelock::reverse_invoice_min_expiry_secs(1).max(3600),
        cltv_expiry_delta: swap_common::timelock::reverse_invoice_cltv_delta(&timelocks(blocks))
            .unwrap(),
        memo: "pubky-swap reverse".into(),
    };
    assert!(backplane
        .provider
        .lookup_hold_invoice(&invoice_request)
        .await
        .unwrap()
        .is_none());
    let mut swap = init_reverse_swap(
        backplane.provider.as_ref(),
        &claim_public,
        refund_key,
        &refund_public,
        payment_hash(&preimage),
        AMOUNT,
        SERVICE_FEE,
        FEE_RATE,
        timeout,
        3600,
        Network::Regtest,
        timelocks(blocks),
    )
    .await
    .unwrap();
    let recovered = backplane
        .provider
        .lookup_hold_invoice(&invoice_request)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.bolt11, swap.invoice);
    let mut mismatched = invoice_request.clone();
    mismatched.amount_msat += 1000;
    assert!(backplane
        .provider
        .lookup_hold_invoice(&mismatched)
        .await
        .is_err());
    mismatched = invoice_request;
    mismatched.memo.push_str(" different creation");
    assert!(backplane
        .provider
        .lookup_hold_invoice(&mismatched)
        .await
        .is_err());
    let contract = BoltzTaprootSwap::new(
        SwapDirection::Reverse,
        &swap.payment_hash,
        &claim_public,
        &refund_public,
        timeout,
    )
    .unwrap();
    swap.htlc_spk = contract.script_pubkey();
    swap.htlc_script = ScriptBuf::new();
    swap.taproot = Some(contract);
    (swap, claim_key, preimage)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two funded LND nodes, Bitcoin Core and Electrum"]
async fn taproot_reverse_payment_claim_and_settlement() {
    let _exclusive = REGTEST_LOCK.lock().await;
    let backplane = Backplane::connect().await;
    let (swap, claim_key, preimage) = reverse_swap(&backplane, 200).await;
    let contract = swap.taproot.clone().unwrap();
    let script = swap.htlc_spk.clone();
    let invoice = swap.invoice.clone();
    let provider = backplane.reverse_driver(swap);
    let payment = backplane.pay(invoice);
    let outpoint = funding(backplane.chain.as_ref(), &script, AMOUNT).await;
    let _miner = Miner::start();
    assert_eq!(
        backplane
            .provider
            .invoice_state(payment_hash(&preimage))
            .await
            .unwrap(),
        InvoiceState::Accepted
    );
    let destination = destination();
    let fee = contract.spend_vsize(&destination, true) * FEE_RATE;
    let claim = contract
        .claim_tx(outpoint, AMOUNT, destination, fee, preimage, &claim_key)
        .unwrap();
    let claim_id = run_blocking(|| backplane.chain.broadcast(&claim)).unwrap();
    assert_eq!(provider.finish().await.unwrap(), SwapState::Claimed);
    assert_eq!(payment.finish().await.unwrap().preimage, preimage);
    assert_eq!(
        backplane
            .provider
            .invoice_state(payment_hash(&preimage))
            .await
            .unwrap(),
        InvoiceState::Settled
    );
    let observed = spend(backplane.chain.as_ref(), &script, outpoint).await;
    assert_eq!(observed.compute_txid(), claim_id);
    assert_eq!(
        observed.input[0].witness.last().unwrap(),
        contract.claim_control_block()
    );
    assert_eq!(
        extract_preimage(&observed, &outpoint, &payment_hash(&preimage)),
        Some(preimage)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two funded LND nodes, Bitcoin Core and Electrum"]
async fn taproot_reverse_timeout_refunds_and_cancels_payment() {
    let _exclusive = REGTEST_LOCK.lock().await;
    let backplane = Backplane::connect().await;
    let (swap, _, preimage) = reverse_swap(&backplane, 40).await;
    let contract = swap.taproot.clone().unwrap();
    let script = swap.htlc_spk.clone();
    let timeout = swap.timeout_height;
    let invoice = swap.invoice.clone();
    let provider = backplane.reverse_driver(swap);
    let payment = backplane.pay(invoice);
    let outpoint = funding(backplane.chain.as_ref(), &script, AMOUNT).await;
    let _miner = Miner::start();
    assert!(run_blocking(|| backplane.chain.tip_height()).unwrap() < timeout);
    assert_eq!(
        backplane
            .provider
            .invoice_state(payment_hash(&preimage))
            .await
            .unwrap(),
        InvoiceState::Accepted
    );
    assert!(
        run_blocking(|| backplane.chain.find_spend(&script, &outpoint))
            .unwrap()
            .is_none()
    );
    let remaining = timeout.saturating_sub(run_blocking(|| backplane.chain.tip_height()).unwrap());
    run_blocking(|| mine(remaining));
    assert_eq!(provider.finish().await.unwrap(), SwapState::Refunded);
    assert!(payment.finish().await.is_err());
    assert_eq!(
        backplane
            .provider
            .invoice_state(payment_hash(&preimage))
            .await
            .unwrap(),
        InvoiceState::Cancelled
    );
    let refund = spend(backplane.chain.as_ref(), &script, outpoint).await;
    assert_eq!(refund.lock_time.to_consensus_u32(), timeout);
    assert_eq!(
        refund.input[0].witness.last().unwrap(),
        contract.refund_control_block()
    );
    assert_eq!(
        extract_preimage(&refund, &outpoint, &payment_hash(&preimage)),
        None
    );
    assert!(refund.output[0].value.to_sat() < AMOUNT);
    assert!(refund.output[0].value.to_sat() >= 546);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires two funded LND nodes, Bitcoin Core and Electrum"]
async fn taproot_submarine_funding_payment_and_provider_claim() {
    let _exclusive = REGTEST_LOCK.lock().await;
    let backplane = Backplane::connect().await;
    let invoice = backplane
        .client
        .create_invoice(AMOUNT * 1000, 3600, "Taproot submarine regtest")
        .await
        .unwrap();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (claim_key, claim_public) = random_keypair(&secp);
    let (_, refund_public) = random_keypair(&secp);
    let tip = run_blocking(|| backplane.chain.tip_height()).unwrap();
    let mut swap = init_submarine_swap(
        backplane.provider.as_ref(),
        &invoice.bolt11,
        &refund_public,
        claim_key,
        &claim_public,
        AMOUNT,
        SERVICE_FEE,
        FEE_RATE,
        100_000,
        tip,
        tip + 200,
        Network::Regtest,
        timelocks(200),
    )
    .await
    .unwrap();
    let contract = BoltzTaprootSwap::new(
        SwapDirection::Submarine,
        &swap.payment_hash,
        &claim_public,
        &refund_public,
        swap.timeout_height,
    )
    .unwrap();
    swap.htlc_spk = contract.script_pubkey();
    swap.htlc_script = ScriptBuf::new();
    swap.taproot = Some(contract.clone());
    let script = swap.htlc_spk.clone();
    let funding_txid: Txid = cli(&[
        "sendtoaddress",
        &contract.address(Network::Regtest).to_string(),
        "0.00051",
    ])
    .parse()
    .unwrap();
    let _miner = Miner::start();
    let outpoint = funding(backplane.chain.as_ref(), &script, AMOUNT + SERVICE_FEE).await;
    assert_eq!(outpoint.txid, funding_txid);
    let state = tokio::time::timeout(
        DEADLINE,
        drive_submarine_swap(
            backplane.provider.as_ref(),
            backplane.chain.as_ref(),
            backplane.wallet.as_ref(),
            &swap,
            1,
            POLL,
            &Resume::default(),
            false,
            &(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(state, SwapState::Claimed);
    assert_eq!(
        backplane
            .client
            .invoice_state(invoice.payment_hash)
            .await
            .unwrap(),
        InvoiceState::Settled
    );
    let claim = spend(backplane.chain.as_ref(), &script, outpoint).await;
    assert_eq!(
        claim.input[0].witness.last().unwrap(),
        contract.claim_control_block()
    );
    assert!(extract_preimage(&claim, &outpoint, &invoice.payment_hash).is_some());
    assert!(claim.output[0].value.to_sat() < AMOUNT + SERVICE_FEE);
}
