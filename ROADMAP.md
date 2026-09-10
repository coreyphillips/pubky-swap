# pubky-swap roadmap

Build order is chosen so every milestone is testable on **regtest** before the next, and
so the safety-critical refund/timelock paths are exercised early.

### ✅ Phase 1: Scaffold
- Cargo workspace + crate boundaries.
- `pubky-transport`: generic, message-type-agnostic transport extracted from the batch
  coordinator.
- `swap-common`: wire messages, `SwapState` lifecycle, P2WSH HTLC builder + preimage
  helpers (unit-tested).
- `LightningBackend` trait + `LndBackend` stub.
- Provider/client skeletons with a working **offer → quote → swap-accept** negotiation.

### ✅ Phase 2: LND backend
`LndBackend` (feature `lnd`) is wired to LND over gRPC via `fedimint-tonic-lnd`:
- `node_info`, `decode_invoice`
- **hold invoices**: `create` / `invoice_state` (lookup) / `settle` / `cancel` (`invoicesrpc`)
- **pay + preimage** via `routerrpc.SendPaymentV2` (streams to a terminal status)

Compiles cleanly with `--features lnd` (needs `protoc`). The provider selects it through
`make_backend`, falling back to the stub if unavailable.

**Live-validated** (`lightning/tests/lnd_smoke.rs`, `#[ignore]`, feature `lnd`): against a
real regtest LND it connects, creates a hold invoice, and verifies `Open → cancel →
Cancelled`. (Also fixed a real bug this surfaced: rustls 0.23 needs a `CryptoProvider`
installed — `LndBackend::connect` now installs the ring provider once, so the production
binary doesn't panic on first connect.)

**Done since:** hold-invoice accept→settle and a real payment's preimage extraction are both
exercised by `swap-provider/tests/full_swap_regtest.rs`, which pays the hold invoice from a
second live LND node and settles it with the preimage recovered from the on-chain claim.

**Phase 2 complete.**

### ✅ Phase 3: On-chain HTLC engine
- `onchain`: build & sign **claim** (preimage) and **refund** (timeout) transactions for the
  P2WSH HTLC — BIP143 sighash, correct branch witnesses, absolute-fee deduction. Validated
  in tests against real script consensus via **libbitcoinconsensus** (claim valid, refund
  valid at timeout, wrong-preimage rejected, wrong-key rejected).
- `chain`: a `ChainWatcher` trait (tip height, find funding UTXO + confirmations, broadcast,
  find spend) with an `ElectrumWatcher` implementation behind feature `electrum`.
- **Regtest integration test** (`swap-common/tests/regtest.rs`, `#[ignore]`, feature
  `electrum`): against a real bitcoind + electrs it funds an HTLC, locates it via electrs,
  builds & **broadcasts a claim that bitcoind accepts**, and recovers the preimage from the
  on-chain claim; and confirms a **refund is rejected before the timeout and accepted
  after** (real CLTV enforcement). Both pass.

**Done:** dynamic fee estimation — claim/refund/funding transactions use a live Electrum
`estimatefee` result clamped to a configured floor (the floor is both the minimum and the
fallback when estimation is unavailable, e.g. on regtest). **RBF fee-bumping** — claim/refund are
built RBF-signalling and `swap-common::fee_bump::confirm_or_bump` re-broadcasts at an escalating
(capped) fee until the spend confirms, with a **CPFP fallback** (`OnchainWallet::cpfp_bump`) when an
RBF replacement is rejected and the swept output is wallet-controlled. **Reorg handling** — spends
are treated as final only at `reorg::FINALITY_DEPTH`; `confirm_or_bump` re-broadcasts a claim/refund
that is reorged out; the submarine provider re-confirms the funding depth right before paying the
(irreversible) invoice; and a background `reorg::ReorgMonitor` (block-hash continuity) flags reorgs
affecting in-flight swaps. Reorg detection is validated live against bitcoind via
`swap-common/tests/reorg_regtest.rs` (`invalidateblock`).

**Phase 3 complete.**

### ✅ Phase 4: Reverse swaps
`swap-provider::reverse` orchestrates the provider side end-to-end: `init_reverse_swap`
(hold invoice + HTLC) and `drive_reverse_swap` (wait for payment → fund HTLC → wait for
confirmations → on client claim, recover the preimage via `onchain::extract_preimage` and
settle the invoice; else refund at timeout and cancel). It is abstracted over
`LightningBackend` / `ChainWatcher` / `OnchainWallet` and **tested end-to-end with mocks**
for both the happy path (invoice settled with the recovered preimage) and the refund path
(refund broadcast + invoice cancelled).

A real `OnchainWallet` exists: `swap-provider::wallet::BdkWallet` (feature `bdk-wallet`) — a
BIP84 wallet synced over Electrum that builds/signs/broadcasts the HTLC funding tx and
supplies a sweep address. **Regtest-tested** (`swap-provider/tests/wallet_regtest.rs`):
funds itself, then funds an HTLC with a tx bitcoind accepts (verified via `gettxout`).

**✅ Reverse swaps work end-to-end on regtest.** `swap-provider/tests/full_swap_regtest.rs`
(`#[ignore]`, `--features full`) runs a complete reverse swap across **two real LND nodes** +
bitcoind + electrs: the client pays the provider's hold invoice over Lightning → the provider
funds the on-chain HTLC (BDK wallet) → the client claims it with the preimage → the provider
recovers the preimage and settles the invoice. Asserts the provider reaches `Claimed` and the
hold invoice is `Settled`. (This live test caught a real race-condition bug: the provider's
redundant "wait for the funding UTXO to be unspent" step lost to the client's immediate claim
and hung — the driver now watches directly for the claim/timeout.)

- **Live-loop wiring** (provider, `--features full`): builds `Arc` backends and, on a
  `SwapRequest`, creates the HTLC/hold invoice, replies with `SwapAccept`, and spawns a
  per-swap `drive_*` task that sends a final `SwapStatusUpdate`.
- **Client execution** (`swap-client::reverse::execute_reverse_swap`): pays the hold invoice
  (in-flight), watches the HTLC, claims with the preimage, awaits settlement. Mock-tested +
  exercised in the full live swap.

**Done since:** the reverse swap is now runnable **end-to-end from the `swap-client` CLI**
(`--features full`): it verifies the provider's HTLC script pays its own claim key, pays the hold
invoice via its own LND, watches the HTLC, and claims it. The provider also **persists in-flight
swaps** (`--data-dir`) and **resumes** them on restart (idempotently — it never re-funds an
already-funded HTLC), and enforces **network-mismatch** and **mainnet-safety** guards plus
**single-use, expiring quotes**.

**Phase 4 complete.** The drivers' blocking chain/wallet calls now run via
`swap-common::chain::run_blocking` (`block_in_place` on a multi-threaded runtime, inline on a
current-thread one), so they no longer stall the async runtime.

### ✅ Phase 5: Submarine swaps (end-to-end)
`swap-provider::submarine` orchestrates the provider side: `init_submarine_swap` (decode the
client's invoice → build the HTLC the client funds, claim = provider) and
`drive_submarine_swap` (wait for the client's on-chain funding → pay the invoice → claim the
HTLC with the learned preimage; the invoice is only paid after the funding confirms, so a
failed payment costs nothing on-chain).

**Client execution** (`swap-client::submarine::execute_submarine_swap`, wired into the CLI under
`--features full`): the client issues the invoice (`LightningBackend::create_invoice`), verifies
the provider's HTLC pays its hash/refund key, funds the HTLC on-chain, and refunds at the timeout
if the provider never pays. The funding wallet (`swap-common::wallet::BdkWallet`) is now shared by
both binaries. Mock-tested on both sides; a live two-node regtest test exists
(`swap-provider/tests/submarine_swap_regtest.rs`, `#[ignore]`).

### Phase 6: Marketplace layer
Offer publishing to the Pubky profile + follow-graph discovery; quote/negotiation hardening;
reputation/abuse handling (port the batch coordinator's `ban_manager` ideas); require
on-chain confirmation before a provider commits funds.

### ✅ Phase 7: Umbrel packaging
[`pubky-swap-umbrel`](https://github.com/coreyphillips/pubky-swap-umbrel) is a **community app
store**: add the repository URL in umbrelOS and install **Pubky Swap**. It runs a supervised
`swap-provider` against the Umbrel's own LND and Electrs apps, with a web panel for the Pubky
identity, the rates and the exposure limits.

- A published multi-arch image (`linux/amd64`, `linux/arm64`) on ghcr, pinned by digest and built
  from a pinned upstream commit. Nothing compiles on the user's node.
- Secrets never reach a command line: the recovery phrase and passphrase are files at `0600` in a
  `0700` directory, named to the daemon through `PUBKY_SWAP_*__FILE`.
- The panel reads the provider's **read-only status API** on loopback rather than scraping its
  logs, so it shows the daemon's own health checks, in-flight swaps, exposure against the limits,
  and earnings.
- The container drops to UID 1000.

Also here: a **config file and secret-source layer** (`swap-config`) shared by both binaries,
`--doctor` for a checked setup, and `--show-config` for a redacted dump.

### Phase 8: Hardening & extensions
Cooperative MuSig2 key-path signing (Taproot script paths are implemented), Core Lightning backend,
optional Liquid chain swaps.

## Remaining for mainnet

`regtest.yml` is **green on a hosted runner**: a fresh `docker-compose.regtest.yml` backplane
brought up from scratch, `scripts/setup-regtest-lnd.sh` opening a balanced channel between two
fresh LND nodes, and every integration test passing against it, including **both end-to-end
swaps** across two real LND nodes (`full_swap_regtest` reverse and `submarine_swap_regtest`).
It runs weekly and on demand.

These remain before any signet/mainnet exposure:

- **Signet soak testing** before any mainnet exposure.
- A **third-party security review** of the atomic-swap paths.
- **Marketplace hardening** (Phase 6): offer publishing/discovery on the Pubky profile, abuse/ban
  handling, requiring on-chain confirmation before a provider commits.

## Safety notes
- Atomic-swap bugs lose real funds. Timelock math, fee-bumping under congestion, and reorg
  handling must be covered by tests before any signet/mainnet exposure.
- A provider must not commit on-chain funds until the counterparty's leg is sufficiently
  confirmed/accepted; a client must not reveal the preimage until the provider's lockup is
  confirmed.
