# pubky-swap

A **self-hosted, decentralized Lightning swap marketplace.** Any node operator can advertise
swaps at their own rates and facilitate them with their own LND node; clients discover providers
and negotiate over the [Pubky](https://pubky.org) network (an encrypted-DM + follow-graph
transport), so there is **no central swap server**.

Swaps are made atomic by a single 32-byte preimage whose SHA256 is the shared Lightning payment
hash — the on-chain HTLC can only be claimed by revealing the preimage that settles the Lightning
leg, and vice-versa.

> ⚠️ **Regtest only — do not use with real funds.** The swap engine (HTLC scripting, timelocks,
> claim/refund, hold invoices, chain watching, crash-resume) is implemented and tested on regtest,
> but mainnet hardening is incomplete (RBF/CPFP fee-bumping and reorg handling are still on the
> roadmap). Atomic-swap bugs lose money. See [`ROADMAP.md`](ROADMAP.md).

## Swap types

- **Reverse** (Lightning → on-chain): the client pays a Lightning hold invoice; the provider locks
  on-chain BTC in an HTLC; the client claims it with the preimage, which lets the provider settle
  the hold invoice. **Runnable end-to-end from the CLI.**
- **Submarine** (on-chain → Lightning): the client locks on-chain BTC in an HTLC; the provider pays
  the client's Lightning invoice and claims the HTLC with the preimage. **Runnable end-to-end from
  the CLI** (the client issues the invoice, funds the HTLC, and refunds on timeout).

## Quickstart

### 1. Prerequisites

- **Rust** (stable) — <https://rustup.rs>
- **protoc** (only for the `lnd` feature, which compiles LND's protobufs) —
  `brew install protobuf` (macOS) / `apt install protobuf-compiler` (Debian/Ubuntu)

Run `./scripts/check-prereqs.sh` to verify your toolchain and build + unit-test the workspace.

### 2. Build & test

```bash
cargo build --all
cargo test --all        # unit tests only; the regtest integration tests are #[ignore]d
```

The default build needs no external services and pulls in no LND/Electrum toolchain.

### 3. Try the negotiation (no Bitcoin/LN node needed)

Each side needs a Pubky identity (a recovery phrase or a `.pkarr` file).

```bash
# Provider — prints its pubky on startup
cargo run -p swap-provider -- --recovery-phrase "<provider phrase>" \
  --network regtest --directions submarine,reverse --min-amount 10000 --max-amount 1000000

# Client (reverse swap of 50k sat) — use the provider pubky it logged
cargo run -p swap-client -- <PROVIDER_PUBKY> --recovery-phrase "<client phrase>" \
  --network regtest --direction reverse --amount 50000
```

The client requests a quote, receives the provider's HTLC details, and **verifies the HTLC script
pays its own claim key** before going further. Without execution credentials (below), it stops
there.

### 4. Run a full reverse swap on regtest

This needs a regtest backplane — bitcoind + electrs + **two** LND nodes with a channel between
them (e.g. via [Polar](https://lightningpolar.com)). Build with `--features full`.

**Provider** (LND + Electrum + a funded BIP84 wallet):

```bash
cargo run -p swap-provider --features full -- --recovery-phrase "<provider phrase>" \
  --network regtest \
  --lnd-address https://127.0.0.1:10009 --lnd-cert ~/.lnd/tls.cert \
  --lnd-macaroon ~/.lnd/.../admin.macaroon \
  --electrum-url tcp://127.0.0.1:60001 \
  --wallet-mnemonic "<bip39 mnemonic for the funding wallet>" \
  --data-dir ./provider-data
```

**Client** (its own LND to pay the hold invoice, Electrum to watch/claim, and a claim address):

```bash
cargo run -p swap-client --features full -- <PROVIDER_PUBKY> --recovery-phrase "<client phrase>" \
  --network regtest --direction reverse --amount 50000 \
  --lnd-address https://127.0.0.1:10011 --lnd-cert ~/.lnd-2/tls.cert \
  --lnd-macaroon ~/.lnd-2/.../admin.macaroon \
  --electrum-url tcp://127.0.0.1:60001 \
  --claim-address bcrt1q...your_regtest_address
```

The client pays the hold invoice, waits for the provider's on-chain HTLC to confirm, claims it with
the preimage, and the provider recovers the preimage to settle the invoice — atomically linking the
two legs.

## Workspace layout

| Crate | Role |
|-------|------|
| `pubky-transport` | Generic encrypted-DM + follow-graph transport (message-type agnostic). |
| `swap-common` | Wire messages, swap state machine, P2WSH HTLC scripts + preimage helpers, on-chain claim/refund signing, `ChainWatcher` (+ Electrum impl). |
| `lightning` (`lightning-backend`) | `LightningBackend` trait, a no-op `StubBackend`, and a real LND gRPC backend behind the `lnd` feature. |
| `swap-provider` | Operator daemon: advertises offers, negotiates, and drives swaps; persists in-flight swaps and resumes them on restart. |
| `swap-client` | Client CLI: discovers providers, requests quotes, verifies the HTLC, and executes a reverse swap. |

## Feature flags

| Feature | Crate(s) | Enables |
|---------|----------|---------|
| `lnd` | `lightning-backend`, `swap-provider`, `swap-client` | Real LND gRPC backend (needs `protoc`). |
| `electrum` | `swap-common` | `ElectrumWatcher` chain access (find funding, broadcast, fee estimation). |
| `bdk-wallet` | `swap-provider` | BIP84 funding wallet over Electrum. |
| `chain` | `swap-provider`, `swap-client` | The Electrum chain watcher. |
| `full` | `swap-provider`, `swap-client` | Everything needed to execute swaps end-to-end. |

Without the execution features a provider runs **negotiation-only** and rejects `SwapRequest`s.

## Configuration & safety

- **Dynamic fees.** Claim/refund/funding transactions use a live Electrum fee estimate, clamped to
  a configured floor (`--onchain-fee-rate`, sat/vB) that is both the minimum and the fallback when
  estimation is unavailable (e.g. on regtest).
- **Network guard.** The provider aborts on startup if its `--network` disagrees with the network
  its LND node reports.
- **Mainnet safety floor.** On `--network bitcoin` the provider refuses to start with unsafe
  parameters (`required_confirmations < 2`, or a fee floor `< 5` sat/vB) unless you pass
  `--allow-unsafe`.
- **Quotes expire.** Issued quotes are valid for `--quote-ttl` seconds (default 300), are
  single-use, and are pruned from memory.
- **Crash recovery.** In-flight swaps are persisted under `--data-dir` (default `./pubky-swap-data`)
  and resumed on restart, so a provider crash doesn't strand HTLC funds.

## Integration tests (regtest)

All are `#[ignore]`d and need real services. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup.

```bash
# HTLC engine + Electrum watcher against bitcoind + electrs
cargo test -p swap-common --features electrum --test regtest -- --ignored --nocapture

# BDK funding wallet against bitcoind + electrs
cargo test -p swap-provider --features full --test wallet_regtest -- --ignored --nocapture

# Live LND smoke test (hold invoice lifecycle)
LND_GRPC_URL=https://127.0.0.1:10011 LND_CERT=/path/tls.cert LND_MACAROON=/path/admin.macaroon \
  cargo test -p lightning-backend --features lnd --test lnd_smoke -- --ignored --nocapture

# Full reverse swap across two LND nodes
LND_A_URL=https://127.0.0.1:10011 LND_A_CERT=.../A/tls.cert LND_A_MAC=.../A/admin.macaroon \
LND_B_URL=https://127.0.0.1:10012 LND_B_CERT=.../B/tls.cert LND_B_MAC=.../B/admin.macaroon \
REGTEST_ELECTRUM_URL=tcp://127.0.0.1:60001 \
  cargo test -p swap-provider --features full --test full_swap_regtest -- --ignored --nocapture

# Full submarine swap across two LND nodes (same env; provider needs outbound liquidity)
  cargo test -p swap-provider --features full --test submarine_swap_regtest -- --ignored --nocapture
```

## License

MIT
