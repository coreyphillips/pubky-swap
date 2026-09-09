# pubky-swap

[![CI](https://github.com/coreyphillips/pubky-swap/actions/workflows/ci.yml/badge.svg)](https://github.com/coreyphillips/pubky-swap/actions/workflows/ci.yml)

A **self-hosted, decentralized Lightning swap marketplace.** Any node operator can advertise
swaps at their own rates and facilitate them with their own LND node; clients discover providers
and negotiate over the [Pubky](https://pubky.org) network (an encrypted-DM + follow-graph
transport), so there is **no central swap server**.

Swaps are made atomic by a single 32-byte preimage whose SHA256 is the shared Lightning payment
hash — the on-chain HTLC can only be claimed by revealing the preimage that settles the Lightning
leg, and vice-versa.

> ⚠️ **Not audited. Do not risk what you cannot lose.** The swap engine (HTLC scripting,
> timelocks, claim/refund, hold invoices, chain watching, crash-resume, RBF/CPFP fee-bumping and
> reorg handling) is implemented and tested end-to-end on regtest against real LND, and every
> fund-touching path has a regression test that fails without its fix. What is missing before
> mainnet is signet soak testing and a third-party security review. Atomic-swap bugs lose money.
> See [`ROADMAP.md`](ROADMAP.md).

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

Each side needs a Pubky identity: a recovery phrase, or a `.pkarr` file passed as the first
argument. **The phrase has no flag.** Put it in a file only you can read and name that file, so it
never reaches the process table or your shell history:

```bash
umask 077 && echo "<twelve words>" > provider.phrase

# Provider — prints its pubky on startup
PUBKY_SWAP_RECOVERY_PHRASE__FILE=provider.phrase \
  cargo run -p swap-provider -- --network regtest \
  --directions submarine,reverse --min-amount 10000 --max-amount 1000000

# Client (reverse swap of 50k sat) — use the provider pubky it logged
PUBKY_SWAP_RECOVERY_PHRASE__FILE=client.phrase \
  cargo run -p swap-client -- <PROVIDER_PUBKY> \
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
PUBKY_SWAP_RECOVERY_PHRASE__FILE=provider.phrase \
PUBKY_SWAP_WALLET_MNEMONIC__FILE=wallet.mnemonic \
  cargo run -p swap-provider --features full -- --network regtest \
  --lnd-address https://127.0.0.1:10009 --lnd-cert ~/.lnd/tls.cert \
  --lnd-macaroon ~/.lnd/.../admin.macaroon \
  --electrum-url tcp://127.0.0.1:60001 \
  --data-dir ./provider-data
```

Not sure what is missing? `swap-provider --doctor` checks everything the daemon needs, says what
to do about anything that fails, and exits non-zero if it could not run.

**Client** (its own LND to pay the hold invoice, Electrum to watch/claim, and a claim address):

```bash
PUBKY_SWAP_RECOVERY_PHRASE__FILE=client.phrase \
  cargo run -p swap-client --features full -- <PROVIDER_PUBKY> \
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
| `status` | `swap-provider` | The read-only status API (adds an HTTP server). |
| `full` | `swap-provider`, `swap-client` | Everything needed to execute swaps end-to-end. |

Without the execution features a provider runs **negotiation-only** and rejects `SwapRequest`s.

## Configuration

Settings come from four places, most specific last: **built-in defaults**, a **TOML file**, the
**environment**, and **flags**. A flag you do not pass leaves the lower layers alone, which is what
makes the file and the environment usable at all.

Every flag has an environment variable: upper-case it and prefix `PUBKY_SWAP_`, so `--lnd-address`
is `PUBKY_SWAP_LND_ADDRESS`. The config file is found at `$PUBKY_SWAP_CONFIG`, then
`$PUBKY_SWAP_DATA_DIR/config.toml`, then `~/.config/pubky-swap/config.toml`, then
`./pubky-swap.toml`, or wherever `--config` says.

```toml
network = "bitcoin"
electrum_url = "tcp://10.21.21.10:50001"
base_fee_sat = 500
fee_ppm = 2000
```

**Secrets have no flag.** The recovery phrase, the wallet mnemonic, the identity passphrase and
the beignet API token can only come from the environment or from a file, because a value in argv
is readable by anything that can see the process table and lands in shell history on the way there.
Each takes either the value or a path to a file holding it:

| Secret | Value | File |
|---|---|---|
| Pubky recovery phrase | `PUBKY_SWAP_RECOVERY_PHRASE__VALUE` | `PUBKY_SWAP_RECOVERY_PHRASE__FILE` |
| Identity passphrase | `PUBKY_SWAP_PASSPHRASE__VALUE` | `PUBKY_SWAP_PASSPHRASE__FILE` |
| Funding wallet mnemonic | `PUBKY_SWAP_WALLET_MNEMONIC__VALUE` | `PUBKY_SWAP_WALLET_MNEMONIC__FILE` |
| beignet API token | `PUBKY_SWAP_BEIGNET_TOKEN__VALUE` | `PUBKY_SWAP_BEIGNET_TOKEN__FILE` |

A secret file more permissive than `0600` is warned about, not refused. `--show-config` prints the
resolved configuration with every secret redacted, so it is safe to paste into an issue.

## Diagnostics

`swap-provider --doctor` runs every check the daemon depends on and prints what to do about
anything that fails, including credentials it can find on this machine:

```
  [ok  ] network                Bitcoin
  [FAIL] identity               no Pubky identity configured
         -> put the phrase in a file readable only by this user and set
            PUBKY_SWAP_RECOVERY_PHRASE__FILE to its path
  [FAIL] lightning.lnd          could not reach LND at https://127.0.0.1:10009
         -> Credentials found on this machine:
         ->   Umbrel -> --lnd-address https://10.21.21.9:10009 --lnd-cert ...
```

It exits non-zero when the daemon could not run, so it works as a container readiness probe.

### Status API

`--status-addr 127.0.0.1:9737` serves a **read-only** JSON API, so a dashboard or a health check
can see what the daemon is doing without parsing its logs:

| Endpoint | What it answers |
|---|---|
| `/health` | the `--doctor` report, as JSON, with `capable` |
| `/status` | pubky, network, directions, in-flight count, committed sats |
| `/swaps` | live swaps, and the most recent finished ones |
| `/limits` | exposure and concurrency against their ceilings, and per counterparty |
| `/offer` | the offer currently being advertised |
| `/earnings` | completed, refunded and failed swaps, volume, and fees earned |

Read-only by design: nothing here moves money or changes a swap. It binds loopback and requires a
bearer token, generated into `<data-dir>/status.token` at `0600` on first start, so a supervisor
sharing that volume can read it and nothing else can. Responses are built from projection types
with no field for a branch key or a preimage, and there is a test asserting that.

## Safety

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
- **Reorg resilience.** Claims/refunds are RBF-bumped and treated as final only once buried a few
  blocks deep; a reorged-out spend is re-broadcast; the submarine provider re-confirms the funding
  depth before paying the invoice; and a background monitor flags reorgs affecting live swaps.

## Running against your own node

To point a provider/client at your own LND or [beignet](https://github.com/coreyphillips/beignet)
daemon (with a generic walkthrough and a step-by-step **Umbrel** setup covering where to find the
cert/macaroon, the Electrs app, and the TLS gotcha), see
[`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md).

On **umbrelOS** there is a one-click app instead: add
`https://github.com/coreyphillips/pubky-swap-umbrel` as a community app store and install
**Pubky Swap**. It runs the provider against your Umbrel's own LND and Electrs, and gives it a
web panel for the identity, the rates and the limits.

⚠️ Not audited. Prefer a regtest/signet/testnet node, or amounts you can afford to lose,
until the [`ROADMAP.md`](ROADMAP.md) mainnet items land.

## Integration tests (regtest)

All are `#[ignore]`d and need real services. A one-command backplane (bitcoind + electrs + two LND
nodes) plus a channel-setup script cover everything:

```bash
docker compose -f docker-compose.regtest.yml up -d
./scripts/setup-regtest-lnd.sh   # opens a funded, balanced channel between the two LND nodes
```

CI runs fmt/clippy/build/unit tests on every push (`.github/workflows/ci.yml`); `regtest.yml` brings
up that backplane and runs **all** the integration tests — including both two-node LND swaps — on a
manual/weekly schedule. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the env vars.

```bash
# HTLC engine + Electrum watcher against bitcoind + electrs
cargo test -p swap-common --features electrum --test regtest -- --ignored --nocapture

# Reorg detection (forces a reorg via bitcoin-cli invalidateblock)
cargo test -p swap-common --features electrum --test reorg_regtest -- --ignored --nocapture

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
