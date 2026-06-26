# pubky-swap

A **self-hosted, decentralized Lightning swap marketplace** — a Boltz alternative where
*any* node operator can advertise swaps with their own rates and facilitate them using
their own LND (later Core Lightning) node. Discovery and negotiation ride on the
[Pubky](https://pubky.org) network (the same encrypted-DM + follow-graph transport used by
`bitcoin-batch-coordinator`), so there is no central swap server.

> ⚠️ **Status: early scaffold.** The negotiation protocol and HTLC scripting exist and are
> tested; the actual fund-moving execution (hold invoices, on-chain lockup/claim/refund,
> chain watching) is **not implemented yet** — see `ROADMAP.md`. Do **not** use with real
> funds. Develop and test on **regtest** only.

## Swap types

- **Submarine** (on-chain → Lightning): client locks on-chain BTC in an HTLC; provider pays
  the client's Lightning invoice and claims the HTLC with the preimage.
- **Reverse** (Lightning → on-chain): client pays a Lightning hold invoice; provider locks
  on-chain BTC in an HTLC; client claims it with the preimage, letting the provider settle
  the hold invoice.

Both are made atomic by a single 32-byte preimage whose SHA256 is the shared Lightning
payment hash.

## Workspace layout

| Crate | Role |
|-------|------|
| `pubky-transport` | Generic encrypted-DM + follow-graph transport (message-type agnostic). |
| `swap-common` | Wire messages, swap state machine, P2WSH HTLC scripts + preimage helpers. |
| `lightning` (`lightning-backend`) | `LightningBackend` trait, a no-op `StubBackend`, and a real LND gRPC backend behind the `lnd` feature. |
| `swap-provider` | Operator daemon: advertises offers, negotiates and runs swaps. |
| `swap-client` | Client CLI: discover providers, request quotes, drive a swap. |

## Build

```bash
cargo build --all
cargo test --all
```

### Enabling the LND backend

The real LND gRPC backend is gated behind the `lnd` cargo feature so the default build
needs no extra toolchain. Enabling it requires **`protoc`** installed (it compiles LND's
protobuf definitions):

```bash
# macOS: brew install protobuf   |   Debian/Ubuntu: apt install protobuf-compiler
cargo build -p swap-provider --features lnd
```

Then point the provider at your node's gRPC URL, TLS cert, and a macaroon with invoice +
router permissions:

```bash
cargo run -p swap-provider --features lnd -- --recovery-phrase "<phrase>" \
  --network regtest \
  --lnd-address https://127.0.0.1:10009 \
  --lnd-cert ~/.lnd/tls.cert \
  --lnd-macaroon ~/.lnd/data/chain/bitcoin/regtest/admin.macaroon
```

Without `--features lnd` (or if the connection fails) the provider runs with a stub backend
whose Lightning operations return `NotImplemented` — fine for exercising the negotiation
flow, not for real swaps.

### On-chain regtest integration test

The HTLC engine + Electrum watcher are validated against a real bitcoind + electrs (the test
mines/funds via `docker exec ... bitcoin-cli` and observes via electrs). It is `#[ignore]`d
and requires the `electrum` feature:

```bash
cargo test -p swap-common --features electrum --test regtest -- --ignored --nocapture
```

Env overrides: `REGTEST_ELECTRUM_URL` (default `tcp://127.0.0.1:60001`), `REGTEST_BTC_CONTAINER`
(default `bitcoin`); it assumes Polar bitcoind RPC defaults (port 43782, `polaruser`/`polarpass`).

There is also a BDK wallet regtest test (`swap-provider --features bdk-wallet --test
wallet_regtest`) and a live LND smoke test:

```bash
LND_GRPC_URL=https://127.0.0.1:10011 LND_CERT=/path/tls.cert LND_MACAROON=/path/admin.macaroon \
  cargo test -p lightning-backend --features lnd --test lnd_smoke -- --ignored --nocapture
```

### Executing real swaps

A fully-configured provider executes swaps (not just negotiation):

```bash
cargo run -p swap-provider --features full -- --recovery-phrase "<phrase>" --network regtest \
  --lnd-address https://127.0.0.1:10009 --lnd-cert ~/.lnd/tls.cert \
  --lnd-macaroon ~/.lnd/.../admin.macaroon \
  --electrum-url tcp://127.0.0.1:60001 \
  --wallet-mnemonic "<bip39 mnemonic for the funding wallet>"
```

With LND + Electrum + a funded BDK wallet present, a `SwapRequest` triggers HTLC/hold-invoice
creation, a `SwapAccept`, and a spawned task that drives the swap to completion. Without them
the provider stays negotiation-only and rejects `SwapRequest`s.

### End-to-end reverse swap (two LND nodes)

`swap-provider/tests/full_swap_regtest.rs` runs a complete reverse swap across two real LND
nodes (a provider node + a client node with a channel to it), bitcoind, and electrs. Provide
both nodes' endpoints/creds + an electrum URL and run:

```bash
LND_A_URL=https://127.0.0.1:10011 LND_A_CERT=.../A/tls.cert LND_A_MAC=.../A/admin.macaroon \
LND_B_URL=https://127.0.0.1:10012 LND_B_CERT=.../B/tls.cert LND_B_MAC=.../B/admin.macaroon \
REGTEST_ELECTRUM_URL=tcp://127.0.0.1:60001 \
  cargo test -p swap-provider --features full --test full_swap_regtest -- --ignored --nocapture
```

It pays the hold invoice, funds + claims the HTLC, and asserts the provider reaches `Claimed`
and the invoice is `Settled` — proving the Lightning and on-chain legs are atomically linked.

## Try the negotiation (regtest)

Each side needs a Pubky identity (recovery phrase or `.pkarr` file).

```bash
# Provider
cargo run -p swap-provider -- --recovery-phrase "<provider pubky phrase>" \
  --network regtest --directions submarine,reverse --min-amount 10000 --max-amount 1000000

# Client (reverse swap of 50k sat) — use the provider pubky it logs on startup
cargo run -p swap-client -- <PROVIDER_PUBKY> --recovery-phrase "<client pubky phrase>" \
  --network regtest --direction reverse --amount 50000
```

The client will receive a quote and the provider's HTLC details. Execution beyond that is
the next set of milestones.

## License

MIT
