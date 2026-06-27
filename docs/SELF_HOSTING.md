# Running pubky-swap against your own node

This guide shows how to point a pubky-swap **provider** (and **client**) at your own Lightning node
— including a walkthrough for an **Umbrel** LND node.

> ⚠️ **Status: not yet safe for mainnet funds.** The swap engine is implemented and tested (incl.
> end-to-end on regtest against real LND), but mainnet hardening isn't finished and the code has not
> had a third-party security audit — see [`ROADMAP.md`](../ROADMAP.md). **Use a regtest, signet, or
> testnet node**, or a node you're willing to lose funds on. On `--network bitcoin` the provider
> refuses obviously-unsafe parameters unless you pass `--allow-unsafe`; that flag does **not** make
> it audited.

## What a provider needs

A fully-functional (swap-executing) provider needs three things, all configurable on the CLI:

| Capability | Flag(s) | Notes |
|---|---|---|
| **Lightning node** (LND, gRPC) | `--lnd-address` `--lnd-cert` `--lnd-macaroon` | A macaroon with **invoice + router** permissions (the `admin.macaroon` works). |
| **Chain access** (Electrum/electrs) | `--electrum-url` | e.g. `tcp://host:50001` (mainnet/electrs) or `ssl://host:50002`. |
| **Funding wallet** (on-chain) | `--wallet-mnemonic` | A BIP39 mnemonic for a BIP84 wallet **holding coins** — it funds reverse-swap HTLCs. |

Build with the `full` feature (needs [`protoc`](https://grpc.io/docs/protoc-installation/)):

```bash
cargo build -p swap-provider --features full
```

Without all three, the provider runs **negotiation-only** and rejects swap requests.

## Run as an always-on provider (advertise swaps at your rate)

The provider is a **long-running daemon**: once started it stays up, advertising an offer and
serving quote/swap requests from anyone who reaches your pubky, until you stop it. Run it under a
process manager (systemd, `tmux`, Docker, …) to keep it alive.

Your **rate** is two knobs, plus the amounts/directions you'll accept:

| Flag | Meaning |
|---|---|
| `--base-fee <sats>` | Flat fee per swap. |
| `--fee-ppm <ppm>` | Proportional fee, parts-per-million of the swap amount. |
| `--min-amount` / `--max-amount` | Swap size bounds (sats). |
| `--directions submarine,reverse` | Which swap types you facilitate. |

The fee you charge is `base_fee + amount × fee_ppm / 1_000_000`. For example
`--base-fee 1000 --fee-ppm 2000` (0.2%) on a 100,000-sat swap charges `1000 + 200 = 1200` sat.

**Discovery (current state).** Counterparties reach you by knowing your **pubky** (printed on
startup — share it), or by following you on the Pubky follow graph: `--broadcast-offer` pushes your
offer to discovered followers when the daemon starts. Publishing your offer to your Pubky *profile*
so strangers can browse/discover it (a public marketplace) is the unstarted **Marketplace layer**
(see [`ROADMAP.md`](../ROADMAP.md), Phase 6) — for now, discovery is "share your pubky" / follow
graph, not a directory.

## Generic: point a provider at your LND

```bash
cargo run -p swap-provider --features full -- \
  --recovery-phrase "<your pubky recovery phrase>" \
  --network <bitcoin|testnet|signet|regtest> \
  --lnd-address https://<lnd-host>:10009 \
  --lnd-cert   /path/to/tls.cert \
  --lnd-macaroon /path/to/admin.macaroon \
  --electrum-url tcp://<electrs-host>:50001 \
  --wallet-mnemonic "<bip39 mnemonic for the funding wallet>" \
  --data-dir ./pubky-swap-data
```

The provider logs its **pubky** on startup — clients use that to reach it. It aborts if its
`--network` disagrees with the network your LND reports (a guard against pointing a testnet config at
a mainnet node, and vice-versa).

### Macaroon permissions

The provider calls `invoicesrpc` (hold invoices) + `routerrpc` (paying invoices) + `lnrpc`
(`GetInfo`, invoice lookup). The `admin.macaroon` covers all of these. To mint a least-privilege
macaroon instead:

```bash
lncli bakemacaroon \
  info:read invoices:read invoices:write offchain:read offchain:write \
  --save_to swap.macaroon
```

### TLS gotcha (connecting to a remote LND)

`--lnd-cert` is used to verify the LND server's TLS certificate, so **the address you connect to
must be present in the cert's SANs**. A node's `tls.cert` often only lists `localhost` / the
container IP, so connecting over the LAN by IP can fail with a certificate error.

Fix it by regenerating the cert with your host's address baked in: add to your LND config
(`lnd.conf`)

```ini
tlsextraip=<your-lan-ip>
tlsextradomain=<your-hostname>
```

then delete `tls.cert` **and** `tls.key` and restart LND (it regenerates both). Or connect using a
hostname/IP that is already in the cert.

## Umbrel walkthrough (provider)

Umbrel runs LND; an **Electrs** app provides chain access. The provider runs on any machine that can
reach your Umbrel over the LAN (or on the Umbrel host itself).

### 1. Find the credentials

LND's `tls.cert` and `admin.macaroon` live under the Lightning app's data dir. Copy them off the
Umbrel (default SSH user `umbrel`, host `umbrel.local`):

```bash
# umbrelOS 1.x (current)
scp umbrel@umbrel.local:~/umbrel/app-data/lightning/data/lnd/tls.cert ./umbrel-tls.cert
scp umbrel@umbrel.local:~/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/admin.macaroon ./umbrel-admin.macaroon

# Legacy Umbrel (0.5.x): paths are ~/umbrel/lnd/tls.cert and
#   ~/umbrel/lnd/data/chain/bitcoin/mainnet/admin.macaroon
```

(On a testnet/signet Umbrel, replace `mainnet` in the macaroon path with `testnet`/`signet`.)

### 2. Endpoints

- **LND gRPC:** `https://umbrel.local:10009` (Umbrel exposes LND's gRPC on the host).
- **Electrs:** install Umbrel's **Electrs** app; it serves Electrum on `tcp://umbrel.local:50001`.

If connecting by IP/hostname fails with a TLS error, apply the **TLS gotcha** fix above (Umbrel lets
you edit the LND config from the Lightning app's advanced settings, then restart it).

### 3. Run the provider

```bash
cargo run -p swap-provider --features full -- \
  --recovery-phrase "<your pubky recovery phrase>" \
  --network bitcoin \
  --lnd-address https://umbrel.local:10009 \
  --lnd-cert   ./umbrel-tls.cert \
  --lnd-macaroon ./umbrel-admin.macaroon \
  --electrum-url tcp://umbrel.local:50001 \
  --wallet-mnemonic "<bip39 mnemonic for a SEPARATE funding wallet>" \
  --base-fee 1000 --fee-ppm 2000 \
  --confirmations 3 \
  --data-dir ./pubky-swap-data
```

Notes:
- The `--wallet-mnemonic` is an **on-chain wallet separate from LND** that funds reverse-swap
  HTLCs. Fund it with the amount you're willing to route through swaps. (It is *not* your LND
  on-chain wallet.)
- On mainnet the provider enforces a minimum confirmation count and fee floor; raise
  `--confirmations` / `--onchain-fee-rate` as appropriate, or it will refuse to start.
- **Strongly prefer testnet/signet first** (`--network testnet`, an Electrs on that network, and a
  testnet macaroon). Umbrel can run LND on testnet via a separate install or the Testnet apps.

## Client setup

The client needs its **own** LND (to pay/issue invoices) and chain access; the flags mirror the
provider's. Build with `--features full`.

**Reverse swap** (you receive on-chain BTC for Lightning):

```bash
cargo run -p swap-client --features full -- <PROVIDER_PUBKY> \
  --recovery-phrase "<client pubky phrase>" \
  --network bitcoin --direction reverse --amount 50000 \
  --lnd-address https://umbrel.local:10009 \
  --lnd-cert ./umbrel-tls.cert --lnd-macaroon ./umbrel-admin.macaroon \
  --electrum-url tcp://umbrel.local:50001 \
  --claim-address bc1q...your_receive_address
```

**Submarine swap** (you send on-chain BTC, receive Lightning) additionally needs a funding wallet
to lock the HTLC:

```bash
cargo run -p swap-client --features full -- <PROVIDER_PUBKY> \
  --recovery-phrase "<client pubky phrase>" \
  --network bitcoin --direction submarine --amount 50000 \
  --lnd-address https://umbrel.local:10009 \
  --lnd-cert ./umbrel-tls.cert --lnd-macaroon ./umbrel-admin.macaroon \
  --electrum-url tcp://umbrel.local:50001 \
  --wallet-mnemonic "<bip39 mnemonic for the funding wallet>"
```

## Just want to try it safely first?

Run the whole thing on regtest with a one-command backplane (no real funds, no node of your own):

```bash
docker compose -f docker-compose.regtest.yml up -d
./scripts/setup-regtest-lnd.sh
```

See [`README.md`](../README.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the regtest demo and
the env vars to run the end-to-end swap tests.
