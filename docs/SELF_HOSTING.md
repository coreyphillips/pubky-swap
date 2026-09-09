# Running pubky-swap against your own node

This guide shows how to point a pubky-swap **provider** (and **client**) at your own Lightning node
— including a walkthrough for an **Umbrel** LND node.

> ⚠️ **Status: not audited.** The swap engine is implemented and tested end-to-end on regtest
> against real LND, and every fund-touching path has a regression test that fails without its fix.
> What is missing is signet soak testing and a third-party security review; see
> [`ROADMAP.md`](../ROADMAP.md). Prefer a regtest, signet or testnet node, or amounts you can
> afford to lose. On `--network bitcoin` the provider refuses obviously-unsafe parameters unless
> you pass `--allow-unsafe`; that flag does **not** make it audited.

## What a provider needs

A fully-functional (swap-executing) provider needs three things, all configurable on the CLI:

| Capability | Flag(s) | Notes |
|---|---|---|
| **Lightning node** | `--lightning lnd` with `--lnd-address` `--lnd-cert` `--lnd-macaroon`, or `--lightning beignet` with `--beignet-url` | For LND, a macaroon with **invoice + router** permissions (the `admin.macaroon` works). |
| **Chain access** (Electrum/electrs) | `--electrum-url` | e.g. `tcp://host:50001` (mainnet/electrs) or `ssl://host:50002`. |
| **Funding wallet** (on-chain) | `--wallet lnd`, `--wallet beignet`, or `--wallet bdk` | `--wallet lnd` funds reverse-swap HTLCs from **LND's own on-chain balance** (no extra seed, and recommended). `--wallet beignet` does the same from a beignet daemon's wallet. `--wallet bdk` is a separate BIP84 wallet from `PUBKY_SWAP_WALLET_MNEMONIC__FILE`. |

Build with the `full` feature (needs [`protoc`](https://grpc.io/docs/protoc-installation/), for
LND's protobufs), adding `beignet` if you want that backend too:

```bash
cargo build -p swap-provider --features full           # LND
cargo build -p swap-provider --features full,beignet   # LND and beignet
```

The `beignet` feature needs no `protoc`. If you only want beignet, `--features chain,bdk-wallet,status,beignet`
builds without the LND toolchain entirely.

Without all three capabilities, the provider runs **negotiation-only** and rejects swap requests.
`--doctor` tells you which one is missing.

### Using beignet instead of LND

[beignet](https://github.com/coreyphillips/beignet) is a single daemon that is both a Lightning
node and an on-chain wallet, which makes it the shorter setup: one URL and one token instead of
an address plus two credential files, and one wallet to fund instead of two.

| Flag | Meaning |
|---|---|
| `--lightning beignet` | Use a beignet daemon for the Lightning leg. |
| `--wallet beignet` | Fund on-chain HTLCs from the same daemon's wallet. |
| `--beignet-url` | Base URL, e.g. `http://127.0.0.1:8080`. |
| `--beignet-tls-cert` | PEM root certificate, if the daemon was started with `--tls-cert`. |
| `--beignet-api-prefix` | API prefix, e.g. `/v1`, if the daemon is behind one. |

The API token is a secret, so it has no flag: `PUBKY_SWAP_BEIGNET_TOKEN__FILE=<path>`, or
`PUBKY_SWAP_BEIGNET_TOKEN__VALUE` to pass it inline. (`__` separates nesting, which is why the
suffix is there: every secret is a `{ value, file }` pair.)

```bash
umask 077 && echo "<token>" > ~/.pubky-swap/beignet.token

PUBKY_SWAP_RECOVERY_PHRASE__FILE=~/.pubky-swap/recovery.phrase \
PUBKY_SWAP_BEIGNET_TOKEN__FILE=~/.pubky-swap/beignet.token \
  swap-provider --network bitcoin \
    --lightning beignet --wallet beignet \
    --beignet-url http://127.0.0.1:8080 \
    --electrum-url tcp://127.0.0.1:50001
```

**A version check, not a leap of faith.** The provider asks the daemon what it can do before
advertising anything, and drops a direction it cannot serve safely rather than discovering it
mid-swap. A reverse swap needs a hold invoice whose final CLTV outlives the on-chain refund, and
a submarine swap needs a bound on the outgoing payment's total CLTV; a daemon that cannot set
either has the matching direction removed from the offer, with a log line saying so. **beignet
0.15.1 or later** supports both. The chain a beignet reports is checked against `--network` at
startup too, and a disagreement aborts.

## Secrets, and where they go

There is no flag for a seed. The Pubky recovery phrase, the funding wallet's mnemonic, the
identity passphrase and the beignet API token come from the environment or from a file, because a
value passed in argv is readable by anything that can see the process table, and lands in shell
history on the way there.

```bash
umask 077
mkdir -p ~/.pubky-swap
echo "<twelve words>" > ~/.pubky-swap/recovery.phrase
echo "<bip39 mnemonic>" > ~/.pubky-swap/wallet.mnemonic

export PUBKY_SWAP_RECOVERY_PHRASE__FILE=~/.pubky-swap/recovery.phrase
export PUBKY_SWAP_WALLET_MNEMONIC__FILE=~/.pubky-swap/wallet.mnemonic
```

Everything that is not a secret can live in a config file instead of a long flag list. Put it at
`~/.config/pubky-swap/config.toml` and it is found automatically:

```toml
network = "bitcoin"
lnd_address = "https://10.21.21.9:10009"
lnd_cert_path = "/home/umbrel/umbrel/app-data/lightning/data/lnd/tls.cert"
lnd_macaroon_path = "/home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/admin.macaroon"
electrum_url = "tcp://10.21.21.10:50001"
wallet_backend = "lnd"
```

Flags still win over the file, and the file wins over the defaults, so you can keep the settled
values in the file and override one for a single run.

## Check it before you run it

```bash
swap-provider --doctor
```

It reports on the identity, the parameters, the data directory, the Lightning node, the chain
backend and the wallet, and every failure says what to do about it. When it cannot reach your LND
it lists the credentials it *can* find on this machine, with the flags to use them, which on an
Umbrel is usually the answer. It exits non-zero when the daemon could not run, so it also works as
a container readiness probe.

`swap-provider --show-config` prints the resolved configuration with every secret redacted, which
is the thing to paste into an issue.

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

**Discovery (current state).** Counterparties reach you by knowing your **pubky**, printed on
startup, so share it. Publishing your offer to your Pubky *profile* so strangers can browse for
it (a public marketplace) is the unstarted **Marketplace layer** (see
[`ROADMAP.md`](../ROADMAP.md), Phase 6). For now discovery is "share your pubky", not a directory.

**How sharing your pubky actually reaches you.** Pubky's private messages live at a path derived
from an ECDH shared secret between the two parties. That is what makes them unlinkable, and it
also means there is no "who has written to me": a provider can only fetch messages from pubkys it
already knows, which is its follow graph.

So a counterparty announces themselves first, over an iroh peer-to-peer connection, and the
provider then starts polling them. Both sides do this by default and `full` builds it in; there
is nothing to configure. `--no-rendezvous-iroh` turns it off on either side, which makes a
provider private: it will then serve only counterparties already in its follow graph, and
`--broadcast-offer` pushes its offer to those followers at startup.

## Generic: point a provider at your LND

```bash
cargo run -p swap-provider --features full -- \
  --network <bitcoin|testnet|signet|regtest> \
  --lnd-address https://<lnd-host>:10009 \
  --lnd-cert   /path/to/tls.cert \
  --lnd-macaroon /path/to/admin.macaroon \
  --electrum-url tcp://<electrs-host>:50001 \
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

> **There is a one-click app.** In umbrelOS, open the App Store, choose **Community App Stores**
> from the menu, add `https://github.com/coreyphillips/pubky-swap-umbrel`, and install **Pubky
> Swap**. It runs the provider on the Umbrel itself against its own LND and Electrs, with a web
> panel for the identity, the rates and the limits, and it handles every credential path below
> for you. The rest of this section is for running the provider on another machine, or for
> wanting the CLI.

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
  --network bitcoin \
  --lnd-address https://umbrel.local:10009 \
  --lnd-cert   ./umbrel-tls.cert \
  --lnd-macaroon ./umbrel-admin.macaroon \
  --electrum-url tcp://umbrel.local:50001 \
  --base-fee 1000 --fee-ppm 2000 \
  --confirmations 3 \
  --data-dir ./pubky-swap-data
```

Notes:
- The command above uses the default `--wallet lnd`, so reverse-swap HTLCs are funded from your
  LND's own on-chain balance: no second seed to back up and nothing separate to fund. Use
  `--wallet bdk` with `PUBKY_SWAP_WALLET_MNEMONIC__FILE` only if you want the swap float kept in
  a wallet of its own, and fund that wallet with the amount you are willing to route.
- Check it with `swap-provider --doctor` before leaving it running. On an Umbrel it will find
  the credentials it can see on the machine and print the flags to use them.
- On mainnet the provider enforces a minimum confirmation count and fee floor; raise
  `--confirmations` / `--onchain-fee-rate` as appropriate, or it will refuse to start.
- **Strongly prefer testnet/signet first** (`--network testnet`, an Electrs on that network, and a
  testnet macaroon). Umbrel can run LND on testnet via a separate install or the Testnet apps.

## Client setup

The client needs its **own** LND (to pay/issue invoices) and chain access; the flags mirror the
provider's. Build with `--features full`.

**Check a provider first.** `--quote-only` requests a quote and prints the provider's
availability/rates without swapping — handy to confirm a pubky is a live provider:

```bash
cargo run -p swap-client --features full -- <PROVIDER_PUBKY> \
  --direction reverse --amount 50000 --quote-only
```

**Seedless with `--wallet lnd`.** Like the provider, the client can fund submarine HTLCs and receive
reverse-swap sweeps via **LND's own wallet**: no funding mnemonic and no `--claim-address`
needed. Add `--wallet lnd` to either command below (and drop those two flags).

**Reverse swap** (you receive on-chain BTC for Lightning):

```bash
cargo run -p swap-client --features full -- <PROVIDER_PUBKY> \
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
  --network bitcoin --direction submarine --amount 50000 \
  --lnd-address https://umbrel.local:10009 \
  --lnd-cert ./umbrel-tls.cert --lnd-macaroon ./umbrel-admin.macaroon \
  --electrum-url tcp://umbrel.local:50001 \
```

## Just want to try it safely first?

Run the whole thing on regtest with a one-command backplane (no real funds, no node of your own):

```bash
docker compose -f docker-compose.regtest.yml up -d
./scripts/setup-regtest-lnd.sh
```

See [`README.md`](../README.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the regtest demo and
the env vars to run the end-to-end swap tests.
