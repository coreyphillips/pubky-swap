# Contributing to pubky-swap

Thanks for your interest! This is safety-critical software — atomic-swap bugs lose real money — so
the bar for changes to the swap engine is high. Please read the safety invariants below before
touching timelock, fee, or HTLC code.

## Development setup

1. Install **Rust** (stable) via <https://rustup.rs>.
2. For anything LND-related, install **protoc** (`brew install protobuf` /
   `apt install protobuf-compiler`). The default build doesn't need it.
3. Verify your toolchain and run the build + unit tests:

   ```bash
   ./scripts/check-prereqs.sh
   ```

## Everyday commands

```bash
cargo build --all
cargo test --all                       # unit tests (fast, no external services)
cargo fmt --all                        # format
cargo fmt --all --check                # CI-style format check
cargo clippy --all-targets             # lint (please keep it warning-free)
cargo clippy -p swap-provider --features full --all-targets   # lint feature-gated code too
```

Both formatting (`cargo fmt --all --check`) and a warning-free `cargo clippy` are expected on every
change.

## Feature flags

Most execution code is behind cargo features so the default build stays toolchain-light:

| Feature | Crate(s) | Enables |
|---------|----------|---------|
| `lnd` | `lightning-backend`, `swap-provider`, `swap-client` | Real LND gRPC backend (needs `protoc`). |
| `electrum` | `swap-common` | `ElectrumWatcher`. |
| `bdk-wallet` | `swap-provider` | BIP84 funding wallet. |
| `chain` | `swap-provider`, `swap-client` | Electrum chain watcher. |
| `full` | `swap-provider`, `swap-client` | Everything needed to execute swaps. |

When you add code behind a feature, build it explicitly (e.g.
`cargo build -p swap-provider --features full`) — the default `cargo build --all` won't compile it.

## Tests

- **Unit tests** run with `cargo test --all` and use trait mocks (no Bitcoin/Lightning needed).
  The on-chain HTLC spends are additionally validated against real Bitcoin script consensus via
  `libbitcoinconsensus`.
- **Integration tests** are marked `#[ignore]` and need a regtest backplane. The easiest setup is
  [Polar](https://lightningpolar.com), which gives you bitcoind + electrs + LND nodes. Defaults the
  tests assume: bitcoind RPC `polaruser`/`polarpass` on port `43782`, Electrum at
  `tcp://127.0.0.1:60001` (override with `REGTEST_ELECTRUM_URL`), bitcoind container name `bitcoin`
  (override with `REGTEST_BTC_CONTAINER`).

  See the command list at the bottom of [`README.md`](README.md). Run them with
  `-- --ignored --nocapture`.

## Safety invariants (do not break these)

- **A provider must not commit on-chain funds until the counterparty's leg is sufficiently
  confirmed/accepted.** A client must not reveal the preimage until the provider's lockup is
  confirmed.
- **Timelocks:** the refund path uses `nLockTime = timeout` with a non-final sequence so
  `OP_CHECKLOCKTIMEVERIFY` is enforced; the claim path has no timelock. Any change here must keep
  the `swap-common` consensus tests (claim valid, refund valid only at/after timeout, wrong-preimage
  and wrong-key rejected) passing.
- **Fees:** claim/refund/funding fees use a live estimate clamped to the configured floor. Never
  let the effective rate drop below the floor, and never produce a sub-dust output.
- **Resume must be idempotent:** a restarted provider must not re-fund an HTLC it already funded
  (it adopts the persisted/observed funding outpoint) and must detect an already-completed claim.

If a change affects any of the above, add or update a test that demonstrates the safe behavior.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for what's done and what's still required before mainnet.
