# Channel purchases: Phase 1 decisions

Status: proposed, 2 Nov 2026.

This records the Phase 1 decisions for [#84](https://github.com/coreyphillips/pubky-swap/issues/84): protocol revisions, the envelope for the first release, backend versions, the order store, the funding flow, and the tests that gate sales. It also unblocks `liquidity/1` in Paykit Capabilities ([pubky/paykit-rs#229](https://github.com/pubky/paykit-rs/issues/229), §13.5).

## Context

- **Bitkit has no channel provider today.** Both apps merged "feat: blocktank sunset" on 27 Oct 2026: bitkit-android [`4eeb421`](https://github.com/synonymdev/bitkit-android/commit/4eeb421b6d3a4eb7a359a78862074288e190bc3d) and bitkit-ios [`86d820a`](https://github.com/synonymdev/bitkit-ios/commit/86d820a9d4b9c77bd8bed2853c78855ba1e9565e). The node config now trusts no peer for zero-conf or no-reserve channels, and its comment reads "Blocktank no longer serves channels" ([LightningService.kt](https://github.com/synonymdev/bitkit-android/blob/e28307b9d5b8dc7e1e47af04adae32567353b1d0/app/src/main/java/to/bitkit/services/LightningService.kt#L115-L133)). Buying a channel from the provider the user scanned is the replacement.
- **No channel-sale code exists yet.**
  - The provider reaches LND through `fedimint-tonic-lnd` 0.4. Its vendored protos already have everything this phase needs:
    - `OpenChannel`, with `funding_shim` and `memo`;
    - `FundingStateStep`, `PendingChannels` and `SubscribeChannelEvents`;
    - `FundPsbt`, with `custom_lock_id` and `lock_expiration_seconds`;
    - `FinalizePsbt`, `LeaseOutput`, `ReleaseOutput` and `ListLeases`.
  - The protos also have `SendCustomMessage`, `SubscribeCustomMessages` and `HtlcInterceptor` for later phases.
  - The `lightning` crate has no channel or lease methods today.
  - A reverse swap is funded with one `SendOutputs` call. LND signs and broadcasts it, so the txid is only known afterwards.
  - The swap store is one JSON file per swap ([`store.rs`](https://github.com/coreyphillips/pubky-swap/blob/8686702/swap-common/src/store.rs#L1-L15)). Exposure accounting lives only in memory and is rebuilt from those files at startup (`swap-provider/src/risk.rs`).
- **The buyer is LDK Node 0.7.0-rc.78** (Bitkit `master`, synonymdev/ldk-node [`1976754`](https://github.com/synonymdev/ldk-node/tree/1976754dd49886e102f2b3132d5f700d6aabd8d7), lightning 0.2.7). Most limits below come from what it accepts.

## Decisions

| | Decision |
| --- | --- |
| D1 | The first release sells prepaid channels, paid on chain, funded with confirmed transactions. |
| D2 | Message shapes follow LSPS1 at bLIP 51 `ba7a34b`. LSPS2 `8b09c57` and LSPS5 `a833e7b` are pinned for later phases. |
| D3 | The first release exposes the Pubky adapter only, with no LSPS0 endpoint and no LSPS conformance claim. |
| D4 | Channel sales are their own domain service, sharing transport, identity, the LND client and one reservation ledger with swaps. |
| D5 | Orders live in a new SQLite store. |
| D6 | An order belongs to the authenticated Pubky, and the buyer proves its Lightning node with a signed challenge. |
| D7 | LND funds through the PSBT flow, and the signed funding transaction is persisted before any broadcast. |
| D8 | Swaps and channel sales reserve inputs and liquidity in one ledger. |
| D9 | Limits come from the protocol, the peers, liquidity and the operator, never from a product cap. |
| D10 | The API is `channel.*.v1`, with a required idempotency key. Quotes reserve nothing. |
| D11 | Purchase, payment, funding, channel and refund each keep their own state. |
| D12 | Refunds go on chain to the address given at create, through a persisted refund intent. |
| D13 | Bitkit trusts no provider automatically. JIT gets its own decision before Phase 5. |
| D14 | Sales stay off on a network until its feasibility gate passes. |

### D1. First release: prepaid, paid on chain, confirmed funding

The first release covers journey 1 (first channel from savings) and the on-chain half of journey 2. It leaves out:

- **Lightning-paid orders.** LSPS1 makes these a hold invoice. #84 Phase 2 requires the hold, settle and funding boundary to be designed together first.
- **JIT channels.** Those are Phase 5.
- **Zero-conf channels, zero-reserve channels and announced channels.**

**Payment confirmations.** The provider funds once the buyer's on-chain payment has 2 confirmations on mainnet, or 1 on regtest. That is the same floor as swaps (`MIN_MAINNET_CONFIRMATIONS`). An operator may raise it as far as 6, where LSPS1 counts a payment as confirmed regardless.

What Bitkit's node implies for this release:

- **Channels are private.** Bitkit sets no alias and no listening address, so LDK Node rejects any announced inbound channel ([event.rs](https://github.com/synonymdev/ldk-node/blob/1976754dd49886e102f2b3132d5f700d6aabd8d7/src/event.rs#L1884-L1898)). The provider opens with `private: true`, and an order with `announce_channel: true` is refused before payment.
- **A channel is usable after 6 confirmations.** LDK's `minimum_depth` defaults to 6 ([config.rs](https://docs.rs/lightning/0.2.7/src/lightning/util/config.rs.html#248)), and Bitkit does not override it. On mainnet, after the payment's own 2 confirmations, that is about 80 minutes from paying to a usable channel. The quote and progress screens must say so.
- **The anchor reserve is not a blocker.** Bitkit sets `per_channel_reserve_sats` to 1. An untrusted anchor channel then needs 1 sat of spendable on-chain balance for each such channel, and LDK Node counts unconfirmed funds.

### D2. Protocol revisions

| Spec | Revision | Used for |
| --- | --- | --- |
| LSPS0, [bLIP 50](https://github.com/lightning/blips/blob/b48e5db/blip-0050.md) | `b48e5db`, 2025-04-29 | Error conventions only: JSON-RPC codes and `data`. This release has no LSPS0 transport. |
| LSPS1, [bLIP 51](https://github.com/lightning/blips/blob/ba7a34b/blip-0051.md) | `ba7a34b`, 2026-01-14 | Field names, units and meaning in the info, quote and order bodies. |
| LSPS2, [bLIP 52](https://github.com/lightning/blips/blob/8b09c57/blip-0052.md) | `8b09c57`, 2024-12-20 | Phase 5 only. |
| LSPS5, [bLIP 55](https://github.com/lightning/blips/blob/a833e7b/blip-0055.md) | `a833e7b`, 2025-08-12 | Phase 5 notifications only. |

All four are Active. An LSPS revision must stay backward compatible, and a breaking change takes a new LSPS number.

Two cautions about the pinned texts:

- **LSPS1 still has errata.** It refers to `lsps1.get_info.options`, `base_api.*` and `onchain_payment`, all left over from its 2024 restructure. Older peers may still send the pre-2024 shape. This implementation follows the field definitions, not the stale references, and refuses the old shape.
- **LSPS2's prose fee formula is wrong.**
  - The prose divides by 10,000,000. The spec's own C and Rust code divide by 1,000,000, and open PR lightning/blips#74 fixes the prose.
  - Phase 5 implements ceil(`payment_size_msat` × `proportional` / 1,000,000), floored at `min_fee_msat`, with checked u64 arithmetic.
  - It is tested against vectors computed independently of both texts. This is the unchecked-formula case #84 warns about.

### D3. Envelope: the Pubky adapter only

Channel requests use the provider's existing transports:

- iroh `pubky-swap/direct/1`;
- `pubky-swap/session/2`, under a scoped authorization;
- Pubky DMs.

Each request body carries the LSPS1 object verbatim in an `lsps1` member, next to the Pubky fields LSPS1 lacks (D10). The provider does not answer `lsps0.list_protocols` and does not set feature bit 729. The API is described as "LSPS1-shaped", never as conforming.

Why:

- **LSPS1 can't express what these orders need.**
  - `create_order` is not idempotent, and there is no idempotency key.
  - There is no way to list orders.
  - Nothing authenticates the client beyond its Lightning node connection. The spec doesn't even limit `get_order` to the node that created the order.
  - Bitkit needs orders that survive retries, restores and identity changes (#84 journey 4).
- **LDK Node's own LSPS clients would grant trust silently.** `set_liquidity_source_lsps1` and `set_liquidity_source_lsps2` both add the LSP to `trusted_peers_0conf` ([builder.rs](https://github.com/synonymdev/ldk-node/blob/1976754dd49886e102f2b3132d5f700d6aabd8d7/src/builder.rs#L516-L548)). Bitkit's post-sunset config deliberately trusts no one, and #84 forbids auto-trusting a scanned provider.
- **One entry point while recovery is proven.** A conforming LSPS0 endpoint invites any wallet, so it needs its own conformance suite before it is safe to expose.

Consequences:

- Standard LSPS1 wallets can't buy from a pubky-swap provider in this release.
- The Pubky transport does not authenticate a Lightning node, so D6 adds a node proof.
- The domain service is transport-neutral, so two later adapters can reuse it unchanged:
  - **LSPS0 over BOLT 8:** message type 37913, through `SubscribeCustomMessages` and `SendCustomMessage`.
  - **`liquidity/1` over Paykit Encrypted Links:** LSPS bodies carried verbatim in `body.lsps`, once pubky/paykit-rs#209 lands.

### D4. Domain boundary

Channel sales are a new module in the provider, with its own drivers and its own recovery worker. They never use `SwapState`, the swap store or the swap drivers. They share these with swaps:

- the authenticated transport and identity;
- the access policy (#88) and per-account rate limits;
- the LND client;
- the chain observer;
- the reservation ledger (D8).

A swap and a channel order never depend on each other's state.

### D5. Order store: SQLite

Orders go in a new database, `channel-orders.sqlite3`, in the provider data directory. It uses `rusqlite`, which is already in the tree, bundled. The store has:

- versioned migrations, applied at startup, that refuse to open a newer schema;
- unique constraints on each of these:
  - (owner, provider, network, idempotency key)
  - order id
  - quote id
  - payment address
  - funding attempt id
  - pending channel id
  - channel point
  - refund id
- every state change written in one transaction with the event that caused it, under a per-order version that only rises;
- chain observations (payment outputs, confirmations, funding and refund transactions) in their own tables, so a reorg rewrites observations, never business state;
- a recovery cursor per worker, and worker ownership leases, so two workers never drive the same order.

Why: one JSON file per record can't enforce uniqueness across orders or change several records atomically, and #84 requires both. A lock held only in memory doesn't survive a restart.

Consequences:

- Backup export and restore must include the database.
- The Umbrel volume must persist it.
- A restore must reconcile with the chain and LND before any new spending.

### D6. Ownership and node proof

- **Owner.** An order belongs to the authenticated Pubky: the root key over `direct/1`, or the account plus its delegated key over `session/2`. Status, list, cancel and any change of refund address require that same owner.
- **Session scope.** The authorization document of a scoped session names the channel-purchase scope, so a swap authorization can neither create nor read orders.
- **Node proof.** The buyer proves its Lightning node with LDK Node's `sign_message`, which produces the zbase32 "Lightning Signed Message" format.
  - The signed challenge binds these:
    - the domain `pubky-swap/channel-node-proof/v1`
    - the owner, the provider and the network
    - the node id
    - the quote id
    - an expiry
  - The provider recovers the key from the signature itself and compares it with the claimed node id.
  - It does not use the `valid` flag of lnrpc `VerifyMessage`. That flag is only true for nodes already in the public graph, and a first-channel buyer is not.
- **Connection direction.** The buyer's node connects out to the provider's node. Bitkit accepts no inbound connections, and LDK Node rc.78 has no Tor or SOCKS support. So `channel.info` must list a clearnet address the buyer can reach (D14).

### D7. Funding flow (LND PSBT)

An order has at most one funding attempt in flight. LND's own publish step is used, not `no_publish`. LND persists the pending channel first, broadcasts only after the buyer's `funding_signed` arrives, and rebroadcasts after a restart ([psbt.md](https://github.com/lightningnetwork/lnd/blob/f8832ca776501c068195bf3865d45e643076bfad/docs/psbt.md)).

Each attempt goes through these steps:

1. **Persist the attempt:** its id, `pending_chan_id` = SHA256(`pubky-swap/channel-funding/v1` ‖ attempt id), the fee rate, and the provider and client amounts.
2. **Call `OpenChannel`** with:
   - `funding_shim.psbt_shim { pending_chan_id }`;
   - `private: true`;
   - `memo` set to the order id;
   - `push_sat` set to the client balance.
3. **On `psbt_fund`, call `FundPsbt`** to its address and amount, with:
   - `custom_lock_id` set to the channel-sales lock id (D8);
   - a `lock_expiration_seconds` that covers the flow.

   Persist the funded PSBT and the leased inputs.
4. **Call `psbt_verify`.** Nothing is broadcast.
5. **Sign with `FinalizePsbt`.** Every input is SegWit, so the txid is already fixed. Persist the signed transaction and its channel point, then never modify it.
6. **Call `psbt_finalize`** with that transaction. This is the first call after which LND may broadcast, so step 5 must be durable first.
7. **On `chan_pending`**, record that the funding is published.
8. **Mark the channel ready** only after checking the peer, outpoint, capacity, balances, private flag, and that it reached the agreed depth.

Recovery starts from the persisted channel point and signed transaction:

- **LND reports a pending or open channel at that point:** continue watching it.
- **LND has no channel there:** if the transaction is in no mempool and not on chain, the attempt died before `funding_signed`. LND keeps PSBT flows only in memory, so an LND restart kills them too.
  - Release the leases.
  - Check every input is unspent.
  - Start a fresh attempt for the same order.
- **LND has no channel there, but the transaction is in a mempool or on chain:** that means LND lost state. Stop the order and flag it for operator recovery. Never fund it again.
- **Never broadcast the signed transaction yourself** while LND has no pending channel for it. Its output would be a 2-of-2 with no commitment transaction to recover the funds.
- **Finish `psbt_fund` to `psbt_finalize` quickly:** within the funding flow's timeout, which is 10 minutes against an LND peer.
- **A timed-out RPC never proves that nothing was funded.**
- **The `memo` is for operators.** It is visible only once LND persists the channel, and it is not the correlation key.

### D8. Reservations and liquidity

Swaps and channel sales share one ledger. Sellable liquidity is the confirmed wallet balance minus:

- the exposure of swaps in flight;
- inputs leased to pending channel funding;
- refunds owed;
- a fee reserve;
- LND's own anchor reserve.

Each subsystem leases inputs under its own LND lock id. Leases survive LND restarts, and leased outputs are excluded from LND's coin selection, so a swap's `SendOutputs` can't spend coins leased to a channel funding.

A customer payment is a liability until it is delivered as a channel or refunded. It never counts as provider capital.

The two share liquidity and coins, not limits. The swap exposure caps in `risk.rs` (by default 5M sat in total and 1M sat per peer) bound swap risk only. They never cap a channel sale (D9).

Today's provider keeps this accounting in memory, and with `--wallet lnd` it checks no wallet balance at all before funding a reverse swap ([#108](https://github.com/coreyphillips/pubky-swap/issues/108)). The shared ledger replaces both behaviours.

### D9. Limits

There is no product cap and no inherited swap cap. A quote names whichever limit binds:

| Limit | Source |
| --- | --- |
| 16,777,215 sat of total channel value | The buyer: LDK's `max_funding_satoshis` default ([config.rs](https://docs.rs/lightning/0.2.7/src/lightning/util/config.rs.html#303-309)), which LDK Node does not expose. Larger channels need an LDK Node change and large-channel support on LND. |
| 20,000 sat minimum channel | LND's floor for an outbound channel. |
| Large channels off | LND's `protocol.wumbo-channels` defaults to off, and Umbrel leaves it off. Raising the 16,777,215 sat ceiling needs it on, as well as the buyer change above. |
| At most 4 unfunded channels per peer | LDK. An LND buyer's `maxpendingchannels` (default 1) would allow one unconfirmed channel at a time. |
| Available liquidity | D8. |
| Operator limits | Optional, and unset by default. |
| Economics | The smallest order whose fees cover the provider's on-chain cost, as `effective_min_amount_sat()` does for swaps. |

Amounts are integer satoshis with checked arithmetic. Nothing is ever clamped silently.

### D10. API

The methods are `channel.info.v1`, `channel.quote.v1`, `channel.create.v1`, `channel.status.v1`, `channel.list.v1` and `channel.cancel.v1`. `channel.events.v1` waits for Phase 5, and may use LSPS5's vocabulary.

- **`info`** returns LSPS1 `get_info`, plus:
  - provider and node identity;
  - clearnet connection strings;
  - the network;
  - supported payment options (on chain only, for now);
  - the confirmation policy;
  - the binding limits.
- **`quote`** is immutable and expiring, with an id and a digest. It itemises:
  - client and provider balance;
  - service fee and funding fee;
  - payment confirmations and channel depth;
  - expiry and refund terms.

  It reserves nothing, so `liquidity_unavailable` can still answer `create`, as with swaps.
- **`create`** takes:
  - the quote id and digest;
  - an idempotency key, generated by the client and persisted before sending;
  - the node proof;
  - the approved maximum charge;
  - a refund address, validated for the network.

  It persists the order before returning a unique payment address. An identical retry returns the same order. The same key with a different digest is refused.
- **`status` and `list`** are scoped to the owner. `list` pages with opaque cursors, and an old order resolves against its recorded provider and network.
- **`cancel`** works only before any payment is seen. A transport timeout is never a cancellation.

Errors carry these typed codes:

- `unsupported_network`
- `unsupported_feature`
- `quote_expired`
- `terms_changed`
- `liquidity_unavailable`
- `wrong_owner`
- `idempotency_conflict`
- `peer_unavailable`
- `node_proof_invalid`
- `payment_mismatch`
- `recovery_pending`
- `refund_action_required`
- `rate_limited`
- `access_denied`
- `internal_error`

### D11. State model

Each order keeps separate purchase, payment, funding, channel and refund state, as #84 sets out. LSPS1's `order_state` (`CREATED`, `COMPLETED`, `FAILED`) and its on-chain payment states are derived from these. They never replace them.

- Only an unpaid order with no liability can expire or be cancelled.
- An order is complete once its channel is verified as usable, or once its refund is fully accounted for.

### D12. Refunds

Refunds go on chain, to the address given at `create`. They follow LSPS1's terms: the order total minus the refund transaction's fee, with a fee bump after 6 hours. The quote states these terms before the buyer pays.

- Persist the refund intent, its inputs and the signed transaction before broadcasting.
- Replace a refund only by RBF, under the same refund id.
- Never send a fresh payment after a timeout.
- An amount too small to refund economically stays a visible obligation.

### D13. Trust

- **No automatic trust.** Bitkit never adds a scanned provider to `trusted_peers_0conf` or `trusted_peers_no_reserve`. This release requests neither zero-conf nor zero-reserve channels.
- **LSPS2 trust modes.** Before Phase 5, a separate decision sets the JIT trust policy: which LSPS2 trust mode, who broadcasts when, and what the user sees.
- **Not through LDK Node's LSPS2 client as it stands.** It auto-trusts the LSP and accepts underpaying HTLCs from it.

### D14. Feasibility gate

Sales stay disabled on a network until `--doctor` passes every check:

- LND is at least 0.19.0-beta.
- The wallet is synced.
- Leases work under the channel-sales lock id.
- Large-channel support is reported.
- A clearnet address is advertised and reachable.
- A regtest or signet purchase has completed against the supported LDK Node version.
- Recovery state is clean.

Lightning reachability is reported separately from Pubky transport availability.

## Supported versions

| Component | Version |
| --- | --- |
| LND | 0.19.0-beta or later, where `FundPsbt` gained `custom_lock_id` and `lock_expiration_seconds` (older LND ignores them silently). Tested against 0.21.6-beta, which Umbrel's lightning app ships. The regtest compose still pins 0.18.5-beta and must move. |
| fedimint-tonic-lnd | 0.4.0 |
| LDK Node (Bitkit) | 0.7.0-rc.78, lightning 0.2.7 |
| Networks | Bitcoin mainnet and regtest |

## Phase 1 exit tests

- **Real-node regtest:** an LND provider and an LDK Node buyer (bitkit-docker), covering:
  - a first channel bought from savings;
  - a second channel;
  - an oversize request, refused before payment;
  - an announced request, refused;
  - a Tor-only provider, refused by the gate.
- **Crash injection** before and after each of these points, for both the provider and LND:
  - writing the attempt;
  - `OpenChannel`;
  - `FundPsbt`;
  - `FinalizePsbt`;
  - persisting the signed transaction;
  - `psbt_finalize`;
  - `chan_pending`;
  - observing the confirmation.

  Every run must end with exactly one funding or exactly one refund. No signed funding transaction may ever be published without a pending channel.
- **Concurrency:**
  - Two creates with the same key produce one order.
  - A changed body is refused.
  - A swap and a channel sale never select the same input.
- **Payment variants:** partial, multiple, late, excess and reorged payments all keep every satoshi assigned.

## Open questions for the feasibility spike

- **The buyer's funding timeout.** How long LDK Node waits, as the receiving side, for a PSBT-funded open to complete. The 10-minute figure is LND's.
- **Clearnet reachability.** Whether Umbrel's LND advertises a clearnet address by default, or only Tor. If it is Tor-only, an operator must enable clearnet before D14 can pass.
- **The 6-confirmation depth.** Whether it is acceptable for the first channel, or Bitkit's fork should expose and lower `minimum_depth` for chosen providers. Lowering it is a trust decision, not a default.
- **LND's sweeper.** Whether it can pull leased channel-sales coins into a `BumpFee` for a swap claim or refund. Leases should exclude them, and the spike confirms it.

## References

- [#84](https://github.com/coreyphillips/pubky-swap/issues/84), and [Paykit Capabilities §13.5](https://github.com/BitcoinErrorLog/paykit-server/blob/575c5c7/docs/paykit-capabilities.md#135-liquidity1-channel-purchase-and-jit-liquidity-sketch).
- The bLIPs at the revisions in D2.
- LND protos as vendored by `fedimint-tonic-lnd` 0.4.0, and LND's [PSBT funding guide](https://github.com/lightningnetwork/lnd/blob/f8832ca776501c068195bf3865d45e643076bfad/docs/psbt.md) at `f8832ca`.
