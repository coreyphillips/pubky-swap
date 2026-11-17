# Swaps on the Pubky Switch

Status: draft for discussion on [pubky/paykit-rs#302](https://github.com/pubky/paykit-rs/issues/302), 17 Nov 2026. Nothing here is implemented.

This proposes swaps as their own protocol on the Pubky Switch, as ben-kaufman suggested on #302, instead of Paykit extension kinds (`paykit-cap.*`, Paykit Capabilities §13.1). The protocol owns discovery, quotes, commitments, contracts, status, claims, refunds and restore. Paykit defines only how a payment uses a swap (Section 9). It builds on the Switch at [`f0bbddd`](https://github.com/pubky/pubky-switch/tree/f0bbddd15c7ecb1ec670f263f36dd4f2373dba8f), the baseline Paykit v0.2 pins, and cites it as "Switch §N" (spec) and "Switch wire N" (wire format).

The comparison with the extension approach is on [#302](https://github.com/pubky/paykit-rs/issues/302#issuecomment-6954882363). In short: v0.2 extension kinds may carry no destination and no payment semantics (Paykit v0.2 §3.3), while a commit carries an invoice and a contract carries a hold invoice and lockup terms; and unread extension messages sit in a bounded pool from which an evicted one may be lost, which a contract or a status message can't afford.

## Context

What pubky-swap does today, at `main` (`93b9cb0`):

- **Carrier.** iroh `direct/1`: one reply per request the client opens. Two wires share it: the native `SwapMessage` (which bitkit-core#182 speaks, at swap-common `f45e204`) and the §13.1 `paykit-cap.*` kinds (`swap_common::paykit_cap::v1`, [CLIENT_ADAPTERS.md](CLIENT_ADAPTERS.md#the-capabilities-131-wire)).
- **Agreement.** Three chained hashes, `terms_hash`, `commit_hash` and `contract_hash`, over JCS objects. The provider signs the quote and the contract. The contract is stored with the swap and returned on replay and `status_request`.
- **Status.** Only in reply on `direct/1`. Terminal states also go over Homeserver DMs (`notify_terminal_peer`), and a reverse swap's "claimable" hint wakes the owner through a wake grant the owner sent (#117, topic `swap.claimable` on synonymdev/wake). Pushing every state change (#141) has no route to the owner.
- **Discovery.** A signed Capability Descriptor on the provider's Homeserver (`/pub/paykit/ext/capabilities/v1/apps/pubky-swap.json`), signed with the capability signing key that `--paykit-setup` delegates (#126, #129).
- **Restore.** The owner lists its swaps at each provider (`SwapListRequest`, #113) and re-derives each swap's secrets from its `owner_ref`.

What the Switch gives a protocol (Switch §1): scopes and the switch permissions each needs, message kinds, collections of shared records with fixed policies, claims, and signed formats under its own labels. Everything else is the Switch's: identities, app certificates and records, sealed and signed messages up to 64 KiB (Switch §5.1), admission, the feed, push (Switch §9), backups and restore.

## Decisions (proposed)

| | Decision |
| --- | --- |
| S1 | The protocol is named `swap`. Its kinds are `swap.<name>` and its app record member is `protocols.swap`. It is not specific to Pubky Swaps: any provider that settles by hash, such as an Orchestra or Arkade swap service, can speak it. |
| S2 | Two scopes: `swap` for owners (wallets) and `swap_provide` for providers. |
| S3 | Offer, RFQ and quote stay on the provider's direct channel, which is fast and creates no state. Every message that creates or changes a swap travels over the Switch. The quote carries a one-use invite code to the provider's switch, so only an owner who got a quote can write to the provider. |
| S4 | The §13.1 objects carry over unchanged, signed under this protocol's labels: `swap/terms/v1`, `swap/commit/v1`, `swap/contract/v1`. |
| S5 | The owner keeps each swap in a `swaps` collection on its own switch, so another own app or a restore reads it there. The provider keeps its state in its own store, as today. |
| S6 | The provider sends `swap.status` on every state change, with the Switch's `notify` flag when the owner has to act. This replaces the wake grant and the Homeserver DM. |
| S7 | Paykit links a payment attempt to a swap. The payee sees an ordinary on-chain or Lightning payment and needs nothing swap-specific (Section 9). |
| S8 | During the transition the provider answers today's `direct/1` wires and this protocol. Bitkit moves from today's wire straight to this one, skipping the §13.1 wire. |

## 1. Terms

| Term | Meaning |
| --- | --- |
| **Owner** | The identity whose wallet starts the swap and receives its result. One of its apps holds `swap`. |
| **Provider** | The identity that quotes and funds swaps. Its app holds `swap_provide`. A provider daemon is a separate identity from any wallet. |
| **Reverse swap** | The owner pays Lightning (a hold invoice) and receives on chain: the provider locks coins the owner claims with the preimage. |
| **Submarine swap** | The owner pays on chain (a lockup) and receives Lightning: the provider pays the owner's invoice and claims the lockup with its preimage. |
| **Lockup** | The on-chain HTLC output, P2WSH or Taproot (`lock_profile`), claimable with the preimage or refundable after `timeout_block_height`. |
| **Direct channel** | The provider's low-latency request/reply channel, named in its offer. iroh `direct/1` today. |

## 2. Scopes and switch permissions

| Scope | Held by | Sends | Receives | Switch permissions | Shared Data Key |
| --- | --- | --- | --- | --- | --- |
| `swap` | Owner apps | `swap.commit`, `swap.status_request`, `swap.list_request` | `swap.contract`, `swap.status`, `swap.list`, `swap.refusal` | `claims.read`, `claims.write` | Yes, for the `swaps` collection |
| `swap_provide` | Provider apps | `swap.contract`, `swap.status`, `swap.list`, `swap.refusal` | `swap.commit`, `swap.status_request`, `swap.list_request` | `conversation.add` | No |

- `conversation.add` lets the provider register invite codes (`invite_code.put`, Switch §7).
- The owner needs no `conversation.add` of its own for this protocol: its first write to the provider adds the provider to its allowlist (Switch §7, "Writing to someone admits them for good"). An app that also holds Paykit scopes has it anyway.
- `claims.*` lets an owner's apps agree which one drives a swap's claim or refund (Section 5).
- A wallet holds `swap` next to its Paykit scopes in one certificate under one App ID (Switch §3.2, "Several protocols in one certificate").

## 3. Discovery: the provider's app record

The provider publishes its offer in its app record (Switch §4.2), on its switch and on its Homeserver, so a wallet reads it without being admitted. The record is signed by the provider app's signing key, which its certificate ties to the provider identity. This replaces both the Capability Descriptor's own signature and the `paykit-cap/subkey/v1` delegation.

```json
"accepts": ["swap.commit", "swap.status_request", "swap.list_request"],
"protocols": { "swap": {
  "v": 1,
  "network": "bitcoin",
  "contact": { "direct": "iroh:pubky-swap/direct/1" },
  "offer": {
    "offer_id": "<uuid>",
    "valid_until": 1795000000,
    "htlc_timeout_blocks": 144,
    "required_confirmations": 2,
    "edges": [ {
      "from": "btc-lightning-bolt11", "to": "btc-bitcoin-p2wpkh",
      "min": "25000", "max": "5000000",
      "fee": { "base": "0", "ppm": "5000", "onchain": "1500" },
      "fund_within_secs": 300,
      "lock_profiles": ["taproot_boltz", "p2wsh"],
      "atomicity": "hash" } ] },
  "features": ["swap-list-v1"] } }
```

- **Edges** are the descriptor's (CLIENT_ADAPTERS.md, "The swap/1 Capability Descriptor"): exact Payment Endpoint Identifiers, one edge per identifier, amounts as integer strings, and the fee formula `base + floor(a * ppm / 1e6) + onchain`.
- **Freshness.** Today the provider rebuilds its offer every `quote_ttl_secs / 2` with a new `offer_id`. Rewriting the app record that often is too much, so the record carries indicative terms with a validity of hours, and the RFQ's quote is binding. Open question 3.

## 4. Message kinds

Every message has the Switch's common fields (Switch §5.3): `v`, `kind`, `msg_id`, `created_at`, `from`, `to`, `refs` and `body`. A reply names the message it answers as the first entry of `refs` (the BLAKE3 of its JSON bytes), replacing §8.1's `rfq_event_id`, `quote_event_id` and `commit_event_id`. Amounts are integer strings (Switch wire 1.1). Times are integer Unix seconds.

| Kind | From to | Carrier | Body | Answers |
| --- | --- | --- | --- | --- |
| `swap.rfq` | Owner to provider | Direct | `offer_id`, `dir`, `from`, `to`, `amount_sat`, `atomicity_min`, `respond_by`, `valid_until` | |
| `swap.quote` | Provider to owner | Direct | §13.1 quote body, `atomicity`, `valid_until`, `sig` over `terms_hash`; outside the signed terms, `invite` | `swap.rfq` |
| `swap.commit` | Owner to provider | Switch | `terms_hash`, §13.1 commit body (`lock_profile`, `payment_hash`, `claim_pubkey` or `refund_pubkey` and `invoice`, optional `owner_ref`), the signed terms as `quote` | `swap.quote` |
| `swap.contract` | Provider to owner | Switch | `commit_hash`, §13.1 contract body, `sig` over `contract_hash`, `invoice_blob`, `lock` | `swap.commit` |
| `swap.status` | Provider to owner | Switch | `swap_id`, `state` (the leg status), `detail` (the `SwapState`), optional `reference` (a txid), optional `claimable` | `swap.commit` or `swap.status_request` |
| `swap.status_request` | Owner to provider | Switch | `swap_id` or `quote_id` | |
| `swap.list_request` | Owner to provider | Switch | optional `after` cursor | |
| `swap.list` | Provider to owner | Switch | the owner's swaps with `owner_ref`, as `SwapListResponse` | `swap.list_request` |
| `swap.refusal` | Provider to owner | Either | `code`, `reason` | Any request |

- **On the direct channel**, `swap.rfq` and `swap.quote` are the same JSON, signed by each side's app key as on the Switch but not sealed: the channel already authenticates both ends. So the commit can name the quote in `refs` whichever carrier brought it.
- **`invite`** is a code the provider registered for this quote at its switch with one use and an expiry at the quote's `valid_until` (Switch §7, "One per visit"). The owner presents it with its `swap.commit` append. It is a bearer secret, so it is not part of the signed terms and the owner never stores it past the commit.
- **No owner `sig`.** §13.1 has the owner sign `commit_hash` because `direct/1` could not authenticate the owner's app. On the Switch, the signed message frame binds the commit to the owner's app and identity, and the signed plaintext is the evidence. Open question 2.
- **`swap.contract`** is the §13.1 contract. The hold invoice stays in `invoice_blob`, so `contract_hash` is unchanged and a contract shown to a third party doesn't reveal the invoice.
- **Refusal codes** are those of CLIENT_ADAPTERS.md "Refusal codes", unchanged.
- **`state` and `detail`** are today's: the leg status `SwapState::leg_status` gives (`pending`, `in_transit`, `delivered`, `refunded`, `failed`, `delivery_failed`) and the provider's `SwapState` (CLIENT_ADAPTERS.md, "Paykit leg status"). `claimable: true` replaces the separate claimable hint: the provider sets it once a reverse lockup has `required_confirmations`.
- **Size.** Every message fits the 64 KiB envelope with room to spare. On `direct/1` today a commit carrying its signed quote is about 1,350 bytes and a signed contract 1,048 to 1,208 bytes (CLIENT_ADAPTERS.md). The 1,000-byte budget of #119 no longer applies.

## 5. State on the owner's switch

**Collection `swaps`.** Read scope `swap`, write scopes `[swap]`. Natural key: the `quote_id` until the contract arrives, then the `swap_id`. Value:

```json
{ "v": 1, "provider": "<pubky id>", "dir": "reverse",
  "quote": "<signed swap.quote JSON>", "commit": "<signed swap.commit JSON>",
  "contract": "<signed swap.contract JSON>",
  "state": "in_transit", "owner_ref": "bitkit-swap-v4:<58 chars>",
  "observed": { "funding_txid": "<hex>", "claim_txid": "<hex>" },
  "paykit": { "attempt_id": "<16 bytes hex>" } }
```

- **Written before sending.** The owner writes the record with the commit before it appends `swap.commit`, as it persists the `SwapRequest` today (CLIENT_ADAPTERS.md, "Durable creation and recovery").
- **No secrets.** Preimages and per-commit keys never enter a record or a message. They derive from the wallet seed and `owner_ref`, so only the wallet that made the swap can claim or refund it.
- **One driver.** Before it broadcasts a claim or refund, an app takes the swap's Switch claim (Switch §10.2), keyed by the `swap_id` and blinded with the naming key, so two devices of one identity never bid against each other's claims.

## 6. Flows

### 6.1 Reverse (owner pays Lightning, receives on chain)

1. The owner reads the provider's app record and picks an edge.
2. Over the direct channel: `swap.rfq`, then `swap.quote` with `invite`. Quotes last 300 s.
3. The owner writes its `swaps` record and appends `swap.commit` to the provider's inbox with the code. The append admits it at the provider's switch, and the write adds the provider to the owner's allowlist.
4. The provider creates the hold invoice and appends `swap.contract` to the owner's inbox.
5. The owner checks the hash chain, the provider's signature and the lockup it derives, records the contract and pays the hold invoice.
6. Within `fund_within_secs` of accepting the payment, the provider funds the lockup and sends `swap.status` (`in_transit`, `LockupConfirmed`, the funding txid in `reference`). When the lockup reaches `required_confirmations` it sends `swap.status` again with `claimable: true` and `notify`.
7. The owner claims. The provider sees the preimage, settles the hold invoice and sends `swap.status` (`delivered`, `Claimed`) with `notify` once it sees the claim.

The failure paths are today's. While the Lightning payment is unsettled, the owner stops claiming `CLAIM_ABORT_MARGIN` (6) blocks before the timeout, and the hold invoice fails back. Once the payment has settled, the owner's claim outbids an unconfirmed refund and stops only on a confirmed one (#136). An owner who never claims has its payment held for up to 216 blocks.

### 6.2 Submarine (owner pays on chain, receives Lightning)

Steps 1 to 4 are the same, with `refund_pubkey` and `invoice` in the commit. The owner funds the lockup. Once it has `required_confirmations`, the provider pays the invoice within `fund_within_secs` and sends `swap.status` (`delivered`, `InvoicePaid`) with `notify`, then claims the lockup with the preimage. If the invoice is never paid, the owner refunds after `timeout_block_height` (144 blocks by default).

## 7. Status, wakes and retention

- **Every state change** goes to the owner's inbox as `swap.status`, which closes #141.
- **`notify`** is set only when the owner has to act or learn an outcome: `claimable` on a reverse swap, `delivered`, and the terminal states. The Switch rate-limits notifying writes per sender (Switch §5.1), and at most two per swap stay well inside it. This replaces the wake grant and the `swap.claimable` topic for swaps on this protocol.
- **Retention.** Inbox entries stay until every current target's cursor has passed them (Switch §6.3). The provider keeps a swap's acceptance and outcome for 30 days after it ends, as today.

## 8. Restore from the seed

- The owner's `swaps` collection survives a lost device with the identity's other shared records (Switch §12.4). A restored wallet reads it, re-derives each swap's secrets from its `owner_ref`, and resumes the claim or refund.
- A swap whose record write never committed is found through `swap.list_request` to the providers the wallet used, as `SwapListRequest` works today.

## 9. Paying with a swap (the Paykit side)

This section lists what Paykit has to specify. The rules belong in Paykit's spec, next to its paying order (Paykit v0.2 §7).

- **Attempt first.** The payer writes Paykit's `attempt` (Paykit v0.2 §7.2 step 1) before `swap.commit`. Its `orphan_after` covers the swap's longest path: for a reverse swap, until the hold invoice can no longer settle (up to 216 blocks, about 36 hours); for a submarine swap, until the refund timeout plus a claim window.
- **Dispatch.** Money moves when the owner pays the hold invoice (reverse) or broadcasts the lockup (submarine), not at the commit. The dispatch window of Paykit v0.2 §7.2 applies to that step.
- **Amount check.** The payment method reports the amount delivered to the payee's endpoint and the largest fee: the quote's service and on-chain fees plus the owner's claim fee budget.
- **Completion evidence.** A reverse swap paying an on-chain endpoint completes when the claim paying that endpoint confirms. The proof is an ordinary on-chain proof. A submarine swap paying a Lightning invoice completes on the invoice's preimage, which the provider's claim reveals. In both cases the payee verifies the payment as any other.
- **Funding is not payment.** A paid hold invoice or a confirmed lockup leaves the attempt open.
- **Failure.** A swap that ends without paying the payee marks the attempt `failed`. If the hold invoice settled and the provider's refund still won (#137), the attempt is `failed` and the wallet records the loss.
- **Recovery.** The `swaps` record names the attempt, and the payer's Paykit record names the `swap_id` and provider, so a restore finds both.
- **Duplicate protection.** The open attempt keeps other own apps from paying the same obligation, and Paykit v0.2 §7.1's `possibly_duplicate` rule applies once it is orphaned.

## 10. Security and privacy

- **Admission.** A provider's switch admits only owners holding a code from a quote it issued. Each code has one use and expires with its quote. Both switches rate-limit each sender (Switch §7).
- **Signatures.** The provider signs quotes and contracts with its app's signing key, and a verifier takes that key from the provider's certificate. A key change is an app certificate renewal (Switch §3.2), so the §13.1 `key_generation` members go.
- **Operators.** The provider's switch operator learns which identities commit to swaps with it, through conversation entries and invite use. The owner's operator learns that the owner corresponds with the provider. Contents are sealed. An invite code's `context` holds no personal data (Switch §7).
- **Replay.** The Switch deduplicates by (sender, `msg_id`). A commit replayed with the same `terms_hash` gets its stored contract, as today.

## 11. Transition

- The provider answers the native `SwapMessage` and the §13.1 kinds over `direct/1`, plus this protocol, until Bitkit has moved.
- Bitkit moves from today's wire to this one once a Switch client SDK is usable. Moving bitkit-core to the §13.1 wire first is skipped.
- Retired once no client uses them: terminal status over Homeserver DMs, the wake grant for `swap.claimable`, the Capability Descriptor under `/pub/paykit/ext/`, the `paykit-cap/subkey/v1` delegation, and #119.

## 12. Open questions

1. **First contact.** The Switch admits no unsolicited first contact in v0.2 (Switch §19, decision 1), and its open mode is left for later (Switch §17). This draft keeps the RFQ and quote on the provider's direct channel and hands the owner a one-use invite in the quote. The alternative is connect requests that the provider accepts automatically (Switch §7), but those carry no content and are limited to 60 a minute per account by default, so the first quote would be slower. Does the Switch team expect a path for public services in v0.2?
2. **Owner signature.** This draft drops the owner's `sig` over `commit_hash` because the Switch message signs the commit. Keep it if a third party must verify a commit without the Switch's message format.
3. **Offer freshness.** Indicative terms in the app record and binding quotes over the direct channel, or the record rewritten with every offer?
4. **Exact amount under fee bumps.** bitkit-core sizes a reverse lockup as the amount plus one claim fee at the quoted rate, so bumping the claim fee lowers what the payee receives. A Paykit payment needs the payee's output exact: a claim with a change output, or a fee budget a bump can't exceed.
5. **Where the Paykit rules live.** A section of Paykit's v0.2 spec, owned by the Paykit team, that this document links to.
6. **`liquidity/1`.** Channel purchases (#84) fit the same pattern: their own protocol with the same first contact and status rules, or more kinds in this one.
7. **Name.** `swap` takes the `swap` root for one protocol (Switch §3.3). That suits a protocol any hash-settled swap provider can speak (S1), but it should be agreed before anything ships.
