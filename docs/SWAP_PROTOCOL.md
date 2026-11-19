# Swaps on the Pubky Switch

Status: second draft for discussion on [pubky/paykit-rs#302](https://github.com/pubky/paykit-rs/issues/302), 18 Nov 2026. Nothing here is implemented. This revision takes in ben-kaufman's review of the first draft ([#302](https://github.com/pubky/paykit-rs/issues/302#issuecomment-6958322694)): quotes over HTTPS, `conversation.add` for owners, the payee's exact amount under fee bumps, the preimage of a submarine swap, and the two recovery cases of Section 9.

This proposes swaps as their own protocol on the Pubky Switch, as ben-kaufman suggested on #302, instead of Paykit extension kinds (`paykit-cap.*`, Paykit Capabilities §13.1). The protocol owns discovery, quotes, commitments, contracts, status, claims, refunds and restore, and its spec lives in this repo. How a swap fulfills a Paykit payment request belongs to the Paykit team, in Paykit's spec; Section 10 lists what that needs from this protocol. It builds on the Switch at [`f0bbddd`](https://github.com/pubky/pubky-switch/tree/f0bbddd15c7ecb1ec670f263f36dd4f2373dba8f), the baseline Paykit v0.2 pins, and cites it as "Switch §N" (spec) and "Switch wire N" (wire format).

The comparison with the extension approach is on [#302](https://github.com/pubky/paykit-rs/issues/302#issuecomment-6954882363). In short: v0.2 extension kinds may carry no destination and no payment semantics (Paykit v0.2 §3.3), while a commit carries an invoice and a contract carries a hold invoice and lockup terms; and unread extension messages sit in a bounded pool from which an evicted one may be lost, which a contract or a status message can't afford.

## Context

What pubky-swap does today, at `main` (`93b9cb0`):

- **Carrier.** iroh `direct/1`: one reply per request the client opens. Two wires share it: the native `SwapMessage` (which bitkit-core#182 speaks, at swap-common `f45e204`) and the §13.1 `paykit-cap.*` kinds (`swap_common::paykit_cap::v1`, [CLIENT_ADAPTERS.md](CLIENT_ADAPTERS.md#the-capabilities-131-wire)).
- **Agreement.** Three chained hashes, `terms_hash`, `commit_hash` and `contract_hash`, over JCS objects. `terms_hash` covers the owner's identity, so a quote signed for one owner doesn't verify for another. The provider signs the quote and the contract. The contract is stored with the swap, and an identical commit gets it back, also after a restart.
- **Status.** Only in reply on `direct/1`, and never with a preimage. Terminal states also go over Homeserver DMs (`notify_terminal_peer`), and a reverse swap's "claimable" hint wakes the owner through a wake grant the owner sent (#117, topic `swap.claimable` on synonymdev/wake). Pushing every state change (#141) has no route to the owner.
- **Discovery.** A signed Capability Descriptor on the provider's Homeserver (`/pub/paykit/ext/capabilities/v1/apps/pubky-swap.json`), signed with the capability signing key that `--paykit-setup` delegates (#126, #129).
- **Restore.** The owner lists its swaps at each provider (`SwapListRequest`, #113) and re-derives each swap's secrets from its `owner_ref`. Only reverse swaps are rebuilt this way: a submarine refund needs the owner's invoice, which the listing doesn't carry.

What the Switch gives a protocol (Switch §1): scopes and the switch permissions each needs, message kinds, collections of shared records with fixed policies, claims, and signed formats under its own labels. Everything else is the Switch's: identities, app certificates and records, sealed and signed messages up to 64 KiB (Switch §5.1), admission, the feed, push (Switch §9), backups and restore.

## Decisions (proposed)

| | Decision |
| --- | --- |
| S1 | The protocol is named `swap`. Its kinds are `swap.<name>` and its app record member is `protocols.swap`. It is not specific to Pubky Swaps: any provider that settles by hash, such as an Orchestra or Arkade swap service, can speak it. |
| S2 | Two scopes: `swap` for owners (wallets) and `swap_provide` for providers. |
| S3 | Quotes come from the provider's quote endpoint, HTTPS by default, named in its signed app record. A wallet compares providers there and uses the Switch only with the one the user picks. On first contact the quote carries a one-use invite code to the provider's switch. Every message that creates or changes a swap travels over the Switch. |
| S4 | The §13.1 objects carry over unchanged, signed under this protocol's labels: `swap/terms/v1`, `swap/commit/v1`, `swap/contract/v1`. The signed terms already name the owner they are for. |
| S5 | Public prices are optional and indicative. The signed quote sets the terms. |
| S6 | The owner keeps each swap in its own store and in a `swaps` collection on its own switch, keyed by the quote's `quote_id`, both written before the commit is sent. The provider keeps its state in its own store, as today. |
| S7 | The provider sends `swap.status` on every state change, with the Switch's `notify` flag when the owner has to act. For a submarine swap it carries the preimage once the invoice is paid. This replaces the wake grant and the Homeserver DM. |
| S8 | The Paykit team specifies paying with a swap, in Paykit's spec. The payee sees an ordinary on-chain or Lightning payment and needs nothing swap-specific (Section 10). |
| S9 | Bitkit moves from today's wire straight to this one, skipping the §13.1 wire. Swaps already funded on today's wire finish or refund there (Section 12). |
| S10 | `liquidity/1` (#84) stays a separate protocol for now. |

## 1. Terms

| Term | Meaning |
| --- | --- |
| **Owner** | The identity whose wallet starts the swap and receives its result. One of its apps holds `swap`. |
| **Provider** | The identity that quotes and funds swaps. Its app holds `swap_provide`. A provider daemon is a separate identity from any wallet. |
| **Reverse swap** | The owner pays Lightning (a hold invoice) and receives on chain: the provider locks coins the owner claims with the preimage. |
| **Submarine swap** | The owner pays on chain (a lockup) and receives Lightning: the provider pays the owner's invoice and claims the lockup with its preimage. |
| **Lockup** | The on-chain HTLC output, P2WSH or Taproot (`lock_profile`), claimable with the preimage or refundable after `timeout_block_height`. |
| **Quote endpoint** | The provider's request/reply endpoint for quotes, named in its app record: HTTPS, or iroh `direct/1` (Section 4). |

## 2. Scopes and switch permissions

| Scope | Held by | Sends | Receives | Switch permissions | Shared Data Key |
| --- | --- | --- | --- | --- | --- |
| `swap` | Owner apps | `swap.commit`, `swap.status_request`, `swap.list_request` | `swap.contract`, `swap.status`, `swap.list`, `swap.refusal` | `conversation.add`, `claims.read`, `claims.write` | Yes, for the `swaps` collection |
| `swap_provide` | Provider apps | `swap.contract`, `swap.status`, `swap.list`, `swap.refusal` | `swap.commit`, `swap.status_request`, `swap.list_request` | `conversation.add` | No |

- **The owner needs `conversation.add`.** Its first write to the provider adds a conversation entry for the provider to its own allowlist, so the provider's `swap.contract` and `swap.status` are admitted, and both sides need the permission for that (Switch §7, Conversation entries). A wallet that also holds Paykit scopes has it anyway, which would hide its absence, so first contact is tested with a wallet that holds `swap` alone.
- **The provider's** `conversation.add` lets it register invite codes (`invite_code.put`, Switch §7).
- `claims.*` lets an owner's apps agree which one drives a swap's claim or refund (Section 6).
- A wallet holds `swap` next to its Paykit scopes in one certificate under one App ID (Switch §3.2, "Several protocols in one certificate").

## 3. Discovery: the provider's app record

The provider publishes its quote endpoint, and optionally indicative prices, in its app record (Switch §4.2), on its switch and on its Homeserver, so a wallet reads it without being admitted. The record is signed by the provider app's signing key, which its certificate ties to the provider identity. This replaces both the Capability Descriptor's own signature and the `paykit-cap/subkey/v1` delegation.

```json
"accepts": ["swap.commit", "swap.status_request", "swap.list_request"],
"protocols": { "swap": {
  "v": 1,
  "network": "bitcoin",
  "quote": { "https": "https://swap.example.com/swap/v1/quote" },
  "edges": [ {
    "from": "btc-lightning-bolt11", "to": "btc-bitcoin-p2wpkh",
    "min": "25000", "max": "5000000",
    "lock_profiles": ["taproot_boltz", "p2wsh"],
    "atomicity": "hash",
    "indicative": { "offer_id": "<uuid>", "base": "0", "ppm": "5000", "onchain": "1500" } } ],
  "features": ["swap-list-v1"] } }
```

- **`quote`** names one endpoint or both: `https`, a URL, and `iroh`, the provider's key on `direct/1` (Section 4).
- **Edges** are the descriptor's (CLIENT_ADAPTERS.md, "The swap/1 Capability Descriptor"): exact Payment Endpoint Identifiers, one edge per identifier, and amounts as integer strings. They say what the provider swaps, so a wallet asks only providers that can serve the payment.
- **`indicative`** is optional: a fee formula, `base + floor(a * ppm / 1e6) + onchain`, that lets a wallet rank providers before asking. It binds nothing, so the record changes when the provider's prices change, not with every quote. A provider that prices per request leaves it out. Timeouts, confirmations and funding windows are in the signed quote.

## 4. Quotes and first contact

The Switch admits no unsolicited first contact in v0.2 (Switch §19, decision 1), so the RFQ and quote go to the provider's quote endpoint, outside the Switch.

1. **Compare.** The wallet reads the app records of the providers it knows, picks those whose edges fit, and asks each for a quote. It writes nothing to any of them over the Switch.
2. **Ask.** `swap.rfq` goes to the quote endpoint: over HTTPS as a `POST` to the URL, over iroh as today. It names the `owner`, and is signed by the wallet's app key with its certificate attached, as a Switch message's plaintext is (Switch §5.2), but not sealed, since TLS or iroh protects the channel.
3. **Quote.** The provider answers `swap.quote`, signed. Its terms name the owner (`terms_hash` covers it), so the quote is no use to anyone else. On first contact, when its switch holds no conversation entry for that owner, the quote also carries an `invite`: a code registered for this quote, with one use and expiring at the quote's `valid_until` (Switch §7, "One per visit"). A later quote to an owner already admitted carries none.
4. **Commit.** The user picks one quote. The wallet appends `swap.commit` to that provider's inbox, presenting the code if it has one. The append admits the owner at the provider's switch, and the owner's own write adds the provider to its allowlist (Section 2). From here on the commit, the contract, status requests and updates all go over the Switch.

- **Who is asking.** The provider verifies the RFQ's signature and certificate whenever its price, limits or allowlist depend on who asks. A provider that prices the same for everyone may skip it, since only the owner the quote names can commit on it: the provider recomputes `terms_hash` with the commit's sender as owner, as it does today.
- **Rate limits.** The provider limits quotes per client address and per named owner, and live invites per owner, and registers a code only with a quote it issues. The Switch limits presentations of each code and appends of each admitted sender (Switch §7).
- **Why iroh too.** A provider on a home node, such as the Umbrel app, usually has no public HTTPS endpoint. iroh reaches it by its key, through NAT traversal and relays. Open question 1.

## 5. Message kinds

Every message has the Switch's common fields (Switch §5.3): `v`, `kind`, `msg_id`, `created_at`, `from`, `to`, `refs` and `body`. A reply names the message it answers as the first entry of `refs` (the BLAKE3 of its JSON bytes), replacing §8.1's `rfq_event_id`, `quote_event_id` and `commit_event_id`. Amounts are integer strings (Switch wire 1.1). Times in a body are integer Unix seconds.

| Kind | From to | Carrier | Body | Answers |
| --- | --- | --- | --- | --- |
| `swap.rfq` | Owner to provider | Quote endpoint | `owner`, `offer_id` (when the record has one), `dir`, `from`, `to`, `amount_sat`, `atomicity_min`, `respond_by`, `valid_until` | |
| `swap.quote` | Provider to owner | Quote endpoint | §13.1 quote body, `atomicity`, `valid_until`, `sig` over `terms_hash`; outside the signed terms, `invite` on first contact | `swap.rfq` |
| `swap.commit` | Owner to provider | Switch | `terms_hash`, §13.1 commit body (`lock_profile`, `payment_hash`, `claim_pubkey` or `refund_pubkey` and `invoice`, `owner_ref`), the signed terms as `quote` | `swap.quote` |
| `swap.contract` | Provider to owner | Switch | `commit_hash`, §13.1 contract body, `sig` over `contract_hash`, `invoice_blob`, `lock` | `swap.commit` |
| `swap.status` | Provider to owner | Switch | `quote_id`, `swap_id`, `state` (the leg status), `detail` (the `SwapState`), optional `reference` (a txid), optional `claimable`, optional `preimage` | `swap.commit` or `swap.status_request` |
| `swap.status_request` | Owner to provider | Switch | `quote_id` | |
| `swap.list_request` | Owner to provider | Switch | optional `after` cursor | |
| `swap.list` | Provider to owner | Switch | the owner's swaps with `owner_ref`, as `SwapListResponse` | `swap.list_request` |
| `swap.refusal` | Provider to owner | Either | `code`, `reason` | Any request |

- **On the quote endpoint**, `swap.rfq` and `swap.quote` are the same JSON as on the Switch, signed by each side's app key but not sealed. So the commit can name the quote in `refs` whichever carrier brought it.
- **`invite`** is a bearer secret, so it is not part of the signed terms and the owner never stores it past the commit.
- **No owner `sig`.** §13.1 has the owner sign `commit_hash` because `direct/1` could not authenticate the owner's app. On the Switch, the message signature binds the commit to the owner's app and identity. The wallet keeps that signed message, so the commit still verifies after a restore (Section 6).
- **`swap.contract`** is the §13.1 contract. The hold invoice stays in `invoice_blob`, so `contract_hash` is unchanged and a contract shown to a third party doesn't reveal the invoice.
- **`preimage`** appears only on a submarine swap, from `InvoicePaid` on. The provider learns it by paying the owner's invoice, and it gives the owner nothing against the provider: the lockup's claim branch also needs the provider's key. The owner checks it against the invoice's payment hash. A reverse swap's preimage is the owner's and never travels.
- **`owner_ref`** is required, so a restored wallet derives the swap's keys directly.
- **Refusal codes** are those of CLIENT_ADAPTERS.md "Refusal codes", unchanged.
- **`state` and `detail`** are today's: the leg status `SwapState::leg_status` gives (`pending`, `in_transit`, `delivered`, `refunded`, `failed`, `delivery_failed`) and the provider's `SwapState` (CLIENT_ADAPTERS.md, "Paykit leg status"). `claimable: true` replaces the separate claimable hint: the provider sets it once a reverse lockup has `required_confirmations`.
- **Size.** Every message fits the 64 KiB envelope with room to spare. On `direct/1` today a commit carrying its signed quote is about 1,350 bytes and a signed contract 1,048 to 1,208 bytes (CLIENT_ADAPTERS.md). The 1,000-byte budget of #119 no longer applies.

## 6. State on the owner's side

**Collection `swaps`** on the owner's switch. Read scope `swap`, write scopes `[swap]`. Key: the `quote_id`. One quote admits one swap, so it names the swap from before the commit to its end. Value:

```json
{ "v": 1, "provider": "<pubky id>", "dir": "reverse", "quote_id": "<uuid>",
  "quote": "<signed swap.quote>", "commit": "<signed swap.commit>",
  "contract": "<signed swap.contract>", "swap_id": "<uuid>",
  "lockup": { "address": "<bech32>", "script": "<hex>", "amount_sat": "250000", "timeout_block_height": 870144 },
  "state": "in_transit", "owner_ref": "bitkit-swap-v4:<58 chars>",
  "observed": { "funding_txid": "<hex>", "claim_txid": "<hex>" },
  "paykit": { "attempt_id": "<16 bytes hex>" } }
```

- **Written before sending.** The owner writes the record, with the quote and the commit, to its own store and to the `swaps` collection before it appends `swap.commit`, as it persists the `SwapRequest` today (CLIENT_ADAPTERS.md, "Durable creation and recovery"). It adds the contract and the lockup it derived and checked from it before it funds anything.
- **Signed messages kept whole.** Each message is kept as sent or received: its exact JSON bytes, the signature, and the sender's certificate (Switch §5.2). A restored wallet so still verifies the commit it sent and the provider's contract. This stands in for §13.1's owner signature.
- **No secrets.** Preimages and per-commit keys never enter a record or a message the owner sends. They derive from the wallet seed and `owner_ref`, so only the wallet that made the swap can claim or refund it.
- **One driver.** Before it broadcasts a claim or refund, an app takes the swap's Switch claim (Switch §10.2), keyed by the `quote_id` and blinded with the naming key, so two devices of one identity never bid against each other's claims.

## 7. Flows

### 7.1 Reverse (owner pays Lightning, receives on chain)

1. The owner reads the providers' app records, asks the fitting ones for quotes (Section 4), and the user picks one. Quotes last 300 s.
2. The owner writes its record and appends `swap.commit` to the provider's inbox, with the code on first contact.
3. The provider creates the hold invoice and appends `swap.contract` to the owner's inbox.
4. The owner checks the hash chain, the provider's signature and the lockup it derives, records the contract and the lockup, and pays the hold invoice.
5. Within `fund_within_secs` of accepting the payment, the provider funds the lockup and sends `swap.status` (`in_transit`, `LockupConfirmed`, the funding txid in `reference`). When the lockup reaches `required_confirmations` it sends `swap.status` again with `claimable: true` and `notify`.
6. The owner claims. The provider sees the preimage, settles the hold invoice and sends `swap.status` (`delivered`, `Claimed`) with `notify` once it sees the claim.

The failure paths are today's. While the Lightning payment is unsettled, the owner stops claiming `CLAIM_ABORT_MARGIN` (6) blocks before the timeout, and the hold invoice fails back. Once the payment has settled, the owner's claim outbids an unconfirmed refund and stops only on a confirmed one (#136). An owner who never claims has its payment held for up to 216 blocks.

**Exact amount under fee bumps.** When the claim pays someone else, such as a payee (Section 10), the payee's output must stay exact. The owner asks for a lockup of the payee's amount plus a claim fee budget, and its claim pays the payee's exact amount and returns the rest of the budget to the owner as change, above the dust limit. A fee bump lowers only the change. Past the budget, the owner bumps with a child that spends its change and adds its own coins. Today bitkit-core sizes a reverse lockup as the amount plus one claim fee at the quoted rate and claims to one output, so a bump lowers what the payee gets: that changes.

### 7.2 Submarine (owner pays on chain, receives Lightning)

Steps 1 to 3 are the same, with `refund_pubkey` and `invoice` in the commit. The owner records the contract and the lockup, then funds the lockup. Once it has `required_confirmations`, the provider pays the invoice within `fund_within_secs` and sends `swap.status` (`delivered`, `InvoicePaid`) with `preimage` and `notify`, then claims the lockup with the preimage. If the invoice is never paid, the owner refunds after `timeout_block_height` (144 blocks by default).

## 8. Status, wakes and retention

- **Every state change** goes to the owner's inbox as `swap.status`, which closes #141.
- **`notify`** is set only when the owner has to act or learn an outcome: `claimable` on a reverse swap, `delivered`, and the terminal states. The Switch rate-limits notifying writes per sender (Switch §5.1), and at most two per swap stay well inside it. This replaces the wake grant and the `swap.claimable` topic for swaps on this protocol.
- **Retention.** Inbox entries stay until every current target's cursor has passed them (Switch §6.3). The provider keeps a swap's contract and outcome, the preimage of a submarine swap included, for 30 days after it ends, as today, and answers `swap.status_request` from them.

## 9. Recovery

### 9.1 The provider accepts the commit, but the owner misses the reply

- **A stable reference before sending.** The `quote_id` and the exact commit are in the owner's record before the commit goes out (Section 6), and the commit carries `owner_ref`, so the provider files the swap under both.
- **First, the inbox.** The contract waits in the owner's inbox until its cursor passes it (Switch §6.3), so an app that crashed before reading it gets it on its next feed read.
- **Then ask.** If no contract or refusal comes within the time the owner allows, or a `missed` item may have covered it (Switch §8.2), the owner sends `swap.status_request` with the `quote_id`. The provider answers with the stored `swap.contract`, the first one stored for that commit, or a `swap.refusal`. Only `not_found` to that authenticated request shows that no swap exists; `pending` means the commit was admitted and its invoice is being recovered, and any other refusal settles nothing (CLIENT_ADAPTERS.md, "Durable creation and recovery").
- **Or send the commit again,** with the same body and a new `msg_id`: the Switch drops a second message with the same sender and `msg_id` (Switch §5.3). The provider answers an identical commit with the same contract, after a restart too, and refuses a changed one for a quote already accepted.
- **Never a second swap for the same payment** while the first may exist: the owner takes no new quote for it until a contract arrives or `not_found` shows there is none.
- **After a restore,** the `swaps` record or `swap.list_request` (matched by `owner_ref`) finds the swap.

### 9.2 The Switch is unreachable after funds are locked

Before it funds anything, the owner holds in its own store the signed quote, commit and contract, the `owner_ref`, and the lockup: script, address, amount and `timeout_block_height` (Section 6). The preimage and the keys derive from the seed. Claim and refund then need only the chain:

- **Reverse.** The owner watches the lockup address, claims with the preimage once the lockup has `required_confirmations`, and stops `CLAIM_ABORT_MARGIN` blocks before the timeout while its payment is unsettled. The provider settles its hold invoice from the preimage it sees on chain. Without the Switch the owner misses the `claimable` push, so it checks the chain whenever Bitkit runs.
- **Submarine.** The provider pays the invoice and claims on chain without the Switch, and its claim reveals the preimage, which is the owner's evidence (Section 10). With no claim by `timeout_block_height`, the owner refunds with its own key.

So no direct recovery call is needed: the Switch carries only status, which the chain also shows. The one case the wallet can't handle alone is a lost device while the Switch is unreachable, with its own store gone and the `swaps` record out of reach. A reverse swap then runs out: the provider refunds its lockup and the owner's Lightning payment fails back. A submarine refund has no deadline, since only the preimage lets the provider claim, so the wallet waits for the Switch or lists the swap at the provider. The `swaps` record also closes today's gap for submarine swaps: it holds the commit with the invoice, so a restore can rebuild the refund.

### 9.3 Restore from the seed

- The owner's `swaps` collection survives a lost device with the identity's other shared records (Switch §12.4). A restored wallet reads it, verifies the kept messages, re-derives each swap's secrets from its `owner_ref`, and resumes the claim or refund.
- A swap whose record write never committed is found through `swap.list_request` to the providers the wallet used, as `SwapListRequest` works today.

## 10. What paying with a swap needs (the Paykit side)

The rules belong to the Paykit team, in Paykit's spec next to its paying order (Paykit v0.2 §7). This protocol gives them:

- **Attempt first.** The payer writes Paykit's `attempt` (Paykit v0.2 §7.2 step 1) before `swap.commit`. The `swaps` record names the attempt, and the payer's Paykit record names the provider and the `quote_id`, so a restore finds both. The attempt's `orphan_after` covers the swap's longest path: for a reverse swap, until the hold invoice can no longer settle (up to 216 blocks, about 36 hours); for a submarine swap, until the refund timeout plus a claim window.
- **Dispatch.** Money moves when the owner pays the hold invoice (reverse) or broadcasts the lockup (submarine), not at the commit. The dispatch window of Paykit v0.2 §7.2 applies to that step.
- **Amount check.** The payee's amount is exact (Section 7.1). The largest fee is the quote's service and on-chain fees plus the owner's claim fee budget.
- **Completion evidence.** The payer marks the request paid when it verifies the confirmed claim output paying the payee's address and amount (reverse), or a preimage matching the payee's Lightning invoice (submarine). The preimage comes from whichever arrives first: `swap.status` from `InvoicePaid` on, an answer to `swap.status_request`, the provider's claim on chain, or the payee's receipt. The payee verifies the payment as any other.
- **Funding is not payment.** A paid hold invoice or a confirmed lockup leaves the attempt open.
- **No second payment while it is uncertain.** A submarine refund without a preimage doesn't show that the invoice went unpaid: the provider may have paid it and failed to claim. So the attempt stays open, it blocks any automatic payment of the request, and only a receipt or the user resolves it, as for any dispatch whose outcome can't be told (Paykit v0.2 §7.2, "Failed means definitively not paid"). A reverse swap fails definitively once nothing can pay the payee: the lockup was never funded and the hold invoice failed back, or the provider's refund of the lockup confirmed.
- **What the method declares** (Paykit v0.2 §7.2): the commit is idempotent on its `quote_id`, and its history is the provider's record, which answers `swap.status_request` until 30 days after the swap ends and doesn't depend on the paying device.

## 11. Security and privacy

- **Admission.** A provider's switch admits an unknown owner only with a code from a quote it issued. Each code has one use and expires with its quote, and the quote it came with names its owner, so a copied code and quote let no one else commit.
- **Abuse.** Quotes and invites are rate-limited by the provider (Section 4), and admitted senders by both switches (Switch §7).
- **Signatures.** The provider signs quotes and contracts with its app's signing key, and a verifier takes that key from the provider's certificate. A key change is an app certificate renewal (Switch §3.2), so the §13.1 `key_generation` members go.
- **Operators.** The quote endpoint learns the client's network address and the owner each RFQ names, for every provider the wallet compares. The provider's switch operator learns which identities commit to swaps with it, through conversation entries and invite use. The owner's operator learns that the owner corresponds with the provider. Contents are sealed. An invite code's `context` holds no personal data (Switch §7).
- **Replay.** The Switch deduplicates by (sender, `msg_id`). A commit sent again with the same `terms_hash` gets its stored contract, as today.

## 12. Transition

- **Swaps funded on today's wire finish there.** The provider answers the native `SwapMessage` and the §13.1 kinds over `direct/1` for every swap created on them until the swap ends and its 30-day retention passes. Claims and refunds need only the chain, so such a swap can finish or refund even without the wire, which carries only its status and listing. bitkit-core keeps today's client for its open swaps and starts new ones on this protocol only.
- **Bitkit moves** once a Switch client SDK is usable. Moving bitkit-core to the §13.1 wire first is skipped.
- **Retired** once no client uses them: terminal status over Homeserver DMs, the wake grant for `swap.claimable`, the Capability Descriptor under `/pub/paykit/ext/`, the `paykit-cap/subkey/v1` delegation, and #119.

## 13. Open questions

1. **iroh beside HTTPS.** This draft lets a provider name an iroh quote endpoint instead of or beside HTTPS, for providers on home nodes. bitkit-core already speaks `direct/1`, so supporting both costs Bitkit little. The alternative is HTTPS only, with home providers behind a tunnel.
2. **A provider's word that it failed.** Is a signed `swap.status` saying that a submarine swap's invoice payment failed enough for Paykit to write `failed`, or does that also need a receipt or the user? (Section 10, for the Paykit team.)
3. **Name.** `swap` takes the `swap` root for one protocol (Switch §3.3). That suits a protocol any hash-settled swap provider can speak (S1), but it should be agreed before anything ships.

Settled since the first draft: first contact (Section 4), the owner signature (Section 6), offer freshness (S5), where the Paykit rules live (S8), the exact amount under fee bumps (Section 7.1), and `liquidity/1` (S10).
