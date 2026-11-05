# External client adapters

An external application can negotiate swaps using `pubky-transport` and the types in
`swap-common::messages`. The existing client binary also handles Lightning payments, wallets,
claim keys, and preimages. An adapter for an application that already owns that material should
use the transport and protocol types directly.

The provider answers the same requests over encrypted Pubky messages and, when both sides support
it, over iroh request streams. [Transports](transports.md) describes which carries what and how a
client falls back. Boltz REST and WebSocket translation belongs in a separate process on the
user's device.

## Contract selection

`SwapRequest.script_type` accepts `p2wsh` or `taproot_boltz`. An absent field selects `p2wsh`, so
existing clients keep their original contract. Executable providers advertise `boltz-taproot-v1`
in `SwapOffer.features`.

For `taproot_boltz`, the provider returns a P2TR address and `SwapAccept.swap_tree`, whose
`claimLeaf` and `refundLeaf` each contain `version` and hexadecimal `output`. The legacy
`htlc_script_hex` field is empty. `swap_common::taproot::BoltzTaprootSwap` reconstructs the
contract from direction, payment hash, both public keys, and timeout. Clients must independently
check the script tree, address, amount, invoice, network, and timeout before committing funds.

Adapters derive the contract and compare, and never use the provider's copy.
`swap_common::validate::verify_contract` rebuilds it from the client's own key, the payment hash,
`provider_pubkey_hex` and `timeout_block_height`. It compares each of `htlc_script_hex`,
`swap_tree` and `htlc_address` that is present, and returns the output script to fund or watch.
An adapter must accept an acceptance that omits `htlc_script_hex` and `htlc_address`. Both
deserialize as empty strings and are derived. The verifier reads the contract type from
`script_type`, so the caller checks it is the type it requested. Providers still send every
field.

Taproot claim and refund transactions use the unilateral script paths. The internal key is the
Boltz-compatible aggregate key, but this protocol does not implement cooperative signature
sessions. `CoopSignature` remains reserved. An adapter must reject unsupported cooperative
operations explicitly and document the supported client flow.

The reverse client supplies its own payment hash and claim public key. The submarine client
supplies its invoice and refund public key. Neither direction requires the adapter to hold the
client's private key. Reverse preimages remain with the original client until its on-chain claim.

## Discovery and correlation

`OfferRequest { request_id }` returns the current `Offer`, echoing `request_id`. Broadcast offers
omit that value. `QuoteRequest.request_id` is echoed by `Quote` or `Reject`. Request identifiers
are optional UUIDs for backward compatibility. Concurrent integrations should always set them.

Only providers configured for execution advertise `boltz-taproot-v1`, `swap-status-v1` and
`swap-list-v1`. Capabilities should be checked before requesting a Taproot contract or a
listing.

A provider built with `paykit` also publishes its offer as a signed Capability Descriptor on its
homeserver; see [The swap/1 Capability Descriptor](#the-swap1-capability-descriptor).

## Refusal codes

Every `Reject` carries `code`, one of the strings below, and `Reject::code()` parses it into
`RejectCode`. Act on the code; `reason` is for people and its wording can change. An absent code
means a provider from before codes. `Reject::code()` also returns `None` for a string this build
does not know. Treat either as a generic decline.

The first eight are refusal reasons from the Paykit Intents draft, with its retry hints.
`not_found` and `pending` answer status queries and creation replays, not intents. The last five
have no Paykit equivalent, and an adapter reports them as its generic decline.

| `code` | Sent when | Paykit | Retry |
| --- | --- | --- | --- |
| `unsupported_route` | The direction is not offered, or the provider cannot execute swaps | same | Other provider |
| `amount_below_minimum` | Below the offer's effective minimum, stated in `reason` | same | Larger amount |
| `amount_above_maximum` | Above `max_amount_sat`, stated in `reason` | same | Smaller amount |
| `liquidity_unavailable` | Capacity or exposure limits are full, or the wallet cannot fund a reverse swap | same | Later or smaller |
| `rate_limited` | The sender has started too many swaps in the last hour | same | Backoff |
| `pricing_unavailable` | The provider has not priced an offer yet | same | Later |
| `quote_expired` | The quote is unknown, expired or already spent | same | New quote |
| `invalid_destination` | The submarine invoice has no amount, a sub-satoshi amount, an amount other than the quoted one, or too long a final CLTV | same | User fix |
| `not_found` | A status query names no swap the sender owns | none | See [recovery](#durable-creation-and-recovery) |
| `pending` | An admission exists and its invoice still needs recovery, or another request is admitting the same swap | none | Query again |
| `access_denied` | The provider's access policy refuses the sender | generic decline | Other provider |
| `invalid_request` | The request is malformed, names another pubky, reuses a payment hash, changes an accepted request, carries an `owner_ref` the provider will not keep, or a listing cursor it did not issue | generic decline | Fix the request |
| `unsupported_protocol` | `protocol_version` is outside what the provider speaks | generic decline | Other provider |
| `offer_stale` | `offer_id` names an offer that is no longer current | generic decline | Fetch the offer, then quote again |
| `internal_error` | The provider failed for its own reasons | generic decline | Later |

The draft's `amount_below_minimum {min}` and `amount_above_maximum {max}` take a number. The offer
carries both: `effective_min_amount_sat()` and `max_amount_sat`.

Capacity and rate limits are checked when quoting, against the provider's counters, so they can
refuse an intent. They are checked again with the wallet balance when the quote is redeemed, so a
quote holds no capacity and `liquidity_unavailable` or `rate_limited` can still answer a
`SwapRequest`.

## Durable creation and recovery

Persist the complete `SwapRequest` before sending it. For reverse swaps the provider writes an
invoice creation intent, including owner, request, keys, quote terms, and an invoice memo containing
the swap UUID, before calling Lightning. After a lost RPC response or restart, LND recovery must
match that exact memo, payment hash, amount, expiry, and CLTV before reusing an invoice. One payment
hash cannot admit several reverse swaps. The acceptance is persisted before delivery. Resending
the identical request from the same authenticated Pubky returns the original acceptance, including
after a restart or terminal outcome. A changed request for an already accepted quote is rejected.
An uncertain delivery leaves the provider's driver active because the counterparty may already
have received the acceptance.

After a creation timeout, retry the original request or query its quote identifier. A status
rejection with `code: "pending"` means an admission exists and its invoice still needs recovery.
Only `code: "not_found"` from an authenticated, correlated status query establishes that no owned
record exists for that identifier. Other refusals, including `internal_error` for an unreadable
store, do not establish absence. Do not create a new quote and assume it names the same swap.
Acceptance recovery is retained with the swap record, currently for 30 days after terminal
completion.

Lightning backends must implement `lookup_hold_invoice` to recover a pending invoice. Unsupported
lookups and unavailable backends leave the intent intact and prevent a second creation attempt.

`SwapStatusRequest` contains `request_id` and exactly one of `swap_id` or `quote_id`. The response
is `SwapStatusSnapshot`, echoing the request identifier and carrying:

- The original `accept` and the explicit Bitcoin `network`.
- The provider's persisted `state` and `required_confirmations`.
- `funding_txid_hex`, `funding_vout`, and `spend_txid_hex` when known. `spend_txid_hex` is the
  provider's own most recent claim or refund broadcast.
- `claim_observed_txid_hex` on a reverse swap, once the provider has seen the owner's claim.
  Providers from before this field omit it.
- `updated_at_unix` for the record and `observed_at_unix` for the response.
- From `swap-list-v1` providers: `created_at_unix`, the swap's `payment_hash_hex`, and the
  `owner_ref` the owner sent. Older providers omit all three, which read as 0, empty and absent.

Only the authenticated original counterparty can recover this information. The snapshot excludes
private keys and preimages. Older records without a stored acceptance cannot provide this response.

## Listing an owner's swaps

Providers advertising `swap-list-v1` answer `SwapListRequest { request_id, cursor, limit,
active_only }` with `SwapList { request_id, snapshots, next_cursor }`:

- Only the authenticated sender's own swaps are listed, matched exactly as a status query matches
  them: the transport key, plus the account and scope when a session was used. Anyone else gets an
  empty page, not a refusal. The listing says nothing about what exists.
- Pages run newest first by `created_at_unix`, then by `swap_id`, so a swap changing state never
  moves between pages. A swap created while paging sorts before the first page and shows up in
  the next listing. `limit` defaults to 10 and is clamped to 16; `next_cursor` is opaque and is
  passed back as `cursor`. A cursor the provider did not issue is refused with `invalid_request`.
- `active_only` leaves out swaps in a terminal state. Either way the listing covers the same
  30-day retention window as status queries. An admission still creating its hold invoice has no
  acceptance to show and is left out; a status query for its quote answers `pending`.
- Each snapshot's `request_id` is absent; the page carries the correlation.
- A provider without the feature cannot parse the request and never answers it. Check the offer
  before asking.

`SwapRequest.owner_ref` is an opaque string of at most 128 printable ASCII characters that the
provider keeps verbatim and echoes in every snapshot and listing. It is for the owner's own
bookkeeping, and is never interpreted. Anything else is refused with `invalid_request` before the
quote is spent, and a provider from before `swap-list-v1` ignores the field.

## Restoring from the seed

A wallet with only its seed finds its swaps by listing them at each provider it used. It has to
restore the identity it negotiated with: the same root key, or the same account and scope for a
session, because that is what the listing is scoped to.

The provider cannot give back the branch key or the preimage, which never left the wallet. A
wallet that derives them from its seed puts the key index in `owner_ref` when it creates the
swap, reads it back from the listing, and derives the keys directly. Without an `owner_ref` it
can scan indices around `created_at_unix` for one whose keys match `payment_hash_hex`.

`swap_client::restore` does the rest: `restore_from_provider` checks the offer for
`swap-list-v1`, lists every swap, hands each snapshot to a resolver for its keys, checks what
comes back against the listed contract (`verify_contract`) and the payment hash, and writes a
record that `resume` drives like any other. Terminal swaps, swaps already in the store, and
snapshots the resolver cannot key are reported rather than written. Only reverse swaps are
rebuilt: a submarine refund needs the client's own invoice, which the listing does not carry.
A restored reverse record carries no saved request, so `resume` asks the node whether the hold
invoice was already paid before paying it.

The final `SwapStatusUpdate` names the transaction behind its outcome in `reference`, which is
the `evidence` of a terminal Paykit intent status:

| `state` | `reference` |
| --- | --- |
| `Claimed`, reverse | the owner's claim, as the provider saw it (`claim_observed_txid_hex`) |
| `Claimed`, submarine | the provider's claim (`spend_txid_hex`) |
| `Refunded` | the provider's refund (`spend_txid_hex`) |
| `Failed`, `Expired` | the HTLC funding (`funding_txid_hex`) |

`reference` is absent when the record has no such transaction, such as an expiry before funding,
and from providers that predate it. After a fee bump, the spend that confirmed can be an earlier
version than the one `spend_txid_hex` names.

### Paykit leg status

Provider lifecycle states describe its progress, not the owner's. `SwapState::leg_status` maps
them to the Paykit Intents leg statuses, from the owner's point of view, so an adapter reports the
same words whichever path filled an intent:

| `SwapState` | Reverse (owner pays Lightning, receives on-chain) | Submarine (owner locks on-chain, receives Lightning) |
| --- | --- | --- |
| `Created` | `pending` | `pending` |
| `LockupPending` | `in_transit` | `pending` (never set by the provider; defensive) |
| `LockupConfirmed` | `in_transit` | `in_transit` |
| `InvoicePending` | `in_transit` | `in_transit` |
| `InvoicePaid` | `in_transit` (owner's claim observed, may be unconfirmed) | `delivered` (owner's invoice paid; the preimage is the evidence) |
| `ClaimPending` | `in_transit` | `delivered` |
| `Claimed` | `delivered` | `delivered` |
| `Refunded` | `refunded` | `refunded` |
| `Expired` | `failed` | `failed` |
| `Failed` | `failed` if no funding is known, else `delivery_failed` | same |

"Funding is known" means the record has `funding_txid_hex`. The status covers the whole route.
Splitting it into Lightning and chain legs is left to the adapter.

`needs_attention` comes only from the provider record's `needs_recovery` flag, which the operator
API shows and the snapshot does not carry. It replaces a non-terminal status and never a terminal
one. A caller working from a snapshot passes `false`. `replaced` is never produced.

The provider sets `LockupConfirmed` as soon as a reverse funding is broadcast, not at depth, so it
means only that the funding outpoint is known. It never maps to `delivered`, which on a reverse
swap requires the owner's own chain view of its claim. The provider never sets `ClaimPending`, so
it reads like `InvoicePaid`. `SwapStatusUpdate` is sent only for terminal states, so non-terminal
statuses come from polling `SwapStatusRequest`.

An adapter must obtain transaction contents and confirmation depth independently before emitting
a status that promises on-chain confirmation or advising a client to reveal its preimage.

## Paykit Capabilities kinds over direct/1

A provider built with `iroh` answers the `paykit-cap.*` kinds for `swap/1` on `direct/1`. A request
is `{"kind": "paykit-cap.<name>", "body": {...}}` in the `message` of a `DirectRequest`. Any other
message is still read as a `SwapMessage`, so offer and list requests are unchanged.

| `paykit-cap` | pubky-swap |
| --- | --- |
| `rfq` | `QuoteRequest` |
| `quote` | `Quote`, signed |
| `commit` | `SwapRequest` |
| `contract` | `SwapAccept`, signed |
| `status` | `SwapStatusUpdate`, or the reply to `status_request` |
| `status_request` | `SwapStatusRequest`, answered from `SwapStatusSnapshot` |
| `refusal` | `Reject` with its `RejectCode` string |

Neither `rfq` nor `commit` has a `client_pkarr`. The owner is the key that authenticated the
connection. A commit gets `pending` as a `status` while another request is still admitting the
same swap: ask again, it is not a decline. Every refusal code passes through, so a commit can get
`liquidity_unavailable`, `rate_limited` or `access_denied`.

Three hashes chain the agreement. Each is SHA-256 over a domain prefix, then the RFC 8785 (JCS)
form of an object:

| Hash | Domain prefix | Object |
| --- | --- | --- |
| `terms_hash` | `paykit-cap/swap/1/terms_hash\0` | `{"owner": <z32>, "provider": <z32>, "rfq": {offer_id, direction, amount_sat}, "quote": <quote without request_id>}` |
| `commit_hash` | `paykit-cap/swap/1/commit_hash\0` | `{"terms_hash": <hex>, "commit": <commit body>}` |
| `contract_hash` | `paykit-cap/swap/1/contract_hash\0` | `{"commit_hash": <hex>, "contract": {"accept": <SwapAccept without invoice>, "invoice_blob_hash": <hex>}}` |

`owner` is the key that authenticated the connection and `provider` is the provider's pubky,
both bare z32, as Capabilities §10.1 lists both identities. A quote signed for one owner does not
verify for another.

The provider signs `terms_hash` in the quote and `contract_hash` in the contract, with Ed25519
over the 32 hash bytes. `signer` is the public key as hex. With `paykit` and a homeserver it is
the capability signing key (see "The capability signing key" below); otherwise, and until that
key's delegation is published, it is the provider's root key, the one a client dials. A client
built with `paykit` accepts either; without it, only the root key. A commit names the
`terms_hash` it accepts, and one that differs from the signed quote is refused.

A commit also carries the signed quote and the rfq it answered, as `quote: {rfq, signed}`.
`commit_hash` does not cover it, because `terms_hash` already binds it. A provider that no longer
holds the quote, after a restart or because a full book evicted it, takes it back only if its own
key signed it, `terms_hash` recomputed with the sender as owner matches both the quote and the
commit, it has not expired, and the direction matches. Every admission check then runs as usual,
so a commit on a valid quote can still get `liquidity_unavailable`, `rate_limited` or
`access_denied`. A quote that a swap already used, or that this run already redeemed, is not
taken back: an identical replay gets its contract, anything else is refused. `quote` is optional
on the wire, so a carrier with a size limit can leave it out, at the cost of `quote_expired` after
a restart.

The reverse hold invoice is not in the contract. It is sealed with ChaCha20-Poly1305 under a
per-swap key and a zero nonce, and the contract signs SHA-256 of the ciphertext. Over `direct/1`
the key and ciphertext travel beside the signed contract as `invoice_blob`, so the signed bytes
are the same ones an Encrypted Link will carry.

The signed contract is stored with the swap record. A replayed commit and every `status_request`
return those bytes, including after a restart. A commit replayed after a restart for a swap with
no stored contract (created over plain kinds, or a crash between creation and signing) is signed
over the `terms_hash` the commit names, since the provider no longer holds the quote.

Golden vectors, from `swap-common/src/paykit_cap.rs` (`golden_vectors`), for signer secret `[7; 32]`:

| | Hex |
| --- | --- |
| `terms_hash` | `273f025818bb3fdcc84dfd3d26092e66592bdf0705c146ea7f2be4a0e8234161` |
| `commit_hash` | `dca484d94be41ef37eb4d7eeac3d2b8686a3e0e92e0bfc9e2a370a77ed0ebdc5` |
| `contract_hash` | `8e52dcc64cdbaaa377d333130d5ab411f14fb21c3962ec28c2e45fe507953974` |
| `signer` | `ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c` |

The inputs are the fixtures in that test. `swap_client::negotiate::CapChannel` is the client side:
it sends these kinds and checks each signature against the provider it dialed. The CLI client
uses it with `--negotiation paykit-cap` (`PUBKY_SWAP_NEGOTIATION`, or `negotiation` in the config
file). It reads the offer first and stops unless the provider advertises `paykit-cap-v1`, and it
never falls back to DMs. The regtest step `cap_swap_regtest` runs a reverse and a submarine swap
this way against a provider daemon, and a reverse swap whose provider restarts between the quote
and the commit, and checks each stored contract as a third party would.

What the client checked lives only in `CapChannel`'s memory. A creation recovered by a later
process (`negotiation_recovery`) is replayed as a plain `SwapRequest` on `direct/1`, which the
provider answers with the same swap; the signed contract stays with the provider's record, and
`status_request` returns it.

The rfq, quote and a commit without its signed quote fit 1,000 bytes. A commit carrying the
signed quote is about 1,350 bytes, and a signed contract is over too: with the P2WSH script or
Taproot tree the provider always sends, it is 1,048 to 1,208 bytes. A `status` reply carries the
full snapshot and contract, and is larger still. #119 tracks fitting them into an Encrypted
Link.

## The swap/1 Capability Descriptor

A provider built with `paykit`, configured for execution and running with a homeserver publishes
a signed `paykit-cap.descriptor` (Paykit Capabilities §6) at
`/pub/paykit/ext/capabilities/v1/apps/pubky-swap.json`. A wallet reads it from the provider's
homeserver instead of asking every contact for an offer, so finding providers tells nobody that a
swap is wanted. `swap_common::cap_descriptor` builds and verifies it. Nothing is written until
`--paykit-setup` has published the App Registry entry and the Noise Key Authorization, since a
reader drops a descriptor whose `app_id` the owner's registry does not list, and the capability
signing key delegation is in place, since a reader verifies the descriptor through it.

It has one `swap/1` entry, built from the current `SwapOffer`:

| Member | From |
| --- | --- |
| `edges[].min` | `effective_min_amount_sat()`: the configured minimum raised to 10 × `onchain_fee_sat` |
| `edges[].max` | `max_amount_sat` |
| `edges[].fee` | `{"base": base_fee_sat, "ppm": fee_ppm, "onchain": onchain_fee_sat}`, so `base + floor(a × ppm / 1e6) + onchain` is `quote_fee(a).total_fee_sat` |
| `edges[].fund_within_secs` | `fund_within_secs` |
| `edges[].lock_profiles` | `taproot_boltz` only when the offer lists `boltz-taproot-v1`, then `p2wsh` |
| `edges[].atomicity`, `sides`, `unit` | `hash`, `["exact_out"]`, `sat` |
| `terms` | `offer_id`, `network`, `htlc_timeout_blocks`, `required_confirmations` |
| `contact.rfq` | `iroh:pubky-swap/direct/1`, when the offer lists `paykit-cap-v1` and `direct-rpc-v1` |
| `contact.intro` | `{"type": "iroh", "alpn": "pubky-swap/direct/1"}`, when the offer lists `direct-rpc-v1` |

Amounts are integer strings. The offer-wide values are the same on every edge.

Edges name exact Payment Endpoint Identifiers, one edge per identifier, as `swap/1` settled on
pubky/paykit-rs#229: a reverse edge runs from `btc-lightning-bolt11` to each on-chain output type a
claim can pay, and a submarine edge from each output type a lockup can be funded from. The types
are `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh` and `p2tr`, so a two-direction offer has ten edges. The rail
segment names the network: `btc-bitcoin-*` on mainnet, `btc-signet-*`, `btc-regtest-*` and
`btc-testnet-*` elsewhere, with `terms.network` saying the same. The Lightning identifier is
`btc-lightning-bolt11` on every network, because the invoice names its own.

The signature is Ed25519 over `paykit-cap/descriptor/v1\0` followed by the JCS form of the
descriptor without `sig`, base64url-encoded without padding into `sig`. The signer is the one the
`paykit-cap.*` adapter uses. `key_generation` is the published Noise Key Authorization's
generation when the provider last signed in, which it does again at least hourly. The envelope is
closed: an unknown member makes it unreadable.

The refresher rebuilds the offer every `quote_ttl_secs / 2` (at least 30 s) with a new `offer_id`,
and an RFQ naming an older id is refused, so every rebuild is a rewrite. A fee move that changes
the effective minimum reaches the file the same way. `valid_until` is the offer's own expiry, so a
provider that stops refreshing lapses within one quote TTL. `seq` rises on every rewrite and
never falls below the Unix time, so it keeps rising across restarts without being stored. A
descriptor whose offer has expired is never written, and the status API's `/descriptor` returns
404 once the published one lapses.

## The capability signing key

Paykit Capabilities §5 has a capability signing key sign descriptors, terms and contracts, and
the routing key sign only one delegation to it per key generation. `paykit_identity` implements
both:

- The key is Ed25519 with seed `derive_key("paykit/cap-signing", K_g)`, Paykit KDF v1's BLAKE3
  `derive_key` under the generation's Paykit identity secret.
- The delegation is a closed object at `/pub/paykit/ext/capabilities/v1/signing-key.json`:
  `version` 1, `kind` `paykit-cap.signing_key`, `owner`, `key_generation`, `signing_key` and
  `sig`. `sig` is the routing key's Ed25519 signature over `paykit-cap/subkey/v1`, `0x00`, then
  the JCS form without `sig`. It holds no timestamp, so every app of the identity writes the same
  bytes.
- §5 leaves two encodings open, so this writes what pubky-swap writes elsewhere: `owner` as bare
  z-base-32, and base64url without padding. A reader also accepts a `pubky`-prefixed `owner`.

`--paykit-setup` writes the delegation after the authorization, and `--doctor` warns when it is
missing or does not verify. The descriptor publisher writes it again on every sign-in if the
file differs, then moves the `paykit-cap` signer to that generation's capability signing key,
and only then signs the descriptor. A delegation is only ever written for the generation the
published authorization names, so a provider still holding an older generation cannot overwrite
a newer one. A rotation reaches the signer at the next sign-in, within an hour.

A reader follows the chain with `paykit_identity::resolve_signing_key`: verify the Noise Key
Authorization through paykit-rs, require the delegation's `owner` and `key_generation` to match
it, verify the delegation with the authorized routing key, then verify the object with the
delegated key. A delegation left at an older generation is refused. The client's `CapChannel`
does this for a reply signed by any key other than the root key it dialed.

Golden vector, from `paykit-identity/src/delegation.rs`
(`the_delegation_bytes_match_the_golden_vector`), for Pubky secret `[7; 32]` at generation 1. It
was recomputed independently from Paykit KDF v1 and §5 with Python's `blake3` and `pynacl`:

```json
{"key_generation":1,"kind":"paykit-cap.signing_key","owner":"7jfgaa9nutjyixzikb7tgmsf9gkwq7iqz498zr1nd5ig1fng4esy","sig":"Sj9Xps4rjkmNrqYv4EU8OuD7gyN4LGNb1SyAbjv0p9PEEg7HekF6unysSnkPRXDn_k9XOBHmll3-Xdo2xkrtAQ","signing_key":"7TrkHFnQPW67doNM4TipjT9CmZygnHHbriRjgBb4Ry8","version":1}
```

What this does not cover yet: `paykit-cap` messages carry no `key_generation` until the §8.1
envelope lands, so a client checks a signer against the currently published generation only. A
contract stored before a rotation, signed by the older generation's key, fails that check.

## Amounts and fees

For submarine swaps, `Quote.amount_sat` is the Lightning invoice amount and the expected on-chain
lockup is `Quote.total_sat`. For reverse swaps, `Quote.amount_sat` is the on-chain output before
the client's claim transaction fee, while `Quote.total_sat` is the hold invoice amount.

The provider fee is `base_fee_sat + floor(amount_sat * fee_ppm / 1_000_000) + onchain_fee_sat`.
An adapter accepting an inclusive reverse invoice amount must invert that integer calculation
and validate the resulting fresh quote. It must not silently reinterpret the invoice amount as
the on-chain amount.

## Timing

`Quote.fund_within_secs` is how long the provider declares it takes to fund its leg once the
owner's funding is final. The quote carries `direction`, so the figure is for that direction.
`SwapOffer.fund_within_secs` repeats it and is advisory, like `SwapOffer.valid_until_unix`. 0 means
undeclared, which is what a provider from before the field sends. The default is 300. Clients
refuse a quote declaring more than `MAX_FUND_WITHIN_SECS` (3600), and a provider refuses to start
with 0 or anything above it.

| Direction | Clock starts | Within the window the provider | Evidence |
| --- | --- | --- | --- |
| Reverse | its node reports the hold invoice accepted | broadcasts the HTLC funding | `funding_txid_hex` in the status snapshot |
| Submarine | the owner's lockup reaches `required_confirmations` | starts paying the owner's invoice | state `InvoicePending` or `InvoicePaid` |

Time before the owner's funding is final never counts. The bound is on the provider's reaction,
not on block times or Lightning routing. An owner sees when it sent its payment, not when the
provider's node accepted it, so timing from its own send includes the routing delay.

The figure is declared, not enforced. The provider does not abort a funding that runs late, and
the owner has nothing to enforce it with: a held Lightning payment cannot be withdrawn, and
cooperative refund is reserved. The Paykit draft's remedy is attribution through signed terms,
which arrives with the adapter, whose `terms_hash` is built from the quote. That is why
`SwapAccept` does not repeat the figure.

## Delivery lifecycle for application adapters

Use persistent `DirectRpcClient` or `SessionRpcClient` connections for interactive requests.
Keep the same request ID and exact creation request across reconnects and transport fallback.
For DMs, initialize `with_receive_journal` and `with_outbox`, send using
`SwapMessage::delivery_scope()`, and carry `Inbound.receipt` until the application has persisted
the corresponding outcome. `enqueue_with_scope` reserves a stable encrypted publication before
network I/O; a bounded application worker calls `process_outbox` to publish or clean it later.

Handle `TransportError::Delivery` by its `DeliveryOperation` and `DeliveryFailure`, and inspect
`outbox_status()` after startup or maintenance to surface paused work. Temporary HTTP failures,
transport outages and timeouts retry automatically; persistent authentication or invalid-request
failures require attention. After resolving the cause, `retry_outbox(id, operation)` durably
resumes the same saved resource without immediate network I/O. Last failure categories are
historical, so use the separate pause flags to determine whether work currently needs attention.
Never replace or delete a funded swap's resource merely to clear an error.

The transport resource ID is separate from the business operation ID. Exact PUT replay avoids
duplicate files, while the authenticated owner and saved creation request prevent a second
contract. Persist complete acceptance data, validate the contract and invoice independently,
and save execution readiness before funding or paying. Do not allow generic retry limits,
request cancellation or cleanup to discard funded-swap recovery records.

Providers advertising `dm-retention-v1` retain read-only traffic for ten minutes and completed
creation/final traffic for a 24-hour recovery window. The status API retains acceptance and
outcome information under the separate 30-day local record policy. Call `complete_scope` only
after a safe terminal transition is durable, preserve ambiguous failures, and let each owner
delete its own exact resources. See [the delivery contract](transports.md#message-retention-contract)
for limits, crash ordering and recovery responsibilities.
