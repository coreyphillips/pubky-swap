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

Only providers configured for execution advertise `boltz-taproot-v1` and `swap-status-v1`.
Capabilities should be checked before requesting a Taproot contract.

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
record exists for that identifier. Other errors, including an unreadable store, do not establish
absence. Do not create a new quote and assume it names the same swap. Acceptance recovery is retained with the
swap record, currently for 30 days after terminal completion.

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

Only the authenticated original counterparty can recover this information. The snapshot excludes
private keys and preimages. Older records without a stored acceptance cannot provide this response.

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
