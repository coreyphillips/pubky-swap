# External client adapters

An external application can negotiate swaps using `pubky-transport` and the types in
`swap-common::messages`. The existing client binary also handles Lightning payments, wallets,
claim keys, and preimages. An adapter for an application that already owns that material should
use the transport and protocol types directly.

The provider continues to exchange encrypted Pubky messages. Boltz REST and WebSocket translation
belongs in a separate process on the user's device.

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
- `funding_txid_hex`, `funding_vout`, and `spend_txid_hex` when known.
- `updated_at_unix` for the record and `observed_at_unix` for the response.

Only the authenticated original counterparty can recover this information. The snapshot excludes
private keys and preimages. Older records without a stored acceptance cannot provide this response.

Provider lifecycle states describe its progress. In particular, `LockupConfirmed` historically
means the funding outpoint is known and can be set immediately after a reverse funding broadcast.
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
