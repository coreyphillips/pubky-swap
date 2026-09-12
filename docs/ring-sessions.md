# Swaps through scoped Pubky sessions

A client authenticated through Pubky Ring has a homeserver session, not the account's private key. The `pubky-swap/session/1` iroh protocol lets that client use a separate communication key while preserving the existing swap engine and non-custodial spending rules.

The client derives its communication key from its own wallet secret with domain separation for the Pubky account, provider, and application scope. It publishes a short-lived authorization under its permitted application wallet namespace, for example `/pub/bitkit.to/bitkit/wallet/swap-authorizations/{transport-public-key}.json`. The document contains the account public key, transport public key, provider public key, protocol version, and expiry. It contains no swap amounts, invoices, claim or refund secrets, preimages, or session credentials.

Before each request, the client renews the document using its existing session. The provider resolves the account through Pubky, reads that document, and checks its owner, authenticated QUIC transport key, provider, version, and expiry. A missing, expired, oversized, or mismatched document fails closed. The provider authenticates the communication key through the QUIC handshake, never through a claimed key inside the request.

The provider records both the delegated communication key and the authorizing account. Status lookup and replay require both to match. Exposure and concurrency limits remain aggregated by account, including after restart, so rotating delegated keys cannot bypass the account limit. The provider records the delegated communication key as the swap counterparty. It does not treat a scoped session as the account's root key. This prevents a session for another application from querying or modifying swaps made with another key. The wrapper keeps its local recovery database under the same delegated identity. Deterministic derivation allows the same wallet, account, provider, and application scope to recover the same identity after session renewal.

Authorization lasts ten minutes, with up to one minute of future-clock tolerance. Normal clients stop renewing when the session is revoked. An already published authorization can remain usable by its communication-key holder until its expiry; revoking the Ring session does not retroactively erase that document. The homeserver is trusted to enforce the delegated namespace, as it is for other session-authorized Pubky data.

The session bearer token is used only with its own homeserver. It is never sent over the swap protocol, persisted in the swap database, or logged by this adapter. Root account keys remain in Ring. Claim and refund keys remain in the customer's wallet. Unilateral chain recovery does not require an active homeserver session.

Requests use bounded, encrypted bidirectional streams. The provider accepts only offer, quote, creation, and status requests, and replies on the requesting stream. Clients poll durable status rather than expecting root-key encrypted DM updates. The existing rendezvous ALPN and DM protocol continue to work for locally managed identities.

Providers need the `iroh` feature and enabled `rendezvous_iroh` configuration. Execution-capable providers advertise `session-rpc-v1`. Existing provider installations must be upgraded before Ring-authenticated clients can use this flow.
