# Pubky and iroh

Pubky is the identity and discovery layer. iroh carries live requests when both sides support it.
Neither replaces the other, and no swap state depends on which one carried a request.

## What each one carries

| Data | Carried by |
|------|------------|
| Account and provider identity (the ed25519 Pubky key) | Pubky. The iroh endpoint id is the same key. |
| Finding a provider, follow graph, profile and offer publication | Pubky homeservers and the DHT. iroh can reach a key it is given, but it cannot list providers. |
| Scoped session grants and swap authorizations (`ring-sessions.md`) | The account's homeserver. |
| Offer, quote, creation and status requests from a supported client | iroh `pubky-swap/direct/1` (root key) or `pubky-swap/session/2` (scoped session). |
| The same requests from older clients or providers | Pubky DMs, after the iroh doorbell. |
| Background status updates from a provider | Pubky DMs, to clients that negotiated over DMs. Stream clients query status instead. |
| Funding, claims and refunds | Bitcoin and Lightning. Neither transport is involved. |

## Which operations still need a homeserver

- A provider answering a `direct/1` request needs none. The QUIC handshake proves the client's key.
- A provider answering a `session/1` or `session/2` request reads the client's authorization from
  the account's homeserver on every request, and the client renews it before every request. Scoped
  sessions do not work while that homeserver is unavailable.
- Pubky DMs need both homeservers: the sender writes, and the receiver polls.
- Provider discovery and resolving where a homeserver lives use Pubky and the DHT.

## Selection and fallback

The CLI client chooses with `negotiation` (`--negotiation`, `PUBKY_SWAP_NEGOTIATION`):

- `auto` (default): iroh `direct/1` first. If the provider refuses the protocol or cannot be
  reached, nothing was sent, and the client uses Pubky DMs for the rest of the run. Signing in to
  the client's homeserver waits until DMs are actually needed.
- `iroh`: `direct/1` only. A provider without it fails the run.
- `dm`: Pubky DMs only, as before this protocol existed.

`rendezvous_iroh` only controls the doorbell rung before the first DM. A build without the `iroh`
feature always uses DMs, and `negotiation = "iroh"` is an error there.

A provider accepts `direct/1` whenever it runs iroh rendezvous (`rendezvous_iroh`, on by default,
and the `iroh` feature). Providers that do advertise `direct-rpc-v1` in their offer alongside
`session-rpc-v1`. The ALPN handshake is the authoritative check, so a client does not need the
offer before it connects.

| Client | Provider | Path |
|--------|----------|------|
| iroh build, `auto` | has `direct/1` | iroh, no DM polling |
| iroh build, `auto` | older, or `rendezvous_iroh` off, or no `iroh` feature | refused before sending, then DMs |
| iroh build, `iroh` | older | fails without sending |
| no `iroh` feature, or `dm` | any | DMs |
| older client | any | DMs |

## Authorization

A `direct/1` request is attributed to the key that authenticated the connection. It carries no
account or scope, and the provider records and checks it exactly as it does DMs from that key. A
swap made over DMs can therefore be replayed or queried over `direct/1`, and the reverse.

A scoped session request is attributed to its transport key and the authorizing account and scope.
Status lookup and replay require all three to match, so a root-key connection cannot reach a swap
made under a session, and a session cannot reach a root-key swap. The two envelopes are distinct
types on distinct ALPNs, and a provider resets a stream that sends one on the other's protocol.

## Lost replies, fallback and restarts

Every request is sent at most once per attempt. When an attempt fails after it may have reached
the provider, the client sends the identical request again: once over iroh on a new connection,
then over DMs if allowed. Offers, quotes and status are read-only, and a spare quote expires
unused. A repeated `SwapRequest` from the same key returns the original persisted acceptance,
including after a provider restart and whichever transport carries it, so it cannot create a
second swap or change the owner. If the repeat is refused, as it is when the first attempt spent
the quote while the repeat was racing it, the client queries status by quote and uses the
persisted acceptance. Only a refusal with no owned record is treated as final. The acceptance is
then validated exactly as a first reply would be.

Nothing about claims, refunds or chain verification changes: the client checks the returned
contract, invoice and amounts before it pays or funds, and resumes from its own store.

## Measuring

Loopback and relayed iroh request latency, for session and root-key requests:

```text
cargo test -p pubky-transport --features iroh --lib request_latency -- --ignored --nocapture
```

DMs against cold and warm iroh to a live provider, with p50, p95, error counts and the client's
homeserver requests:

```text
PUBKY_SWAP_RECOVERY_FILE=... PUBKY_SWAP_PASSPHRASE=... \
  cargo run -p swap-client --features iroh --example negotiation_latency -- <provider> 20
```

The homeserver count covers sign-in, sends and conversation reads, where a read is two listings
and one fetch per stored message. It grows with the conversation. The iroh rows are zero on the
client, and a provider answering them makes no homeserver requests either.
