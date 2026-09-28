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
  reached, nothing was sent, and the client uses Pubky DMs for the rest of the run. Message-storage authentication waits until DMs are actually needed.
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

The homeserver count comes from actual messenger request-engine attempts, including listing
pages, body reads, writes, deletes, retries and storage-session establishment. It excludes SDK
account, profile and follow operations. Acknowledged message bodies are not downloaded again,
but directory listings still grow with retained history. Direct root-key rows make no message
storage requests; scoped sessions still renew and verify their authorization.

The local homeserver fixture compares full-history reads with acknowledged incremental polls:

```text
cargo test -p pubky-transport --lib local_homeserver_read_poll_benchmark -- --ignored --nocapture
```

These fixtures measure transport operations, not funded swap settlement. Report loopback,
public relay, local homeserver and live provider results separately. See the implementation
handoff and performance results for the measured revision.

## Durable delivery and completion

Use `Transport::with_receive_journal` and `Transport::with_outbox` together for DM applications.
Journals belong to one identity and process. The CLI separates them by owner and provider under
`data_dir/transport`; applications that support several Bitcoin networks must also isolate the
whole data directory by network. An identity mismatch, corrupt file, competing writer or uncertain
save fails visibly. Unsupported receive journal versions require explicit recovery, not automatic
reset. The receive journal contains decrypted pending messages and must be included in protected
storage and recovery planning.

`SwapMessage::delivery_scope()` associates creation requests and acceptances with a quote and
lifecycle notifications with a swap. `send_with_scope` saves the signed encrypted resource before
publication. Repeating the same scope and payload reuses its resource ID and bytes, even after an
ambiguous PUT. `enqueue_with_scope` performs only that durable preparation. Applications schedule
`process_outbox` to retry saved work; constructing a transport starts no implicit worker.

`poll_from` and `receiver` return an `Inbound` carrying a leased `Receipt`. A handler acknowledges
only after persisting its outcome. Dropping a receipt, cancellation, an absent offer, queue overflow
or a failed handler leaves the delivery pending. The durable body can be processed after restart
even when the publisher is offline or has already deleted the remote resource. Publisher and URL
identify a delivery; sender timestamps and content hashes do not decide whether it is new.

The provider admits different peers independently and reserves a lane for creation work. Per-peer
ordering, shared creation admission and persistent acceptance replay apply across DM and direct
requests. A stalled peer cannot occupy every polling slot. Pending inbox capacity is 32 per peer
and 1,024 globally; capacity applies backpressure without dropping pending work.

The CLI persists the exact request, quote, payment hash, keys, invoice and original chain-tip
anchor before creation. It saves the complete acceptance before acknowledging its receipt, then
validates the contract and invoice and saves the execution destination before funding or payment.
A separate execution-ready field prevents an unvalidated acceptance from entering chain recovery.
An unresolved creation is replayed or recovered by its existing quote ID before another swap can
start. Before submitting a reverse payment, the client saves its payment-start marker. Recovery
distinguishes authoritative `NotFound` from ambiguous `Unknown` and does not repay an uncertain
started invoice. Funded records still enter recovery when another negotiation cannot be resolved.

These changes retain the existing atomic swap store rather than introducing a second settlement
database. Cross-file ordering is explicit:

| Interrupted after | Recovery |
| --- | --- |
| Swap intent saved, publication absent | Reuse the saved request and keys. A never-sent expired quote can be retired. |
| Encrypted resource saved, PUT absent or ambiguous | Publish the same resource ID and exact bytes. |
| Provider admission saved, reply absent | Replay its persisted acceptance, including the recovered hold invoice. |
| Pending body saved, handler incomplete | Deliver the saved body again after restart. |
| Acceptance saved, inbox acknowledgment absent | Redeliver and acknowledge only the identical saved acceptance. |
| Acceptance saved, validation incomplete | Validate and persist execution readiness before moving funds. |
| Terminal outcome saved, final reply absent | Reconstruct the same final notification during the retention window. |
| Remote DELETE succeeded, local removal absent | Retry the exact DELETE; already absent is success. |

## Message retention contract

Executable providers advertise `dm-retention-v1`:

- Read-only offer, quote and status exchanges expire after ten minutes from preparation. Changed
  read-only replies get distinct resources. The client can repeat the query after expiration.
- Creation resources and final notifications become eligible 24 hours after a durably recorded
  `Claimed`, `Refunded`, or an unfunded `Expired` outcome. Generic failure, ambiguous funded expiry
  and a missing terminal timestamp do not authorize deletion.
- Each participant removes only its own exact resources. Completion of one swap does not clear
  the conversation or remove another swap's traffic. A successful PUT is not peer acknowledgment.
- Final notifications can disappear after that explicit recovery window even if unread. The
  authenticated status API and original acceptance remain available under the independent local
  record retention policy, currently 30 days after terminal completion. Offline clients must use
  that recovery API and keep their own keys, contracts and chain evidence.

The provider continuously retries publication and cleanup. The CLI performs bounded maintenance
when a used DM channel closes and on later recovery runs. A stopped application cannot clean its
homeserver until it runs again. Partial failures remain in the journal, with persisted backoff;
cleanup receives only a limited share of request capacity. Each maintenance pass checks saved
outcomes and uses `reopen_scope` to revoke deferred deletion after reorg or uncertainty. Deletion
already sent to a homeserver cannot be recalled; local recovery records remain authoritative.
Per-resource locks prevent a late PUT
from recreating a resource after the same running transport has deleted it.

Outbox capacity is 1,024 entries and 16 MiB, with a maximum 128 KiB encrypted resource. Read-only
traffic can occupy at most 768 entries, reserving 256 entry slots for creation and recovery.
The 16 MiB byte budget remains shared, so it can fill before the entry limit. A full outbox fails
admission and retains existing work. These are bounds on pending and retained
outgoing work, not claims of unlimited provider scale.

Acknowledged receive identities are deliberately retained independently of remote deletion. A
resource can be republished, so absence or a timestamp alone does not permit forgetting its
identity. The current JSON journal rewrites on mutation and its acknowledged history can grow.
A future segmented exact-identity store can reduce that cost without reviving handled work.
Whole-conversation clear and auto-ack helpers remain compatibility APIs; new production delivery
uses explicit receipts and scopes. They must not be used to finish an individual swap.

## Operational limits

A root-key direct request needs no per-request homeserver access. Current provider startup still
signs in and publishes/discovers through Pubky before serving, so a fresh boot is not independent
of homeserver availability. Scoped-session requests still check the account's live authorization
on every request. Neither path removes Bitcoin confirmation or Lightning settlement requirements.

Each public CLI negotiation operation has one 60-second deadline covering connection retries,
fallback, queue wait and status recovery. Cancellation preserves ambiguous creation intent.
Applications should keep their outer UI deadlines longer and recover the existing operation
before allocating another swap. The messenger's per-attempt deadlines alone do not bound total
queue wait or retry backoff.
