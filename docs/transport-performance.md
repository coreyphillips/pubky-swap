# Local homeserver read and polling benchmark

The complete benchmark passed on 2026-09-28 in 271.47 seconds. Messenger was pinned to published commit `4fff0ce2183f7273c0418801c262ed291a0a145a`. The two normal local homeserver integration tests also passed: durable publication after restart with scoped cleanup, and changed ephemeral replies retaining distinct stable resources.

| Acknowledged history | Read strategy | p50 ms | p95 ms | LIST per poll | GET per poll | Response body bytes per poll | Receive journal bytes |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | Full history | 5.461 | 7.948 | 2 | 0 | 38 | N/A |
| 0 | Incremental | 3.558 | 4.345 | 2 | 0 | 38 | 252 |
| 200 | Full history | 1,346.890 | 1,441.268 | 3 | 200 | 323,859 | N/A |
| 200 | Incremental | 14.034 | 36.657 | 3 | 0 | 37,818 | 39,508 |
| 10,000 | Full history | 8,252.010 | 13,797.403 | 12 | 10,000 | 16,240,404 | N/A |
| 10,000 | Incremental | 290.905 | 609.093 | 12 | 0 | 1,890,009 | 1,960,308 |

At 10,000 acknowledged resources, incremental polling used about 28 times less median wall time and about 88% fewer response body bytes per poll in this run. Every old body GET was eliminated. Directory listings still traverse the full history, so polling cost is not constant as the history grows. Local acknowledgment state also grows with retained resource identities.

## Method

- One sender and one reader per history size, with all incoming messages in one conversation. Resources were real encrypted messenger messages containing a JSON object with a sequence number and 128-byte data field.
- Seed publication was bounded to 16 concurrent operations. No outbox admission limit was bypassed because this setup used messenger publication directly, outside the measured transport read path.
- The comparison used the current messenger's full-history `get_messages` strategy and transport incremental polling against the same resources. It did not compare two released binaries.
- Each full-history case had one excluded warmup and three measured reads. Each incremental case explicitly acknowledged the known fixture history, performed one excluded warmup, then measured seven polls. The test asserted that incremental polls downloaded zero historical bodies.
- p50 and p95 use nearest-rank sample quantiles. With three and seven samples, these are descriptive observations, not reliable production tail-latency estimates. The debug build ran on a shared development machine, without isolated CPU scheduling.
- All measured read phases had zero PUT, DELETE and session requests, zero retries and zero timeouts. Metrics count complete HTTP response bodies, excluding headers and TLS. The JSON output includes every method's total attempts and body bytes, plus aggregate queue wait. Aggregate queue wait is summed across concurrent requests and can exceed elapsed wall time.
- The 10,000-resource seed completed with 10,003 PUT attempts, three timed-out attempts and three retries. The subsequent read verified exactly 10,000 resources. Seeding took 186.24 seconds and is excluded from the read quantiles.
- This measures read and polling behavior. It does not run a funded swap, Lightning payment, settlement or end-to-end negotiation.

## Fixture and reproduction

The standard pubky-testnet helper gives its homeserver a fixed 10 MiB LMDB map, which is too small for this fixture. The benchmark uses the public pubky-homeserver 0.1.2 builder with its normal virtual map capacity, a newly created private temporary storage directory, local DHT bootstrap, generated identities and local signup tokens. No dependency fork or local source patch is needed.

Ports 6286 and 6287 must both be unused. The fixture probes both ports and fails before server startup if either is occupied. The upstream builder does not expose port or listen-address setters. Its listeners bind all interfaces and its published address is loopback. Signup tokens and administration credentials belong only to the generated fixture and are not logged. Existing services are neither stopped nor reconfigured.

From the swap repository:

```sh
cargo test -p pubky-transport --lib delivery_tests:: --locked -- --nocapture
cargo test -p pubky-transport --lib delivery_tests::local_homeserver_read_poll_benchmark --locked -- --ignored --exact --nocapture
```

Source: `pubky-transport/src/delivery_tests.rs`.

Structured measurement rows: [local homeserver measurements](benchmarks/local-read-poll-2026-09-28.json).

## Retention interpretation

Removing a local acknowledgment merely because its remote resource is absent permits that same prepared resource to be delivered again if it reappears. Absence-only or time-only tombstone deletion would weaken replay protection. Exact resource identities can be encoded more compactly, or retained in durable segments, without discarding that evidence. The measured journal size makes the current storage cost explicit; this change does not silently prune acknowledged history.


## Cold and reused iroh connections

The existing request-latency fixture passed on 2026-09-28. Each cold row measures 40 independent
endpoint/connection setups. Each warm row measures 40 requests after one excluded first request,
using one connection for 41 requests. The fixture reported the selected path explicitly.

| Envelope and path | Cold p50 ms | Cold p95 ms | Warm p50 ms | Warm p95 ms |
| --- | ---: | ---: | ---: | ---: |
| Root key, loopback direct | 51.298 | 132.661 | 5.116 | 21.575 |
| Root key, public relay | 330.194 | 437.445 | 69.015 | 116.525 |
| Scoped envelope, loopback direct | 45.741 | 90.833 | 4.308 | 14.571 |
| Scoped envelope, public relay | 360.920 | 544.269 | 84.515 | 143.067 |

These are transport echo requests. The scoped-envelope fixture does not perform the production
homeserver authorization lookup, so those rows are not end-to-end delegated-session latency.
Root-key direct requests require no message-storage calls. The test ran in a debug build on the
same shared development machine; public relay conditions and contention can change results.

```sh
cargo test -p pubky-transport --features iroh --lib request_latency --locked -- --ignored --nocapture
```

The local homeserver and iroh fixtures measure different operations. Do not divide their timings
to claim a measured end-to-end swap speedup. The live `negotiation_latency` example remains the
way to compare offer requests against one configured provider, and downstream mobile measurements
must include authorization, app lifecycle and the actual provider. Bitcoin confirmation and
Lightning settlement time are unaffected by these transport measurements.
