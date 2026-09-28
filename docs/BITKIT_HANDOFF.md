# Downstream handoff for reliable Pubky swap delivery

Status: upstream implementation handoff, based on code and downstream inspection on 2026-09-28. Use the exact revisions in the implementation PR and lockfile; run the downstream checks before opening dependent PRs. The wrapper, core and Android worktrees already contain unrelated uncommitted work. Preserve that work and coordinate commits with their owners.

The messenger prepared-message change is merged in [PR 19](https://github.com/coreyphillips/pubky-messenger/pull/19), following cleanup [PR 18](https://github.com/coreyphillips/pubky-messenger/pull/18). The swap lockfile pins messenger `4fff0ce2183f7273c0418801c262ed291a0a145a` (package 0.4.0), with no local override. Pin every pubky-swap crate to implementation revision `30c6a0ab0d553094644fd258708c04b2fa482456`. The following documentation commit does not change its code. Merge and CI status are linked from [the upstream tracker](https://github.com/coreyphillips/pubky-swap/issues/85).

The dependency order is pubky-messenger, pubky-swap, pubky-swap-boltz, bitkit-core, then bitkit-android. A dependency update alone will not enable the new delivery lifecycle in all callers. The wrapper currently makes individual rendezvous and exchange calls, and core has its own reconciliation loop.

## Upstream API and persistence changes

Read [the transport contract](transports.md) and [measured performance](transport-performance.md)
before updating callers. The implementation keeps existing settlement primitives and adds:

- Persistent `p2p::DirectRpcClient` and `SessionRpcClient`, with `new`, `request`, and `close`.
  Reuse connections. Keep account/scope authorization checks for delegated sessions.
- `Transport::unsigned_from_recovery`, `with_receive_journal`, and `with_outbox` for lazy DM
  authentication and identity-bound, exclusive journals. Storage must also be isolated by network.
- `send_with_scope(peer, &message.delivery_scope(), &message)` and synchronous
  `enqueue_with_scope` reserve stable encrypted bytes. A worker runs `process_outbox(now, limit)`.
- `poll_from` and `receiver` return `Inbound<SwapMessage>`. Persist the handled outcome before
  calling `inbound.receipt.acknowledge()`. Drop releases a lease for retry, including cancellation.
- `complete_scope` schedules exact owned resources after a safe terminal state. `reopen_scope`
  revokes cleanup after a reorg and schedules byte-identical republication if deletion may have
  overlapped. Recheck the current domain state before every cleanup batch.
- `request_stats()` counts actual message-storage attempts and body bytes, retries, timeouts and
  queue wait. SDK account, profile and follow calls are excluded.
- `SwapRecord` stores `client_quote`, `client_creation_started`, `client_creation_tip`, and
  `client_execution_ready`. Save the complete acceptance before acknowledgment; validate the
  contract, invoice and remaining execution window before setting readiness. Preserve the saved
  tip anchor when validating acceptance after restart.
- `Resume.invoice_pay_started_at_unix` carries the existing durable payment marker.
  `ClaimSink::payment_started` is fallible and must save it before submitting a reverse payment.
  `PaymentStatus::NotFound` means authoritative absence; `Unknown` remains ambiguous. Update
  exhaustive matches and custom backend implementations accordingly. An ambiguous resumed
  payment must not be submitted again merely because funding progress is still empty.

The CLI's negotiation operations have a total 60-second deadline. Expired, definitely unsent
creation intent can retire; ambiguous started intent stays recoverable. Endpoint close and
cancellation stop local request watchers without pretending an already submitted node payment
has been cancelled.

Retention is ten minutes for read-only exchanges and 24 hours after safe persisted completion
for creation/final DM resources. Status and acceptance recovery remain under the separate
30-day record policy. A successful PUT is not peer consumption. Never clear the whole peer
conversation to finish one swap. Outgoing capacity is 1,024 entries, at most 768 read-only,
with backpressure; the 16 MiB byte budget remains shared. Receive pending capacity is 32 per peer and 1,024 total. Exact acknowledged
identities remain retained and the JSON journal can grow; do not invent TTL pruning.

The receive journal format is version 2 and the outbox format is version 1. Corrupt, mismatched
or unsupported journals fail visibly. Preserve pending data when designing migration. The
receive journal contains decrypted pending payloads, while the outbox stores signed encrypted
resources. Both belong in protected storage and backup decisions.

## Validated upstream revision

Use this shared dependency source for `pubky-transport`, `swap-common`, `swap-config` and any
other workspace crate consumed downstream:

```toml
pubky-transport = { git = "https://github.com/coreyphillips/pubky-swap", rev = "30c6a0ab0d553094644fd258708c04b2fa482456" }
```

Preserve each caller's required features. The implementation was checked with locked workspace
tests and doctests, full-feature client tests, strict all-target client/provider Clippy, iroh
transport/provider tests, targeted journal/outbox tests and local homeserver lifecycle tests.
The local read/poll fixture and cold/warm iroh measurements are recorded in
[transport-performance.md](transport-performance.md). CI and the funded regtest must pass on
the final PR head before merge; use the tracker links to verify that result before downstream
integration. Local fixtures alone do not demonstrate complete funded swap or mobile behavior.

## 1. Update pubky-swap-boltz

Repository: `/Users/coreyphillips/Documents/testing/pubky-swap-boltz`.

- `Cargo.toml:44` pins pubky-transport, swap-common and swap-config to swap revision `0867de2ce94b8a2932a64372de4cd14aaa70040d`. Local patches start at line 69. Pin the merged swap revision consistently and remove development patches from published dependency resolution.
- `Cargo.toml:30` defines the rendezvous feature; `mobile` includes rendezvous, JNI and platform certificate verification. Keep the same dependency feature set in desktop and mobile validation.
- `src/provider.rs:163` admits requests through a queue of eight and carries request deadlines and cancellation. `run_inbox` at line 222 skips cancelled or expired requests, respects a closed response receiver, and discards a failed transport. Preserve these properties when replacing the exchange implementation.
- `src/provider.rs:271` performs rendezvous for each exchange, sends once through the transport and polls every 500 ms. Reuse the transport's durable outbox and acknowledged inbox. Keep one request ID through timeouts and reconnects. Retain peer connections or multiplexed sessions across exchanges rather than performing new rendezvous for every read-only request.
- `src/provider/session.rs:74` performs authorization and invokes the one-shot `p2p::session_request` at line 86. Integrate the persistent session API where appropriate and preserve authorization, network binding, deadlines and cancellation. A connection failure after transmission must remain an ambiguous outcome, never an automatic new logical request.
- Persist accepted quotes and creation intent before publication. On restart, resume the saved IDs and status lookup before allocating another swap. Only complete a quote or swap cleanup scope after its domain terminal record is durable. Read-only ephemeral scopes may expire independently.
- Add wrapper tests for cancellation before send, cancellation after possible send, reconnection using the same request ID, server restart, ambiguous acceptance followed by status recovery, and two concurrent swaps with the same provider. Keep pending requests when the bounded queue is full.

Acceptance: desktop and mobile features compile against the same merged swap revision; lost replies recover without another accepted swap; process restart preserves pending work and independent swaps remain unaffected by cleanup.

## 2. Integrate in bitkit-core

Repository: `/Users/coreyphillips/Documents/synonym/bitkit-core`.

- `Cargo.toml:40` pins pubky-swap-boltz at `d65ccf6881d7df7635b00e00f73a771e79f79918` with `default-features = false` and `mobile`. Local wrapper and swap patches start at lines 79 and 83. Replace them with the reviewed published dependency chain once available.
- `src/modules/boltz/pubky.rs:15` defines `PubkySwapConfig`; its provider timeout is 60 seconds at line 36. `configure_secret` at line 41 and the session constructor at line 58 need the new storage paths and durable transport initialization. Line 94 derives a delegated session identity. Do not put a new request journal in a location shared by different identities, networks or providers.
- `configure_provider` at line 123 binds identity, provider and network before `Store::open` at line 148 and bridge construction at line 156. Preserve that binding for both inbox and outbox journals. `prepare_switch` at line 188 and disconnect at line 196 must keep rejecting switches that strand pending funded work.
- `src/modules/boltz/listener.rs:181` reconciles native pending swaps sequentially on a five-second interval. The legacy reconciliation interval is 60 seconds at line 77, and interrupted creation recovery currently follows that slower cadence. Integrate notifications as wakeups and bounded per-swap work, while retaining periodic reconciliation after missed notifications, app suspension and reconnect. Claims, refunds and persisted broadcast decisions must remain serialized per swap.
- Extend `src/modules/boltz/pubky_tests.rs`: interrupted creation and restart coverage at line 394, unresolved switch handling at line 46, active creation at line 70, create/spend at line 214 and broadcast journaling at line 484 provide useful fixtures. Add ambiguous acceptance, transport expiry, durable retry, cleanup isolation, and reconnect tests using those domain records.
- `src/modules/boltz/backup.rs:77` expects a flat active-store location and traverses the root at line 91. Android now uses nested identity/network/provider stores. Update export and restore traversal and schema validation before claiming backups include the new stores or journals. Preserve wallet-derived key counters, claim and refund recovery data, creation records, replay protection and still-pending delivery records. Message retention must not delete domain records.

Acceptance: saved negotiations and funded swaps recover after process death; switching identity or provider cannot reuse another journal; backups either include the nested layout with tests or explicitly report it unsupported; public documentation does not claim recovery coverage that has not been implemented.

## 3. Build matching Android bindings and native libraries

- `src/lib.rs:2299` exports the Android Pubky networking bootstrap, including platform certificate verification and iroh JNI context. Keep this initialization before native network operations.
- `build_local_android.sh:25` builds armeabi-v7a, arm64-v8a, x86 and x86_64. It then generates Kotlin bindings from the actual library, packages matching native libraries, archives symbols and checks stripped libraries and 16 KiB alignment. Do not copy bindings without matching native libraries.
- Use the documented Rust 1.95.0 toolchain and JDK 21. JDK 21, NDK 28.2.13676358, Android targets, protoc and adb were available during inspection. The system Java default was 25, so select JDK 21 explicitly. Recheck toolchain availability at build time.
- Publish a distinct local development version with `LOCAL_BITKIT_CORE_VERSION`, then select that exact version in Android. Do not overwrite the earlier local package and assume Gradle has refreshed all native artifacts.

The existing core Android build script is the supported local artifact path. Verify repository guidance before executing wider build scripts; some older Android build scripts alter Cargo.toml and must not run alongside dependency edits.

## 4. Integrate and verify bitkit-android

Repository: `/Users/coreyphillips/Documents/testing/rust-trezor/github/bitkit-android`.

- `settings.gradle.kts:39` restricts the development core package to Maven Local. `app/build.gradle.kts:471` accepts `localBitkitCoreVersion`; `gradle/libs.versions.toml` currently selects `0.5.14-pubky-swap-boltz-local`. Keep dependency selection explicit and update generated API use against the matching artifact.
- `app/src/main/java/to/bitkit/services/PubkySwapInit.kt:7` loads the native library and synchronizes initialization. Retain initialization ordering when sessions are reused after resume.
- `app/src/main/java/to/bitkit/services/PubkySwapBridge.kt:22` caches configuration and a credential hash under a mutex. Cancellation disconnects at line 50. Preserve serialized switch/disconnect behavior while deciding whether ordinary request cancellation should end only the request or the entire reusable session.
- `app/src/main/java/to/bitkit/services/PubkySwapStorage.kt:9` isolates stores by identity, network and provider, and accepts legacy storage only when its binding matches. Put delivery state under this same scope and preserve stores during wallet wipe until coordinated domain recovery and cleanup are implemented.
- `app/src/main/java/to/bitkit/repositories/PubkyRepo.kt:312` configures the managed swap bridge, preferring an imported identity where present; the managed path at line 336 currently uses the managed secret. Recheck the current code when implementing delegated session integration, since older documentation describes a different transitional flow.
- `app/src/main/java/to/bitkit/services/BoltzService.kt:240` builds provider, Electrum and storage configuration; line 293 limits the implemented route to mainnet and regtest and requires an explicit provider on regtest. Do not silently route an unsupported network to mainnet.
- Savings Swap remains disabled by default in `app/src/main/java/to/bitkit/data/SettingsStore.kt:143`, with no provider configured by default. Keep enablement and provider selection explicit until the new path is validated.
- `app/src/main/java/to/bitkit/repositories/SwapRepo.kt:45` uses a 65-second quote deadline, a 30-second terms TTL and a 30-second claim timeout. Do not reduce the UI deadline below the core's 60-second request deadline merely because average latency improved. Expose cancellation and recoverable ambiguous outcomes accurately.
- Review `PubkySwapBridgeTest`, `PubkySwapConfigTest`, `PubkySwapStorageTest`, `PubkyRepoTest`, `SwapRepoTest`, `WipeWalletUseCaseTest` and `SavingsSwapQuoteTest` after changing lifecycle or error mappings.

The documented Gradle checks in `docs/pubky-swaps.md:66` are:

```sh
./gradlew compileDevDebugKotlin compileMainnetDebugKotlin assembleMainnetDebug
./gradlew testDevDebugUnitTest
./gradlew detekt --rerun-tasks
```

`AGENTS.md:168` requires `just compile`, `just test` and `just lint` before the final PR update or push for code changes. The checkout has `Justfile` definitions. Run these mandatory checks in addition to any focused tests needed for the change.

For packaged bootstrap only, select the single instrumentation method `to.bitkit.services.PubkySwapNativeTest#packagedBridgeInitializesAndroidNetworkingAndNativeBindings` using the `connectedDevDebugDeviceIntegrationAndroidTest` task. The second method in `app/src/androidTest/java/to/bitkit/services/PubkySwapNativeTest.kt:43` requires an installed Pubky Ring APK with matching signature permissions. Running the whole class includes that prerequisite. Use a dedicated emulator. The bootstrap test creates no wallet or swap and does not establish swap settlement.

Acceptance: all four ABI artifacts and bindings match; initialization and reconnect work on a device; app process death during negotiation recovers the same swap; one swap's cleanup cannot interrupt another; existing Boltz routes and funded recovery remain intact.

## 5. Validation gate and benchmark requirements

The tracked regtest item is [pubky-swap issue 40](https://github.com/coreyphillips/pubky-swap/issues/40). Its older description should be reconciled with the workflow now present.

- The inspected `.github/workflows/regtest.yml` supports pull requests, manual dispatch and weekly runs. Its PR path filter now includes `pubky-transport/**` and `swap-config/**`, plus dependency files. Superseded runs are cancelled so the final head receives the validation.
- The required job should be the real `full regtest integration tests` job, including HTLC behavior, spend history, reorg handling, wallet behavior and reverse, submarine and taproot flows using LND. Main branch protection was absent and repository rulesets were empty during inspection. Require the final commit's successful run in the merge process; do not treat an older green commit as validation of the merged work. Repository branch protection was not changed by this implementation.
- The last observed successful reference run was [35600418780](https://github.com/coreyphillips/pubky-swap/actions/runs/35600418780), for commit `51493f872961a2123ce2651613d67b1278e8e046`. This is a historical reference only.
- Docker 29.5.3 and its daemon were available. Existing `bitcoin`, `electrum` and `lnd` containers were live, with names or ports overlapping the repository stack. Do not run fixed-name compose teardown or regtest setup against them. Use CI or a separately named stack with distinct ports and data directories.
- A local homeserver benchmark does not require Docker. Messenger's `pubky-testnet` fixtures create temporary identities and homeservers. `tests/test_prepared_messages.rs` covers persisted prepared resources and restart. The older `tests/test_delete_methods.rs` also contains external tests requiring local key files, so select the local fixture tests rather than running that file unfiltered.
- `pubky-transport/src/session_rpc.rs:658` has a local DHT and raw-public-key TLS fixture on ephemeral loopback ports. `p2p.rs:933` has an ignored cold/warm latency test whose relay branch depends on external relay reachability. Keep public relay results separate from repeatable local measurements.
- Benchmark cold and warm direct sessions against local homeserver delivery, reporting p50/p95 wall time and LIST/GET/PUT/DELETE/session attempts and bytes. Include fresh history, old history, restart with pending work, ambiguous response loss, rate limiting, unavailable peer, and two active scopes. Report injected delays separately from measured network latency. Verify that cleanup reduces old resource listings without removing pending or recovery state.

Downstream files, existing live services, credentials and wallet data were left untouched. No downstream build is implied by this document. Use the integration PR checks for upstream regtest evidence, then repeat the relevant tests after downstream changes.

## Completion checklist for the next integration

- Pin all swap crates to one reviewed revision, then pin the wrapper in core. Remove local
  overrides from the published dependency graph and verify a clean locked build.
- Add persistent connection ownership, stable request IDs and domain intent recovery in the
  wrapper. Test restart and cancellation before and after possible publication.
- Carry durable receipt acknowledgment, payment-start markers, safe cleanup and reorg reopening
  through the core adapter. Preserve claim/refund serialization and broadcast evidence.
- Fix or explicitly limit nested-store backup support before describing it as complete.
- Build matching Kotlin bindings and native libraries for every ABI, selecting a distinct local
  package version. Run core checks and Android's required compile/test/lint commands.
- Run device lifecycle and two-active-swap scenarios on an isolated regtest setup. Compare live
  application quote/create/status latency separately from the upstream transport fixtures.
- Link final dependency revisions, CI runs, benchmark methodology and any remaining limitations
  in the downstream PRs. Keep the tracking issues current as each layer lands.
