# Compact verifier successor and Soroban cost evidence

Updated 2026-10-20. The successor preserves the original 539,888-byte Binius
leaf proof, transcript, 232 queries, rate, masking and all 131,072 padded
constraints. It improves representation and implementation; it does not approve
quantum security or supply a production recovery account.

## Corrections implemented

The exact original 2,714,051-byte preprocessing artifact is transcoded to
**1,286,664 bytes**, a 52.6% reduction. Canonical bounded ULEB32 stores operand
counts and packed wire indices. The transcoder expands back to byte-identical
original preprocessing. The loader checks a compiled artifact SHA256 before
nested decoding, rejects nonminimal/overflowing integers and trailing bytes,
and preserves every constraint, source identity, oracle, field basis and FRI
parameter. No caller-selected circuit hash is accepted.

The successor moves the unpadded outer constraints into an exactly reserved
padded vector, retaining the original 82,373 count and dimensional metadata.
This removes a duplicate vector. A metadata-only object cannot be exported as a
complete unpadded circuit: the retained-circuit getter returns None and the old
export accessor fails closed. All verifier consumers still use the complete
padded vector. The full constraint fingerprint remains
`0d289309fc17e9b8e6e2d6a4b99d2cf4350547864fde5f79d7eb06929ee31938`.

An explicit optional arithmetic strategy replaces a 49,152-byte Frobenius lookup
table with repeated application of the existing field squaring operation. It
preserves the upstream inversion addition chain and zero convention. Across
**646 deterministic field vectors**, the new Wasm arithmetic matches both the
unchanged native reference and original Wasm table implementation, including
basis vectors and inverse/multiplication identities. These are equivalence checks,
not a formal arithmetic or quantum-security proof; the fork needs external review.

Size-oriented compilation, LTO, external input buffers and immutable source-hash
constants remove embedded proof/setup and runtime source-text hashing. Native
verification and actual optimized/raw Wasm checks accept the unchanged proof and
reject altered actions, corruption, trailing/truncated/empty proof, scalar changes
and changed/oversized/trailing setup. Allocation bounds and one-time buffer use
are tested. The source package contains exact provenance and a local reproducer.

## Scope of the size and memory result

The complete raw module is **127,068 bytes**, below the refreshed **131,072-byte**
cap by 4,004 bytes. The successor also unifies loader SHA256 with the SHA2
version already used upstream, avoiding a duplicate implementation. Its ABI is a
bounded raw input slab, not the Soroban contract ABI. The canonical proof uses
**27,852,800 bytes of linear memory**, down from 39,911,424 in the earlier fixture.
Actual optimized checks have no traps, imports, float operators, SIMD or threads;
module memory is capped at 640 pages (40 MiB). Artifact sizes and hashes are in
[successor evidence](verifier-next-research.json).

This result closes the earlier raw-module size blocker. It does not establish
contract-code admission, complete transaction transport, Soroban memory accounting
or verification CPU fit. A separate mathematical key-binding component supports
strict generic Ed25519 points, but proof fixtures still pin the published RFC8032
identity. Generic account-policy integration is not silently inferred.

## Actual Soroban ABI measurements

A separate research contract calls the same verifier through the actual SDK ABI.
Its compact loader checks host SHA256 of the exact immutable Bytes against the
compiled artifact digest before copying or private decoding. This avoids hashing
megabytes again in software. Decoder checks remain intact. Short static diagnostic
strings reduce error-reporting code without weakening validation.

The current SDK wrapper is **183,090 bytes**, larger than the code cap. To measure execution despite
that independent admission failure, the harness **explicitly overrides only
registration resource limits**, then restores explicit call CPU/memory limits.
This is a local diagnostic, not an admitted network transaction. Large setup/proof
host objects are created outside the measured call; ledger staging and complete
transport costs remain excluded. The harness does not mock proof verification or
authorization, change account keys or enable a recovery backend.

The canonical proof exhausts **400 million metered instructions**. A further
local diagnostic also exhausts **12 billion instructions / 256 MiB configured
budget** without completing verification. Its measured prefix uses 25,135,107
memory bytes and 12,000,657,199 metered instructions; this is not a complete
verification cost. Measurements use SDK25's local cost model, not a live
protocol29 simulation. This is an execution failure, never evidence that a
valid proof was cryptographically rejected. No successful complete Soroban
verification or full exact verification cost is claimed.

[SDK execution evidence](binius-soroban-research.json) records the exact current
module and call. Additional diagnostic records preserve the expanded-budget
measurement. The registry, patched counter and disabled seed account retain their
previous binaries; no transaction or deployment was submitted.

## Reproduce and remaining work

```sh
python3 scripts/check_verifier_next_evidence.py --require-artifacts
python3 tools/recovery-key-binding/scripts/verify_provenance.py
python3 tools/binius-verifier-next/scripts/run_next.py --help
python3 scripts/run_binius_soroban_research.py --help
```

Source/record checkers do not rerun proofs. The successor's runner actually builds
and executes native/Wasm checks using retained public fixtures and locked offline
Cargo dependencies. The SDK runner separately compiles and measures a real ABI;
`--allow-oversize-registration` explicitly selects the local admission override,
and `--expanded-diagnostic` selects a budget that is not a network setting.

The refreshed [read-only Testnet snapshot](verifier-network-limits.json) reports
131,072-byte code, 132,096-byte transaction, 400M instruction and 40 MiB memory
limits. CLI26 reports protocol29, so this is a partial snapshot, not full protocol
compatibility. The [official resource guide](https://developers.stellar.org/docs/networks/resource-limits-fees)
explains how to refresh settings. The original historical snapshots remain intact.

A follow-up research tool (`tools/binius-verifier-profile-research/`) timed the
pinned verifier's own pre-existing `tracing::info_span!` instrumentation,
unmodified, over 8 native release-build runs against the same canonical
fixtures. Reading the call site directly (`crates/verifier/src/zk_config.rs:153-170`,
`ZKVerifier::verify`) shows two sequential, non-nested steps: a cheap inner
structural-IOP pass that only *records* claims through a wrapping channel
(3-5% of wall time, despite including a sub-span literally named "PCS
Opening"), followed by the real outer Spartan verification plus the actual
BaseFold/FRI opening (94-97% of wall time), which upstream leaves otherwise
unspanned. The dominant cost is this second, currently undecomposed step, not
the structural IOP's bit-operation reduction phases. See
[verifier profile evidence](verifier-profile-research.json) for the full
finding, per-run data, and exact source citations. This narrows where a
reduction effort should focus; it does not itself reduce instructions.

A section-size breakdown of the actual 183,090-byte SDK wrapper against the
127,068-byte raw module (which fits the cap) found the 56,022-byte gap
concentrated in the code and data sections (+38,913 and +16,438 bytes), not in
Soroban's small required metadata sections. Checking the two likely quick fixes
ruled both out: both builds already use identical, maximally size-aggressive
Cargo release flags, and `soroban-sdk` 25.3.2 defines no default features to
disable beyond the `alloc` feature the verifier's heap use already requires.
The gap is inherent `soroban-sdk` contract-entry-point glue (host-function
bindings, Env/Val/XDR marshaling, the guest allocator), not a tuning oversight.
See [SDK code-size breakdown](sdk-code-size-breakdown.json). Closing it further
would mean hand-rolling the contract ABI without `soroban-sdk`, a larger
undertaking not attempted here, and would not alone fix the larger
CPU-instruction gap below.

Next work must reduce SDK code and select a fully measured verification/transport
architecture, focused on the Spartan/BaseFold-opening step identified above.
Native hashes and immutable preprocessing caching may help, but no unmeasured
acceleration is promised. Further decomposing that CPU cost below tracing-span
granularity would need a real sampling profiler (perf or valgrind/callgrind);
neither is installed in this environment, and installing one requires `sudo`,
which was not pursued without the user's explicit go-ahead.

A pure-userspace, signal-based sampling profiler (`pprof`, no `sudo` or
`perf_event_open` needed) then got past that limit directly, once a
frame-pointer build setting it needs was found and scoped to the research
tool alone. Across 8000+ sampled stacks, roughly 71% fall inside
`binius_spartan_verifier::wiring`'s MLE-evaluation functions
(`evaluate_segment_wiring_mle`, `evaluate_wiring_mle_public`), not the
BaseFold/FRI Merkle-and-hash machinery one might expect (under 5% combined).
Reading the pinned source confirms this is structurally expected (cost scales
with constraint count times operand fan-in), plus one unconfirmed candidate
inefficiency (an `r_x`-side cache exists with no equivalent `r_y`-side cache).
See [verifier wiring-hotspot evidence](verifier-wiring-hotspot-research.json).
This narrows the hotspot to function granularity; it does not close F-01, and
no change was made to the pinned verifier to act on it.

Binding the trusted account key, canonical request, current entitlement,
revocation, replacement possession and atomic one-time transition is additional
work. The seed account remains disabled until independent quantum knowledge/ZK
and implementation review, resource feasibility and the complete lifecycle pass.
See [current implementation status](RECOVERY_IMPLEMENTATION_STATUS.md).
