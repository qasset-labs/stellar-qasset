# SAC authority demonstration threat model

Scope: the two fresh disposable Testnet assets in the deployment record,
their fixed SAC administrators, the fresh registry and recorded evidence.
The current QCTL issuer was locked in the explicitly approved fresh run.
This is a narrow authority experiment.

ML-DSA-65 runs inside Wasm through unaudited RustCrypto `ml-dsa` 0.1.1,
not CAP-87 host verification. No production security assurance follows from
successful functional tests.

## Assets and trust boundaries

The protected asset is permission to change a holder's authorization flag
through SAC `set_authorized`. The operator's fresh seed must stay outside
the repository. Host authorization binds the credential to its network,
nonce, expiry, contract, function, arguments and invocation tree.

Classic issuer account authority, transaction-envelope authority, declared
registry policy and custom-account authority are separate boundaries.
The registry is not consulted by `__check_auth`; changing a declaration
cannot add an authorization path to the fixed administrator contract.

| Actor | Attempt | Observed control or residual limitation |
| --- | --- | --- |
| Operator with the enrolled ML-DSA key | Authorize a holder | Accepted on-chain for both SACs. Local tests also clear authorization. |
| Unregistered or corrupt signer | Forge administrator consent | Real signatures and malformed credentials are exercised locally; corrupted and wrong-network credentials reject in live enforced simulations. |
| Relay | Change signed arguments, replay, or compose an unrelated invocation | Argument and composite-tree tests reject locally. Live replay rejects in enforced simulation. Exact signed operations can be relayed. |
| Classic issuer key holder | Mint through classic Payment or change trustline flags after SAC handover | Both paths succeed for QEXP. QCTL classic Payment rejects with txBAD_AUTH after its issuer lock. A separate QCTL SetTrustLineFlags probe was not run. |
| Quantum adversary able to forge Ed25519 | Use a remaining issuer, registrar, transaction source or fee-payer path | Residual QEXP, registrar and fee-payer paths remain visible; retiring QCTL's issuer does not remove those paths. |
| Registry administrator | Misdeclare policy or replace quorums | Registry output remains `DECLARED`; revision comparison detects a changed snapshot. The guarded write API rejects stale revisions atomically; the legacy unconditional setter remains available. |
| Evidence editor | Change statuses, citations, input hashes or decoded state | Checksums and independent derivation reject the tested edits, including status edits with a recomputed checksum. |
| Compromised RPC/Horizon service | Fabricate read responses or historical simulation transcripts | Trusted endpoints remain a dependency. Checksums provide consistency, not an authenticated ledger-state proof. |

## Assumptions

The Soroban host correctly forms authorization payloads and enforces nonce,
expiry and invocation matching. The observed SAC implementation preserves
the documented administrator semantics. Local build artifacts match the
deployed executable hashes, as checked against live code bytes. The OS
random generator and machine holding disposable private keys are trusted.

The operator key is immutable. Availability depends on retaining that seed
and maintaining contract storage. An expired entry must be restored with
its original state; expiration is not an authorization or rotation mechanism.

## Exclusions

Production funds, Mainnet issuers, issuer recovery, generalized wallets,
mint/clawback administration, fee-payer replacement, consensus security,
side-channel hardening, external cryptographic audit and a complete asset
scanner are outside this experiment. The Binius64 and RoKoko work is separate
research and is not integrated into this administrator.

The gated lock, classic Payment rejection before inclusion and subsequent
ML-DSA transaction were exercised live. This establishes the recorded operation
outcomes, not comprehensive testing of every classic issuer operation.
A live repeated declaration advanced QEXP revision 3 to 4; the separate
verifier returned STALE for its 16 paths and exited nonzero. The current
assessment uses the refreshed revisions. Historical simulation transcripts
remain RPC observations rather than authenticated ledger receipts.

Evidence editors may recompute every checksum. Verification therefore checks
credential semantics and raw diagnostic causes, configuration/ledger consistency,
issuer signatures and tool provenance in addition to checksums. Schema v1 is
accepted only for the exact immutable historical assessments. Changed live
configuration and unavailable evidence have distinct structured results.
