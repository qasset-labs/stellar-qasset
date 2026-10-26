# Durable local recovery evidence

2026-10-20. This public-fixture experiment extends the [sequential ceremony](SCALAR_RECOVERY_EVIDENCE.md) with local persistence and concurrent consumption. It uses the same real original-root proof and native ML-DSA-65 replacement-possession verification. The proof has deliberately insecure eight-round parameters. This is a local state-machine experiment, not a production recovery protocol, Stellar deployment or independent security audit.

The earlier ceremony returns an immutable updated state, which a caller could discard and reuse the old unconsumed input. The new `DurableRecoveryStore` stores the complete typed policy, active key, epoch, local ledger, consumed flag and monotonic revision in SQLite. Real proof and possession verification run outside the write transaction. Before committing, the adapter acquires `BEGIN IMMEDIATE`, reloads state, compares the exact canonical snapshot and revision, checks current policy/expiry, then atomically rotates the key, increments the epoch, consumes eligibility and inserts a unique request receipt. Every fixture policy or ledger update advances the revision, including no-ops and revoke–reenable changes. A changed ledger also invalidates an in-flight snapshot; a fresh attempt must satisfy the new expiry window.

The separate [execution record](durable-recovery-research.json) contains nine checks:

| Experiment | Required observed result |
| --- | --- |
| Two independent processes both verify the actual proof and replacement PoP before competing | Exactly one commit, one explicit snapshot conflict, one receipt |
| Replay from a newly started process | Persisted consumed state rejects |
| Initialize an existing consumed database | Exclusive creation rejects |
| Revoke eligibility after verification, before commit | Snapshot conflict, no rotation or receipt |
| Reverse retirement after verification, before commit | Snapshot conflict, no rotation or receipt |
| Advance local ledger beyond expiry before commit | Snapshot conflict, no rotation or receipt |
| Revoke then reenable before commit | Revision detects the intervening change despite identical final policy |
| Abort receipt insertion after the state UPDATE | The entire transaction rolls back, including epoch and consumption |
| Remove the abort trigger and verify again | A fresh real-proof attempt commits |

Eight actual proof-and-possession verifications precede those commit attempts. The runner pauses independent subprocesses through a logging handler only after native cryptographic verification has completed. It never substitutes an accepting verifier, proof callback or caller-created authorization ticket. Receipt failure uses a SQLite trigger raising `ABORT` after the state update. This tests transaction rollback; power-loss durability was not experimentally tested.

Twelve additional unit tests cover strict state decoding, full unsigned 64-bit epoch preservation, monotonic ledger values, revision overflow, initialization, persistence and crypto failure leaving no writes. No mocked verifier returns a positive authorization in these tests. Source and binary hashes bind the separate experiment record to its inputs; routine validation checks record lineage without rerunning the expensive proofs.

Reproduce from the repository after retaining the original proof and building the two native tools:

```sh
python3 scripts/run_durable_recovery_research.py
python3 -m unittest discover -s scripts -p 'test_durable_recovery_research.py'
```

All witnesses and signing keys are published fixtures. The original proof is 83,779,038 bytes and the verifier is an off-chain native executable. Current eligibility, classical retirement and ledger values are operator-controlled model inputs, not observed network facts. `change_model_inputs` is an operator-only test control without product authentication. All writers must follow this adapter's revision discipline. A malicious operator, database/binary modification, trusted-file mutation or restoring an old filesystem snapshot can defeat this local model. Receipts bind the request and local states; they are not network attestations or independent proof certificates. A commit error can leave the caller uncertain, so callers must inspect persisted state before retrying.

The experiment supports the concurrency and local transactional invariants above. It does not solve the compact proof backend, quantum knowledge assumptions, Soroban verifier cost, on-chain classical retirement, external authority/cache lifecycle or a complete asset adapter. The legacy-seed contract remains disabled.
