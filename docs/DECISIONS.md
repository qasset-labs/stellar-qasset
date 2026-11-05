# Architecture decisions

These records describe the coherent design in [architecture](ARCHITECTURE.md).
"Accepted design" does not imply implementation, appointment or hosting controls.
A future decision records context, alternatives, consequences, accountable owner,
status, date and acceptance evidence. No owner is fabricated below.

## ADR-001: declarations remain separate from verified authority

Status: implemented boundary; 2026-11-05 documentation baseline.

Context: tenants can label algorithms and roles without proving actual asset
control or signer code. A score-only gate would permit invented declarations to
authorize operations.

Decision: expose declared QS predicates and `Unverified` assessments; verified
APIs reject until a supported complete/fresh adapter is independently validated.
Do not promote a declaration via an admin flag or unauthenticated RPC response.

Alternatives: trust tenant metadata; certify arbitrary bytecode; use a trusted
attester as if it were on-chain verification. These change or fail the claim.

Consequences: useful intent analysis is available now. Off-chain tested assessments
and any future signed attestations have explicit scope/trust. Classic-state
verification inside contracts remains an unresolved integration.

## ADR-002: immutable scoped SAC administrator for the reference experiment

Status: implemented; production lifecycle replacement required.

Context: direct SAC administration can invoke a contract's auth policy, whereas
an outgoing wrapper method can receive direct-invoker authority without running
its own `__check_auth`.

Decision: fixed SAC/key, exactly one supported `set_authorized` auth context and
no outgoing SAC calls, rotation, upgrade or alternate entry point.

Alternatives: broad admin signer, general wallet or dynamic wrapper. Each needs
additional policy/caching/direct-invoker analysis.

Consequences: narrow, testable authority. Genuine operator signatures cannot mint
or hand over the SAC. Key loss/compromise has no contract rotation/migration
escape. This constraint prevents adopting the prototype as a production lifecycle.

## ADR-003: production monitoring requires durable indexing

Status: accepted target design; unimplemented.

Context: the registry cannot enumerate all tenant storage; RPC history is finite;
issuer/admin drift and historical comparisons outlive normal RPC retention.

Decision: archive raw ledger/evidence bytes and maintain replayable relational
projections with ledger checkpoints, reconciliation and explicit gap/freshness
status. Filtered event APIs are convenience sources, not the whole authority graph.

Alternative: poll latest state only. Adequate for a finite PoC but cannot establish
unbroken history or reproduce missed intermediate changes.

Consequences: database/history budgets, schema migrations and operations ownership
are release dependencies. Index data grants no contract approval authority.

## ADR-004: exact units and no invented fee model

Status: accepted target design; current contracts perform no token accounting.

Decision: decimal-string external amounts, checked integer base units, token-specific
decimals and classic-capacity checks. Reject excess precision rather than round.
Separate XLM payer fees from principal; there is no Q-Asset token or protocol fee.

Alternatives: floating-point user amounts or copying unrelated fee/share constants.
These introduce accounting ambiguity without repository economic justification.

Consequences: consumers need explicit serialization and range/error handling.
Any service-charge model needs a new economic decision and signed amount behavior.

## ADR-005: keep seed recovery conditional and independently gated

Status: implemented unavailable boundary; target recovery unresolved.

Context: native proof execution, scalar/key math, transport and raw Wasm feasibility
are separate from complete quantum knowledge/privacy and Soroban account authority.

Decision: retain disabled seed authentication. Require exact backend/statement/
parameter review, feasible complete verifier, prior enrollment/revocation, finalized
classical retirement where needed, replacement possession and atomic one-time
consumption. Restrict the current PQ counter to its own action.

Alternatives: lower-security parameters, pairing compression or a hidden trusted
approval gateway. None preserves the intended claim without a different explicit
trust model.

Consequences: assessment and scoped enforcement proceed independently. Research
results cannot promise a production recovery delivery date.

## ADR-006: transaction outcomes are durable state

Status: accepted target design; current runner is a finite demonstration.

Decision: journal exact envelopes/hashes before submit, serialize source sequences,
reconcile unknown outcomes and consume treasury intent nonces on-chain. Distinguish
simulation, enqueue/rejection, included failure and confirmed effects. Reset uses
a new generation even if passphrase is unchanged.

Alternative: rebuild/re-sign on timeout or treat `NOT_FOUND` as failure. This can
repeat economic effects or merge reset histories.

Consequences: operation journal, historical lookup and explicit recovery UI are
required for writes. Database idempotency alone does not solve on-chain duplicates.
