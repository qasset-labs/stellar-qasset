# Proof-of-concept handoff: status and remaining work

Current release: see `QASSET_POC_EVIDENCE.md` and `POC_TEST_REPORT.md`.
The remediation request superseded the earlier unchanged-registry and
uncommitted-baseline restrictions for the guarded write API and reproducible
source snapshot. The historical instructions below describe the earlier phase.

Historical starting instructions. Continuation results, live receipts and
completed gated work are now recorded in `POC_TEST_REPORT.md` and
`QASSET_POC_EVIDENCE.md`. The "never built" status below describes the handoff
point, not the current working tree.

Recorded 2026-10-25. This document lets another engineer continue the
focused authority-coverage proof of concept without re-deriving earlier
decisions. Read it fully before changing anything.

## 1. What the proof of concept must demonstrate

A post-quantum signature alone does not secure a Stellar asset if a
classical issuer or administrator keeps an independent authorization path.
Q-Asset identifies those paths, supports stronger authorization where the
platform allows it, and produces reproducible evidence of the resulting
coverage.

Concretely, the finished work shows:

1. One SAC administrative operation (`set_authorized`) protected by an
   ML-DSA-65 credential through a Soroban custom account.
2. Two disposable Testnet assets:
   - `QEXP` (exposed): SAC administration moved to the ML-DSA contract, but
     the classic issuer can still sign, and still mints with a plain classic
     payment. The evidence must report that path as `EXPOSED`.
   - `QCTL` (restricted): same handover, then the disposable issuer is locked
     (master weight 0, no other signers), only behind an explicit
     confirmation gate. The classic mint attempt must then fail.
3. The existing `qasset-registry` reused unchanged as the declared policy
   store. A declared ML-DSA policy must never be reported as verified.
4. A narrow analyzer that reads live Testnet state plus the registry policy
   and writes `evidence/qasset-authority-assessment.json`.
5. An independent evidence verifier that recomputes the assessment from
   recorded inputs, detects tampering, and marks the evidence `STALE` after
   a registry policy revision.

## 2. Current progress

### Done and committed

- Commit `b92a0a7`: `docs/POC_BASELINE.md` (full reproduced baseline: toolchain,
  Testnet protocol 29, 67 Rust tests, 81 Python tests, 5 evidence checkers,
  Wasm hashes, live deployment checks, carried-in findings, registry
  limitations) and the previously untracked
  `tools/binius-soroban-research/research-scripts/wasm_sections.py` with its
  README.

### Done, not yet compiled or committed

`contracts/qasset-sac-admin/` (new crate, picked up by the workspace glob
`contracts/*`):

- `Cargo.toml`: `soroban-sdk` (workspace), `ml-dsa = "=0.1.1"` with
  `default-features = false`, `testutils` in dev-dependencies. Same pattern
  as `contracts/pq-recovery-demo/Cargo.toml`.
- `src/lib.rs` (153 lines): `QAssetSacAdmin`.
  - `__constructor(sac: Address, operator_key: Bytes)` stores the SAC and a
    1,952-byte ML-DSA-65 public key; rejects a malformed key.
  - Getters `sac()`, `operator_key()`, `protected_function()`.
  - `__check_auth` accepts exactly one `Context::Contract` whose contract is
    the configured SAC, whose function is `set_authorized`, with exactly 2
    arguments. Anything else (empty, multiple contexts, other functions such
    as `mint`/`clawback`/`set_admin`, other contracts, contract creation)
    returns `UnsupportedAuthContext` before any signature work. It then
    verifies a 3,309-byte ML-DSA-65 signature over the host payload
    (`signature_payload`) with domain context `qasset-sac-admin-auth-v1`.
  - Errors: `BadKeyLength=1`, `BadSignatureLength=2`, `InvalidSignature=3`,
    `UnsupportedAuthContext=4`.
  - Deliberately absent: upgrade, key rotation, any other admin function, and
    any entry point where the contract itself calls the SAC (that call would
    be authorized as direct invoker and would bypass `__check_auth`).
- `src/test.rs` (537 lines): adversarial tests using real ML-DSA signatures
  over real Soroban authorization payloads (`set_auths`), not
  `mock_all_auths`. `mock_auths` appears only for the issuer's one-call
  `set_admin` consent during setup, and in the stale-authority test.
  Tests written:
  - handover sets the contract as SAC admin; handover without the current
    admin's authorization fails
  - valid signature sets and clears authorization (positive)
  - missing authorization; corrupted signature; unregistered key; signature
    under the recovery candidate's context `qasset-pq-auth-v1`; wrong
    network id; credential signed for different arguments
  - valid signature for `mint` and for `set_admin` rejected by policy
  - valid signature for a second SAC also administered by this contract
    rejected
  - replay of a consumed entry; expired entry
  - previous administrator's authority stale after handover
  - nested tree through a `Relay` test contract rejected; relayed
    single-context submission accepted only for the exact signed arguments
  - direct `try_invoke_contract_check_auth` matrix: empty, duplicated,
    `mint`/`clawback`/`set_admin`/`transfer`, other contract, 3 arguments,
    self address, `CreateContractHostFn`; then wrong payload, short
    signature, wrong key
  - constructor rejects a 32-byte key

**The crate has never been built.** The first run of
`cargo test -p qasset-sac-admin --offline` was interrupted. Expect some
compile fixes. Likely spots:
- `IssuerFlags::RevocableFlag` (it is an alias of `xdr::AccountFlags`;
  check the variant name) and `asset.issuer().set_flag(...)`.
- `MockAuthInvoke` into `xdr::SorobanAuthorizedInvocation` conversion
  (`(&invoke).into()` may be needed), and the signature `Val` to `ScVal`
  conversion in `entry()`. Copy whatever
  `contracts/pq-recovery-demo/src/test.rs` does in its `auth_entry` helper,
  which is known to compile.
- `try_invoke_contract_check_auth` error mapping in `check()`.
- `StellarAssetClient::authorized` and `try_*` method names.
- Unused imports (`Ledger as _`, `ContractExecutable`) depending on fixes.
Fix the tests, not the security behavior. If a test exposes a real policy
gap, fix `lib.rs` and record it in `docs/POC_SECURITY_FINDINGS.md`.

### Not started

Everything in section 4.

## 3. Decisions already made (do not reopen)

- **Integration: Option A**, a generic SAC administrator via
  `__check_auth`, not a wrapper contract with its own entry points.
  Reason: the SAC calls `require_auth` on its admin, so a custom account
  sees every administrative call and can refuse all but one; a wrapper
  would add a second authority surface.
- **ML-DSA-65 is verified inside the contract's Wasm** with RustCrypto
  `ml-dsa` 0.1.1 (unaudited). Testnet is protocol 29, so the CAP-87 host
  functions (`verify_sig_ml_dsa_*`, Protocol 30, Testnet vote 2026-11-03)
  are not available. Every document must say this plainly.
- **Fresh key, never a fixture.** `tools/pq-demo` derives all keys from a
  public root (`[0x42; 64]`); anyone can sign with them. They must not
  protect the PoC authority.
- **Registry unchanged.** No new semantics, no compare-and-set. The lack of
  revision compare-and-set and the classical registry admin are documented
  limitations.
- **Only `set_authorized` is protected.** Mint, clawback and set_admin are
  deliberately refused by the admin contract (permanently, for this PoC).
- **Transaction source and fee payer stay Ed25519.** This is a protocol
  property and is reported, not hidden.

## 4. Remaining tasks, in order

### Task 1. Build and test the contract

```sh
cargo test -p qasset-sac-admin --offline
cargo test --workspace --offline          # all 67 earlier tests must still pass
cargo build -p qasset-sac-admin --release --target wasm32v1-none --offline
sha256sum target/wasm32v1-none/release/qasset_sac_admin.wasm
```

Record the Wasm size and hash. Check the size against the Soroban code limit
(131,072 bytes; `pq_recovery_demo.wasm`, which embeds the same verifier, is
63,267 bytes, so this should fit). If simulation on Testnet later exceeds
the CPU budget, record it as a finding rather than weakening verification.

### Task 2. Fresh-key signer tool

New crate `tools/qasset-sac-signer/` (own `[workspace]` table, like the
other `tools/*` crates; do not add to the root workspace members).

- `keygen --out <path outside repo>`: 32-byte seed from the OS RNG
  (`getrandom` or `/dev/urandom`), writes the seed file with mode 0600 and
  prints the 1,952-byte public key as hex. Refuse to write inside the
  repository tree.
- `public --key <path>`: prints the public key hex.
- `sign --key <path> --payload <64 hex chars>`: prints the 3,309-byte
  ML-DSA-65 signature hex, using context `qasset-sac-admin-auth-v1` and
  `ml-dsa = "=0.1.1"` (same signing call as the tests:
  `sign_deterministic(digest, context)`).
- Default key location: `~/.config/qasset-poc/sac-operator.seed`. Add a
  `.gitignore` guard for `*.seed` anyway.
- Unit test: a signature it produces verifies with the contract's exact
  verification code path (or at least with `verify_with_context` and the
  same context).

### Task 3. Testnet demonstration script

`scripts/qasset_poc_testnet.py`, Python `stellar-sdk==14.0.0` (already in
`scripts/requirements-testnet.txt`). Reuse conventions from
`scripts/testnet_demo.py` (RPC URL, passphrase, retry helper). Testnet only;
refuse any other passphrase.

Steps:
1. Create fresh disposable accounts with Friendbot: issuer-QEXP,
   issuer-QCTL, deployer, two holders. Keep their secrets in a local file
   outside the repository (or in memory); never write secrets to any
   committed file.
2. Set issuer flags `AUTH_REQUIRED` and `AUTH_REVOCABLE` on both issuers
   (needed for `set_authorized` to matter).
3. Deploy the SAC for each asset (`createStellarAssetContract`).
4. Upload `qasset_sac_admin.wasm` once; deploy one admin instance per asset
   with the constructor `(sac, operator_public_key)`.
5. `set_admin(admin_contract)` on each SAC, signed by the issuer.
6. Deploy a **fresh** registry instance from the existing registry Wasm
   (`fab41a07…`; do not touch the existing deployment
   `CCAUPFWUQD2GFSREMVWAJH7YEPKNXPW4EVSN5JNN52H64OE4K5DYCMCT`). Register both
   SACs and declare policies (e.g. `Freeze` role quorum = one `MlDsa65`
   signer, which is the admin contract address; `Mint`/`Clawback` declared
   as the issuer's Ed25519 key). Record each `policy_revision`.
7. Holders open trustlines.
8. Positive: build `set_authorized(holder, true)` invocation, simulate to
   obtain the auth entry, compute the payload
   `sha256(HashIdPreimage::SorobanAuthorization{network_id, nonce, expiry, invocation})`,
   sign it with the signer tool, insert the signature `ScVal::Bytes`, submit.
   Record the tx hash and confirm the trustline is authorized on-chain.
9. Negative (each must be rejected; record whether it was rejected in
   **simulation** or as a **failed on-chain transaction**, and never mix
   the two up): corrupted signature, wrong-network signature, `mint` signed
   by the operator key, replayed entry.
10. Residual classic path on QEXP: the issuer sends a classic `Payment` of
    QEXP to an authorized holder. It succeeds. Record the hash. Also record
    that the issuer can still `SetTrustLineFlags` classically.
11. Issuer lock on QCTL, **only if** the environment variable
    `QASSET_ALLOW_DISPOSABLE_ISSUER_LOCK=YES` is set and the issuer was
    created by this same run. Otherwise stop before the lock and record the
    step as `PENDING`. The lock: `SetOptions(master_weight=0)` with no other
    signers. Afterwards a classic payment from that issuer must be impossible
    (record the rejection), and `set_authorized` via the ML-DSA admin must
    still work (record the hash).
12. Write `deployments/testnet/qasset-poc.json`: network passphrase, ledger
    range, account public keys (never secrets), contract IDs, Wasm hashes,
    operator public-key hash, every tx hash with expected and observed
    outcome, and the lock gate state.

Never use this procedure with an existing issuer account. Never attempt to
undo the lock.

### Task 4. Analyzer and evidence generator

`scripts/qasset_authority_analyzer.py` (or a small `tools/` CLI). Inputs:
the deployment record, live Horizon/RPC reads, and registry
`get_role_quorum` / `policy_assessment`. For each asset, enumerate paths:

- classic issuer signers and thresholds (from Horizon account record)
- issuer flags
- SAC admin address and whether it is the ML-DSA admin contract
- each SAC admin function (`set_authorized`, `mint`, `clawback`,
  `set_admin`) and what can authorize it
- admin contract upgrade path (none exists; say so)
- transaction source / fee payer (always Ed25519)
- registry admin (classical)

Assign exactly one status per path, from this closed set only:
`DECLARED`, `TESTED_PASS`, `TESTED_REJECT`, `EXPOSED`, `UNCOVERED`, `STALE`,
`INCONCLUSIVE`. There is no `QUANTUM_SAFE` or overall security grade.
Every `TESTED_*` status must cite a recorded tx hash or simulation result
from the deployment record. A declared registry policy alone is only ever
`DECLARED`. Expected: QEXP classic mint `EXPOSED`; QCTL classic mint
`TESTED_REJECT` (if lock ran) or `INCONCLUSIVE`/pending; `set_authorized`
`TESTED_PASS`; operator-signed `mint` `TESTED_REJECT`.

Output `evidence/qasset-authority-assessment.json` with: schema version,
generated time, network, ledger sequence read, the registry address and
`policy_revision` per asset, the SHA-256 of every input (deployment record,
Wasm files), the paths with statuses and citations, and a SHA-256 over the
canonical JSON of the assessment body.

### Task 5. Independent evidence verifier

`scripts/verify_qasset_evidence.py`, standard library plus `stellar-sdk`
only, sharing no code with the analyzer. It:

- recomputes the body hash and input hashes;
- rechecks every cited tx hash on Testnet (exists, success or failure
  matches the claim);
- rereads each asset's current registry `policy_revision`; if it differs
  from the recorded one, the result is `STALE` for the affected paths and the
  command exits non-zero;
- rejects any status outside the closed set and any `TESTED_*` without a
  citation.

Tests (`scripts/test_qasset_evidence.py`, offline with recorded fixtures):
edited status, edited tx hash, removed citation, injected `QUANTUM_SAFE`,
altered input hash, bumped policy revision → each must fail. One untouched
fixture must pass.

Optionally a staleness demo: call `set_role_quorum` once more on the fresh
registry instance and show the verifier reporting `STALE`.

### Task 6. Documents

All in `docs/`, factual, no marketing language:

- `POC_ARCHITECTURE.md`: authority layers, Option A versus B decision,
  contract design, data flow, what is and is not protected.
- `POC_THREAT_MODEL.md`: assets, actors (classic issuer key holder, quantum
  adversary forging Ed25519, relay, registry admin), trust boundaries,
  out-of-scope items.
- `POC_TEST_REPORT.md`: every command run and its real output counts.
- `POC_SECURITY_FINDINGS.md`: residual classic issuer powers after SAC
  handover; Ed25519 transaction source and fee payer; classical registry
  admin; no revision compare-and-set; unaudited `ml-dsa` crate; in-Wasm
  verification cost; any issues found in Task 1 to 5.
- `POC_CRYPTO_RESEARCH_SUMMARY.md`: short, points to existing Binius64 and
  RoKoko research without expanding it; states A-01 and F-01 remain open.
- `QASSET_POC_EVIDENCE.md`: reviewer walkthrough (the 7-step CLI demo below)
  with addresses and tx hashes from the deployment record.

CLI walkthrough to document:
1. Show baseline and build.
2. Deploy assets, admin contracts, registry instance.
3. Positive ML-DSA `set_authorized`.
4. Negative attempts rejected.
5. QEXP classic mint succeeds (exposed path).
6. QCTL lock (gated) and failed classic mint.
7. Generate the assessment, verify it, bump a revision, see `STALE`.

### Task 7. Internal review passes

Do eight review passes, each written up briefly in
`POC_SECURITY_FINDINGS.md` under "Internal review passes": contract auth
logic; test honesty (no blanket mocks behind security claims); key handling;
Testnet script safety gates; analyzer status logic; verifier independence;
documentation accuracy against recorded data; repository hygiene (no secrets,
no unrelated changes). These are internal reviews and must not be called
independent or external audits.

### Task 8. Final report

A short final summary listing: files changed, commands run with results,
test counts, Testnet addresses and hashes, limitations, and remaining work.
Then stop. Do not expand into other features.

## 5. Rules that apply to all remaining work

- No seeds, secret keys or private key files in Git, ever. Check
  `git diff --cached` before every commit.
- Testnet only. No Mainnet credentials, real assets, production issuers or
  institutional funds.
- Do not use blanket `mock_all_auths()` to support an authentication claim.
- Do not replace ML-DSA with Ed25519 anywhere and call the result quantum
  resistant.
- Do not introduce a `QUANTUM_SAFE` classification or any overall safety
  score.
- Do not invent deployment records, tx hashes, test counts or benchmarks.
  Only report what a command actually produced.
- Do not call internal reviews independent external audits.
- Do not convert `contracts/pq-recovery-demo` into a general smart account.
- Do not expand the Binius64 or RoKoko implementations.
- Do not overwrite unrelated research or modify the uncommitted backlog
  listed in `POC_BASELINE.md`. Stage only PoC files by explicit path; never
  `git add -A` or `git add .`.
- Never modify pinned or vendored upstream source.
- Do not touch unrelated local Stellar CLI identities (for example
  `crossing-*`, `buyer`, `channel-account-1`).
- Do not run filesystem searches from `/`; stay inside the repository.
- Keep project documents and code free of references to grant programs and
  to automated or assisted authorship tools.
- Distinguish "rejected in simulation" from "failed transaction recorded
  on-chain" in every record and document.

## 6. Useful references in the repository

- `contracts/pq-recovery-demo/src/lib.rs` and `src/test.rs`: working
  ML-DSA-65 `__check_auth` and a compiling `auth_entry` helper that builds a
  real `SorobanAuthorizationEntry`.
- `contracts/qasset-registry/src/lib.rs`: `Role`, `SignerAlgo`, `Quorum`,
  `register_asset`, `set_role_quorum`, `get_role_quorum`,
  `policy_assessment` (always `Unverified`), `quantum_security_level`
  (always fails).
- `scripts/testnet_demo.py`, `scripts/verify_testnet.py`: Testnet RPC
  helpers, deployment-record style, verification style.
- `docs/POC_BASELINE.md`: numbers every later report should compare
  against.
