# Q-Asset cryptographic review

First-party, AI-assisted adversarial review; not independent external certification.

Follow-up: [original-seed evidence](RECOVERY_EVIDENCE.md) and a
[conditional security argument](RECOVERY_SECURITY_ARGUMENT.md) now accompany an
actual off-chain root-proof experiment. The experiment uses deliberately insecure
reduced rounds and leaves the on-chain seed verifier disabled. It does not upgrade
the security conclusions below.

The detailed source observations below record the pre-fix snapshot. The local candidate now rejects empty, external and composite authorization contexts, allowing only one call to its own protected counter with no arguments. The cached-authorization regression failed on the previous source and passes after this restriction. The candidate has not been redeployed. This mitigation is specific to the counter demo; a general wallet needs a separate authorization and epoch design.

Current candidate library SHA256: `f162126d5e5dfa1b5ad10a348dbab70ba1d56f97aa3134ec4184d422894bc8cb`.

Q-ASSET CRYPTOGRAPHIC APPROACH AND IMPLEMENTATION REVIEW
2026-10-19; AI-assisted adversarial review, not a human independent audit or certification.

INSPECTED SOURCE SNAPSHOT
contracts/pq-recovery-demo/src/lib.rs SHA256 f9ae606ac1936ac8495cd12b22a50f9d4afd59c37fcaaaac174587acc67b9366
contracts/pq-recovery-demo/src/test.rs SHA256 8eea4aba16f88b10c657468de6afb719e1aae8e9b88fac214f3010eb8ebe806a
tools/pq-demo/src/main.rs SHA256 94bcfa398aa9ad5fb22ea733634a60d10fc2d1b3f2cc690cf52000d3e16be774
Cargo.toml SHA256 d28e2e78dd139b3cd196e3696ea7b8204f259af247f9f6ed3e0c861eeaaef2cc
Cargo.lock SHA256 0755129f9e331504ac126c379df0a4bc864e58a77f162e2c3fa8d72d394b1a5b

SCOPE AND VERDICT
The proposed Ed25519 seed-lifting idea is cryptographically plausible under substantial,
explicit assumptions. It is NOT established secure or implementable on Soroban by the current
repository. The implemented pre-enrolled ML-DSA recovery baseline is a different construction:
real signatures and real key handover, with coherent message/action binding but a CONFIRMED same-transaction authority-retirement
composition defect in the inspected deployed version (finding A6). No unauthenticated
outsider-alone bypass is established: exploitation needs the old active signing key and a
valid recovery intent. Its public fixture keys are deliberately
known to everyone. Neither this review nor the existing same-library tests establish full
FIPS conformance, end-to-end post-quantum security, mainnet readiness, or novelty of the proof.
No fee-payer transaction signing, deployments or network submissions were performed during this review; local tests use public-fixture signatures.

FINDING A1 -- HIGH: FLAGSHIP LEGACY RECOVERY HAS NO VALIDATED PROOF BACKEND
Location: architecture seed-lifting design; separately disabled seed verifier.
Impact: the flagship legacy ownership relation currently has no implemented, reviewed,
quantum-secure on-chain proof verification path. This is a missing assurance/implementation
milestone, NOT a demonstrated mathematical break in seed lifting. Current rejection of all
legacy proofs correctly prevents an unimplemented verifier becoming an authority bypass.
Required closure: select and pin an actual backend and exact relation; validate quantum
knowledge/extraction and zero-knowledge assumptions, QROM transform/parameters, full verifier,
negative cases, and complete Soroban cost. Do not activate based on simulated success, an
administrator assertion, or desktop timings from a different relation.

FINDING A2 -- CONDITIONAL MEDIUM: BACKUP ENTROPY AND PUBLIC-KEY ANCHOR LIMIT SECURITY
Location: proposed root/leaf relation; docs' seed-security claims; helper main.rs:12,19-39.
A 12-word randomly generated mnemonic has 128 bits of entropy: ideal generic quantum search
is about 2^64 queries, not 128-bit quantum security. Twenty-four words are not proof of entropy.
Even ideal high-entropy inputs anchored ONLY to an RFC8032 public key face an approximately
2^125.5 generic quantum any-seed-preimage search ceiling, derived below. HKDF and a larger
ML-DSA parameter set do not increase backup entropy. This finding matters if a design
promises certified 128-bit PQ security or NIST category 3 for the entire recovery construction.
No practical attack of this magnitude is demonstrated. State idealized work bounds and
threat assumptions; enforce/generate appropriate secrets without claiming wordcount proves it.

FINDING A3 -- CONDITIONAL MEDIUM: SHA256 DIGEST IS A SYSTEM SECURITY BOTTLENECK
Location: pq-recovery-demo/src/lib.rs:141-155 and :230-239.
Recovery signs SHA256(canonical action) with ML-DSA-65; normal authentication signs the host's
32-byte payload. Collision resistance is part of the composed action-binding argument.
The generic quantum chosen-message collision algorithm has asymptotic query exponent n/3,
so SHA256 alone does not justify a category-3/192-bit security claim. This is distinct from
targeted second-preimage search (~2^128 ideal quantum queries): a collision exponent is NOT
a demonstrated chosen-action forgery, whose constraints require separate analysis. Recovery's
fixed contract/epoch/expiry and restricted action reduce attack freedom. No practical exploit
or signing-oracle collision construction was produced. Document the actual composed claim;
a production design must review digest/host assumptions rather than infer them from ML-DSA-65.

FINDING A4 -- INITIAL MEDIUM ASSURANCE GAP; BOUNDED MITIGATION NOW TESTED
Location: pq-recovery-demo/src/test.rs, helper main.rs:110-139.
Positive tests generate and verify using the same ml-dsa0.1.1 library. Agreement can preserve
a common implementation error. Existing malformed zero signatures do not cover all canonical
hint/norm boundaries. External NIST ACVP and Wycheproof fixtures, including repeated-hint tc19,
are appropriate bounded additions. A few such vectors improve regression evidence but neither
constitute ACVP validation nor FIPS certification. The three checked RustCrypto advisories
below affect earlier release candidates, not the pinned 0.1.1, and source contains their fixes.
STATUS: three new tests using eight pinned official NIST/Wycheproof vectors now PASS; see final
addendum. This mitigates the identified same-library-only regression gap, not full conformance
or independent implementation audit. Production cryptographic assurance remains conditional.

FINDING A5 -- LOW, OPERATIONAL: NO CONTRACT TTL MAINTENANCE PATH
Location: pq-recovery-demo/src/lib.rs:101-109,:211-218.
Instance-state lifetime is not extended by this demo. Dormant recovery may require restoration
and current network resource/fee support. Archival does not reset epoch/Consumed: persistent
restoration preserves entries; missing required state unwraps and fails closed. This is a
liveness/product-maintenance issue, not evidence of replay after archival. Production recovery
must specify maintenance, restoration, maximum proof horizon and fee funding.

FINDING A6 -- MEDIUM IN COUNTER DEMO; HIGH FOR FUTURE CUSTODY LIFECYCLE
CONFIRMED: OLD AUTHORIZATION REMAINS CACHED THROUGH RECOVERY WITHIN ONE TRANSACTION
Affected source: inspected lib.rs:230-239 (__check_auth ignores contexts), combined with
lib.rs:131-138 protected() and :211-218 atomic key/epoch handover. These line numbers refer
to the initial SHA256 snapshot at the head of this report; the mitigation changes source.

Attack preconditions: attacker can sign with the OLD active ML-DSA key (the threat recovery
is meant to retire), and obtains a valid, not-yet-consumed recovery intent/signature pair
which installs the legitimate replacement key. Permissionless relaying means a copied signed
intent can be used; neither the enrolled recovery secret nor replacement secret is required
by the attacker once those valid signatures are available.

Reproduction: attacker-controlled aggregator.run first calls account.require_auth(), using a
real old-key signature over an actual Soroban host authorization tree rooted at aggregator.run
and containing account.protected as an authorized child. The aggregator then calls recover
with the captured valid intent, followed by account.protected. The first requirement verifies
the old key; the host caches that credential's verified authorization tracker. The subsequent
child requirement consumes the already-authorized tree without invoking __check_auth anew,
so it succeeds after ActiveKey changed. The resulting state is epoch1, consumedtrue, counter1.
No signature cryptanalysis, nonce reuse, key substitution, or account-auth mocking is involved.

Root's regression authorization_must_not_survive_a_handoff_in_an_unrelated_invocation_tree
fails on the old deployed implementation: 'old-key authorization survived recovery: Ok(Ok(1))'.
This reviewer's local cargo test independently compiled the same newly appended regression
and reproduced that exact failure; 12 other tests, including all 3 new external-vector tests,
passed. This is an ACTUAL reproduced composition defect, replacing the earlier caveat.
Existing across-transaction fresh-nonce tests miss this same-transaction authorization cache.

Practical impact in THIS contract is a counter increment using retired authority. There are
no assets, transfers or asset-policy enforcement in this demo. A general wallet allowing
sensitive post-handoff actions under an earlier cached tree could violate its promised
retirement boundary; treat as HIGH before using that lifecycle for custody. Attacker could
already act BEFORE recovery, so this is not a new ability for an uncompromised outsider: the
specific broken invariant is that successful handoff immediately retires old authorization
for subsequent operations inside the SAME transaction.

Root's planned scope-limited fix: accept exactly one Context::Contract naming THIS account,
function protected and empty args; reject aggregator/unrelated/multicontext authorization.
Because protected makes no nested calls, this closes the reproduced generic-tree route for
this counter-only API. Root owns production fix and follow-up validation. It is NOT a generic
wallet solution: future batch/delegated/action policies require explicit epoch-aware operation
checks, terminal recovery semantics, or a carefully specified deferred activation boundary.
Merely putting epoch in __check_auth is insufficient if the host skips that hook after caching;
current epoch must be checked where each operation is actually executed, with the expected
signed epoch bound into the operation payload. Review all authorization trees and residual
permissions, not only signatures. Earlier testnet WASM a927b6ee03411ebe4e8425ff07eac501c85e1d4006617d8b61b1d55c408b32da
and source f9ae606ac1936ac8495cd12b22a50f9d4afd59c37fcaaaac174587acc67b9366
remain HISTORICAL PRE-FIX evidence; they cannot validate the new local candidate. No redeploy
or signing/sending was performed or authorized by this audit update.

PUBLIC-FIXTURE STOP CONDITION (DISCLOSED DESIGN, NOT A HIDDEN BUG)
The helper's root [0x42;64] and fixed demo context make all three private keys reproducible by
anyone. Every deployment using them shares those keys. Thus anyone can authenticate and recover
an unconsumed demo. This is intentional public-testnet fixture behavior, prominently documented,
and invalid for funds or private accounts. HKDF role labels separate keys, but shared-root
compromise reveals all roles. They are not independent backup factors. The helper is not a
production wallet and does not claim secret handling, secure erasure, randomness or HSM support.

EXACT PROPOSED LEGACY RELATION AND THREAT MODEL
Let S be the raw BIP39-derived HD root seed (normally 64 bytes), k=D(S,n) the 32-byte
SLIP-0010 hardened child seed at m/44'/148'/n', h=SHA512(k),
a=LE(clamp(h[0:32])), equivalently a=2^254+8r with 0<=r<2^251, and A=[a]B.
The RFC8032 clamp clears three low bits, clears bit255 and sets bit254. In this report k is
always the secret leaf seed, a the clamped scalar, and S the HD root. These are not synonyms.
Shor on public A recovers a mod subgroup order l; it does not directly recover k or S.

Suggested relation, with canonical action m:
 R_leaf((A,m,z),k) := EdPublic(k)=A AND z=H(domain || len(m) || m || k).
 R_root((A,n,m,z),S) := EdPublic(D(S,n))=A AND
                       z=H(domain || len(m) || m || S).
This states knowledge of a seed preimage and binds the requested action inside the relation.
An independently justified quantum-secure signature-of-knowledge transform may bind m without
this additional z; generic 'a ZK proof verifies' is not that justification. The public action
must bind protocol/version, network, parent account, verifier/program/parameter ID, eligibility
epoch, pinned old A, permitted derivation mode/index, exact operation, replacement key/policy,
nonce/session and expiry. Include delegated signer identity when delegation is used.

Proving only A=[a]B is BROKEN FOR THE STATED THREAT: a quantum attacker already knows a.
An ownership certificate not bound to the replacement action can be copied/front-run to take
control. Proofs of expired eligibility let a removed DAO member's valid old seed recover rights.
A proof against freely attacker-substituted A proves nothing about the protected account.
These are concrete attack scenarios the full implementation must reject, not claims that the
current disabled verifier accepts them.

Root versus leaf: leaf seed knowledge already separates an owner from the Shor-only attacker.
It supports raw Stellar S-seeds and avoids three expensive hardened HMAC derivations inside
ZK. Root-only proof additionally excludes an attacker who stole/exported k but not S, assuming
the actual recovery policy independently freezes the classical path. Root derivation increases
circuit cost and format commitments; it does not cure low input entropy or the public-A anchor
ceiling. To prove actual mnemonic provenance, the witness/relation must additionally specify
BIP39 entropy, normalization, passphrase and PBKDF2; raw S alone proves none of those facts.

WHY KNOWLEDGE, NOT ORDINARY SOUNDNESS, IS ESSENTIAL
For an honestly generated A, existence of a seed preimage is already true. Merely proving
membership of that true statement does not establish that a forger knows the seed. Require a
suitable quantum proof/signature-of-knowledge security definition, adaptive chosen-message
security and extraction/simulation-extractability properties appropriate to the construction.
Quantum zero-knowledge is separate: transcripts must not leak the backup to quantum verifiers.
Fiat-Shamir transforms need a QROM justification with concrete losses and repetitions, not
just a classical random-oracle argument or a library's '128-bit' label. Correlated HD keys and
multiple messages/paths must be included in the model. There is no reviewed composition proof
for Q-Asset in the current repository.

ANY-PREIMAGE BOUND (IDEALIZED REVIEWER DERIVATION, NOT A SECURITY LOWER BOUND)
Clamped scalars form a=2^254+8r for 0<=r<2^251. This set maps injectively modulo l:
if 8(r-r')=t*l, odd l implies t is divisible by8, whereas the scalar difference is <2^254<8l;
therefore t=0. There are 2^251 possible clamped public keys, and a uniform 256-bit leaf seed
has about 32 preimages per fixed legitimate A in a random-hash model. After Shor recovers a,
a generic arbitrary-seed search therefore needs about 2^251 classical trials or 2^125.5 ideal
Grover queries. A root-only anchor to the same A inherits this output bottleneck. A known
128-bit mnemonic distribution gives a much cheaper ~2^64 ideal quantum search. Multi-target
attacks and side information can further reduce security. Quantum circuit depth, memory and
fault-tolerant implementation cost are omitted: these query estimates are NOT near-term attacks.
Neither a per-message z nor claiming the 'original historical seed' increases anchor security.
A separately authenticated high-entropy seed commitment would change the statement and
security anchor, at the cost of enrollment. A proof shows SOME valid preimage, not historical
uniqueness or continuing legal/governance ownership.

PROOF BACKEND AND SOROBAN FEASIBILITY
Groth16 or another pairing-based classical wrapper does not preserve PQ soundness under Shor.
Conversely a hash-based proof doing finite-field arithmetic in BN254's scalar field is not
inherently pairing-based: inspect actual commitments and assumptions before rejecting it.
MPC-in-the-head/hash-based systems and appropriate transparent proof systems are plausible
candidates, but quantum knowledge, hiding, transform and parameters all need review. WHIR is
a PCS/IOPP component, not by itself a complete private wallet proof. Published desktop proof
sizes/timings for BIP32/xpriv/QBIP32 are not SEP5 Soroban measurements.

First implement and benchmark an exact fixed leaf relation before paying root HMAC costs,
unless root provenance is an explicit requirement. Bind fixed code/parameters and use adversarial
max-cost proofs. Incremental verification is a proposed engineering direction, not an implemented
optimization: preserve the exact Fiat-Shamir transcript, precommit immutable proof bytes, prevent
chunk mixing/reset/early acceptance and bind session/account/epoch/action/expiry. Uploading chunks
does not reduce total verifier work. Soroban __check_auth cannot pause across transactions;
a completed proof certificate must be consumed atomically with the still-current parent policy.
Recheck revocation/expiry at consumption. Native host support is a separate protocol-dependent
path. No current measurement establishes flagship contract-only feasibility within 18 weeks.

ENROLLMENT NECESSITY AND THE REAL PRODUCT DIFFERENTIATOR
For owners enrolling today, derive a domain-separated PQ signing seed from the SAME backup,
register its PQ public key, and use a standard signature later. This needs no second mnemonic
and is simpler than generic ZK. Root-derived PQ recovery also survives isolated leaf-seed theft.
The potential distinctive seed-proof value is a compatible wallet-wide rule that verifies
against ALREADY recorded old A for dormant users without each user registering a new PQ key.
This still needs authorized wallet code/rules and revocation; it cannot retrofit arbitrary
classic G accounts simply by deploying a contract. Parent C-wallet authorization/delegation
must be real and bound to the exact signer. Shared root backups are not independent factors.
This is a defensible engineering hypothesis, not a certified 'first' or a theorem of novelty.

CLASSICAL RETIREMENT IS A REQUIRED SECURITY ASSUMPTION
If Shor-forgeable classical authority can still spend, upgrade, replace A, remove the verifier,
change quorum/roles or lower the security floor, a seed proof does not protect assets. An
attacker can bypass recovery entirely or enroll their own key. Specify irreversible retirement,
a securely governed cutoff, or another PQ authority. A fixed future cutoff assumes the secret
quantum break occurs after that cutoff. A classical administrator permitted to move the cutoff
can defeat it. Delayed changes with seed veto require owner availability and do not automatically
protect dormant users. A removed member's honest old root must not resurrect revoked rights.

IMPLEMENTED BASELINE: AUTHORIZATION ARGUMENT
- Constructor (lib.rs:87-109) requires declared owner consent and writes both distinct fixed-size
  public keys atomically. Reserved host constructor cannot be called again as a public method.
  No owner address is retained; no initializer, key-admin or upgrade bypass exists in this code.
  Enrollment correctness/possession of initial keys is the consenting deployer's responsibility.
- protected (:131-138) requires the contract's real custom-account authority. __check_auth
  (:230-239) verifies the HOST payload rather than a caller-provided substitute. Soroban host
  binds network, nonce, expiry and full authorized invocation tree and consumes the nonce.
  Initially ignoring contexts allowed arbitrary authorization roots; finding A6 demonstrates
  why that unrestricted policy is unsafe for a claimed immediate handoff boundary. The planned
  demo mitigation restricts context to this exact counter operation.
- recover (:160-220) is permissionlessly relayed but fixed-effect. Both enrolled recovery key
  and exact replacement key sign the same canonical digest, in a recovery-only ML-DSA context.
  Epoch and expiry are checked before expensive crypto. Recovery and replacement keys differ
  from current active key and each other. The second signature establishes signing ability
  under chosen key bytes, not honest key generation or entropy. Degenerate t1=0 public keys
  can be forgeable yet FIPS-verification-valid (official Wycheproof explicitly covers this).
  Trusted enrollment/key generation remains necessary. An outsider cannot select such a
  replacement without the enrolled recovery signature; this is not a demonstrated bypass.
- State writes follow BOTH verifications. Active key, incremented epoch and consumed flag update
  atomically; repeated recovery and stale epoch fail. No external call/callback exists between
  checks and state mutation. Transaction copying can relay the same intended handover but cannot
  alter destination, account, network, epoch or expiry. There is one immutable recovery slot;
  inability to recover a second time is intended scope, not hidden revocation support.
- On later transactions, old-key signatures fail against current ActiveKey even with a fresh nonce.
  Same-transaction authorization caching DOES preserve old authority across this key update:
  finding A6 reproduces it with real signatures. Across-transaction retirement alone is not
  sufficient evidence for the stronger immediate-retirement claim. The initial demo code must
  not be used for custody; mitigation and updated tests remain required.

CRYPTO API / ENCODING REVIEW
ml-dsa exactly0.1.1, default-features=false; public pure-MLDSA verify_with_context is used, not
verify_internal/verify_mu or an unchecked fallback. Message is the exact 32-byte digest and
context is qasset-pq-auth-v1 or qasset-recover-v1. FIPS204 framing includes 0||ctxlen||ctx||M.
PK1952 and signature3309 lengths are exact. Public-key rho/t1 has no unused bit encoding to
reject; fixed-size decoding is valid. Signature decoding checks z norm and canonical hints:
ordered polynomial cutoffs, total weight, zero padding and STRICTLY increasing indices in
each polynomial. Repeat indices are rejected. UseHint r0=0 branch has the patched strict
positive condition. Deterministic FIPS204 signing uses seeded KeyGen and specified rnd=0;
no ambient RNG failure becomes silent success. This is source review, not a full constant-time
or cryptanalytic proof. Zeroization disabled is relevant to a future secret-handling helper,
not protection of this deliberately public fixture.

PINNED LIBRARY ADVISORY CHECKS (BOUNDED, NOT WHOLE-TREE ATTESTATION)
GHSA-5x2r-hc65-25f9: repeated-hint signature malleability <=0.1.0-rc.3, fixedrc.4.
GHSA-h37v-hp6w-2pp8: UseHint edge <=0.1.0-rc.4, fixedrc.5.
RUSTSEC-2025-0144: signing timing issue patched >=0.1.0-rc.3.
Pinned0.1.1 lies outside these affected ranges. Root performs the separate current RustSec scan.
https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9
https://github.com/RustCrypto/signatures/security/advisories/GHSA-h37v-hp6w-2pp8
https://rustsec.org/advisories/RUSTSEC-2025-0144.html

PRIMARY APPROACH REFERENCES AND ACCESS LIMITS
https://eprint.iacr.org/2025/1368 Baldimtsi et al.: abstract/metadata read; fullPDF403.
https://github.com/SoundnessLabs/pqchain/tree/598cdff516c3086487a173d7d9f9af2830e04a32
  actual private leafseed->Ed25519A plus per-message hash relation source inspected; no code run.
https://eprint.iacr.org/2026/1508 ZKPoSP: abstract/authornotes read; fullPDF403.
https://hackmd.io/@vba/post-quantum-hd-wallet-proofs-mobile
https://hackmd.io/@vba/plonky3-zero-knowledge-deadlock
  author reports server12-13s proving/9-10ms verification; mobile derivation much slower;
  not a benchmark for Stellar SEP5 or Soroban. QBIP32 not byte-compatible SEP5.
https://eprint.iacr.org/2024/1586 WHIR: abstract/author/codeREADME, no fullPDF access.
https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_giacomelli.pdf
  full original ZKBoo paper read; not a certification of later project's QROM parameters.
https://arxiv.org/html/2303.06754v2 full Signature Lifting read, including correlated-key concerns.
https://eprint.iacr.org/2023/362 correct Signature Lifting ID; 2025/1307 is another paper.
https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md
https://www.rfc-editor.org/rfc/rfc8032
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

TEST/EVIDENCE LIMITS AND RELEASE POSITION
Existing real-host tests cover valid MLDSA auth, context and nonce mutation, replay, old-key
fresh-nonce rejection after handover, both recovery signatures, action/network/contract/expiry
binding and one-time use. Constructor mocks are limited to deployment consent; constructor
rebind regression uses correct arity and distinct valid keys. Existing testnet receipts show
four successful transactions and 17 checks, recovery204473156 instructions; successful
execution proves this baseline on that network/configuration, not cryptographic certification.
No private secret was used or exposed in this review; no upstream repo code was executed.

Do not proceed with further deployment until the local A6 mitigation is reviewed and tested;
no further deployment is performed here. Any later release remains an isolated, explicitly
public-fixture testnet demo unless separately hardened. Do not represent this
baseline as implemented legacy seed lifting or mainnet-ready protection. The flagship remains
conditional research with a viable mathematical direction, open backend/performance work and
load-bearing authority lifecycle assumptions. The above conditional weaknesses do not amount
to a demonstrated break of ML-DSA0.1.1 or a proven impossibility of the proposed recovery system.

EXTERNAL VECTOR ADDENDUM -- SOURCE DATA PINNED, THREE TESTS PASS
Official NIST ACVP revision975de31eb83d87039ec88934fdc47d8c312b892d,
ML-DSA-sigVer-FIPS204/internalProjection.json SHA256
47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437.
Matches the formerly vendored copy exactly. Group3 pure/external/externalMu=false, tc43 valid
and tc38 invalid hint selected. These messages have166 and1 bytes respectively; they exercise
the underlying public API, not successful 32-byte host-auth payloads.
Official C2SP/Wycheproof revision7a325932231bd7a724c791c8b0d65ea4d6d2f435,
testvectors_v1/mldsa_65_verify_test.json SHA256
1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034.
Selected32-byte cases tc21 valid, tc16 reverse hints, tc18 nonzero padding, tc19 repeated hint
exercise the unchanged actual verify wrapper; tc3 nonempty context and tc138 exact norm boundary
exercise the underlying public pure interface. Three tests appended and data/provenance/license
added under contracts/pq-recovery-demo/test-vectors; no production library/dependency changes.
This reviewer ran cargo test --offline --locked -p pq-recovery-demo. All three external-vector
tests PASS, including actual wrapper positives/negatives and noncanonical/norm decode rejects.
Total snapshot result12PASS/1FAIL: the new authority-cache regression failed as described in A6.
Root owns the context-policy fix, updated whole-workspace run and clippy. No FIPS/ACVP certification
is claimed. Only fixtures/test code were added by this reviewer; production changes belong to Root.

## Compact verifier and actual host-cost follow-up

The [successor](VERIFIER_NEXT_EVIDENCE.md) preserves the original proof, scalar/action transcript,232queries, masking and full constraint fingerprint. Compact integers and table-free Frobenius arithmetic change representation/implementation, not the relation or claimed security level.646 arithmetic vectors and actual proof checks are empirical equivalence evidence, not a formal proof. The [generic point helper](../tools/recovery-key-binding/README.md) requires strict full clamping and canonical nonidentity prime-subgroup keys; trusted current key selection, seed knowledge and recovery authorization remain separate obligations.
