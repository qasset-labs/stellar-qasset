> **Superseded testnet revision:** The transactions below demonstrate the earlier direct-call scenario. The subsequent audit reproduced cached old-key authorization surviving a recovery inside a composite invocation tree. The local candidate now authorizes only one self/protected/no-argument context. Its changed WASM has not been redeployed. These historical receipts do not approve the patched candidate. See [security review](SECURITY_REVIEW.md).

# Recovery proof of concept: scope and cryptography

The ML-DSA recovery demonstration is a **pre-enrolled recovery baseline**. Its
purpose is to exercise real signature verification, replacement-key authorization
and account recovery on Soroban. It does not implement the separate
zero-knowledge seed-lifting construction. The separate `SeedRecoveryVerifier`
continues to reject every proof with `BackendUnavailable`.

All ML-DSA demonstration keys derive from public test fixtures. They cannot protect funds.
Use the demonstration only on testnet. Implementation and testnet receipts are
engineering evidence, not an independent cryptographic audit.

## Recorded testnet result

The end-to-end baseline **passed on Stellar Testnet, protocol 29**, recorded on
19 October 2026 in Asia/Dubai. The fetched contract WASM matched the local build:
60,289 bytes, SHA-256
`a927b6ee03411ebe4e8425ff07eac501c85e1d4006617d8b61b1d55c408b32da`.

[Deployed demonstration account](https://stellar.expert/explorer/testnet/contract/CAU3EUMD27VGQOBWLPD66SS2752L4BHYU547LEWYEOWTWQ2JZ3IK3PLA)

| Confirmed operation | RPC simulation instructions | Committed transaction |
| --- | ---: | --- |
| Initial key authorizes the protected counter | 102,857,643 | [Initial authorization](https://stellar.expert/explorer/testnet/tx/d9de25b5300865137f4c8beb4ac2d1d7a7b3c662067afe89ae010c8b7c8d3f1e) |
| Recovery key and replacement key authorize the handoff | 204,473,156 | [Successful recovery](https://stellar.expert/explorer/testnet/tx/8df78c1f40af8c00d5bedf49262e1089900621c227c9242cfbb7ca9730674cb6) |
| Replacement key authorizes the protected counter | 102,868,184 | [Replacement authorization](https://stellar.expert/explorer/testnet/tx/f830aa32aca8a1ac6d38fbfb12705a63c6d06dba74e7313fa047299b46ac2224) |

The [deployment transaction](https://stellar.expert/explorer/testnet/tx/308860622f102124a33ce7664c6d497a9ba61c90242f5ffd9cee13ebebc55077)
plus these three operations produced four confirmed `SUCCESS` receipts. Seventeen
RPC checks covered reads, valid operations and rejected attempts. In particular,
a forged recovery signature, wrong replacement-key possession, consumed recovery,
old key with a fresh host nonce, and missing PQ authorization were rejected.
The client independently reconstructed the canonical recovery digest and matched
the contract's output. The final state was epoch 1, counter 2, recovery disabled,
with the replacement public key active.

[recovery-testnet.json](recovery-testnet.json) contains receipts, checks, source
hashes and resource observations. Rejections and reads are RPC simulations;
they are not represented as committed transactions. Instruction figures describe
this compiled implementation and observed network configuration, not a throughput
guarantee or a measurement of ZK seed lifting. The demonstration changes a counter;
it does not recover a token balance or integrate a verified asset-policy adapter.
Testnet state may expire or reset.

[validation.json](validation.json) records ten passing local validation commands:
49 contract tests across the workspace, three native-helper tests, 168 public
SEP-5 fixture checks, formatting, strict Clippy, WASM/native builds. These results do not constitute an independent cryptographic audit.

## What the two approaches establish

| Question | Pre-enrolled ML-DSA baseline | Proposed seed lifting |
| --- | --- | --- |
| What must be recorded before recovery? | A specific recovery public key and its authorization rule. | At least an authorized recovery rule and the protected existing public key. |
| What does the owner produce later? | An ML-DSA signature under the enrolled recovery key. | A quantum-secure proof of knowledge of seed material deriving the protected key. |
| Is another mnemonic inherently necessary? | No. Derive the recovery signing seed from an existing backup with a domain-separated KDF. | No. The witness can be existing seed material. |
| Does the chain prove that a PQ key came from an existing mnemonic? | No. Registration establishes the authority; client derivation is a separate step. | A correctly constrained root-derivation proof could establish the supported derivation relation. |
| Can it cover an arbitrary dormant classic G-account by deploying a contract? | No. | No. Actual protocol authorization or migration is required. |
| Can dormant individual users avoid registering a new PQ key? | Generally requires their PQ keys to have been registered already. | Potentially, if compatible wallet code already authorizes proofs over their recorded keys. This needs a concrete integration. |

For an owner available to enroll today, deterministic PQ recovery is a strong,
simpler alternative to ZK recovery. The proposed differentiator for seed lifting
is enabling an authorized wallet-wide recovery rule over existing public-key
records without every owner separately registering a new PQ key. That is a
system-design hypothesis to implement and measure, not a proven novelty claim.

## The seed is different from the signing scalar

For SEP-5, a mnemonic and optional BIP-39 passphrase produce a root seed `S`.
SLIP-0010 hardened derivation at `m/44'/148'/n'` produces a 32-byte leaf seed `k`.
RFC 8032 then computes:

```text
h = SHA-512(k)
a = clamp(h[0:32])
A = a * B
```

A quantum discrete-log attack is modeled as recovering `a` modulo the subgroup
order from `A`. It does not automatically recover `k` or `S`. Proving knowledge
of `a` alone therefore does not establish the intended recovery property.

Two candidate ZK statements have different scopes:

- A **leaf-seed proof** establishes `A = EdPublic(k)`. An honest SEP-5 owner can
  derive `k` before proving; a raw Stellar secret seed can also supply `k`.
- A **root-seed proof** establishes `A = EdPublic(SLIP10(S, path))`. This adds HD
  root provenance and can exclude a party who has only the leaf seed, at greater
  proving cost. A proof starting from raw `S` does not establish the originating
  mnemonic's word count or entropy.

Both require a suitable quantum-secure proof system, message binding, current
recovery eligibility and retirement of classical bypass paths. A public hash
beside an unbound proof is insufficient. A correct Groth16 proof over BN254 would
still not provide the promised post-quantum guarantee. Using BN254 merely as an
arithmetic field in a hash-based proof system is a different matter; the actual
commitment and proof assumptions must be inspected.

The public compatibility checker makes the root/leaf/scalar distinction
reproducible:

```sh
python3 -m pip install -r scripts/requirements-crypto-demo.txt
python3 scripts/check_recovery_relation.py
```

It covers all five official SEP-5 examples, including a passphrase example, and
accounts 0, 1 and 9 from each. It checks public G-addresses, Base32/CRC/version
encoding, altered inputs, and the scalar-to-public-key relation. It prints no
mnemonic, seed, chain code or scalar bytes. It performs ordinary derivation from
published fixtures, not a zero-knowledge proof or a simulated quantum attack.
The fixtures and pinned source are in
[recovery-relation-vectors.json](recovery-relation-vectors.json).

## Demonstration protocol

The implemented demonstration interface uses constructor-based deployment with
`(owner, initial_key, recovery_key)`. The owner's deployment authorization records
consent; the owner must not remain a classical key-rotation authority afterward.
`protected()` exercises the current key through the host's account authorization
path. The separate recovery action is:

```text
recover(epoch, replacement, expiry, recovery_sig, replacement_sig)
```

`recovery_digest` exposes the action digest so the client and contract agree on
its exact encoding. The contract constructs SHA-256 of an XDR tuple containing the
recovery domain, network ID, contract address, epoch, replacement key and expiry.
Both the enrolled recovery key and the replacement key sign the same digest using
the ML-DSA context `qasset-recover-v1`. Normal host authorization uses the separate
context `qasset-pq-auth-v1`. These are pure ML-DSA signatures over protocol messages;
they are not a claim to implement the distinct standardized HashML-DSA interface.

The demonstration allows one successful recovery. It is deliberately limited to
an account-authorization exercise and does not implement a wallet's full token or
asset-governance interface. Before citing a successful run, inspect the regression results and recorded
testnet receipt; source inspection alone does not establish a successful deployment.

The public-fixture signing helper is a separate native tool:

```sh
cargo test --manifest-path tools/pq-demo/Cargo.toml --locked
cargo run --manifest-path tools/pq-demo/Cargo.toml --release --locked -- public-key recovery
```

Its `sign ROLE DIGEST_HEX AUTH|RECOVERY` command accepts a 32-byte digest encoded
as 64 hexadecimal characters. Roles are `active`, `recovery` and `replacement`.
It prints only a public key or signature. It has no option for importing a user's
backup and must not be adapted to real keys by replacing its fixture constant.

The helper uses HKDF-SHA-512 with salt `qasset-pq-demo-kdf-v1`. Its information
string starts with `qasset-pq-demo-key-v1` and contains four fields with big-endian
32-bit length prefixes: the testnet network ID, the fixed demonstration context,
`ML-DSA-65`, and the role. The 32-byte output seeds standard ML-DSA key generation.
This separates roles and protocols. The fixed demonstration context means the
same role keys are reused across demonstration deployments; this is **not a
production account-scoped derivation standard**. A real backup design requires
an explicit account/deployment scope and its own review.

## Recovery lifecycle requirements

The enrolled recovery authority must authorize the exact replacement key for the
current account and network, with a current epoch and bounded expiry. The new key
must demonstrate possession before becoming an authority. State changes must be
atomic; a failed signature or expired request must leave the old state intact.
Copied signatures must not authorize a different replacement, account or epoch.

After successful recovery, an old operational key must stop authorizing actions.
If recovery is one-time, the contract must enforce consumption rather than rely
on the client to avoid reuse. A new host nonce does not make a stale recovery
signature current. There must be no administrator or classical-signature route
that bypasses these checks.

A recovery key derived from the same root as other keys shares that root's
compromise risk. Domain separation prevents accidental key reuse; it does not
create an independent backup factor or increase the root's entropy. Likewise,
knowing a historical owner's seed does not restore revoked DAO membership.

The contract regression suite can be run with:

```sh
cargo test -p pq-recovery-demo --locked
```

Its source covers a real host `require_auth()` handoff, old-key rejection after
recovery, copied and nonce-modified authorization entries, wrong signature
contexts, replacement-key possession, changed replacement/expiry/network/account,
expiry boundaries, constructor consent and one-time recovery consumption.
Authorization mocks are confined to deployment consent or explicitly rejected
owner-bypass attempts; the positive signing flow uses real ML-DSA signatures.
These tests use the same ML-DSA implementation for signing and verification. They
do not independently validate FIPS conformance through a second implementation.

## Assurance and review limits

The baseline uses RustCrypto `ml-dsa` 0.1.1 with `default-features = false`.
The crate implements FIPS 204 and explicitly states that it has not received an
independent audit. It is dual licensed under Apache-2.0 or MIT. Exact encoding,
context and payload choices are part of the contract protocol; mismatches must
fail rather than fall back to another scheme. No signing seed belongs in a
contract argument, ledger entry, event or deployment receipt.

Measure the complete WASM transaction, including both recovery and replacement
proof-of-possession verification. Native unit tests alone do not measure Soroban
limits. The recorded transaction hashes, contract/code identifiers and measured resources
above establish this limited testnet demonstration. A PQ-authenticated contract
account does not make the transaction fee payer or Stellar consensus post-quantum.

The baseline does not establish a quantum-sound ZK backend, a usable incremental
proof verifier, automatic recovery for unprepared accounts, full asset-authority
coverage, production safety or release approval. Those remain separate technical
gates.

## Primary sources

- [SEP-5 public derivation vectors, pinned revision](https://github.com/stellar/stellar-protocol/blob/f2d364902615af726b3533021403c8b225aa6e5d/ecosystem/sep-0005.md)
- [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- [RFC 8032 key generation](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5)
- [RustCrypto ML-DSA 0.1.1 documentation](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)
- [Baldimtsi et al., Post-Quantum Readiness in EdDSA Chains](https://eprint.iacr.org/2025/1368)
- [SoundnessLabs PQChain relation source](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/sdk/cpp/examples/PQChain/pqchain.cpp)
- [ZKPoSP abstract](https://eprint.iacr.org/2026/1508) and [authors' benchmark note](https://hackmd.io/@vba/post-quantum-hd-wallet-proofs-mobile)
- [SDF Quantum Preparedness Plan](https://stellar.org/blog/foundation-news/introducing-the-quantum-preparedness-plan)

The two ePrint abstracts and accessible source were reviewed; the full
Baldimtsi/ZKPoSP PDFs were unavailable during this review. No upstream code was
executed. The relation checker executes the installed, pinned PyNaCl library on
public fixtures only. AI assisted this documentation and implementation review.
