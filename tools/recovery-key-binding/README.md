# Exact public scalar/key binding experiment

This small `no_std` library checks the missing mathematical anchor for the
scalar-exposed recovery relation: the full, strictly clamped RFC8032 scalar must
multiply the Ed25519 base point to the exact expected canonical public-key bytes.
It uses unmodified `curve25519-dalek = 4.1.3`, with default features disabled.
The default build needs no heap allocation or precomputed base-point table.

`CanonicalEd25519PublicKey::from_bytes` validates encoding and the nonidentity
prime subgroup. `check_clamped_scalar_binding` checks the original full scalar,
without repairing invalid bits or accepting a reduced scalar encoding. Invalid
lengths, noncanonical encodings, identity, small-order and mixed-order keys
reject. The optional `precomputed-tables` feature is a size/performance choice;
the default measurements do not use it.

The caller must obtain the expected protected key from independently trusted
account configuration. The type attests only mathematical point validity.
Accepting a claimant's chosen key does not establish authority. This library
does not check a seed preimage or proof, canonical request, program/parameters,
current eligibility, revocation, epoch, expiry, retirement or one-time handoff.
It must never replace those checks or be presented as successful recovery.

The public scalar is a working classical signing secret. Every effective
classical/reused-key authority must already be retired with finality before its
disclosure to an untrusted party. An atomic public retire-and-reveal transaction
does not close prepublication front-running.

The source includes three [RFC8032 vectors](https://www.rfc-editor.org/rfc/rfc8032#section-7.1)
and 15 account vectors from the [pinned official SEP5 examples](https://github.com/stellar/stellar-protocol/blob/f2d364902615af726b3533021403c8b225aa6e5d/ecosystem/sep-0005.md).
Python hashlib/HMAC and PyNaCl/libsodium independently check seed expansion,
published public keys and scalar multiplication. SEP5 derivation is test fixture
preparation, not part of this library's proved relation. All credentials are
published test fixtures; never fund or reuse them.

```sh
python3 scripts/run.py
```

The reproducer uses cached locked Cargo dependencies, tests the native library,
checks strict formatting/Clippy, builds `wasm32v1-none`, and actually executes the
same mathematical library through a minimal public-fixture Wasm ABI in Node/V8.
This ABI is not the Soroban contract ABI. Code size, raw timing and linear-memory
observations are not whole Soroban host costs or a deployment guarantee. The
fixture ABI has no secret input, signature flow, ledger policy, RPC or transaction.
Source hashes and dependency checksums establish reproducibility, not independent
external audit, constant-time certification or quantum security of recovery.

The initial default release probe is 25,886 bytes and its raw linear memory is
1,114,112 bytes; all 18 positive and seven rejection fixtures plus an unknown-case
guard execute successfully. The probe embeds public test data. These numbers do
not predict the marginal size or metered resource cost of an integrating contract.
`scripts/verify_provenance.py` checks the retained local record/source hashes and
the Wasm hash when its ignored artifact is available, without rerunning execution.
The dependency's original BSD license is retained under `licenses`.
