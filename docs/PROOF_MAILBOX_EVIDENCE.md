# Research proof transport on Soroban

The [mailbox contract](../contracts/recovery-proof-mailbox/src/lib.rs) stores a
large proof in authenticated, ordered temporary chunks. It never verifies a
cryptographic proof or authorizes recovery. Its state is explicitly
`sealed_unverified`; `backend_available` is false and `require_verified` always
rejects. It cannot rotate keys, consume recovery eligibility or control assets.

## Actual local results

The actual 11,940-byte Wasm contract was executed in the Soroban SDK host with
mocked uploader authentication. It uploaded the retained 539,888-byte proof in
17 chunks and recovered the same bytes through 66 bounded reads. Independent
Python XDR session and rolling-commitment calculations matched the contract.
Across 87 measured calls, the largest call used 4,318,575 metered instructions
and 1,638,802 metered memory bytes under local 400 million / 40 MiB budgets.
These are **transport costs**, not proof-verifier costs or live-network results.

The Python probe serialized 19 unsigned envelopes (open, 17 appends, seal), each
with an explicit footprint and source-account authorization entry. The largest
was 66,288 bytes against the historical 132,096-byte transaction snapshot. A
zero placeholder outer signature provides realistic length only. Resources,
fees, sequence numbers and network admission were not simulated or validated.
Nothing was signed or submitted. See [execution record](proof-mailbox-research.json).

Thirteen Rust tests and four Python tests cover authorization rejection,
immutable chunks and sessions, ordering and sizes, cross-session commitment
replay, maximum 1 MiB uploads, exact logical expiry, TTL extension, bounded reads,
overflow rejection and a shared independent XDR golden vector.

## Boundaries

An upload session binds network, contract, uploader, nonce, 64-byte statement,
verifier identity, parameters, total length, expiry and fixed chunk size. First
opening fixes the expected rolling commitment; repeated opens cannot reset it.
An independent sponsor can pay for and authenticate transport. Their signature
is not authorization for a protected account. Statement/verifier labels are
unverified input, not endorsements of a backend.

Chunks are 32 KiB, reads at most 8 KiB, uploads at most 1 MiB, and logical lifetime
at most 1,000 ledgers. Reads require sealing; expired sessions are rejected even
if network minimum TTL retains entries longer. TTL is not secure data erasure.
All upload bytes are public. A hash commitment establishes byte consistency,
not seed knowledge, zero knowledge, witness entropy or safe authority retirement.

Staging removes the need to carry the whole proof in one transaction, but does
not settle final verification feasibility. Since protocol 23, live Soroban state
reads use an in-memory resource model; disk-read byte caps apply to classic and
restored archived entries. A blanket 200 KB limit on all live proof reads would
therefore be incorrect. Footprint, CPU, memory, writes and applicable network
settings still constrain a complete operation. See [CAP-0066](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md)
and [Stellar storage guidance](https://developers.stellar.org/docs/build/guides/storage/storage-strategies).
Limits must be refreshed against the deployment network; this iteration did not
query its live settings. SDK execution does not validate envelope footprint
completeness or admission fees.

A real consumer must read the exact pinned session, verify its entire proof and
all request bindings, recheck current eligibility/revocation/epoch/expiry, and
commit a one-time authority transition atomically. Successful upload must never
be treated as successful recovery. The current seed account stays disabled.

## Reproduce

```sh
cargo test -p recovery-proof-mailbox --locked
cargo build -p recovery-proof-mailbox --locked --target wasm32v1-none --release
python3 scripts/run_proof_mailbox_research.py --help
```

The Python script accepts retained proof, actual Wasm and build-target paths,
then executes the real local Wasm host probe and serializes unsigned envelopes.
Its output is invalidated before execution. It never calls RPC or signs a
transaction. Public fixtures must never hold funds.
