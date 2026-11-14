# License scope and third-party maintenance

Baseline: repository inspection on 2026-11-05; re-checked 2026-11-15. No
repository-wide license file is published. Some research packages have
component-specific manifest declarations and license texts; these do not license
the repository as a whole. This document does not
add a license, assign copyright, waive rights, appoint an owner or grant rights
to first-party material. Existing license/copyright text is preserved. A public
checkout and `publish = false` do not establish permission to redistribute a
combined product. First-party distribution and contribution terms need an actual
authorized rights decision before a public package/release program.

## Current status (2026-11-15)

| Question | Finding |
| --- | --- |
| Root license | None. GitHub reports no license for the repository |
| Core first-party crates (`qasset-sac-admin`, `qasset-registry`, `qasset-sac-signer`, `qasset-evidence-crypto`, recovery contracts) | No `license` field; `publish = false` |
| SPDX identifiers | Absent from first-party core sources; present in some research and vendored files |
| Published packages or release artifacts | None |
| Rights to reuse first-party code | Not granted by this repository; requires an authorized decision |

Core contract and tool dependencies, from their package metadata:

| Dependency | Version | Declared license |
| --- | --- | --- |
| `soroban-sdk` (with `soroban-env-host`, `stellar-xdr`) | 25.3.2 (25.2.2, 25.0.0) | Apache-2.0 |
| `ml-dsa` (RustCrypto) | 0.1.1 | Apache-2.0 OR MIT |
| `sha2` (transitive, via the Soroban crates) | 0.10.9 | MIT OR Apache-2.0 |
| Python `stellar-sdk` | 14.0.0 | Apache-2.0 |
| Python `PyNaCl`, `requests`, `requests-sse` | 1.6.2, 2.34.2, 0.5.3 | Apache-2.0 |

These are package declarations for the main dependencies, not a transitive SBOM. The remaining
Python lock entries (`pydantic`, `urllib3`, `certifi`, `cffi` and others) and
every transitive Cargo crate still need an inventory before distribution.

Wycheproof ML-DSA vectors in `contracts/pq-recovery-demo/test-vectors/` are covered
by the adjacent `LICENSE.wycheproof` (Apache-2.0); NIST ACVP vectors in the same
directory are identified in `provenance.json`. Wycheproof vectors are also compiled into the SAC administrator's vector tests
(`contracts/qasset-sac-admin/tests/ml_dsa_vectors.rs`) through `include_str!`; any
distribution of those tests carries that notice.

Two research tools (`tools/seed-recovery-research`, `tools/scalar-seed-research`)
declare LGPL-3.0-or-later. They are isolated research crates outside the core
workspace; linking or redistributing them with other code must satisfy LGPL terms.

Publication prerequisites for any first-party package or release:

1. An authorized decision on the first-party license and contribution terms.
2. A transitive inventory from the exact locked graph, with notices bundled.
3. SPDX identifiers and package `license` metadata matching that decision.
4. Release-blocker review of any uncertain license or attribution.

Existing component-specific texts include:

| Location | Existing licensing evidence |
| --- | --- |
| Research wrapper `Cargo.toml` manifests (including Binius tools, key binding and gadget research) | Several declare MIT for their package; preserve the declaration and separately inventory upstream/dependency terms |
| `contracts/pq-recovery-demo/test-vectors/LICENSE.wycheproof` | Wycheproof fixture license; adjacent provenance identifies vectors |
| `tools/binius-seed-research/licenses/`, including `rate-study/licenses/` | Binius64 Apache-2.0/MIT texts and ShorStop MIT text |
| `tools/binius-verifier-port/vendor/binius64/` and `tools/binius-verifier-next/vendor/binius64/` | Upstream Apache-2.0/MIT files and contribution guidance |
| `tools/compact-seed-research/vendor/shorstop/LICENSE` | Upstream MIT text |
| `tools/seed-recovery-research/LICENSE`, `tools/scalar-seed-research/LICENSE` | Existing LGPL-3.0 license texts; scope does not extend to repository siblings |
| `tools/recovery-key-binding/licenses/curve25519-dalek-BSD-3-Clause.txt` | BSD-3-Clause dependency notice |
| `tools/rokoko-relation-research/LICENSE`, `incomplete-rexl/LICENSE` | Existing upstream license/copyright texts; preserve exact scopes |

This is a navigation inventory, not a complete transitive SBOM or rights
clearance. Registry dependencies have their own source license files, resolved
versions and package metadata. Do not assume one vendored license covers every
library linked into an artifact. External reference links do not import source
or grant permission to copy it.

For each distributable, generate an inventory from its exact locked feature/target
graph and included source/data. Keep license texts and copyright attribution;
identify modified upstream files and retain their pins/patches/provenance.
For permissive components, carry the notices required by their actual text.
For Apache-licensed components, include the license, identify changes and retain
applicable upstream NOTICE material if supplied. If a selected dependency has
source-availability/copyleft requirements, satisfy its actual distribution/linkage
terms or choose a compatible reviewed alternative. Do not invent a blanket
relicensing rule or substitute this paragraph for those texts.

Every future native/SDK/contract/source bundle must contain applicable third-party
notices or a durable bundled notice directory. Validate packed contents against
the dependency inventory. Where a license, author attribution or contribution
right is uncertain, record it as a release blocker for the affected artifact and
obtain an authorized decision. Never manufacture a root LICENSE to make packaging
checks pass. [Contribution policy](../CONTRIBUTING.md) does not impose an unstated
CLA or copyright assignment.

Dependency maintenance requires scanning all independent Cargo lockfiles and the
Python lock, not just the root workspace. Record advisory database/date and
target/feature scope; assess yanked/unmaintained dependencies and cryptographic
code separately. The retained `dependency-audit.json` is an October snapshot,
not a current advisory clearance. Proposed monitoring cadence and accountability
are in [maintenance](MAINTENANCE.md).
