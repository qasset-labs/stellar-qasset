# Contributing to Q-Asset

Start with [architecture](docs/ARCHITECTURE.md), [contract interfaces](docs/CONTRACTS.md)
and [current reproduction](docs/QASSET_POC_EVIDENCE.md). This repository is
experimental; production and research scopes are separate. Follow the
[conduct policy](CODE_OF_CONDUCT.md) and [security reporting](SECURITY.md).

A repository-wide license/contribution grant is not published. Preserve every
existing copyright/license notice. Submit only material you are entitled to
share; identify third-party sources, their exact version and license. No CLA,
DCO/sign-off requirement, copyright assignment or automatic relicensing is
established here. Resolve intended contribution/distribution rights with the
repository's authorized decision makers before relying on redistribution; see
[license scope](docs/LICENSE_SCOPE.md).

For a change, describe the concrete problem and supported configuration in an
issue or pull request. Use the repository's
[issue tracker](https://github.com/qasset-labs/stellar-qasset/issues) for public
reproduction/support, without secrets or exploit details requiring coordination.
Keep source, evidence, documentation and tests consistent. Record current,
proposed and historical behavior explicitly. Prefer small changes, stable error
semantics and explicit scope to sweeping unrelated refactors.

Before a pull request:

1. Inspect local changes; preserve unrelated work and use explicit file paths.
   Do not include local identities, `.seed`, private logs, ignored build outputs
   or unrelated drafts. Public test keys must be labelled fixtures.
2. Run checks appropriate to the change. Documentation needs local links/anchors,
   examples, distribution dependencies and consistency checks. Contract/auth
   changes need actual host authorization and adversarial rollback/cache/replay
   cases. Do not replace security checks with blanket authorization mocks.
3. For behavior affecting recorded evidence, version the change and generate new
   evidence; preserve historical raw records. A new checksum cannot make a
   changed configuration historical truth. Do not run submitting/issuer-lock
   scripts as part of routine verification.
4. Reproduce relevant builds with locked dependencies from an exported candidate.
   The [release procedure](docs/OPERATIONS.md) distinguishes source checks from
   expensive proof execution and live-network checks. State what was not run.
5. Explain behavior, migration/compatibility impact, validation and remaining
   assumptions. Supply a decision record for a new trust boundary, economics,
   authority lifecycle, storage schema or public interface.

Review policy: the author does not solely approve a security-sensitive release.
Require a component-competent reviewer; authentication, custody, accounting,
recovery and migration changes additionally require security review. Proof-system
activation requires independent cryptographic review for exact code/parameters.
A reviewer checks supported/unsupported paths, conservation, bounded cost,
state/TTL lifecycle, actual credentials and package contents, not only happy-path
tests. Exceptions need a recorded rationale and accountable release approval;
unresolved security/rights gates block the affected release.

These are review requirements. No CI workflow, branch protection or enforced
approval rule is established by this file. Actual appointment and repository
controls follow [governance](GOVERNANCE.md). Do not commit, push, deploy or publish
as a side effect of a review or local validation request.
