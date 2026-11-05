# Governance and release authority

Baseline: 2026-11-05. No maintainers, organization ownership, quorum of people,
security contact or succession rights are appointed by this document. Existing
copyright/hosting authority is preserved. Git authorship alone does not establish
current publishing permission, custody or copyright ownership.

The following roles must be explicitly appointed by the repository's existing
authorized decision makers before an operated production release:

| Role | Responsibility | Present documentation status |
| --- | --- | --- |
| Project steward | Product scope, contributor rights decisions, appointments and succession | Unassigned here |
| Contract/security owner | ABI, authority/accounting/lifecycle review, security response | Unassigned here |
| Client/service owner | SDK, dApp, schema compatibility and data accuracy | Unassigned here |
| Operations owner | Hosting, history, TTL, backups, funding and incident coverage | Unassigned here |
| Release authority | Candidate approval, verified signing/publishing credentials and artifact retention | Unassigned here |

The [maintenance matrix](docs/MAINTENANCE.md) describes component obligations.
The current registrar/tenant/operator addresses in deployment records are
on-chain authorities, not appointments to these project roles. Service operators
cannot override contract permissions by governance resolution.

Routine changes require component review. Changes to public semantics, support
policy, trust, economics, storage or cryptographic assumptions require a written
[decision record](docs/DECISIONS.md) with alternatives, consequences and acceptance
evidence. Release approval records candidate source/artifact identity, approver
roles, checks and unresolved limits. Security-sensitive changes require a reviewer
other than the author and independent expertise where the assurance claim needs it.
No release can waive unimplemented authorization, unresolved rights or an unsafe
recovery backend through a policy vote.

An actual release needs verified repository/package/hosting permissions and an
approved publisher key, separate from customer contract approval keys. Repository
admin rights, branch protection, private reporting, tag protection and release
signing must be configured and verified; this policy does not enable them.
No public token voting or on-chain project-governance system exists.

Succession procedure to adopt when roles are appointed: document outgoing and
incoming consent through authenticated project channels, verify permissions and
key fingerprints, transfer repository/package/storage/alert access, test backup
and release verification, revoke former credentials and publish the effective
role change. If an owner is unavailable, existing authorized governance must
resolve authority before transferring access; do not infer control from silence.
Avoid a single unrecoverable hosting/release credential, and keep recovery access
separate from approval keys. This is a future operational requirement, not a
claim that redundant access or custody is configured.

Disagreements should be documented in the relevant issue/decision with concrete
technical evidence. Unresolved critical security or compatibility objections
block affected releases until an accountable decision and verification exist.
Code-of-conduct concerns follow [conduct policy](CODE_OF_CONDUCT.md); vulnerability
reports follow [security policy](SECURITY.md). Neither route invents a private
contact or response-time guarantee.
