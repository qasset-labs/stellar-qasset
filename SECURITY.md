# Security reporting and supported scope

Q-Asset is experimental Testnet infrastructure. The repository contains a limited
proof of concept, not the full Q-Asset product. No production custody release,
independent external security approval, paid response service or vulnerability
bounty is established. The immutable administrator, restricted counter and
unavailable seed verifier have different boundaries; see
[architecture](docs/ARCHITECTURE.md), [contracts](docs/CONTRACTS.md),
[authority findings](docs/POC_SECURITY_FINDINGS.md) and the preserved separate
[cryptographic/implementation review](docs/SECURITY_REVIEW.md).

## Reporting a vulnerability

No private reporting email/contact or enabled GitHub private-reporting feature
has been verified for this repository. Do not assume that posting an issue is
private. If the repository's Security tab actually offers private vulnerability
reporting, use that channel and verify its destination. Otherwise request a
private coordination route through a minimal public issue containing no exploit,
secrets or affected customer identity. Wait for an authenticated project route
before sharing sensitive details. This document cannot enable hosting features
or promise confidentiality for an unconfigured channel.

Provide affected source/artifact versions, network/generation, component,
preconditions, impact, public-fixture reproduction and any mitigation. Distinguish
forgery, policy bypass, resource failure, pre-inclusion rejection and included
transaction failure. Do not send real seeds, mnemonic phrases, private keys or
confidential customer records. Do not test against others' funds or lock an
existing issuer to demonstrate impact.

## Coordination process

An appointed security responder must acknowledge, reproduce, classify scope,
contain affected distributions/services and coordinate a fix and validation with
reporters. No responder, acknowledgement deadline or disclosure timer is assigned
here. Agree a practical disclosure plan based on exploitability, user mitigation
and release readiness; do not imply an indefinite embargo. Publish a factual
advisory with affected hashes/versions, prerequisites, fix/migration and remaining
limits, crediting reporters only with their consent.

Do not silently overwrite evidence or release artifacts. Emergency fixes retain
authorization/rollback tests and independent review proportional to risk. Service
shutdown is not on-chain revocation. Current fixed SAC administration cannot rotate
its operator or authorize `set_admin`; compromise/key loss may require an
issuer-specific migration and may leave capability unavailable.

## Versions and trust boundaries

There is no supported production version or established long-term support line.
The checked-in reference is Rust1.94.1/Soroban SDK25.3.2/Python SDK14.0.0 with
schema-v2 evidence; these are reproduction pins, not current network-support
promises. Historical pre-fix recovery deployment is superseded. Its public fixture
keys offer no security. Seed-proof authentication stays disabled until exact
cryptography, feasibility and lifecycle gates pass.

A source fix does not update an immutable deployed instance. Advisories must
identify deployed code separately. [Maintenance](docs/MAINTENANCE.md) and
[operations](docs/OPERATIONS.md) define target compatibility, patch, backup,
incident and retirement responsibilities. Branch protections, dependency alerts,
private reports and signed releases remain actual hosting/operational work.
