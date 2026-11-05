# Security policy

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Report it privately through
[GitHub Security Advisories](https://github.com/aoheyra/aoMesh/security/advisories/new)
("Report a vulnerability") on this repository. The maintainers will acknowledge
the report, investigate and coordinate a fix and disclosure with you.

Include the affected area (packet codec, forwarding, store and sync, presence,
…), the `MSH-xx` issue if known, impact and a minimal reproducer or seed if
you have one. Simulator repros are ideal: paste the failing seed.

## Scope

In scope: anything that lets a remote or local peer crash or panic the
engine, loop or amplify traffic, exhaust the store or queues, forge or
suppress packets, or bypass rate limits and quotas.

Not in scope: issues that require a compromised local device; sibling crates
(`aoNetwork`, `aoIdents`, `aoheyra`), reported against their own repos.

## Supported versions

Pre-`v0.1.0` the `master` branch is the only supported target; fixes land
there. After the `v0.1.0` tag, security fixes are backported to the latest
minor line.
