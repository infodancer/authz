# Security policy

## Reporting a vulnerability

Report privately via [GitHub's private vulnerability reporting][gh-pvr]
for this repository. As a fallback, you can email
matthewjayhunter@gmail.com with the subject line `[authz security]
<short description>`. Use PGP if you'd like — keys on keys.openpgp.org
under that address.

[gh-pvr]: https://github.com/infodancer/authz/security/advisories/new

This is a personal/internal-use library maintained on nights and
weekends; please don't expect commercial-grade response times, but I
will take credible reports seriously, especially anything that affects
the authorization decision path.

## In scope

- **Role lookup correctness** — anything that causes `Resolver.Resolve`
  to return a role the user was not granted, or to omit a role they
  were granted. This includes SQL injection in the store, off-by-one
  in module-scoping logic, and any path where claim data short-circuits
  the local store lookup (it shouldn't ever — claims are identity-only).
- **Cross-tenant leaks** — a query that, given `(issuer_A, subject_A)`,
  returns rows belonging to `(issuer_B, subject_B)`. The composite
  `(issuer, subject, module, role)` key is the only legitimate lookup
  shape.
- **CLI grant/revoke integrity** — `authzctl` writes must be auditable
  via `granted_by` and idempotent. A grant must not silently overwrite
  a different existing grant.
- **Migration safety** — migrations against a database with existing
  data must not lose or rewrite role assignments.

## Out of scope

- Authentication: validating tokens, checking signatures, managing
  cookies. That's [infodancer/oidclient](https://github.com/infodancer/oidclient)
  or whatever else the host plugs in as a `CookieValidator`.
- Per-resource permissions: this library tracks `(issuer, subject,
  module, role)`. Permissions scoped to a specific resource (this
  campaign, this subsite) belong in the consuming module's own schema
  where they can have a real foreign key.
- The host application's authorization decisions: authz provides the
  data; how the host translates `principal.Roles` into "allowed to
  edit X" is the host's responsibility.
- Centralized role management from an IdP. By design, roles do not
  come from JWT claims, so a misconfigured IdP can never escalate a
  user's privileges in any authz-using application.

## Cryptography

None. authz performs no signing, no key handling, no token validation.
The only cryptographic boundary is the host's auth-N layer, which
authz consumes as an opaque `CookieValidator` interface.
