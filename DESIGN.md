# authz — design

Status: v0.1 design. Implementation pending.

## 1. Goals

- Provide a small, embeddable Go module that lets a host application
  decide whether an authenticated subject is allowed to perform an
  action.
- Be **authentication-agnostic**. The host's auth-N layer produces an
  identity; authz consumes it as an opaque interface.
- Be **module-aware**. Multiple modules in one host (faq, blog,
  newsletter, ...) share the same role table without their roles
  colliding.
- Be **federation-safe**. A user signed in via a federated IdP
  (Google, GitHub) is treated identically to a user signed in via the
  host's own Keycloak. No IdP, owned or otherwise, can grant a role
  the host didn't write to the local store.
- Be **revocable in real time**. Revoking a role takes effect on the
  next request, not on the next token refresh.

## 2. Non-goals (v0.1)

- **Per-resource permissions.** "Alice is admin of subsite 42" is not
  in authz. That belongs in the consuming module's own schema with a
  real foreign key. authz handles `(issuer, subject, module, role)`
  and nothing finer.
- **Role hierarchies / inheritance.** A user either has a role or they
  don't. If "admin implies editor" is wanted, the consuming code
  checks both — or the role-grant logic in the host writes both.
- **JIT seeding from JWT claims.** Tempting but a federation footgun.
  See §4.
- **Centralized role management from the IdP.** Same reason. Roles
  live exclusively in authz's database.
- **Distributed role replication.** Each host application has its own
  authz table. "Admin in osg" and "admin in sf" are independent
  grants for the same OIDC subject.

## 3. The trust model

```
+----------+      +---------------+      +------------------+
| OIDC IdP | ---> | host auth-N   | ---> | authz.Resolver   |
| (any)    |      | (cookie/JWT)  |      | (this library)   |
+----------+      +---------------+      +------------------+
                          |                       |
                          v                       v
                 identity (iss, sub,        roles, looked up
                  email, name)              in local store
```

The clean separation:

- **The IdP authenticates.** It tells us this request belongs to OIDC
  subject `sub-abc123` at issuer `https://auth.example.com`. The host
  validates the token. authz believes that.
- **The local store authorizes.** authz reads
  `authz_user_roles WHERE (issuer, subject) = ($1, $2)` and returns
  the granted roles. The host decides what to do with them.

Claims never carry roles, even from trusted issuers. Even from your
own Keycloak. Reasons:

1. **Federation cleanliness.** If `accounts.google.com` could ever
   contribute a role claim that authz read, the trust model would have
   to enumerate which IdPs are role-trusted and which aren't. By
   simply not reading role claims, this distinction collapses.
2. **Revocation latency.** A JWT with a one-hour expiry that includes
   `roles: ["admin"]` keeps that admin role for an hour after the IdP
   revokes it. Reading from the local store closes that gap.
3. **Audit clarity.** Every grant has a `granted_by` field that
   identifies the operator. There is no "this came from the JWT" case
   to disambiguate in the logs.

## 4. Schema

```sql
CREATE TABLE authz_user_roles (
    issuer      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    module      TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by  TEXT NOT NULL,
    PRIMARY KEY (issuer, subject, module, role)
);
CREATE INDEX authz_user_roles_lookup_idx ON authz_user_roles (issuer, subject);
```

**module** is the URL-safe name of the consuming module ("faq", "blog",
"sf") or the empty string for a global grant. The empty-string-not-NULL
convention sidesteps the Postgres NULL-distinct-in-unique-constraint
gotcha and makes the API symmetric: callers always pass a string.

**granted_by** is free-text but conventional:
- `cli:<operator>` — granted via authzctl
- `host:<application>:<endpoint>` — granted via the host's admin UI

**Idempotency.** The PK makes grants idempotent: `ON CONFLICT (issuer,
subject, module, role) DO NOTHING`. Re-granting the same tuple is a
no-op; `granted_at` is preserved from the first grant so the audit
trail records when the role was actually conferred, not the last time
someone re-ran authzctl.

**SQLite parity.** The SQLite migration produces the same logical
schema with `TIMESTAMPTZ` mapped to `TEXT NOT NULL DEFAULT (datetime('now'))`.
Both backends pass the same Store-contract test suite.

## 5. The Store interface

```go
type Grant struct {
    Issuer, Subject, Module, Role string
    GrantedBy string
}

type Principal struct {
    Issuer, Subject string
    DisplayName, Email string
    Roles []string
}

type Store interface {
    // Roles returns every role granted to (issuer, subject) where
    // module IN ('', requested). Result is deduplicated and sorted.
    Roles(ctx context.Context, issuer, subject, module string) ([]string, error)

    // Grant inserts a role assignment. Idempotent on the PK.
    Grant(ctx context.Context, g Grant) error

    // Revoke removes a specific (issuer, subject, module, role) tuple.
    // Hard delete. No-op if the tuple doesn't exist.
    Revoke(ctx context.Context, issuer, subject, module, role string) error

    // Holders lists every (issuer, subject) holding role in any module.
    // Returns up to holdersMaxRows rows (10k); callers that hit the cap
    // get a non-nil cap-hit signal so the CLI can warn.
    Holders(ctx context.Context, role string) ([]Principal, error)
}
```

Postgres and SQLite implementations live alongside in the same module
(`postgres.go`, `sqlite.go`). Both pass `store_test.go`'s table-driven
test set.

## 6. The Resolver

```go
// IdentitySource extracts an authenticated identity from an HTTP
// request. Implementations include an oidclient adapter (cookie/JWT),
// an mTLS adapter (client cert), or anything else that can produce
// (issuer, subject, email, name) from the request.
type IdentitySource interface {
    // Identify returns the authenticated subject for r. Returns
    // (nil, nil) for anonymous, (nil, err) for present-but-invalid
    // credentials (the host should produce 401, not 500).
    Identify(r *http.Request) (*Identity, error)
}

type Identity struct {
    Issuer, Subject string
    DisplayName, Email string
}

type Resolver struct {
    Source IdentitySource
    Store  Store
    Module string  // "" for a global checker; "faq" for the faq mount, etc.
}

func (r *Resolver) Resolve(ctx context.Context, req *http.Request) (*Principal, error)
```

The Resolver depends only on `IdentitySource` — an interface defined
in authz itself. authz does not import `oidclient` or any other
specific auth-N package. A trivial adapter in the host wires
oidclient's `*Client` into the interface; the same pattern works for
mTLS or API-key auth.

The interface is named `IdentitySource` rather than `CookieValidator`
deliberately: the contract is "produce an identity from a request,"
not "validate a cookie." Naming it after the typical implementation
would mislead non-cookie consumers and require renaming after v1.0.

## 7. JIT, trust policies, and what they're not

Earlier design iterations included a per-issuer `TrustPolicy` that
mapped JWT role claims into local grants at login time. We dropped
it. The reasons:

- **It blurs the trust boundary.** Some claims are honored, others
  aren't, by configuration. The audit story becomes "I think this was
  granted by JIT from the Keycloak claim, unless an operator manually
  granted it, in which case granted_by would say that — let me check."
- **It complicates federation.** The minute one IdP's claims are
  honored, every other IdP becomes "the one whose claims we *don't*
  honor," which is a permissions decision dressed up as an integration
  detail.
- **It doesn't solve a real problem.** Bootstrapping admins is a
  one-time operation per consuming application. `authzctl grant` is
  enough. Ongoing admin grants happen rarely and benefit from an
  explicit operator action — that's the audit win.

If a future need arises for IdP-driven provisioning at scale, the
right pattern is **SCIM** (RFC 7644), not JIT-from-claims. SCIM is a
push protocol from the IdP into the application's user/role store and
respects the auth-Z/auth-N split. A future `infodancer/authzscim` is
imaginable as a peer module that writes to the same `authz_user_roles`
table. Not in v0.1 scope.

## 8. The CLI (authzctl)

```
authzctl --driver postgres --dsn $DATABASE_URL grant ISSUER SUBJECT ROLE [--module M] [--by OPERATOR]
authzctl --driver postgres --dsn $DATABASE_URL revoke ISSUER SUBJECT ROLE [--module M]
authzctl --driver postgres --dsn $DATABASE_URL roles ISSUER SUBJECT [--module M]
authzctl --driver postgres --dsn $DATABASE_URL holders ROLE
authzctl --driver postgres --dsn $DATABASE_URL migrate
```

- `--driver` defaults to postgres; `sqlite` is also supported.
- `--dsn` is the connection string (postgres URL or sqlite file path).
- `--by` defaults to `cli:$USER` so even casual operators get
  attribution without thinking about it.
- `migrate` runs the embedded goose migrations for the selected
  driver.

The CLI is the canonical bootstrap path: granting the first global
admin before any UI exists. After bootstrap, the host's admin UI is
expected to take over for routine operations.

## 9. Migrations and goose ownership

The module ships migrations under `migrations/{postgres,sqlite}/` and
runs them via goose with table name `authz_goose_db_version`. Distinct
from the host application's `goose_db_version` so the two trees don't
shadow each other when sharing a database.

```go
// MigratePostgres applies all pending authz migrations against db.
// Safe to call repeatedly.
func MigratePostgres(ctx context.Context, db *sql.DB) error

// MigrateSQLite is the SQLite analogue. The host must have opened
// the connection with `?_pragma=foreign_keys(1)` or equivalent.
func MigrateSQLite(ctx context.Context, db *sql.DB) error
```

Consumer migration timing is the consumer's call. faq runs its own
`AutoMigrate` on startup; authz expects the same pattern.

## 10. Consuming the module

The faq integration is the reference case. Today faq embeds an admin
check that reads `claims.Roles` and matches against a config string.
The new shape:

```go
// faq calling code
resolver := &authz.Resolver{
    Source: hostOIDCAdapter,
    Store:  authz.NewPostgresStore(pool),
    Module: "faq",
}

faqMod, err := faq.New(faq.Config{
    DB:        pool,
    Resolver:  faqAuthzAdapter(resolver),  // ~15-line adapter to faquser.UserResolver
    // ...
})
```

The adapter projects `*authz.Principal` to `*faquser.User`:

```go
return &faquser.User{
    Subject: p.Subject,
    Issuer:  p.Issuer,
    DisplayName: p.DisplayName,
    Email: p.Email,
    Admin: slices.Contains(p.Roles, "admin"),
}
```

`Admin` is the only role faq currently understands. Future faq work
might add `moderator`, `subsite-admin`, etc., but per-subsite admin
remains a faq-table concern (see §2) — authz's `(module, role)` pair
isn't fine-grained enough for that.

## 11. Resolved design decisions

The following were settled during the 2026-05-19 design conversation
that produced v0.1:

- **Re-grant preserves the original `granted_at`.** `ON CONFLICT
  (issuer, subject, module, role) DO NOTHING`. Re-running authzctl
  grant against an existing tuple is a no-op. See §4.
- **Revoke is a hard delete.** No `revoked_at` column in v0.1.
  Revocation audit, if needed later, gets a separate
  `authz_revocations` table without changing the main table's hot
  path. See §5.
- **`authzctl holders` returns up to 10k rows.** Unbounded relative
  to grant-table sizes that realistic deployments will see (dozens
  to hundreds); the cap is a misuse guard, not a paging mechanism.
  Pagination revisited only if a real host hits the cap. See §5, §8.
- **The identity interface is `IdentitySource`, not `CookieValidator`.**
  The contract is identity-from-request; cookies are the typical
  implementation but not the contract. See §6.

## 12. Roadmap

- **v0.1** — Store interface + Postgres + SQLite + Resolver + authzctl
  + migrations + first faq consumer. Tag when faq integrates cleanly
  and the two backend test suites both pass under CI.
- **v0.2** — `authz_revocations` audit table if a consumer needs it.
  Possible `authzscim` peer for SCIM-driven provisioning if a real
  external need emerges. Pagination on holders if a host hits the cap.
- **v1.0** — API stability commitment after a second non-faq consumer
  has exercised the interface and shaken out edge cases.

