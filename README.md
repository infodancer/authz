# authz

[![CI](https://github.com/infodancer/authz/actions/workflows/ci.yml/badge.svg)](https://github.com/infodancer/authz/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/infodancer/authz.svg)](https://pkg.go.dev/github.com/infodancer/authz)
[![Go Report Card](https://goreportcard.com/badge/github.com/infodancer/authz)](https://goreportcard.com/report/github.com/infodancer/authz)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Experimental — internal use.** This library is developed for
> [infodancer](https://github.com/infodancer) and [matthewjhunter](https://github.com/matthewjhunter)
> projects. The API is unstable and may change without notice.

A small authorization layer for Go web applications. authz provides a
role store keyed on `(issuer, subject, module, role)` plus a resolver
that maps an authenticated identity into a list of granted roles. It is
deliberately decoupled from authentication: it never reads roles from
JWT claims, federated or otherwise.

## The trust model

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

- **Identity** is whatever the host's auth-N layer produces. The host
  validates the request and constructs an `authz.Identity`
  `(issuer, subject, email, name)` — from OIDC, mTLS, API keys, any
  scheme. authz never sees the request; it has no HTTP dependency.
- **Roles** are looked up in authz's own `authz_user_roles` table. They
  are never read from claims. Even for IdPs you control. Federated
  IdPs (Google, GitHub, ...) are treated identically to your own.
- **Grants** happen out-of-band via `authzctl` or an admin UI in the
  consuming application. There is no JIT seeding from claims and no
  trust-policy configuration.

This costs you centralized role management from the IdP. It buys
immediate revocation, a crisp audit trail, and a federation story
that works trivially.

## Schema

One table, two backends (PostgreSQL and SQLite). The shape is the same:

```sql
CREATE TABLE authz_user_roles (
    issuer      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    module      TEXT NOT NULL DEFAULT '',  -- '' = global, otherwise module name
    role        TEXT NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by  TEXT NOT NULL,
    PRIMARY KEY (issuer, subject, module, role)
);
CREATE INDEX authz_user_roles_lookup_idx ON authz_user_roles (issuer, subject);
```

Migrations ship in `migrations/{postgres,sqlite}/` and run via the
module's own goose tree (table `authz_goose_db_version`) so they don't
collide with the host application's migration history.

## Use

```go
import "github.com/infodancer/authz"

// db is a *sql.DB opened with any PostgreSQL driver. A pgxpool host
// can wrap its pool with stdlib.OpenDBFromPool(pool).
if err := authz.MigratePostgres(ctx, db); err != nil {
    return err
}
store := authz.NewPostgresStore(db)

resolver := &authz.Resolver{
    Store:  store,
    Module: "faq",          // "" if this resolver checks global roles
}

// The host turns the request into an identity (anonymous requests are
// handled before this point), then asks authz for that identity's roles.
id := authz.Identity{Issuer: iss, Subject: sub, DisplayName: name, Email: email}
principal, err := resolver.Resolve(ctx, id)
```

`principal.Roles` carries both global roles (`module = ''`) and roles
granted with `module = "faq"`, deduped. `principal.HasRole("admin")`
is the typical check.

## Bootstrap

```
authzctl --driver postgres --dsn $DATABASE_URL grant \
    https://auth.example.com sub-uuid admin --module faq --by matthew
```

The CLI is also the canonical way to grant the first global admin
before any UI exists.

## See also

- [DESIGN.md](DESIGN.md) — full architecture rationale
- [infodancer/oidclient](https://github.com/infodancer/oidclient) — the auth-N
  side of the same toolchain

## License

Apache-2.0. See [LICENSE](LICENSE).
