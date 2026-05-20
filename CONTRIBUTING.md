# Contributing

## Local development

Requires Go (see `.github/workflows/ci.yml` for the version),
[Task](https://taskfile.dev), and Docker (the PostgreSQL test cases run
against a real database via testcontainers; the SQLite cases need neither).

```
task test       # tests with race detector (both backends)
task check      # fmt + vet + lint + test + vulncheck
task build      # build authzctl into ./bin/
task install    # install authzctl to $GOPATH/bin
```

`task check` is the gate for "ready to push" — CI runs the same checks.

## Conventions

- **Authentication is out of scope.** authz never validates tokens or reads
  roles from claims. It consumes identity through the `IdentitySource`
  interface and looks up roles in its own store. See [DESIGN.md §3](DESIGN.md).
- **Dual backend.** PostgreSQL and SQLite live behind one `dbStore` on
  `database/sql`, differing only by a dialect (placeholder syntax). Every
  behavioral test runs against both via the `eachBackend` helper. Migrations
  ship per-backend under `migrations/{postgres,sqlite}/`.
- **No postgres driver in library code.** The caller opens the `*sql.DB` with
  their own driver and hands it over. Binaries (`cmd/authzctl`) register the
  drivers they need.
- All table and type names are prefixed `authz_` so the schema coexists with a
  host application's schema in a shared database. Migrations run under a
  dedicated `authz_goose_db_version` table.
- All exported symbols carry doc comments.
- Tests are table-driven against both backends, with an error-path case per
  behavior.

## Design changes

Substantive design changes belong in [DESIGN.md](DESIGN.md). Treat it as the
source of truth; PR discussion of architecture should reference section numbers
there. The four decisions settled for v0.1 (re-grant preserves `granted_at`,
hard-delete revoke, 10k holders cap, `IdentitySource` over `CookieValidator`)
are recorded in §11.
