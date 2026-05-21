// Package migrate applies authz's embedded schema migrations.
//
// It is deliberately a separate package: consumers that use only the role
// [github.com/infodancer/authz.Store] and Resolver get a pure-standard-
// library dependency, and only those that want authz to manage its own
// schema import this package and pull in goose. Hosts that run their own
// migration tooling can ignore it entirely and apply the SQL under
// migrations/ themselves.
package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	pgmig "github.com/infodancer/authz/migrations/postgres"
	sqlitemig "github.com/infodancer/authz/migrations/sqlite"
	"github.com/pressly/goose/v3"
)

// migrationsTable is authz's dedicated goose version table. Distinct from
// the default goose_db_version so the module's migration history does not
// collide with the host application's own goose tree when both share a
// database.
const migrationsTable = "authz_goose_db_version"

// Postgres applies the embedded PostgreSQL migrations against db. Safe to
// call repeatedly; goose tracks applied versions in
// authz_goose_db_version. The caller owns db and its driver registration
// (typically the pgx stdlib driver).
func Postgres(ctx context.Context, db *sql.DB) error {
	return run(ctx, db, goose.DialectPostgres, pgmig.FS)
}

// SQLite applies the embedded SQLite migrations against db. Safe to call
// repeatedly. The caller owns db and its driver registration (typically
// modernc.org/sqlite).
func SQLite(ctx context.Context, db *sql.DB) error {
	return run(ctx, db, goose.DialectSQLite3, sqlitemig.FS)
}

func run(ctx context.Context, db *sql.DB, d goose.Dialect, fsys fs.FS) error {
	p, err := goose.NewProvider(d, db, fsys,
		goose.WithTableName(migrationsTable),
		goose.WithLogger(goose.NopLogger()),
	)
	if err != nil {
		return fmt.Errorf("authz: goose provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("authz: goose up: %w", err)
	}
	return nil
}
